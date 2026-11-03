#!/usr/bin/env python3
"""Shared helpers for the Arthas stage-0 experiments. Test-only code, not part of the product.

Every experiment writes its raw results as JSON under $JA_OUT/<experiment>/ (default ./results).
The attach and API calls go through bin/ja-attach (run with sudo: it needs root to send SIGQUIT,
enter the container network namespace and read /proc of the container's processes).
"""
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
BIN = ROOT / "bin" / "ja-attach"
RUN = ROOT / "run"
OUT = pathlib.Path(os.environ.get("JA_OUT", ROOT / "results"))
PROJECT = os.environ.get("COMPOSE_PROJECT_NAME", "jvm-arthas")
PROFILES = ["--profile", "jre", "--profile", "variants"]

# All command names Arthas 4.3.5 registers (@Name values under core/.../command).
ALL_COMMANDS = ("base64 cat classloader cls dashboard dump echo getstatic grep groovy heapdump help history "
                "jad jfr july jvm keymap line logger mbean mc memory monitor ognl options perfcounter profiler "
                "pwd redefine reset retransform sc session sm stack stop sysenv sysprop tee thanks thread trace "
                "tt version vmoption vmtool watch").split()
# Commands the plan allows at level L1 (section 4) plus the two the cleanup needs.
L1_COMMANDS = "dashboard thread jvm memory sc sm classloader logger sysprop version session help stop reset".split()
L2_COMMANDS = L1_COMMANDS + "watch trace stack monitor jad".split()

ARTHAS_FLAVOR = {"min": "/opt/arthas-min", "minlog": "/opt/arthas-minlog", "stock": "/opt/arthas-stock"}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, file=sys.stderr, flush=True)


def run(args, check=True, timeout=300, input=None, cwd=None):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input, cwd=cwd)
    if check and p.returncode != 0:
        raise RuntimeError(f"{args} -> {p.returncode}\n{p.stdout}\n{p.stderr}")
    return p


def compose(*args, **kw):
    return run(["docker", "compose", *PROFILES, *args], cwd=ROOT, **kw)


def http_get(url, timeout=5):
    """GET without any proxy (the environment sets http_proxy and Python's no_proxy has no CIDR support)."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(url, timeout=timeout) as r:
        return r.read().decode()


def write_json(exp, name, data):
    d = OUT / exp
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str))


def disabled_for(enabled):
    return ",".join(sorted(set(ALL_COMMANDS) - set(enabled)))


class Target:
    """One compose service and its JVM."""

    def __init__(self, svc):
        self.svc = svc
        self.container = f"{PROJECT}-{svc}-1"
        self.pw_file = RUN / "secrets" / f"{svc}.pw"
        self.opts_file = RUN / "secrets" / f"{svc}.opts"
        (RUN / "secrets").mkdir(parents=True, exist_ok=True)
        self.http_port = None
        self.arthas_port = None

    # lifecycle ---------------------------------------------------------------------------------
    def up(self, recreate=True, wait=120):
        args = ["up", "-d"] + (["--force-recreate"] if recreate else []) + [self.svc]
        if recreate:
            (RUN / self.svc / "logs").mkdir(parents=True, exist_ok=True)
            for f in (RUN / self.svc / "logs").glob("*"):
                try:
                    f.unlink()
                except OSError:
                    run(["sudo", "rm", "-rf", str(f)])
        compose(*args)
        self.wait_ready(wait)
        return self

    def down(self):
        compose("rm", "-sf", self.svc)

    def wait_ready(self, wait=120):
        end = time.time() + wait
        while time.time() < end:
            try:
                if http_get(f"http://{self.ip()}:8080/ping", 2) == "pong":
                    time.sleep(2)
                    return
            except Exception:
                pass
            time.sleep(1)
        raise RuntimeError(f"{self.svc} did not become ready")

    # lookups -----------------------------------------------------------------------------------
    def ip(self):
        out = run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.container]).stdout
        return out.strip()

    def pid(self):
        out = run(["docker", "top", self.container, "-eo", "pid,args"]).stdout
        for line in out.splitlines()[1:]:
            pid, _, args = line.strip().partition(" ")
            if re.search(r"(^|/)java( |$)", args.strip().split(" ")[0]) or "java " in args[:40]:
                return int(pid)
        raise RuntimeError(f"no java process in {self.container}")

    def cgroup(self):
        cid = run(["docker", "inspect", "-f", "{{.Id}}", self.container]).stdout.strip()
        return pathlib.Path(f"/sys/fs/cgroup/system.slice/docker-{cid}.scope")

    def diag(self):
        return json.loads(http_get(f"http://{self.ip()}:8080/diag"))

    def docker_exec(self, *args, user=None, check=False, timeout=120):
        cmd = ["docker", "exec"] + (["-u", user] if user else []) + [self.container, *args]
        return run(cmd, check=check, timeout=timeout)

    def logs(self, since=None):
        a = ["docker", "logs"] + (["--since", since] if since else []) + [self.container]
        p = run(a, check=False)
        return p.stdout + p.stderr

    # arthas ------------------------------------------------------------------------------------
    def new_secret(self):
        pw = secrets.token_hex(16)
        self.pw_file.write_text(pw)
        os.chmod(self.pw_file, 0o600)
        return pw

    def attach(self, enabled=L1_COMMANDS, flavor="minlog", port=18563, session_timeout=300, extra="", pw=None,
               raw_opts=None, **load_kw):
        """Loads Arthas with the section 3.1 parameters. Returns ja-attach's JSON result."""
        pw = pw or self.new_secret()
        self.arthas_port = port
        opts = (f"telnetPort=-1;httpPort={port};ip=127.0.0.1;password={pw};localConnectionNonAuth=false;"
                f"mcpEndpoint=;disabledCommands={disabled_for(enabled)};sessionTimeout={session_timeout}")
        if extra:
            opts += ";" + extra
        if raw_opts is not None:
            opts = raw_opts.replace("@PW@", pw)
        self.opts_file.write_text(opts)
        os.chmod(self.opts_file, 0o600)
        base = ARTHAS_FLAVOR[flavor]
        args = ["sudo", str(BIN), "load", "-pid", str(self.pid()), "-agent", f"{base}/arthas-agent.jar",
                "-core", f"{base}/arthas-core.jar", "-opts-file", str(self.opts_file)]
        load_kw.setdefault("file_owner", "target")
        load_kw.setdefault("conn_user", "target")
        for k, v in load_kw.items():
            args += [f"-{k.replace('_', '-')}", str(v)]
        return json.loads(run(args, timeout=120).stdout)

    def api(self, action=None, cmd=None, session=None, consumer=None, exec_timeout=None, auth=True, port=None,
            method="POST", path="/api", timeout=120, body=None, pass_file=None):
        args = ["sudo", str(BIN), "api", "-pid", str(self.pid()), "-port", str(port or self.arthas_port),
                "-method", method, "-path", path, "-timeout", f"{timeout}s"]
        if action:
            args += ["-action", action]
        if cmd:
            args += ["-cmd", cmd]
        if session:
            args += ["-session", session]
        if consumer:
            args += ["-consumer", consumer]
        if exec_timeout:
            args += ["-exec-timeout", str(exec_timeout)]
        if body:
            args += ["-body", body]
        if not auth:
            args += ["-no-auth"]
        else:
            args += ["-pass-file", str(pass_file or self.pw_file)]
        p = run(args, timeout=timeout + 30)
        return json.loads(p.stdout)

    def exec(self, cmd, exec_timeout=None, **kw):
        r = self.api("exec", cmd=cmd, exec_timeout=exec_timeout, **kw)
        return r

    def probe(self, secret=True, all_threads=False):
        args = ["sudo", str(BIN), "probe", "-pid", str(self.pid())]
        if secret and self.pw_file.exists():
            args += ["-secret-file", str(self.pw_file)]
        if all_threads:
            args += ["-all-threads"]
        return json.loads(run(args).stdout)

    def inspect(self):
        return json.loads(run(["sudo", str(BIN), "inspect", "-pid", str(self.pid())]).stdout)


def results_of(resp):
    """Flattens the Arthas exec response to (state, [result dicts])."""
    b = (resp.get("body") or {})
    inner = b.get("body") or {}
    return b.get("state"), inner.get("results") or [], inner


def short(resp):
    st, res, inner = results_of(resp)
    return {"http": resp.get("status"), "state": st, "jobStatus": inner.get("jobStatus"),
            "types": [r.get("type") for r in res], "message": (resp.get("body") or {}).get("message"),
            "elapsed_ms": resp.get("elapsed_ms"), "error": resp.get("error")}
