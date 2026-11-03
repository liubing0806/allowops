#!/usr/bin/env python3
"""Stage-0 item 1: do the agent parameters of plan section 3.1 take effect, and does the password leak?

Usage: exp_params.py [svc ...]    (default: jdk8 jdk11 jdk17 jdk21 for the main run, jdk17 jdk8 for the variations)
"""
import sys

from ja import *

EXP = "item1-params"
SECRET_PLACES = ["/home", "/tmp", "/app", "/logs", "/root", "/var/tmp"]


def listener_ports(p):
    return sorted({(x["proto"], x["addr"], x["port"]) for x in p["listeners"]})


def scan_secret(t, pw):
    """Looks for the password in every file the container can show us, in docker logs and in /proc."""
    found = []
    q = pw
    for place in SECRET_PLACES:
        r = t.docker_exec("sh", "-c", f"grep -rIl --exclude-dir=proc -F '{q}' {place} 2>/dev/null", user="0")
        found += [f"file:{ln}" for ln in r.stdout.split() if ln]
    if q in t.logs():
        found.append("docker logs (stdout/stderr of the JVM)")
    for f in (RUN / t.svc / "logs").glob("*"):
        try:
            if q in f.read_text(errors="ignore"):
                found.append(f"jvm log: {f.name}")
        except OSError:
            pass
    pr = t.probe()
    found += [f"proc:{x}" for x in pr.get("secret_found", [])]
    return found


def main_run(svc):
    t = Target(svc).up()
    res = {"svc": svc}
    base = t.probe(secret=False)
    res["baseline_listeners"] = listener_ports(base)
    res["baseline_threads"] = base["status"]["threads"]
    res["baseline_diag"] = t.diag()

    a = t.attach()
    res["attach"] = a
    time.sleep(2)
    p = t.probe()
    res["after_attach_listeners"] = listener_ports(p)
    res["new_listeners"] = [x for x in listener_ports(p) if x not in res["baseline_listeners"]]
    res["arthas_threads"] = p["arthas_threads"]
    res["arthas_fds"] = p["arthas_fds"]
    res["threads_after"] = p["status"]["threads"]

    # authentication
    res["auth_none"] = short(t.exec("version", auth=False))
    wrong = RUN / "secrets" / "wrong.pw"
    wrong.write_text("not-the-password")
    res["auth_wrong"] = short(t.exec("version", pass_file=wrong))
    res["auth_right"] = short(t.exec("version"))
    res["auth_right_version"] = [r.get("version") for r in results_of(t.exec("version"))[1] if r.get("type") == "version"]
    res["auth_console_root_none"] = short(t.api(method="GET", path="/", auth=False))
    # the telnet port is closed, and the HTTP port is not reachable from outside the namespace
    res["telnet_3658"] = t.api("exec", cmd="version", port=3658, auth=False).get("error")
    out = run(["sudo", str(BIN), "api", "-host-ns", "-host", t.ip(), "-port", str(t.arthas_port), "-action", "exec",
               "-cmd", "version", "-no-auth"]).stdout
    res["from_host_to_container_ip"] = json.loads(out).get("error")
    # MCP
    res["mcp_with_auth"] = short(t.api(method="GET", path="/mcp"))
    res["mcp_post_with_auth"] = short(t.api(method="POST", path="/mcp", body="{}"))
    # disabled commands: all must answer "command not found"
    dis = {}
    for c in ["ognl '1+1'", "watch demo.HotService work", "redefine /x.class", "vmtool --action getInstances", "heapdump /tmp/x.hprof",
              "tt -t demo.HotService work", "profiler start", "mc /x.java", "jad demo.HotService", "trace demo.HotService work",
              "stack demo.HotService work", "monitor demo.HotService work", "sysenv", "getstatic a b", "vmoption", "options"]:
        dis[c] = (short(t.exec(c)).get("message") or "")[:120]
    res["disabled_commands"] = dis
    ena = {}
    for c in ["version", "jvm", "memory", "dashboard -n 1", "thread -n 5", "thread -b", "sc -d demo.HotService", "sm -d demo.HotService work",
              "classloader -t", "logger", "sysprop java.version", "session"]:
        ena[c] = short(t.exec(c, exec_timeout=20000))
    res["enabled_commands"] = ena
    # does Arthas output contain the password?
    leak_out = []
    for c in ["session", "jvm", "sysprop", "dashboard -n 1", "thread -n 5"]:
        r = t.exec(c if c != "sysprop" else "sysprop java.version", exec_timeout=20000)
        if open(t.pw_file).read() in json.dumps(r):
            leak_out.append(c)
    res["password_in_command_output"] = leak_out
    # password in logs / files / proc
    res["password_found_in"] = scan_secret(t, open(t.pw_file).read())
    # where Arthas wrote its files
    fnd = t.docker_exec("sh", "-c", "find / -xdev \\( -name 'arthas*' -o -name 'logs' \\) -newer /app/app.jar 2>/dev/null | grep -v '^/proc' | head -20", user="0")
    res["new_arthas_files"] = fnd.stdout.split()
    res["arthas_log_head"] = t.docker_exec("sh", "-c", "tail -n 40 /home/app/logs/arthas/arthas.log", user="0").stdout
    res["target_stdout_tail"] = t.logs().splitlines()[-15:]
    write_json(EXP, f"main-{svc}.json", res)
    return res


def variation(svc, name, flavor, raw_opts, check_none=True, port=18563, extra_ports=(), literal_pw=None, alt_pw=None):
    """Attach with deliberately different parameters on a fresh JVM and record what is reachable."""
    t = Target(svc).up()
    base = t.probe(secret=False)
    a = t.attach(flavor=flavor, raw_opts=raw_opts, port=port)
    time.sleep(2)
    p = t.probe(secret=False)
    r = {"variation": name, "flavor": flavor, "opts_template": raw_opts, "attach_ok": a["ok"], "attach_reply": a.get("reply"),
         "agent_arg_len": a.get("agent_arg_len"),
         "new_listeners": [x for x in listener_ports(p) if x not in listener_ports(base)]}
    if literal_pw is not None:
        t.pw_file.write_text(literal_pw)
        r["auth_with_literal_pw"] = short(t.api("exec", cmd="version"))
        alt = RUN / "secrets" / "alt.pw"
        alt.write_text(alt_pw)
        r["auth_with_decoded_pw"] = short(t.api("exec", cmd="version", pass_file=alt))
    ports = [port, *extra_ports]
    for pt in ports:
        r[f"port{pt}_noauth_exec"] = short(t.api("exec", cmd="version", port=pt, auth=False))
        r[f"port{pt}_auth_exec"] = short(t.api("exec", cmd="version", port=pt))
        r[f"port{pt}_mcp_noauth"] = short(t.api(method="GET", path="/mcp", port=pt, auth=False))
        r[f"port{pt}_mcp_auth"] = short(t.api(method="GET", path="/mcp", port=pt))
    r["ognl_noauth"] = short(t.api("exec", cmd="ognl '1+1'", auth=False))
    r["arthas_log_tail"] = t.docker_exec("sh", "-c", "tail -n 25 /home/app/logs/arthas/arthas.log", user="0").stdout
    out = t.logs().splitlines()
    r["target_stdout_lines_total"] = len(out)
    r["target_stdout_lines_debug"] = sum(1 for ln in out if " DEBUG " in ln)
    r["target_stdout_lines_arthas_error"] = [ln for ln in out if ln.startswith("[ERROR]")][:3]
    write_json(EXP, f"variation-{svc}-{name}.json", r)
    return r


def variations(svc):
    dis = disabled_for(L1_COMMANDS)
    base = "telnetPort=-1;httpPort=18563;ip=127.0.0.1;password=@PW@;localConnectionNonAuth=false;mcpEndpoint=;disabledCommands=" + dis
    out = []
    # a: stock properties file (as shipped) with the section 3.1 parameters
    out.append(variation(svc, "a-stock-props-plan-args", "stock", base))
    # g: the file set of plan section 6 (three jars + properties, no logback.xml)
    out.append(variation(svc, "g-min-no-logback", "min", base))
    # b: stock properties, mcpEndpoint not given in the args (the shipped /mcp must then win)
    out.append(variation(svc, "b-stock-props-no-mcp-arg", "stock",
                         "telnetPort=-1;httpPort=18563;ip=127.0.0.1;password=@PW@;localConnectionNonAuth=false;disabledCommands=" + dis))
    # c: stock properties, only a port (what a bare attach with defaults looks like): telnet 3658 + local no-auth
    out.append(variation(svc, "c-stock-props-bare", "stock", "httpPort=18563", extra_ports=(3658, 8563)))
    # d: password set but localConnectionNonAuth left at its default
    out.append(variation(svc, "d-password-without-localNonAuth-false", "minlog",
                         "telnetPort=-1;httpPort=18563;ip=127.0.0.1;password=@PW@;mcpEndpoint=;disabledCommands=" + dis))
    # e: password with characters the agent argument decoder treats specially
    out.append(variation(svc, "e-password-special-chars", "minlog",
                         "telnetPort=-1;httpPort=18563;ip=127.0.0.1;password=ab+cd%41ef;localConnectionNonAuth=false;mcpEndpoint=;disabledCommands=" + dis,
                         literal_pw="ab+cd%41ef", alt_pw="ab cdAef"))
    # f: no sessionTimeout and no disabledCommands (everything enabled) for reference
    out.append(variation(svc, "f-no-disabledCommands", "minlog",
                         "telnetPort=-1;httpPort=18563;ip=127.0.0.1;password=@PW@;localConnectionNonAuth=false;mcpEndpoint="))
    return out


if __name__ == "__main__":
    # exp_params.py main jdk8 jdk11 ...   |   exp_params.py var jdk17 jdk8   |   exp_params.py (everything)
    mode, which = (sys.argv[1], sys.argv[2:]) if len(sys.argv) > 1 else ("all", [])
    if mode in ("main", "all"):
        for s in which or ["jdk8", "jdk11", "jdk17", "jdk21"]:
            log("main run", s)
            main_run(s)
    if mode in ("var", "all"):
        for s in which or ["jdk17", "jdk8"]:
            log("variations", s)
            variations(s)
