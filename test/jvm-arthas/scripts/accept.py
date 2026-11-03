#!/usr/bin/env python3
"""Stage-2 acceptance: measurements of the jvm_arthas builtin (docs/arthas-stage2-acceptance-report.md).

Every call goes through bin/ja-call (acceptcall/), which runs jvmarthas.RunWith, the code path of the builtin,
and records the steps of the call, the memory and processes of the container and the hsperfdata counters.
Raw data goes to $JA_OUT/<experiment>/...; nothing touches the JVMs except the calls and, where stated, jcmd.

Run from test/jvm-arthas with COMPOSE_FILE=compose.yaml:compose.accept.yaml, a COMPOSE_PROJECT_NAME of its own
and JA_PORT_PREFIX at 32 or lower. Subcommands:

  latency   one JVM under load: warm-up, a before window, a window with jvm_arthas calls, an after window
            (items 1, 2, 3, 7, 8). Output: latency/<svc>/<scenario>/rep<k>/, readable by analyze.py.
  cycles    the four JVMs at once, no load: 3 Full GCs, 50 calls, 3 Full GCs (items 2, 3, 4, 5).
  leak      per command kind, a new JVM: 5 calls, 4 Full GCs, a class histogram (item 4).
  limits    the four JVMs at once under light load with the default checks and a kept state directory:
            a call every 61 s until the checks refuse (items 5, 9).
  metaspace JVMs with a MaxMetaspaceSize: calls until the metaspace check refuses (item 6).
"""
import argparse
import collections
import concurrent.futures
import subprocess
import sys
import threading

from ja import *
from bench import Collector, LOADGEN, LOAD_CPUS, PROFILES as LOAD_PROFILES

CALL = ROOT / "bin" / "ja-call"
FILES = RUN / "arthas-minlog"
CALL_CPUS = os.environ.get("CALL_CPUS", "12-15")
JDKS = ["jdk8", "jdk11", "jdk17", "jdk21"]
# Every L1 command kind; dashboard first because it takes longest.
ALL_KINDS = ["dashboard", "thread_top", "thread_blocking", "thread_info", "memory", "jvm", "class_info", "method_info",
             "classloader_tree", "classloader_list", "logger", "sysprop", "version"]
# compose.stage3.yaml sets LOGDIR=/logs-tmpfs; JA_LOGDIR_TMPFS tells keep_logs to read the JVM logs from there.
LOGDIR_TMPFS = os.environ.get("JA_LOGDIR_TMPFS", "")
# "Reference Handler" exists for the whole life of the JVM; its id differs on JDK 21 (9, and 10 with compose.stage3.yaml).
THREAD_ID = {"jdk21": 10 if LOGDIR_TMPFS else 9}


def ja_call(svc, out, label, kinds, calls=None, start=None, every=None, gap=None, state="fresh", extra=(), evidence=None):
    args = ["sudo", "-n", "taskset", "-c", CALL_CPUS, str(CALL), "-container", f"{PROJECT}-{svc}-1", "-files", str(FILES),
            "-kinds", ",".join(kinds), "-label", label, "-out", str(out), "-state", state, "-thread-id", str(THREAD_ID.get(svc, 2)),
            "-diag", f"http://{Target(svc).ip()}:8080/diag"]
    if calls:
        args += ["-calls", str(calls)]
    if start:
        args += ["-start", f"{start:.3f}"]
    if every:
        args += ["-every", f"{every}s"]
    if gap:
        args += ["-gap", f"{gap}s"]
    if evidence:
        args += ["-evidence", str(evidence)]
    return subprocess.run(args + list(extra), capture_output=True, text=True)


def snapshot(svc):
    p = run(["sudo", "-n", str(CALL), "-container", f"{PROJECT}-{svc}-1", "-snapshot"], check=False)
    try:
        return json.loads(p.stdout)
    except ValueError:
        return {"error": p.stderr}


def jvm_pid_in_container(t):
    for ln in t.docker_exec("jcmd", "-l").stdout.splitlines():
        if "app.jar" in ln:
            return ln.split()[0]
    raise RuntimeError("jcmd -l shows no app.jar")


def full_gc(t):
    """System.gc() through jcmd, which is a Full GC with G1 and the default flags."""
    t0 = time.time()
    p = t.docker_exec("jcmd", jvm_pid_in_container(t), "GC.run", timeout=120)
    return {"t": t0, "ms": round((time.time() - t0) * 1000), "rc": p.returncode}


def start_loadgen(t, d, total, flows, cpus=LOAD_CPUS):
    return subprocess.Popen(["sudo", "-n", "nice", "-n", "-10", "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                             "taskset", "-c", cpus, str(LOADGEN), "-base", f"http://{t.ip()}:8080", "-duration", f"{total}s", "-out", str(d / "load.jsonl"),
                             *[x for f in flows for x in ("-flow", f)]], stdout=subprocess.DEVNULL, stderr=open(d / "loadgen.err", "w"))


def keep_logs(t, svc, d):
    for f in (RUN / svc / "logs").glob("*"):
        run(["cp", str(f), str(d / f.name)], check=False)
    if LOGDIR_TMPFS:
        # compose.stage3.yaml: the JVM logs to a tmpfs of the container, which docker cp does not see
        for f in ("safepoint.log", "gc.log", "redefine.log"):
            p = t.docker_exec("cat", f"{LOGDIR_TMPFS}/{f}")
            if p.returncode == 0:
                (d / f).write_text(p.stdout)
    (d / "stdout.log").write_text(run(["docker", "logs", "--timestamps", t.container], check=False).stdout)


class Others(threading.Thread):
    """Every 10 s, from /proc only: the busy time of the cpus the test uses and the processes that used the most cpu in the
    interval, with the cpu each last ran on and its cgroup, so that the runs disturbed by other work can be found. With jvm_pid,
    also the 8 threads of that JVM that used the most cpu ("jvm_threads") and the number of its threads by name ("jvm_thread_names")."""

    def __init__(self, path, cpus="4-9,12-15", every=10.0, jvm_pid=None):
        super().__init__(daemon=True)
        self.path, self.every, self.stop_ev, self.jvm_pid = path, every, threading.Event(), jvm_pid
        self.cpus = {f"cpu{c}" for part in cpus.split(",") for c in range(int(part.split("-")[0]), int(part.split("-")[-1]) + 1)}

    @staticmethod
    def procs():
        out = {}
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                s = open(f"/proc/{pid}/stat").read()
            except OSError:
                continue
            rest = s[s.rindex(")") + 2:].split()
            out[pid] = (s[s.index("(") + 1:s.rindex(")")], int(rest[11]) + int(rest[12]), int(rest[36]))
        return out

    def threads(self):
        out = {}
        try:
            tids = os.listdir(f"/proc/{self.jvm_pid}/task")
        except OSError:
            return out
        for tid in tids:
            try:
                st = open(f"/proc/{self.jvm_pid}/task/{tid}/stat").read()
            except OSError:
                continue
            rest = st[st.rindex(")") + 2:].split()
            out[tid] = (st[st.index("(") + 1:st.rindex(")")], int(rest[11]) + int(rest[12]))
        return out

    def busy(self):
        out = {}
        for ln in open("/proc/stat"):
            f = ln.split()
            if f and f[0] in self.cpus:
                v = [int(x) for x in f[1:9]]
                out[f[0]] = sum(v) - v[3] - v[4]
        return out

    def run(self):
        prev_t, prev_p, prev_b = time.time(), self.procs(), self.busy()
        prev_th = self.threads() if self.jvm_pid else {}
        with open(self.path, "w") as f:
            while not self.stop_ev.wait(self.every):
                t, p, b = time.time(), self.procs(), self.busy()
                dt_s = t - prev_t
                rows = []
                for ticks, pid in sorted(((v[1] - prev_p[k][1], k) for k, v in p.items() if k in prev_p), reverse=True)[:12]:
                    if ticks <= 0:
                        break
                    try:
                        cg = open(f"/proc/{pid}/cgroup").read().strip().split("::")[-1][-48:]
                    except OSError:
                        cg = ""
                    rows.append({"pid": int(pid), "comm": p[pid][0], "cpu_pct": round(ticks / dt_s, 1), "last_cpu": p[pid][2], "cgroup": cg})
                rec = {"t": t, "seconds": round(dt_s, 2), "cpu_busy_pct": {k: round((b[k] - prev_b.get(k, b[k])) / dt_s, 1) for k in sorted(b)}, "top": rows}
                if self.jvm_pid:
                    th = self.threads()
                    top = sorted(((v[1] - prev_th[k][1], v[0]) for k, v in th.items() if k in prev_th), reverse=True)[:8]
                    rec["jvm_threads"] = [{"name": n, "cpu_pct": round(d / dt_s, 1)} for d, n in top if d > 0]
                    rec["jvm_thread_count"] = len(th)
                    # thread names (15 characters, from /proc) with the digits replaced, to see which threads a call leaves
                    names = collections.Counter(re.sub(r"\d+", "#", v[0]) for v in th.values())
                    rec["jvm_thread_names"] = dict(sorted(names.items()))
                    prev_th = th
                f.write(json.dumps(rec) + "\n")
                f.flush()
                prev_t, prev_p, prev_b = t, p, b


def start_probes(t, d, seconds, watch=True):
    """docs/arthas-jvm-pause-report.md section 7 item 4: host_io_probe.py on the file system of the repository (/) and on the one of
    the raw data, and pause_watch.py on the JVM; both run on the cpus of the calls and end by themselves after `seconds`."""
    here = pathlib.Path(__file__).resolve().parent
    (RUN / "io-probe-root").mkdir(parents=True, exist_ok=True)
    subprocess.Popen(["sudo", "-n", "taskset", "-c", CALL_CPUS, sys.executable, str(here / "host_io_probe.py"), str(d / "host_io.jsonl"), str(int(seconds)),
                      "--dir", str(RUN / "io-probe-root"), "--dir", str(OUT / "io-probe-data"), "--disk", os.environ.get("JA_DISK", "nvme0n1")],
                     stdout=subprocess.DEVNULL, stderr=open(d / "host_io.err", "w"))
    if watch:
        subprocess.Popen(["sudo", "-n", "taskset", "-c", CALL_CPUS, sys.executable, str(here / "pause_watch.py"), str(t.pid()), str(d / "watch.jsonl"), str(int(seconds))],
                         stdout=subprocess.DEVNULL, stderr=open(d / "watch.err", "w"))


def set_env(mem, java_extra=""):
    os.environ["APP_MEM"] = mem
    os.environ["JA_JAVA_EXTRA"] = java_extra


# latency --------------------------------------------------------------------------------------------------
def latency(a, rep):
    scenario = a.scenario
    d = OUT / "latency" / a.svc / scenario / f"rep{rep}"
    if (d / "done").exists():
        log("skip", d)
        return
    d.mkdir(parents=True, exist_ok=True)
    set_env(a.mem, a.java_extra)
    for other in JDKS:
        if other != a.svc:
            Target(other).down()  # an idle JVM on the same cpus is noise
    t = Target(a.svc).up()
    ip = t.ip()
    events = []
    ev = lambda what: events.append({"t": time.time(), "what": what})
    if a.retain:
        try:
            ev("retain " + http_get(f"http://{ip}:8080/load/retain?mb={a.retain}&size={a.retain_size}", 300))
        except Exception as e:
            ev(f"retain failed: {e!r}")
    col = Collector(t, d / "metrics.jsonl")
    col.start()
    total = a.warm + a.phase * 2 + a.after + 8 + 8 + 6
    others = None
    if a.probe:
        start_probes(t, d, total + 30)
        others = Others(d / "others.jsonl", jvm_pid=t.pid())
        others.start()
    lg = start_loadgen(t, d, total, LOAD_PROFILES[a.profile])
    t_start = time.time()
    try:
        if a.threads_total:
            time.sleep(min(20, a.warm / 2))
            live = json.loads(http_get(f"http://{ip}:8080/diag"))["threads"]
            n = max(0, a.threads_total - live)
            deep = f"&depth={a.depth}&holders={a.holders}&locks={a.locks}" if a.depth else ""
            ev(f"threads before {live}; " + http_get(f"http://{ip}:8080/load/threads?n={n}&blocked={a.blocked}{deep}", 120))
        elif a.blocked:
            ev(http_get(f"http://{ip}:8080/load/threads?n={a.blocked + 1}&blocked={a.blocked}", 60))
        time.sleep(max(0, t_start + a.warm - time.time()))
        b0 = int(time.time()) + 1
        time.sleep(b0 - time.time())
        ev("window before start")
        d0 = b0 + a.phase
        time.sleep(max(0, d0 - time.time()))
        ev("window during start")
        extra = []
        if a.threads_live:
            extra += ["-threads-live", str(a.threads_live)]
        if a.max_old_gen:
            extra += ["-max-old-gen", str(a.max_old_gen)]
        if a.kinds == "none":  # noise reference: the same windows without a call
            (d / "calls.jsonl").write_text("")
        else:
            kinds = a.kinds.split(",")
            p = ja_call(a.svc, d / "calls.jsonl", f"{a.svc}-{scenario}-rep{rep}", kinds, calls=a.calls or len(kinds), start=d0 + a.offset,
                        every=a.every, extra=extra, evidence=d / "calls")
            (d / "ja-call.err").write_text(p.stderr)
            ev(f"calls finished rc={p.returncode} {d0 + a.phase - time.time():.1f}s before the end of the window")
        time.sleep(max(0, d0 + a.phase - time.time()))
        a0 = d0 + a.phase + 8
        time.sleep(max(0, a0 - time.time()))
        ev("window after start")
        time.sleep(a.after)
        ev("window after end")
        (d / "live.json").write_text(http_get(f"http://{ip}:8080/diag/live", 30))
    finally:
        try:
            lg.wait(timeout=total - (time.time() - t_start) + 30)
        except subprocess.TimeoutExpired:
            lg.terminate()
        col.stop_ev.set()
        col.join(timeout=5)
        if others:
            others.stop_ev.set()
    meta = {"svc": a.svc, "scenario": scenario, "rep": rep, "profile": a.profile, "phase_s": a.phase, "warm_s": a.warm,
            "windows": {"before": [b0, b0 + a.phase], "during": [d0, d0 + a.phase], "after": [a0, a0 + a.after]},
            "events": events, "args": vars(a), "app_cpuset": os.environ.get("APP_CPUS", "4-7"), "load_cpus": LOAD_CPUS,
            "project": PROJECT, "image": run(["docker", "inspect", "-f", "{{.Image}}", t.container], check=False).stdout.strip()}
    if a.probe:
        meta["env"] = {k: os.environ.get(k, "") for k in ("COMPOSE_FILE", "JA_GC", "JA_JAVA_EXTRA", "JA_LOGDIR_TMPFS", "APP_MEM")}
        meta["java_cmdline"] = open(f"/proc/{t.pid()}/cmdline").read().replace("\0", " ").strip()
    keep_logs(t, a.svc, d)
    (d / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    (d / "done").write_text("ok")
    log("finished", a.svc, scenario, "rep", rep)


# cycles ---------------------------------------------------------------------------------------------------
def cycles_one(svc, n, d, kinds):
    t = Target(svc)
    out = {"svc": svc, "steps": []}
    ip = t.ip()
    step = lambda what, **kw: out["steps"].append({"t": time.time(), "what": what, "diag": json.loads(http_get(f"http://{ip}:8080/diag")), **kw})
    for path in ("/ping", "/hot?calls=10", "/work", "/db?id=3"):
        for _ in range(200):
            http_get(f"http://{ip}:8080{path}")
    time.sleep(20)
    step("start", snap=snapshot(svc))
    for i in range(3):
        step(f"full gc {i + 1} before", gc=full_gc(t))
        time.sleep(3)
    step("baseline", snap=snapshot(svc))
    p = ja_call(svc, d / "calls.jsonl", f"{svc}-cycles", kinds, calls=n, evidence=d / "calls")
    (d / "ja-call.err").write_text(p.stderr)
    step("after calls", snap=snapshot(svc), rc=p.returncode)
    for i in range(3):
        step(f"full gc {i + 1} after", gc=full_gc(t))
        time.sleep(3)
        step(f"after full gc {i + 1}", snap=snapshot(svc))
    step("live", live=json.loads(http_get(f"http://{ip}:8080/diag/live", 30)))
    keep_logs(t, svc, d)
    (d / "steps.json").write_text(json.dumps(out, indent=2))
    log("cycles finished", svc)


def cycles(a):
    set_env(a.mem)
    root = OUT / a.name
    for svc in a.svcs.split(","):
        (root / svc).mkdir(parents=True, exist_ok=True)
        Target(svc).up()
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        list(ex.map(lambda s: cycles_one(s, a.calls, root / s, a.kinds.split(",")), a.svcs.split(",")))


# leak -----------------------------------------------------------------------------------------------------
def leak_one(svc, a):
    for kind in a.kinds.split(","):
        d = OUT / a.name / svc / kind
        if (d / "steps.json").exists():
            continue
        d.mkdir(parents=True, exist_ok=True)
        t = Target(svc).up()
        ip = t.ip()
        steps = []
        step = lambda what, **kw: steps.append({"t": time.time(), "what": what, "diag": json.loads(http_get(f"http://{ip}:8080/diag")), **kw})
        for path in ("/ping", "/hot?calls=10", "/work", "/db?id=3"):
            for _ in range(200):
                http_get(f"http://{ip}:8080{path}")
        for i in range(3):
            full_gc(t)
            time.sleep(2)
        step("baseline", snap=snapshot(svc))
        p = ja_call(svc, d / "calls.jsonl", f"{svc}-leak-{kind}", [kind], calls=a.calls, evidence=d / "calls")
        (d / "ja-call.err").write_text(p.stderr)
        step("after calls")
        for i in range(a.gcs):
            full_gc(t)
            time.sleep(2)
            step(f"after full gc {i + 1}", snap=snapshot(svc))
        hist = t.docker_exec("jcmd", jvm_pid_in_container(t), "GC.class_histogram", timeout=120).stdout.splitlines()
        # All lines: the ArthasClassloader line comes far down the histogram, which is sorted by size.
        loaders = t.docker_exec("jcmd", jvm_pid_in_container(t), "VM.classloaders" if svc != "jdk8" else "VM.classloader_stats", timeout=120).stdout
        step("histogram", arthas=[ln for ln in hist if "arthas" in ln.lower()], loaders=loaders)
        (d / "steps.json").write_text(json.dumps(steps, indent=2))
        log("leak finished", svc, kind)


def leak(a):
    """A few calls of one command kind on a new JVM, then Full GCs and a class histogram: which commands leave
    metaspace behind that the Full GCs do not free (item 4)."""
    set_env(a.mem)
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        list(ex.map(lambda s: leak_one(s, a), a.svcs.split(",")))


# limits ---------------------------------------------------------------------------------------------------
def limits_one(svc, a, d):
    t = Target(svc)
    col = Collector(t, d / "metrics.jsonl")
    col.start()
    total = a.warm + a.every * (a.calls + 1) + 30
    lg = start_loadgen(t, d, total, ["hot=/hot?calls=1@300", "work=/work?iterations=50@300", "db=/db?id=7@100"])
    state = f"/tmp/ja-limits-{PROJECT}-{svc}/arthas"
    try:
        time.sleep(a.warm)
        p = ja_call(svc, d / "calls.jsonl", f"{svc}-limits", a.kinds.split(","), calls=a.calls, start=time.time() + 1, every=a.every,
                    state=state, evidence=d / "calls")
        (d / "ja-call.err").write_text(p.stderr)
        time.sleep(30)
    finally:
        try:
            lg.wait(timeout=total + 60)
        except subprocess.TimeoutExpired:
            lg.terminate()
        col.stop_ev.set()
        col.join(timeout=5)
        run(["sudo", "-n", "rm", "-rf", os.path.dirname(state)], check=False)
    keep_logs(t, svc, d)
    log("limits finished", svc)


def limits(a):
    set_env(a.mem)
    root = OUT / "limits"
    for svc in a.svcs.split(","):
        (root / svc).mkdir(parents=True, exist_ok=True)
        Target(svc).up()
    (root / "args.json").write_text(json.dumps(vars(a), indent=2))
    with concurrent.futures.ThreadPoolExecutor(4) as ex:
        list(ex.map(lambda s: limits_one(s, a, root / s), a.svcs.split(",")))


# metaspace ------------------------------------------------------------------------------------------------
def metaspace(a):
    """Calls with a new state directory each, so that only the metaspace check (and the memory check) can refuse."""
    set_env(a.mem, a.java_extra)
    d = OUT / "metaspace" / a.case
    d.mkdir(parents=True, exist_ok=True)
    t = Target(a.svc).up()
    ip = t.ip()
    for path in ("/ping", "/hot?calls=10", "/work", "/db?id=3"):
        for _ in range(200):
            http_get(f"http://{ip}:8080{path}")
    time.sleep(10)
    diag = lambda: json.loads(http_get(f"http://{ip}:8080/diag"))
    steps = [{"t": time.time(), "what": "start", "snap": snapshot(a.svc), "diag": diag()}]
    state = f"/tmp/ja-metaspace-{PROJECT}-{a.case}/arthas" if a.keep_state else "fresh"
    p = ja_call(a.svc, d / "calls.jsonl", f"{a.svc}-{a.case}", a.kinds.split(","), calls=a.calls, gap=a.gap, state=state, evidence=d / "calls")
    (d / "ja-call.err").write_text(p.stderr)
    if a.keep_state:
        run(["sudo", "-n", "rm", "-rf", os.path.dirname(state)], check=False)
    inspect = run(["docker", "inspect", "-f", "{{json .State}}", t.container], check=False).stdout
    steps.append({"t": time.time(), "what": "end", "snap": snapshot(a.svc), "diag": diag(), "ping": http_get(f"http://{ip}:8080/ping"),
                  "state": json.loads(inspect or "{}"), "oome_in_stdout": "OutOfMemoryError" in t.logs()})
    (d / "steps.json").write_text(json.dumps(steps, indent=2))
    (d / "meta.json").write_text(json.dumps({"args": vars(a), "project": PROJECT}, indent=2))
    keep_logs(t, a.svc, d)
    log("metaspace finished", a.case)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    lp = sub.add_parser("latency")
    lp.add_argument("--svc", default="jdk17")
    lp.add_argument("--scenario", required=True)
    lp.add_argument("--kinds", default=",".join(k for k in ALL_KINDS if k != "thread_blocking"), help='"none": no call (noise reference)')
    lp.add_argument("--calls", type=int, default=0)
    lp.add_argument("--every", type=float, default=11.5)
    lp.add_argument("--offset", type=float, default=5)
    lp.add_argument("--phase", type=int, default=160)
    lp.add_argument("--after", type=int, default=60)
    lp.add_argument("--warm", type=int, default=60)
    lp.add_argument("--rep", type=int, default=1)
    lp.add_argument("--reps", type=int, default=1)
    lp.add_argument("--profile", default="p1k")
    lp.add_argument("--mem", default="2g")
    lp.add_argument("--java-extra", default="")
    lp.add_argument("--threads-total", type=int, default=0, help="start parked threads after half the warm-up until the JVM has this many")
    lp.add_argument("--blocked", type=int, default=0, help="threads blocked on a monitor that one more thread holds")
    lp.add_argument("--threads-live", type=int, default=0, help="java.threads.live the checks see (ja-call -threads-live)")
    lp.add_argument("--retain", type=int, default=0, help="MB of heap kept reachable before the warm-up")
    lp.add_argument("--retain-size", type=int, default=1048512)
    lp.add_argument("--max-old-gen", type=int, default=0)
    lp.add_argument("--depth", type=int, default=0, help="stack frames every started thread descends before it parks or blocks")
    lp.add_argument("--holders", type=int, default=0, help="of the parked threads, how many hold monitors on the way down")
    lp.add_argument("--locks", type=int, default=0, help="monitors each holder takes over its depth")
    lp.add_argument("--probe", action="store_true", help="also run host_io_probe.py, pause_watch.py and the sampler of other processes (stage 3)")
    cp = sub.add_parser("cycles")
    cp.add_argument("--svcs", default=",".join(JDKS))
    cp.add_argument("--calls", type=int, default=50)
    cp.add_argument("--mem", default="4g")
    cp.add_argument("--kinds", default=",".join(ALL_KINDS))
    cp.add_argument("--name", default="cycles", help="directory under JA_OUT")
    kp = sub.add_parser("leak")
    kp.add_argument("--svcs", default=",".join(JDKS))
    kp.add_argument("--kinds", default=",".join(ALL_KINDS))
    kp.add_argument("--calls", type=int, default=5)
    kp.add_argument("--gcs", type=int, default=4)
    kp.add_argument("--mem", default="2g")
    kp.add_argument("--name", default="leak", help="directory under JA_OUT")
    mp = sub.add_parser("limits")
    mp.add_argument("--svcs", default=",".join(JDKS))
    mp.add_argument("--kinds", default="dashboard,thread_top,thread_blocking,memory,jvm,version")
    mp.add_argument("--calls", type=int, default=6)
    mp.add_argument("--every", type=float, default=61)
    mp.add_argument("--warm", type=int, default=60)
    mp.add_argument("--mem", default="1g")
    sp = sub.add_parser("metaspace")
    sp.add_argument("--svc", default="jdk17")
    sp.add_argument("--case", required=True)
    sp.add_argument("--java-extra", default="")
    sp.add_argument("--kinds", default="jvm")
    sp.add_argument("--calls", type=int, default=8)
    sp.add_argument("--gap", type=float, default=2)
    sp.add_argument("--mem", default="2g")
    sp.add_argument("--keep-state", action="store_true", help="keep one state directory across the calls, so the attach count and interval checks apply")
    a = ap.parse_args()
    if a.cmd == "latency":
        for rep in range(a.rep, a.rep + a.reps):
            latency(a, rep)
    else:
        globals()[a.cmd](a)
