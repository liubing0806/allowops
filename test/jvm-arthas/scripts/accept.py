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
import concurrent.futures
import subprocess
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
# "Reference Handler" exists for the whole life of the JVM; its id differs on JDK 21.
THREAD_ID = {"jdk21": 9}


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
    (d / "stdout.log").write_text(run(["docker", "logs", "--timestamps", t.container], check=False).stdout)


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
    lg = start_loadgen(t, d, total, LOAD_PROFILES[a.profile])
    t_start = time.time()
    try:
        if a.threads_total:
            time.sleep(min(20, a.warm / 2))
            live = json.loads(http_get(f"http://{ip}:8080/diag"))["threads"]
            n = max(0, a.threads_total - live)
            ev(f"threads before {live}; " + http_get(f"http://{ip}:8080/load/threads?n={n}&blocked={a.blocked}", 60))
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
    meta = {"svc": a.svc, "scenario": scenario, "rep": rep, "profile": a.profile, "phase_s": a.phase, "warm_s": a.warm,
            "windows": {"before": [b0, b0 + a.phase], "during": [d0, d0 + a.phase], "after": [a0, a0 + a.after]},
            "events": events, "args": vars(a), "app_cpuset": os.environ.get("APP_CPUS", "4-7"), "load_cpus": LOAD_CPUS,
            "project": PROJECT, "image": run(["docker", "inspect", "-f", "{{.Image}}", t.container], check=False).stdout.strip()}
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
