#!/usr/bin/env python3
"""Stage-3 measurements (docs/arthas-stage3-acceptance-report.md) that accept.py does not cover. Every call goes through
bin/ja-call, the code path of the jvm_arthas builtin, as in the stage-2 acceptance. Run from test/jvm-arthas with
COMPOSE_FILE=compose.yaml:compose.stage3.yaml, COMPOSE_PROJECT_NAME=jvm-arthas-s3m, JA_PORT_PREFIX=27 and
JA_LOGDIR_TMPFS=/logs-tmpfs (scripts/run_s3.sh sets them). Raw data goes to $JA_OUT/<subcommand>/...

  envcheck  per JDK: where /tmp, the log directory and hsperfdata live in the container, which JVM flags are in effect, where the
            attach file and the attach socket appear during a call, and one call of every L1 command kind except logger
  oldgen    one JVM under the p1k load with a chosen collector (--gc): calls at a low old generation occupancy; heap retained up
            to --target percent of the old generation and a Full GC; a call within 60 s of it; calls near the target
  metaspace a JVM with -XX:MaxMetaspaceSize, no load, one state directory kept across the calls (so the attach count, the attach
            interval and the A69 compensation for the lagging metaspace counter apply), a call every --gap seconds
  interval  one JVM under the p1k load, the default checks and one kept state directory: calls --gap seconds apart, the first
            ones closer than 60 s (refused by the interval check), then every 61 s (item 9)
"""
import argparse
import signal
import subprocess

from ja import *
from bench import Collector
from accept import CALL, CALL_CPUS, LOAD_PROFILES, Others, full_gc, ja_call, keep_logs, set_env, snapshot, start_loadgen, start_probes

KINDS_NOLOGGER = ["dashboard", "thread_top", "thread_blocking", "thread_info", "memory", "jvm", "class_info", "method_info",
                  "classloader_tree", "classloader_list", "sysprop", "version"]

# Polls the container's /tmp and working directory every 2 ms during a call and prints every .attach_pid / .java_pid entry that
# appears, with the file system it is on (root needed for /proc/<pid>/root).
WATCH_ATTACH = r'''
import os, sys, time, json
pid, secs = sys.argv[1], float(sys.argv[2])
root = f"/proc/{pid}/root"
dirs = ["/tmp", os.readlink(f"/proc/{pid}/cwd")]
seen, end = {}, time.time() + secs
while time.time() < end:
    for d in dirs:
        try:
            names = os.listdir(root + d)
        except OSError:
            continue
        for n in names:
            if n.startswith((".attach_pid", ".java_pid")):
                k = d + "/" + n
                if k not in seen:
                    try:
                        st = os.lstat(root + k)
                        seen[k] = {"t": time.time(), "uid": st.st_uid, "mode": oct(st.st_mode)}
                    except OSError:
                        seen[k] = {"t": time.time()}
    time.sleep(0.002)
print(json.dumps(seen))
'''


def stop_loadgen(lg):
    """ja-loadgen writes the seconds it still holds when it gets SIGINT (sudo passes the signal on)."""
    lg.send_signal(signal.SIGINT)
    try:
        lg.wait(timeout=30)
    except subprocess.TimeoutExpired:
        lg.terminate()


def envcheck(a):
    set_env(a.mem)
    root = OUT / "envcheck"
    root.mkdir(parents=True, exist_ok=True)
    for svc in a.svcs.split(","):
        d = root / svc
        d.mkdir(parents=True, exist_ok=True)
        t = Target(svc).up()
        pid = t.pid()
        time.sleep(5)
        info = {"svc": svc, "pid": pid, "cmdline": open(f"/proc/{pid}/cmdline").read().replace("\0", " ").strip(),
                "mounts": t.docker_exec("grep", "-E", " (/tmp|/logs-tmpfs|/logs) ", "/proc/mounts").stdout.strip().splitlines(),
                "df_tmp": t.docker_exec("df", "-P", "/tmp").stdout.strip().splitlines()[-1:],
                "hsperfdata": t.docker_exec("sh", "-c", "ls -l /tmp/hsperfdata_*/; stat -f -c '%T %n' /tmp/hsperfdata_*/*").stdout.strip().splitlines(),
                "logs_tmpfs": t.docker_exec("ls", "-l", "/logs-tmpfs").stdout.strip().splitlines(),
                "logs_host": sorted(p.name for p in (RUN / svc / "logs").glob("*")),
                "threads": [ln for ln in run(["sudo", "-n", "sh", "-c", f"cat /proc/{pid}/task/*/comm"], check=False).stdout.splitlines() if "Log" in ln or "log" in ln],
                "snapshot": snapshot(svc)}
        watch = subprocess.Popen(["sudo", "-n", "taskset", "-c", CALL_CPUS, sys.executable, "-c", WATCH_ATTACH, str(pid), "15"], stdout=subprocess.PIPE, text=True)
        time.sleep(0.5)
        p = ja_call(svc, d / "calls.jsonl", f"{svc}-envcheck", ["version"], evidence=d / "calls")
        info["attach_files_seen"] = json.loads(watch.communicate(timeout=60)[0] or "{}")
        info["after_first_call"] = run(["sudo", "-n", "sh", "-c", f"ls -la /proc/{pid}/root/tmp /proc/{pid}/root/app | grep -E 'attach|java_pid|total|tmp|app'"], check=False).stdout.strip().splitlines()
        p2 = ja_call(svc, d / "calls.jsonl", f"{svc}-envcheck", KINDS_NOLOGGER, evidence=d / "calls")
        (d / "ja-call.err").write_text(p.stderr + p2.stderr)
        info["logs_tmpfs_after"] = t.docker_exec("ls", "-l", "/logs-tmpfs").stdout.strip().splitlines()
        info["tmp_after"] = t.docker_exec("ls", "-la", "/tmp").stdout.strip().splitlines()
        keep_logs(t, svc, d)
        (d / "envcheck.json").write_text(json.dumps(info, indent=2))
        t.down()
        log("envcheck finished", svc)


# oldgen -------------------------------------------------------------------------------------------------------------------
def old_pct(svc):
    perf = snapshot(svc).get("perf") or {}
    if perf.get("old_max_capacity"):
        return 100.0 * perf["old_used"] / perf["old_max_capacity"], perf
    return None, perf


def oldgen(a, rep):
    d = OUT / "oldgen" / a.case / f"rep{rep}"
    if (d / "done").exists():
        log("skip", d)
        return
    d.mkdir(parents=True, exist_ok=True)
    os.environ["JA_GC"] = a.gc
    set_env(a.mem, a.java_extra)
    t = Target(a.svc).up()
    ip = t.ip()
    col = Collector(t, d / "metrics.jsonl")
    col.start()
    total = a.warm + a.low_calls * a.every + 60 + 20 + a.near_calls * a.every + 300
    start_probes(t, d, total + 30)
    others = Others(d / "others.jsonl", jvm_pid=t.pid())
    others.start()
    lg = start_loadgen(t, d, total, LOAD_PROFILES["p1k"])
    phases, calls_out = {}, d / "calls.jsonl"
    mark = lambda name: phases.__setitem__(name, time.time())
    try:
        time.sleep(a.warm)
        mark("low_start")
        pct, perf = old_pct(a.svc)
        phases["low_old_pct"] = pct
        ja_call(a.svc, calls_out, f"{a.case}-rep{rep}-low", a.kinds.split(","), calls=a.low_calls, start=time.time() + 1, every=a.every, evidence=d / "calls")
        mark("low_end")
        time.sleep(3)
        # Retain heap up to the target occupancy of the old generation, then a Full GC, so that the occupancy is live data.
        pct, perf = old_pct(a.svc)
        phases["before_retain"] = {"old_pct": pct, "old_used": perf.get("old_used"), "old_max": perf.get("old_max_capacity")}
        if pct is not None:
            mb = max(0, int((a.target / 100.0 * perf["old_max_capacity"] - perf["old_used"]) / 2**20))
        else:
            mb = int(a.target / 100.0 * 512) - 100  # no old generation counter (Shenandoah): the whole heap
        mark("retain_start")
        phases["retain"] = http_get(f"http://{ip}:8080/load/retain?mb={mb}&size={a.retain_size}", 300)
        phases["retain_mb"] = mb
        phases["full_gc"] = full_gc(t)
        mark("retain_end")
        pct, perf = old_pct(a.svc)
        phases["after_full_gc_old_pct"] = pct
        # One call 10 s after the Full GC: the check should refuse it (except where the collector has no stop-the-world full GC).
        time.sleep(10)
        mark("recent_start")
        ja_call(a.svc, calls_out, f"{a.case}-rep{rep}-recent", ["jvm"], calls=1, evidence=d / "calls")
        mark("recent_end")
        # Wait until the Full GC is 62 s old; the 20 s before the near calls are their reference window.
        time.sleep(max(0, phases["retain_end"] + 62 - 20 - time.time()))
        mark("near_ref_start")
        time.sleep(20)
        mark("near_start")
        pct, perf = old_pct(a.svc)
        phases["near_old_pct"] = pct
        ja_call(a.svc, calls_out, f"{a.case}-rep{rep}-near", a.kinds.split(","), calls=a.near_calls, start=time.time() + 1, every=a.every, evidence=d / "calls")
        mark("near_end")
        time.sleep(15)
        mark("end")
        pct, perf = old_pct(a.svc)
        phases["end_old_pct"] = pct
    finally:
        stop_loadgen(lg)
        col.stop_ev.set()
        col.join(timeout=5)
        others.stop_ev.set()
    meta = {"svc": a.svc, "case": a.case, "rep": rep, "gc": a.gc, "phases": phases, "args": vars(a), "project": PROJECT,
            "cmdline": open(f"/proc/{t.pid()}/cmdline").read().replace("\0", " ").strip(),
            "env": {k: os.environ.get(k, "") for k in ("COMPOSE_FILE", "JA_GC", "JA_JAVA_EXTRA", "JA_LOGDIR_TMPFS", "APP_MEM")}}
    keep_logs(t, a.svc, d)
    (d / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    (d / "done").write_text("ok")
    t.down()
    log("oldgen finished", a.case, "rep", rep)


# metaspace ------------------------------------------------------------------------------------------------------------------
def metaspace(a):
    """Calls with one kept state directory: every check at its default. With no load the hsperfdata metaspace counter lags."""
    d = OUT / "metaspace" / a.case
    if (d / "done").exists():
        log("skip", d)
        return
    d.mkdir(parents=True, exist_ok=True)
    os.environ["JA_GC"] = a.gc
    set_env(a.mem, a.java_extra)
    t = Target(a.svc).up()
    ip = t.ip()
    for path in ("/ping", "/hot?calls=10", "/work", "/db?id=3"):
        for _ in range(200):
            http_get(f"http://{ip}:8080{path}")
    time.sleep(10)
    diag = lambda: json.loads(http_get(f"http://{ip}:8080/diag"))
    steps = [{"t": time.time(), "what": "start", "snap": snapshot(a.svc), "diag": diag()}]
    state = f"/tmp/ja-s3-metaspace-{PROJECT}-{a.case}/arthas"
    run(["sudo", "-n", "rm", "-rf", os.path.dirname(state)], check=False)
    p = ja_call(a.svc, d / "calls.jsonl", f"{a.svc}-{a.case}", a.kinds.split(","), calls=a.calls, gap=a.gap, state=state, evidence=d / "calls")
    (d / "ja-call.err").write_text(p.stderr)
    steps.append({"t": time.time(), "what": "counter", "counter": run(["sudo", "-n", "sh", "-c", f"cat {state}/*.count"], check=False).stdout})
    run(["sudo", "-n", "rm", "-rf", os.path.dirname(state)], check=False)
    inspect = run(["docker", "inspect", "-f", "{{json .State}}", t.container], check=False).stdout
    steps.append({"t": time.time(), "what": "end", "snap": snapshot(a.svc), "diag": diag(), "ping": http_get(f"http://{ip}:8080/ping"),
                  "state": json.loads(inspect or "{}"), "oome_in_stdout": "OutOfMemoryError" in t.logs()})
    (d / "steps.json").write_text(json.dumps(steps, indent=2))
    (d / "meta.json").write_text(json.dumps({"args": vars(a), "project": PROJECT, "cmdline": open(f"/proc/{t.pid()}/cmdline").read().replace("\0", " ").strip()}, indent=2))
    keep_logs(t, a.svc, d)
    (d / "done").write_text("ok")
    t.down()
    log("metaspace finished", a.case)


# interval -------------------------------------------------------------------------------------------------------------------
def interval(a):
    d = OUT / "interval" / a.case
    if (d / "done").exists():
        log("skip", d)
        return
    d.mkdir(parents=True, exist_ok=True)
    os.environ["JA_GC"] = "-XX:+UseG1GC"
    set_env(a.mem)
    t = Target(a.svc).up()
    col = Collector(t, d / "metrics.jsonl")
    col.start()
    gaps = [float(x) for x in a.gaps.split(",")]
    total = a.warm + sum(gaps) + 20 * len(gaps) + 60
    start_probes(t, d, total + 30)
    others = Others(d / "others.jsonl", jvm_pid=t.pid())
    others.start()
    lg = start_loadgen(t, d, total, LOAD_PROFILES["p1k"])
    state = f"/tmp/ja-s3-interval-{PROJECT}-{a.case}/arthas"
    run(["sudo", "-n", "rm", "-rf", os.path.dirname(state)], check=False)
    kinds = a.kinds.split(",")
    try:
        time.sleep(a.warm)
        for i, g in enumerate([0.0] + gaps):
            time.sleep(g)
            ja_call(a.svc, d / "calls.jsonl", f"{a.case}-{i}", [kinds[i % len(kinds)]], calls=1, state=state, evidence=d / "calls")
        time.sleep(30)
    finally:
        stop_loadgen(lg)
        col.stop_ev.set()
        col.join(timeout=5)
        others.stop_ev.set()
        run(["sudo", "-n", "rm", "-rf", os.path.dirname(state)], check=False)
    (d / "meta.json").write_text(json.dumps({"svc": a.svc, "args": vars(a), "project": PROJECT}, indent=2))
    keep_logs(t, a.svc, d)
    (d / "done").write_text("ok")
    t.down()
    log("interval finished", a.case)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    ep = sub.add_parser("envcheck")
    ep.add_argument("--svcs", default="jdk8,jdk11,jdk17,jdk21")
    ep.add_argument("--mem", default="2g")
    op = sub.add_parser("oldgen")
    op.add_argument("--svc", default="jdk17")
    op.add_argument("--case", required=True)
    op.add_argument("--gc", default="-XX:+UseG1GC")
    op.add_argument("--java-extra", default="")
    op.add_argument("--target", type=float, default=80, help="old generation occupancy (percent of its maximum) to retain heap up to")
    op.add_argument("--retain-size", type=int, default=1048512)
    op.add_argument("--kinds", default="jvm,thread_top,memory,dashboard")
    op.add_argument("--low-calls", type=int, default=3)
    op.add_argument("--near-calls", type=int, default=4)
    op.add_argument("--every", type=float, default=12)
    op.add_argument("--warm", type=int, default=60)
    op.add_argument("--mem", default="2g")
    op.add_argument("--rep", type=int, default=1)
    op.add_argument("--reps", type=int, default=1)
    mp = sub.add_parser("metaspace")
    mp.add_argument("--svc", default="jdk17")
    mp.add_argument("--case", required=True)
    mp.add_argument("--gc", default="-XX:+UseG1GC")
    mp.add_argument("--java-extra", default="")
    mp.add_argument("--kinds", default="jvm")
    mp.add_argument("--calls", type=int, default=5)
    mp.add_argument("--gap", type=float, default=61)
    mp.add_argument("--mem", default="2g")
    ip_ = sub.add_parser("interval")
    ip_.add_argument("--svc", default="jdk17")
    ip_.add_argument("--case", required=True)
    ip_.add_argument("--gaps", default="20,40,61,61,61", help="pause before each call after the first, seconds")
    ip_.add_argument("--kinds", default="jvm,memory,thread_top")
    ip_.add_argument("--warm", type=int, default=60)
    ip_.add_argument("--mem", default="2g")
    a = ap.parse_args()
    if a.cmd == "oldgen":
        for rep in range(a.rep, a.rep + a.reps):
            oldgen(a, rep)
    else:
        globals()[a.cmd](a)
