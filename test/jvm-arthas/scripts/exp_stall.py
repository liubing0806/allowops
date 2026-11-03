#!/usr/bin/env python3
"""Stage-0 item 5 follow-up: during a `watch` job at 10k calls/s, the JDK 11 and JDK 21 runs of bench.py showed freezes of the whole JVM
(0.3 to 3 s, JVM cpu 0 %, no long safepoint in the JVM log). This repeats that scenario and records, for every 100 ms,
the state of every thread of the JVM (stall_sampler.py) and, every second, a thread dump (SIGQUIT, written to the container's stdout).

Usage: exp_stall.py run <svc> [job-seconds=50] [dumps=1] [tag] [jobs=1]   output: $JA_OUT/item5-stall/<svc><tag>/
       dumps=0 leaves out the SIGQUIT thread dumps (each dump is a safepoint and may hide a stall);
       jobs=2 splits job-seconds into two watch jobs with a `reset` between them, as bench.py does
       exp_stall.py show <dir>                      prints, for every second with a p99 above 100 ms, the thread states of that second
"""
import collections
import json
import subprocess
import sys
import threading

from ja import *
from bench import LOAD_CPUS, LOADGEN, PROFILES, WATCH  # after `from ja import *`: ja also defines PROFILES


def one(svc, job_s, dumps=True, tag="", jobs=1):
    d = OUT / "item5-stall" / (svc + tag)
    d.mkdir(parents=True, exist_ok=True)
    t = Target(svc).up()
    pid = t.pid()
    warm, before = 40, 20
    total = warm + before + job_s + 25
    lg = subprocess.Popen(["sudo", "-n", "nice", "-n", "-10", "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                           "taskset", "-c", LOAD_CPUS, str(LOADGEN), "-base", f"http://{t.ip()}:8080", "-duration", f"{total}s", "-out", str(d / "load.jsonl"),
                           *[x for f in PROFILES["p10k"] for x in ("-flow", f)]], stdout=subprocess.DEVNULL, stderr=open(d / "loadgen.err", "w"))
    time.sleep(warm)
    t_before = time.time()
    time.sleep(before)
    sampler = subprocess.Popen(["sudo", "-n", sys.executable, str(pathlib.Path(__file__).resolve().parent / "stall_sampler.py"), str(pid),
                                str(d / "threads.jsonl"), str(job_s + 6)])
    stop = threading.Event()

    def dump_loop():
        while not stop.is_set():
            run(["sudo", "-n", "kill", "-QUIT", str(pid)], check=False)
            stop.wait(1.0)

    events = [{"t": t_before, "what": "before window start"}, {"t": time.time(), "what": "attach"}]
    a = t.attach(enabled=L2_COMMANDS, session_timeout=300)
    events.append({"t": time.time(), "what": f"attached ok={a['ok']}"})
    th = threading.Thread(target=dump_loop, daemon=True)
    if dumps:
        th.start()
    events.append({"t": time.time(), "what": "watch job start"})
    for i in range(jobs):
        if i:
            events.append({"t": time.time(), "what": "watch job start"})
        r = t.exec(WATCH, exec_timeout=int(job_s * 1000 / jobs))
        events.append({"t": time.time(), "what": f"watch job end {short(r)['state']}"})
        t.exec("reset", exec_timeout=15000)
    t.exec("stop", exec_timeout=15000)
    events.append({"t": time.time(), "what": "stopped"})
    time.sleep(4)
    stop.set()
    if dumps:
        th.join(timeout=5)
    sampler.wait(timeout=60)
    try:
        lg.wait(timeout=total - (time.time() - (t_before - warm)) + 30)
    except subprocess.TimeoutExpired:
        lg.terminate()
    (d / "stdout.log").write_text(run(["docker", "logs", "--timestamps", t.container], check=False).stdout)
    for f in (RUN / svc / "logs").glob("*"):
        run(["cp", str(f), str(d / f.name)], check=False)
    (d / "meta.json").write_text(json.dumps({"svc": svc, "job_s": job_s, "dumps": dumps, "jobs": jobs, "events": events, "pid": pid}, indent=2, default=str))
    log("done", svc)


BASE = 1.01


def val(b):
    return (BASE ** (int(b) + 0.5) - 1) / 1000.0


def pct(h, q):
    n = sum(h.values())
    acc = 0
    for b in sorted(h):
        acc += h[b]
        if acc >= q * n:
            return val(b)
    return 0.0


def show(dirname):
    d = pathlib.Path(dirname)
    meta = json.load(open(d / "meta.json"))
    per = collections.defaultdict(collections.Counter)
    for ln in open(d / "load.jsonl"):
        r = json.loads(ln)
        if r["flow"] == "hot":
            c = per[int(r["t"])]
            for b, n in r["h"].items():
                c[int(b)] += n
    samples = [json.loads(x) for x in open(d / "threads.jsonl")]
    t0 = meta["events"][0]["t"]
    print("events:", [(round(e["t"] - t0, 1), e["what"]) for e in meta["events"]])
    stalls = [s for s in sorted(per) if pct(per[s], .99) > 100]
    print("seconds with p99 > 100 ms (relative to the before window):", [s - int(t0) for s in stalls])
    for sec in stalls:
        win = [s for s in samples if sec <= s["t"] < sec + 1]
        states = collections.Counter()
        wch = collections.Counter()
        for s in win:
            for comm, st, w, _ in s["threads"]:
                states[st] += 1
                if st != "R":
                    wch[(comm.rsplit("-", 1)[0] if comm.startswith(("http-nio", "arthas")) else comm[:15], w)] += 1
        n = max(1, len(win))
        print(f"--- second +{sec - int(t0)} p99={pct(per[sec], .99):.0f} ms, {len(win)} samples; mean threads per sample by state: " + ", ".join(f"{k}={v / n:.1f}" for k, v in sorted(states.items())))
        print("    most common (thread group, wchan):", [(k, round(v / n, 1)) for k, v in wch.most_common(6)])
    # thread dumps: for the stall seconds list what the Tomcat worker threads do
    txt = (d / "stdout.log").read_text(errors="ignore")
    dumps = txt.split("Full thread dump")
    print(f"{len(dumps) - 1} thread dumps in stdout")
    for i, dmp in enumerate(dumps[1:], 1):
        head = dmp.splitlines()[0] if dmp else ""
        states = collections.Counter()
        tops = collections.Counter()
        cur = None
        for ln in dmp.splitlines():
            if ln.startswith('"http-nio-8080-exec'):
                cur = "exec"
            elif ln.startswith('"'):
                cur = None
            if cur and "java.lang.Thread.State:" in ln:
                states[ln.split("State:")[1].strip()] += 1
                cur = "exec-top"
            elif cur == "exec-top" and ln.strip().startswith("at "):
                tops[ln.strip()[3:90]] += 1
                cur = None
        if states and (states.get("BLOCKED", 0) or "BLOCKED" in "".join(states)):
            print(f"dump {i}: exec threads {dict(states)} top frames {tops.most_common(3)}")


if __name__ == "__main__":
    if sys.argv[1] == "run":
        one(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 50, (sys.argv[4] if len(sys.argv) > 4 else "1") == "1", sys.argv[5] if len(sys.argv) > 5 else "", int(sys.argv[6]) if len(sys.argv) > 6 else 1)
    else:
        show(sys.argv[2])
