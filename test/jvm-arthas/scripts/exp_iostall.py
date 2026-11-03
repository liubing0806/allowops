#!/usr/bin/env python3
"""Stage-0 item 5 follow-up: the JDK 11 and JDK 21 runs of bench.py (`l2:watch@p10k`, repeat 1) contain freezes of the whole JVM of 0.3 to 1.9 s
with a JVM cpu of 0 %. The JVM's safepoint log shows the freezes inside the safepoint, in the phase before "Entering safepoint region" (JDK 11) or
in the cleanup phase (JDK 21), and the VM thread writes the log (-Xlog to /logs, a bind mount on the host's ext4) at that point.
This run tests whether a busy disk alone causes such freezes: no Arthas at all, the benchmark's load (10k calls/s), and writes with fsync
to the same file system from the host during a window of the run.

Usage: exp_iostall.py run <svc> [stress-seconds=70] [mb-per-second=300] [tag]     output: $JA_OUT/item5-iostall/<svc><tag>/
       exp_iostall.py show <dir>                                                  seconds with p99 > 100 ms and the safepoint-log gaps
The write load goes to $STRESS_DIR (default ~/.cache/ja-iostress, same file system as run/<svc>/logs) and is deleted afterwards.
"""
import collections
import json
import re
import shutil
import subprocess
import sys
import threading
import datetime as dt

from ja import *
from bench import LOAD_CPUS, LOADGEN, PROFILES  # after `from ja import *`: ja also defines PROFILES

STRESS_DIR = pathlib.Path(os.environ.get("STRESS_DIR", pathlib.Path.home() / ".cache" / "ja-iostress"))
WARM, BEFORE, AFTER = 30, 30, 25


def small_writer(stop, counter):
    """Creates, writes and fsyncs small files: every fsync forces a journal commit."""
    i = 0
    while not stop.is_set():
        fd = os.open(STRESS_DIR / f"small{i % 64}", os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
        os.write(fd, b"x" * 16384)
        os.fsync(fd)
        os.close(fd)
        i += 1
        counter[0] += 1


def bulk_writer(stop, mb_s, counter):
    """Writes 64 MB chunks, fsync after each, at about mb_s MB/s."""
    chunk = b"\0" * (64 << 20)
    fd = os.open(STRESS_DIR / "bulk", os.O_WRONLY | os.O_CREAT | os.O_TRUNC)
    while not stop.is_set():
        t0 = time.time()
        os.write(fd, chunk)
        os.fsync(fd)
        counter[1] += 64
        if os.lseek(fd, 0, os.SEEK_CUR) >= (2 << 30):
            os.lseek(fd, 0, os.SEEK_SET)
        stop.wait(max(0.0, 64.0 / mb_s - (time.time() - t0)))
    os.close(fd)


def one(svc, stress_s, mb_s, tag=""):
    d = OUT / "item5-iostall" / (svc + tag)
    d.mkdir(parents=True, exist_ok=True)
    STRESS_DIR.mkdir(parents=True, exist_ok=True)
    t = Target(svc).up()
    pid = t.pid()
    total = WARM + BEFORE + stress_s + AFTER
    lg = subprocess.Popen(["sudo", "-n", "nice", "-n", "-10", "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                           "taskset", "-c", LOAD_CPUS, str(LOADGEN), "-base", f"http://{t.ip()}:8080", "-duration", f"{total}s", "-out", str(d / "load.jsonl"),
                           *[x for f in PROFILES["p10k"] for x in ("-flow", f)]], stdout=subprocess.DEVNULL, stderr=open(d / "loadgen.err", "w"))
    t_start = time.time()
    stop_metrics = threading.Event()

    def metrics():
        with open(d / "metrics.jsonl", "w") as f:
            while not stop_metrics.is_set():
                stat = pathlib.Path(f"/proc/{pid}/stat").read_text()
                fields = stat[stat.rindex(")") + 2:].split()
                f.write(json.dumps({"t": time.time(), "ticks": int(fields[11]) + int(fields[12])}) + "\n")
                f.flush()
                stop_metrics.wait(1.0)

    threading.Thread(target=metrics, daemon=True).start()
    time.sleep(WARM + BEFORE)
    events = [{"t": time.time(), "what": "stress start"}]
    stop, counter = threading.Event(), [0, 0]
    workers = [threading.Thread(target=small_writer, args=(stop, counter)), threading.Thread(target=bulk_writer, args=(stop, mb_s, counter))]
    for w in workers:
        w.start()
    time.sleep(stress_s)
    stop.set()
    for w in workers:
        w.join()
    events.append({"t": time.time(), "what": f"stress end: {counter[0]} small files fsynced, {counter[1]} MB written in bulk"})
    shutil.rmtree(STRESS_DIR, ignore_errors=True)
    try:
        lg.wait(timeout=total - (time.time() - t_start) + 30)
    except subprocess.TimeoutExpired:
        lg.terminate()
    stop_metrics.set()
    (d / "stdout.log").write_text(run(["docker", "logs", "--timestamps", t.container], check=False).stdout)
    for f in (RUN / svc / "logs").glob("*"):
        run(["cp", str(f), str(d / f.name)], check=False)
    (d / "meta.json").write_text(json.dumps({"svc": svc, "stress_s": stress_s, "mb_s": mb_s, "t_start": t_start, "events": events, "pid": pid}, indent=2, default=str))
    log("done", svc, events[-1]["what"])


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


def ts(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def show(dirname):
    d = pathlib.Path(dirname)
    meta = json.load(open(d / "meta.json"))
    t0 = meta["t_start"]
    s0, s1 = meta["events"][0]["t"], meta["events"][1]["t"]
    print("events:", [(round(e["t"] - t0, 1), e["what"]) for e in meta["events"]])
    per = collections.defaultdict(collections.Counter)
    for ln in open(d / "load.jsonl"):
        r = json.loads(ln)
        if r["flow"] == "hot":
            for b, n in r["h"].items():
                per[int(r["t"])][int(b)] += n
    ticks = {}
    rows = [json.loads(x) for x in open(d / "metrics.jsonl")]
    for a, b in zip(rows, rows[1:]):
        ticks[int(b["t"])] = (b["ticks"] - a["ticks"]) / (b["t"] - a["t"])
    for name, a, b in (("before stress", t0 + WARM, s0), ("stress", s0, s1), ("after stress", s1, t0 + 1e9)):
        secs = [s for s in sorted(per) if a <= s < b]
        over = [(s - int(t0), round(pct(per[s], .99)), round(ticks.get(s, -1))) for s in secs if pct(per[s], .99) > 100]
        print(f"{name}: {len(secs)} seconds, p99 > 100 ms in {len(over)} (second since start, p99 ms, JVM cpu %): {over}")
    # safepoint log: JDK 11 wall time between the "Application time" line and the end of the safepoint, against the time the JVM reports
    sp = d / "safepoint.log"
    app, gaps, n = None, [], 0
    for ln in open(sp, errors="ignore"):
        m = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Application time: ", ln)
        if m:
            app = ts(m.group(1))
            continue
        m = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Total time for which application threads were stopped: ([0-9.]+) seconds", ln)
        if m and app is not None:
            n += 1
            wall, rep = (ts(m.group(1)) - app) * 1000, float(m.group(2)) * 1000
            if wall - rep > 20:
                gaps.append((round(app - t0, 1), round(wall, 1), round(rep, 1)))
            app = None
        m = re.match(r'^\[([^\]]+)\]\[[^\]]+\] Safepoint "([^"]+)".*Cleanup: (\d+) ns.*Total: (\d+) ns', ln)
        if m and int(m.group(4)) > 20e6:
            gaps.append((round(ts(m.group(1)) - t0, 1), m.group(2), f"cleanup {int(m.group(3)) / 1e6:.1f} ms, total {int(m.group(4)) / 1e6:.1f} ms"))
    print(f"safepoints parsed in the JDK 11 format: {n}; wall time minus reported stop time > 20 ms, or safepoints > 20 ms in the JDK 17+ format: {gaps}")


if __name__ == "__main__":
    if sys.argv[1] == "run":
        one(sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 70, float(sys.argv[4]) if len(sys.argv) > 4 else 300.0, sys.argv[5] if len(sys.argv) > 5 else "")
    else:
        show(sys.argv[2])
