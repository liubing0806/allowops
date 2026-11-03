#!/usr/bin/env python3
"""The JVM's log directory on a block device that stops answering (docs/arthas-jvm-pause-report.md).

One run = one freshly started JVM under the p10k load of bench.py, no Arthas. After the warm-up, the device under
run/stallfs (scripts/stallfs.sh) is suspended for --stall seconds, --count times, --every seconds apart. The JVM writes
safepoint.log, gc.log and redefine.log either to that device or elsewhere, depending on the case:
  disk    -Xlog files in /logs = run/stallfs/<run>/ (the device that stalls)
  tmpfs   -Xlog files in /logs-tmpfs, a tmpfs inside the container; the device still stalls, the JVM has no file on it
  async   like disk, plus -Xlog:async (JDK 17 and later: a separate thread writes the log lines)
  hsperf  -Xlog files on the tmpfs, /tmp of the container (and with it the memory-mapped performance data file
          /tmp/hsperfdata_app/<pid>) on the device that stalls (compose.pause-tmp.yaml)
  hsperf-off  like hsperf, plus -XX:+PerfDisableSharedMem (the performance data stays in ordinary memory)
Output: $JA_OUT/stall/<svc>/<case>/rep<k>/: load.jsonl (loadgen), metrics.jsonl (1 Hz collector of bench.py), watch.jsonl
(pause_watch.py), stalls.jsonl (start and end of every suspension), the JVM log files, stdout.log, meta.json.

--how suspend (default) stops the device (scripts/stallfs.sh stall); --how freeze freezes the file system (stallfs.sh freeze) and
writes to stall/<svc>/<case>-freeze/.

Usage: exp_logstall.py --svc jdk11 --case disk [--how suspend|freeze] [--rep 1] [--warm 40] [--stall 6] [--count 3] [--every 30]
"""
import argparse
import shutil
import subprocess

from ja import *
from bench import Collector, LOADGEN, LOAD_CPUS, PROFILES

HERE = pathlib.Path(__file__).resolve().parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--svc", required=True)
    ap.add_argument("--case", required=True, choices=["disk", "tmpfs", "async", "hsperf", "hsperf-off"])
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--warm", type=int, default=40)
    ap.add_argument("--stall", type=float, default=6)
    ap.add_argument("--count", type=int, default=3)
    ap.add_argument("--every", type=float, default=30)
    ap.add_argument("--profile", default="p10k")
    ap.add_argument("--how", default="suspend", choices=["suspend", "freeze"])
    a = ap.parse_args()

    d = OUT / "stall" / a.svc / (a.case if a.how == "suspend" else f"{a.case}-freeze") / f"rep{a.rep}"
    if (d / "done").exists():
        log("skip", d)
        return
    d.mkdir(parents=True, exist_ok=True)
    logs_host = RUN / "stallfs" / f"{a.svc}-{a.case}-{a.how}-rep{a.rep}"
    if logs_host.exists():
        shutil.rmtree(logs_host)
    logs_host.mkdir(parents=True)
    os.chmod(logs_host, 0o777)
    os.environ["JA_LOGS_HOST"] = str(logs_host)
    os.environ["JA_LOGDIR"] = "/logs-tmpfs" if a.case in ("tmpfs", "hsperf", "hsperf-off") else "/logs"
    os.environ["JA_JAVA_EXTRA"] = {"async": "-Xlog:async", "hsperf-off": "-XX:+PerfDisableSharedMem"}.get(a.case, "")
    if a.case.startswith("hsperf"):
        tmp = logs_host / "tmp"
        tmp.mkdir()
        os.chmod(tmp, 0o1777)
        os.environ["JA_TMP_HOST"] = str(tmp)
        os.environ["COMPOSE_FILE"] = os.environ.get("COMPOSE_FILE", "compose.yaml:compose.pause.yaml") + ":compose.pause-tmp.yaml"

    t = Target(a.svc).up()
    pid = t.pid()
    insp = t.inspect()
    total = a.warm + a.count * a.every + 20
    col = Collector(t, d / "metrics.jsonl")
    col.start()
    lg = subprocess.Popen(["sudo", "-n", "nice", "-n", "-10", "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                           "taskset", "-c", LOAD_CPUS, str(LOADGEN), "-base", f"http://{t.ip()}:8080", "-duration", f"{int(total)}s",
                           "-out", str(d / "load.jsonl"), *[x for f in PROFILES[a.profile] for x in ("-flow", f)]],
                          stdout=subprocess.DEVNULL, stderr=open(d / "loadgen.err", "w"))
    subprocess.Popen(["sudo", "-n", "taskset", "-c", "12-15", sys.executable, str(HERE / "pause_watch.py"), str(pid), str(d / "watch.jsonl"), str(total)])
    t0 = time.time()
    events = []
    try:
        with open(d / "stalls.jsonl", "w") as sf:
            for i in range(a.count):
                time.sleep(max(0, t0 + a.warm + i * a.every - time.time()))
                r = run([str(HERE / "stallfs.sh"), "stall" if a.how == "suspend" else "freeze", str(a.stall)], timeout=a.stall + 60)
                rec = json.loads(r.stdout.strip().splitlines()[-1])
                sf.write(json.dumps({"n": i + 1, "seconds": a.stall, **rec}) + "\n")
                sf.flush()
                events.append({"t": rec["suspended"], "what": f"stall {i + 1} start"})
                events.append({"t": rec["resumed"], "what": f"stall {i + 1} end"})
        time.sleep(max(0, t0 + total - time.time()))
    finally:
        try:
            lg.wait(timeout=total - (time.time() - t0) + 30)
        except subprocess.TimeoutExpired:
            lg.terminate()
        col.stop_ev.set()
        col.join(timeout=5)
    if a.case in ("tmpfs", "hsperf", "hsperf-off"):
        # docker cp does not see files on a tmpfs mount of the container
        for f in ("safepoint.log", "gc.log", "redefine.log"):
            (d / f).write_text(run(["docker", "exec", t.container, "cat", f"/logs-tmpfs/{f}"], check=False).stdout)
    else:
        for f in logs_host.glob("*"):
            shutil.copy(f, d / f.name)
    (d / "stdout.log").write_text(run(["docker", "logs", "--timestamps", t.container], check=False).stdout)
    meta = {"svc": a.svc, "case": a.case, "how": a.how, "rep": a.rep, "profile": a.profile, "warm_s": a.warm, "stall_s": a.stall, "count": a.count,
            "every_s": a.every, "start": t0, "events": events, "target": insp, "logs_host": str(logs_host),
            "java_version": t.logs().splitlines()[0] if t.logs() else "", "java_extra": os.environ["JA_JAVA_EXTRA"],
            "logdir": os.environ["JA_LOGDIR"], "tmp_host": os.environ.get("JA_TMP_HOST", ""), "app_cpuset": os.environ.get("APP_CPUS", "4-7"), "load_cpus": LOAD_CPUS}
    (d / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    (d / "done").write_text("ok")
    t.down()
    log("finished", a.svc, a.case, "rep", a.rep)


if __name__ == "__main__":
    main()
