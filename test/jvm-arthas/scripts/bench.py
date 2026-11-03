#!/usr/bin/env python3
"""Stage-0 item 5: effect of attach, L1 and L2 commands on latency.

One scenario = one freshly started JVM, a warm-up, then three consecutive windows of PHASE seconds under constant
load: before (no Arthas), during (Arthas busy), after (Arthas stopped). Output goes to
$JA_OUT/bench/<svc>/<scenario>/rep<k>/ ; scripts/analyze.py turns it into tables.

Usage: bench.py --svc jdk17 --scenario noop,attach_cycle,l1c:thread -n 5 [--rep 1] [--phase 60] [--warm 100]
Scenario names:
  noop                    nothing happens in the middle window (measures the noise floor)
  attach_hold             attach once, hold 60 s with Arthas idle, stop
  attach_cycle            attach, stop, 2 s pause, repeated (no command)
  l1c:<command>           repeated {attach, command, stop, 2 s pause}        (L1 call as the product would make it)
  l1s:<command>           attach once, run the command once a second, stop   (session style)
  l2:<watch|trace|stack|monitor>  attach, two enhancement jobs of 30 s each separated by reset, stop
  l2keep:<watch>          like l2 but the classes are left enhanced (no reset, no stop) until the end of the after window
  l2stuck:<watch>         async watch, then `stop` while it still runs: Arthas is gone, the class stays enhanced (see exp_session2 scenario f)
Load profile (--profile): p1k (observed method at 1k calls/s) or p10k (10k calls/s), both with 3 control endpoints.
"""
import argparse
import glob
import subprocess
import threading

from ja import *

PROFILES = {
    "p1k": ["hot=/hot?calls=1@1000", "ping=/ping@300", "work=/work?iterations=50@300", "db=/db?id=7@300"],
    "p10k": ["hot=/hot?calls=10@1000", "ping=/ping@300", "work=/work?iterations=50@300", "db=/db?id=7@300"],
}
LOADGEN = ROOT / "bin" / "ja-loadgen"
LOAD_CPUS = os.environ.get("LOAD_CPUS", "8-9")
APP_CPUS_RANGE = os.environ.get("APP_CPUS", "4-7").split("-")

WATCH = "watch demo.HotService work '{params,returnObj,throwExp}' '#cost>1000000' -n 5 -x 1"
L2_CMDS = {
    "watch": WATCH,
    "trace": "trace demo.HotService work '#cost>1000000' -n 5",
    "stack": "stack demo.HotService work '#cost>1000000' -n 5",
    "monitor": "monitor -c 5 demo.HotService work",
}


class Collector(threading.Thread):
    """1 Hz: process CPU ticks, container CPU and memory, and the JVM's own counters from /diag."""

    def __init__(self, t, path):
        super().__init__(daemon=True)
        self.t, self.path, self.stop_ev = t, path, threading.Event()
        self.pid = t.pid()
        self.cg = t.cgroup()
        self.url = f"http://{t.ip()}:8080/diag"

    def run_delay(self):
        """Nanoseconds all threads of the JVM have spent runnable but not running (field 2 of schedstat): contention for the cpu."""
        total = 0
        for p in glob.glob(f"/proc/{self.pid}/task/*/schedstat"):
            try:
                total += int(open(p).read().split()[1])
            except (OSError, ValueError, IndexError):
                pass
        return total

    @staticmethod
    def host_cpu():
        """Busy jiffies (all but idle and iowait) of the cpus the test uses, from /proc/stat."""
        want = {f"cpu{c}" for c in range(int(APP_CPUS_RANGE[0]), int(LOAD_CPUS.split("-")[-1]) + 1)}
        out = {}
        for ln in open("/proc/stat"):
            f = ln.split()
            if f and f[0] in want:
                v = [int(x) for x in f[1:]]
                out[f[0]] = sum(v) - v[3] - v[4]
        return out

    def run(self):
        with open(self.path, "w") as f:
            while not self.stop_ev.is_set():
                row = {"t": time.time()}
                try:
                    st = open(f"/proc/{self.pid}/stat").read().rsplit(")", 1)[1].split()
                    row["ticks"] = int(st[11]) + int(st[12])       # utime + stime
                    row["mem"] = int((self.cg / "memory.current").read_text())
                    for ln in (self.cg / "cpu.stat").read_text().splitlines():
                        if ln.startswith("usage_usec"):
                            row["cg_cpu_usec"] = int(ln.split()[1])
                    row["rundelay_ns"] = self.run_delay()
                    row["host_cpu"] = self.host_cpu()
                    row["diag"] = json.loads(http_get(self.url, 2))
                except Exception as e:
                    row["error"] = repr(e)
                f.write(json.dumps(row) + "\n")
                f.flush()
                self.stop_ev.wait(1.0)


class Calls:
    """Timings of every Arthas call made during the middle window."""

    def __init__(self, path):
        self.f = open(path, "w")

    def rec(self, kind, t0, t1, **kw):
        self.f.write(json.dumps({"kind": kind, "start": t0, "end": t1, "ms": round((t1 - t0) * 1000, 1), **kw}) + "\n")
        self.f.flush()

    def timed(self, kind, fn, **kw):
        t0 = time.time()
        r = fn()
        self.rec(kind, t0, time.time(), **kw)
        return r


def cleanup_arthas(t):
    for c in ("reset", "stop"):
        try:
            t.exec(c, exec_timeout=15000)
        except Exception:
            pass


# actions ------------------------------------------------------------------------------------------------
def act_noop(t, deadline, calls, ev):
    time.sleep(max(0, deadline - time.time()))


def act_attach_hold(t, deadline, calls, ev):
    a = calls.timed("attach", lambda: t.attach())
    ev("attached")
    time.sleep(max(0, deadline - 3 - time.time()))
    calls.timed("stop", lambda: t.exec("stop", exec_timeout=15000))


def act_attach_cycle(t, deadline, calls, ev):
    while time.time() < deadline - 6:
        calls.timed("attach", lambda: t.attach())
        calls.timed("stop", lambda: t.exec("stop", exec_timeout=15000))
        time.sleep(2)


def act_l1_cycle(cmd):
    def f(t, deadline, calls, ev):
        while time.time() < deadline - 10:
            t0 = time.time()
            a = calls.timed("attach", lambda: t.attach())
            r = calls.timed("cmd", lambda: t.exec(cmd, exec_timeout=30000), cmd=cmd)
            calls.timed("stop", lambda: t.exec("stop", exec_timeout=15000))
            calls.rec("call_total", t0, time.time(), cmd=cmd, state=short(r)["state"])
            time.sleep(2)
    return f


def act_l1_session(cmd):
    def f(t, deadline, calls, ev):
        calls.timed("attach", lambda: t.attach())
        while time.time() < deadline - 5:
            r = calls.timed("cmd", lambda: t.exec(cmd, exec_timeout=30000), cmd=cmd)
            time.sleep(1)
        calls.timed("stop", lambda: t.exec("stop", exec_timeout=15000))
    return f


def act_l2(kind, keep=False):
    cmd = L2_CMDS[kind]

    def f(t, deadline, calls, ev):
        calls.timed("attach", lambda: t.attach(enabled=L2_COMMANDS, session_timeout=300))
        for i in range(2):
            ev(f"{kind} job {i + 1} start")
            r = calls.timed("job", lambda: t.exec(cmd, exec_timeout=min(30000, int((deadline - time.time() - 4) * 1000 / (2 - i)))), cmd=cmd, n=i)
            s = short(r)
            ev(f"{kind} job {i + 1} end state={s['state']} job={s['jobStatus']}")
            if not keep:
                calls.timed("reset", lambda: t.exec("reset", exec_timeout=15000))
        if keep:
            # leave the classes enhanced, the job over, the server idle
            ev("leaving classes enhanced, no reset")
            return
        calls.timed("stop", lambda: t.exec("stop", exec_timeout=15000))
    return f


def act_l2_stuck(kind):
    cmd = L2_CMDS[kind]

    def f(t, deadline, calls, ev):
        calls.timed("attach", lambda: t.attach(enabled=L2_COMMANDS, session_timeout=300))
        sid = t.api("init_session")["body"]["sessionId"]
        r = calls.timed("async_exec", lambda: t.api("async_exec", cmd=cmd, session=sid), cmd=cmd)
        ev(f"async {kind} started state={short(r)['state']}")
        time.sleep(3)
        calls.timed("stop", lambda: t.exec("stop", exec_timeout=15000))
        ev("stopped while the job was running; class left enhanced")
    return f


def pick(name):
    if name == "noop":
        return act_noop
    if name == "attach_hold":
        return act_attach_hold
    if name == "attach_cycle":
        return act_attach_cycle
    kind, _, arg = name.partition(":")
    if kind == "l1c":
        return act_l1_cycle(arg)
    if kind == "l1s":
        return act_l1_session(arg)
    if kind == "l2":
        return act_l2(arg)
    if kind == "l2keep":
        return act_l2(arg, keep=True)
    if kind == "l2stuck":
        return act_l2_stuck(arg)
    raise SystemExit(f"unknown scenario {name}")


def safe(name):
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name)


def run_one(svc, name, rep, profile, phase, warm, out_root, sampler=False, tripwire=False, watch=False):
    d = out_root / "bench" / svc / f"{safe(name)}__{profile}" / f"rep{rep}"
    if (d / "done").exists():
        log("skip", d)
        return
    d.mkdir(parents=True, exist_ok=True)
    action = pick(name)
    t = Target(svc).up()
    pid = t.pid()
    insp = t.inspect()
    col = Collector(t, d / "metrics.jsonl")
    col.start()
    total = warm + phase * 3 + 8 + 8 + 6
    lg = subprocess.Popen(["sudo", "-n", "nice", "-n", "-10", "setpriv", f"--reuid={os.getuid()}", f"--regid={os.getgid()}", "--init-groups",
                           "taskset", "-c", LOAD_CPUS, str(LOADGEN), "-base", f"http://{t.ip()}:8080", "-duration", f"{total}s", "-out", str(d / "load.jsonl"),
                           *[x for f in PROFILES[profile] for x in ("-flow", f)]], stdout=subprocess.DEVNULL, stderr=open(d / "loadgen.err", "w"))
    if tripwire:
        # what the kernel says while the JVM makes no cpu progress for 200 ms (stall_tripwire.py reads /proc, it does not touch the JVM)
        # and fsync probes on the file system of the JVM's log files (/) and on the one of the raw data (/data)
        subprocess.Popen(["sudo", "-n", "taskset", "-c", "12-15", sys.executable, str(pathlib.Path(__file__).resolve().parent / "stall_tripwire.py"),
                          str(pid), str(d / "tripwire.jsonl"), str(total),
                          "--probe-dir", str(RUN / "fsync-probe"), "--probe-dir", str(out_root / "fsync-probe")])
    if watch:
        # JVM threads that stay in a write-type system call or in uninterruptible sleep for 100 ms, with their kernel stacks
        # (pause_watch.py reads /proc, it does not touch the JVM and does no I/O of its own besides its output file)
        subprocess.Popen(["sudo", "-n", "taskset", "-c", "12-15", sys.executable, str(pathlib.Path(__file__).resolve().parent / "pause_watch.py"),
                          str(pid), str(d / "watch.jsonl"), str(total)])
    events = []
    ev = lambda what: events.append({"t": time.time(), "what": what})
    calls = Calls(d / "calls.jsonl")
    try:
        t_start = time.time()
        time.sleep(warm)
        b0 = int(time.time()) + 1
        time.sleep(b0 - time.time())
        ev("window before start")
        time.sleep(phase - (time.time() - b0))
        d0 = b0 + phase
        ev("window during start")
        if sampler:
            # state of every JVM thread at 10 Hz during the middle window (stall_sampler.py reads /proc, it does not touch the JVM)
            threads = subprocess.Popen(["sudo", "-n", "taskset", "-c", "12-15", sys.executable, str(pathlib.Path(__file__).resolve().parent / "stall_sampler.py"),
                                        str(pid), str(d / "threads.jsonl"), str(phase + 4)])
        try:
            action(t, d0 + phase, calls, ev)
        except Exception as e:
            ev(f"action error: {e!r}")
        left = d0 + phase - time.time()
        ev(f"action finished {left:.1f}s before the end of the window")
        time.sleep(max(0, d0 + phase - time.time()))
        ev("gap start")
        if name.startswith(("l2keep", "l2stuck")):
            pass
        else:
            cleanup_arthas(t)
        a0 = d0 + phase + 8
        time.sleep(max(0, a0 - time.time()))
        ev("window after start")
        time.sleep(phase)
        ev("window after end")
        if name.startswith("l2keep"):
            cleanup_arthas(t)
    finally:
        try:
            lg.wait(timeout=total - (time.time() - t_start) + 30)
        except subprocess.TimeoutExpired:
            lg.terminate()
        col.stop_ev.set()
        col.join(timeout=5)
    meta = {"svc": svc, "scenario": name, "rep": rep, "profile": profile, "phase_s": phase, "warm_s": warm,
            "windows": {"before": [b0, b0 + phase], "during": [d0, d0 + phase], "after": [a0, a0 + phase]},
            "events": events, "target": insp, "java_version": t.logs().splitlines()[0] if t.logs() else "",
            "app_cpuset": os.environ.get("APP_CPUS", "4-7"), "load_cpus": LOAD_CPUS}
    # JVM logs: JDK 9+ write files; JDK 8 prints safepoint statistics to stdout
    for f in (RUN / svc / "logs").glob("*"):
        run(["cp", str(f), str(d / f.name)], check=False)
    (d / "stdout.log").write_text(run(["docker", "logs", "--timestamps", t.container], check=False).stdout)
    (d / "meta.json").write_text(json.dumps(meta, indent=2, default=str))
    (d / "done").write_text("ok")
    log("finished", svc, name, "rep", rep)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--svc", default="jdk17")
    ap.add_argument("--scenario", required=True, help="comma separated; a scenario may contain commas only inside its command, use ';' there")
    ap.add_argument("--rep", type=int, default=1)
    ap.add_argument("--reps", type=int, default=1)
    ap.add_argument("--phase", type=int, default=60)
    ap.add_argument("--warm", type=int, default=100)
    ap.add_argument("--profile", default="p1k")
    ap.add_argument("--sampler", action="store_true", help="also record the state of every JVM thread at 10 Hz during the middle window (threads.jsonl)")
    ap.add_argument("--tripwire", action="store_true", help="also record, for the whole run, the kernel state of the JVM's threads while it makes no cpu progress (tripwire.jsonl)")
    ap.add_argument("--watch", action="store_true", help="also record, for the whole run, the JVM threads that stay 100 ms in a write-type system call or in state D (watch.jsonl)")
    a = ap.parse_args()
    out_root = OUT
    for name in a.scenario.split(","):
        name = name.replace(";", ",")
        for rep in range(a.rep, a.rep + a.reps):
            prof = a.profile
            if name.startswith(("l2:", "l2keep:", "l2stuck:")) and "@" in name:
                name, prof = name.split("@")
            run_one(a.svc, name, rep, prof, a.phase, a.warm, out_root, a.sampler, a.tripwire, a.watch)
