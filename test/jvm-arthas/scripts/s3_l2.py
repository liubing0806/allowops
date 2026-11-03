#!/usr/bin/env python3
"""Stage-3 L2 measurements (docs/arthas-stage3-l2-report.md): watch, trace, stack, monitor and jad through the product
code. Every call goes through bin/ja-call (acceptcall/), which runs jvmarthas.RunWith with the product defaults (enhance_duration
30s, max_methods 5, checks.max_cpu_percent 50, no guard) and class_prefixes [demo.]. Raw data goes to $JA_OUT/l2/... and
$JA_OUT/l2func/...; analysis: s3_l2_analyze.py.

Run from test/jvm-arthas with COMPOSE_FILE=compose.yaml:compose.stage3.yaml:compose.s3d.yaml, COMPOSE_PROJECT_NAME=jvm-arthas-s3d,
JA_PORT_PREFIX=23 and JA_LOGDIR_TMPFS=/logs-tmpfs (scripts/run_s3_l2.sh sets them). Subcommands:

  run    one new JVM under the p1k or p10k load of stage 0: warm-up, a before window, the calls --every seconds apart, an after
         window. The calls keep one state directory, so the attach count and interval checks of the product apply.
         --mode steady: watch, trace, stack and monitor with the condition #cost>10000 (ms), which the method never meets: the
           enhancement lasts the whole enhance_duration and every call of the method evaluates the condition (count 5; monitor
           -c 5 -n 5, 25 s). --mode plain: no condition, count 1 (monitor -c 1 -n 1): the job ends at the first result.
         The order of the commands turns by one place per repetition. --burn threads,duty keeps busy threads running from the
         start of the warm-up (a JVM that already uses part of its CPU limit; with --variant, results apart). Besides the
         probes of stage 3, thread_cpu.py records the CPU of the JVM's threads by group (threads.jsonl).
  func   functional checks of the L2 paths on a new JVM (not measurements): affect2 (max_methods 1, a method with 2 overloads),
         affect6 (default max_methods, a method with 6 overloads), cpu (busy threads before the call: the CPU check refuses),
         guard (guard.max_cpu_percent 80 and one busy thread: the guard aborts the job once the 5 s after the start of the
         enhancement are over). Each prints PASS or FAIL per expectation.
  host   one sample of the load of the host (the "others" record written before and after every run).
"""
import argparse
import os
import signal

os.environ.setdefault("JA_LOGDIR_TMPFS", "/logs-tmpfs")

from ja import *  # noqa: E402,F403
from analyze import load  # noqa: E402
from bench import Collector  # noqa: E402
from accept import CALL_CPUS, LOAD_PROFILES, Others, ja_call, keep_logs, set_env, start_loadgen, start_probes  # noqa: E402

JDKS = ["jdk8", "jdk11", "jdk17", "jdk21"]
ORDER = ["watch", "trace", "stack", "monitor", "jad"]
MODES = {
    "steady": ["-count", "5", "-min-cost-ms", "10000", "-cycle", "5"],
    "plain": ["-count", "1", "-cycle", "1"],
}
STATE_ROOT = pathlib.Path("/tmp/ja-s3d-state")
MEASURE_CPUS = os.environ.get("JA_MEASURE_CPUS", "4-9,12-15")
DISK = os.environ.get("JA_DISK", "nvme0n1")


def cpu_list(spec):
    return [c for part in spec.split(",") for c in range(int(part.split("-")[0]), int(part.split("-")[-1]) + 1)]


def host_sample(seconds=5.0, cpus=MEASURE_CPUS, disk=DISK):
    """The load of the host over `seconds`, from /proc: busy percent of each measured cpu, the processes that used the most cpu
    (with the cpu each last ran on), the reads and writes of the disk, the load average and the containers of other copies of the
    environment."""
    want = {f"cpu{c}" for c in cpu_list(cpus)}

    def busy():
        out = {}
        for ln in open("/proc/stat"):
            f = ln.split()
            if f and f[0] in want:
                v = [int(x) for x in f[1:9]]
                out[f[0]] = sum(v) - v[3] - v[4]
        return out

    def diskstats():
        for ln in open("/proc/diskstats"):
            f = ln.split()
            if len(f) > 13 and f[2] == disk:
                return {"read_sectors": int(f[5]), "write_sectors": int(f[9]), "io_ms": int(f[12])}
        return {}

    t0, b0, p0, d0 = time.time(), busy(), Others.procs(), diskstats()
    time.sleep(seconds)
    t1, b1, p1, d1 = time.time(), busy(), Others.procs(), diskstats()
    dt = t1 - t0
    top = []
    for ticks, pid in sorted(((v[1] - p0[k][1], k) for k, v in p1.items() if k in p0), reverse=True)[:10]:
        if ticks <= 0:
            break
        top.append({"pid": int(pid), "comm": p1[pid][0], "cpu_pct": round(ticks / dt, 1), "last_cpu": p1[pid][2]})
    dk = {k: d1[k] - d0[k] for k in d1 if k in d0}
    names = run(["docker", "ps", "--format", "{{.Names}}"], check=False).stdout.split()
    return {"t": t0, "seconds": round(dt, 2), "loadavg": open("/proc/loadavg").read().split()[:3],
            "cpu_busy_pct": {k: round((b1[k] - b0[k]) / dt, 1) for k in sorted(b1, key=lambda x: int(x[3:]))},
            "top": top, "disk": {"device": disk, "read_mb_s": round(dk.get("read_sectors", 0) * 512 / dt / 1e6, 2),
                                 "write_mb_s": round(dk.get("write_sectors", 0) * 512 / dt / 1e6, 2),
                                 "util_pct": round(dk.get("io_ms", 0) / dt / 10, 1)},
            "other_jvm_arthas": sorted(n for n in names if n.startswith("jvm-arthas") and not n.startswith(PROJECT + "-")),
            "containers": len(names)}


def turned(order, k):
    k %= len(order)
    return order[k:] + order[:k]


def fresh_state(name):
    d = STATE_ROOT / name
    run(["sudo", "-n", "rm", "-rf", str(d)], check=False)
    return d / "arthas"


def remove(d):
    """An earlier attempt of a run; ja-call (root) wrote its calls/ directory."""
    if d.exists():
        run(["sudo", "-n", "rm", "-rf", str(d)])


def drop_state(path):
    run(["sudo", "-n", "rm", "-rf", str(path.parent)], check=False)


# run -------------------------------------------------------------------------------------------------------------------------------
def l2run(a):
    order = turned(a.order.split(","), a.rep - 1)
    d = OUT / "l2" / (a.mode + (f"-{a.variant}" if a.variant else "")) / a.svc / a.profile / f"rep{a.rep}"
    if (d / "done").exists():
        log("skip", d)
        return
    remove(d)
    d.mkdir(parents=True)
    host_before = host_sample()
    set_env(a.mem)
    for other in JDKS:
        if other != a.svc:
            Target(other).down()  # an idle JVM on the same cpus is noise
    t = Target(a.svc).up()
    events = []
    ev = lambda what: events.append({"t": time.time(), "what": what})
    during = a.every * len(order)
    total = a.warm + a.phase + during + 8 + a.after + 6
    if a.burn:
        threads, duty = a.burn.split(",")
        ev("burn " + http_get(f"http://{t.ip()}:8080/l2/burn?threads={threads}&seconds={total + 30}&duty={duty}"))
    col = Collector(t, d / "metrics.jsonl")
    col.start()
    start_probes(t, d, total + 30)
    threads = subprocess.Popen(["taskset", "-c", CALL_CPUS, sys.executable, str(pathlib.Path(__file__).with_name("thread_cpu.py")),
                                f"{PROJECT}-{a.svc}-1", str(total + 30), str(d / "threads.jsonl")])
    others = Others(d / "others.jsonl")
    others.start()
    lg = start_loadgen(t, d, total, LOAD_PROFILES[a.profile])
    t_start = time.time()
    state = fresh_state(f"{a.mode}-{a.svc}-{a.profile}-rep{a.rep}")
    try:
        time.sleep(max(0, t_start + a.warm - time.time()))
        b0 = int(time.time()) + 1
        time.sleep(b0 - time.time())
        ev("window before start")
        d0 = b0 + a.phase
        time.sleep(max(0, d0 - time.time()))
        ev("window during start")
        p = ja_call(a.svc, d / "calls.jsonl", f"{a.svc}-{a.mode}-{a.profile}-rep{a.rep}", order, calls=len(order), start=d0 + a.offset,
                    every=a.every, state=str(state), extra=MODES[a.mode], evidence=d / "calls")
        (d / "ja-call.err").write_text(p.stderr)
        ev(f"calls finished rc={p.returncode} {d0 + during - time.time():.1f}s before the end of the window")
        time.sleep(max(0, d0 + during - time.time()))
        a0 = d0 + during + 8
        time.sleep(max(0, a0 - time.time()))
        ev("window after start")
        time.sleep(a.after)
        ev("window after end")
        (d / "live.json").write_text(http_get(f"http://{t.ip()}:8080/diag/live", 30))
    finally:
        try:
            lg.wait(timeout=total - (time.time() - t_start) + 30)
        except subprocess.TimeoutExpired:
            lg.terminate()
        col.stop_ev.set()
        col.join(timeout=5)
        others.stop_ev.set()
        threads.terminate()
        drop_state(state)
    meta = {"svc": a.svc, "mode": a.mode, "variant": a.variant, "burn": a.burn, "profile": a.profile, "rep": a.rep, "order": order, "every_s": a.every, "offset_s": a.offset,
            "windows": {"before": [b0, b0 + a.phase], "during": [d0, d0 + during], "after": [a0, a0 + a.after]},
            "events": events, "args": vars(a), "mode_args": MODES[a.mode], "app_cpuset": os.environ.get("APP_CPUS", "4-7"),
            "load_cpus": os.environ.get("LOAD_CPUS", "8-9"), "call_cpus": CALL_CPUS, "project": PROJECT,
            "image": run(["docker", "inspect", "-f", "{{.Image}}", t.container], check=False).stdout.strip(),
            "env": {k: os.environ.get(k, "") for k in ("COMPOSE_FILE", "JA_GC", "JA_JAVA_EXTRA", "JA_LOGDIR_TMPFS", "APP_MEM")},
            "java_cmdline": open(f"/proc/{t.pid()}/cmdline").read().replace("\0", " ").strip(),
            "host_before": host_before}
    keep_logs(t, a.svc, d)
    meta["host_after"] = host_sample()
    # run.json, not meta.json: l2_threshold.py analyses the per-call views that s3_l2_analyze.py builds from this directory
    (d / "run.json").write_text(json.dumps(meta, indent=2, default=str))
    (d / "done").write_text("ok")
    log("finished", a.mode, a.svc, a.profile, "rep", a.rep, "rc", p.returncode)


# func ------------------------------------------------------------------------------------------------------------------------------
def expect(results, name, ok, detail):
    results.append({"check": name, "pass": bool(ok), "detail": detail})
    log("PASS" if ok else "FAIL", name, "-", detail)


def job_times(rec):
    """Seconds from the start of the call to async_exec of the job, and from async_exec to the first request that ends it."""
    reqs = sorted(rec["steps"].get("requests") or [], key=lambda r: r["open"])
    idx = next((i for i, r in enumerate(reqs) if r.get("action") == "async_exec"), None)
    if idx is None:
        return None, None, None
    j0 = reqs[idx]["open"]
    end = next((r for r in reqs[idx + 1:] if r.get("action") not in ("pull_results",)), None)
    return j0 / 1000, (end["open"] - j0) / 1000 if end else None, end.get("action") if end else None


def clean_after(results, case, rec):
    """After every call: no class stays enhanced (a call refused before the attach has no enhanced_classes row), no Arthas port,
    no arthas- thread, no new process."""
    post = rec.get("post", {})
    if rec["status"] != "refused":
        expect(results, f"{case}: enhanced_classes 0", (rec.get("enhanced_classes") or "").startswith("0 "), rec.get("enhanced_classes") or "(no row)")
    expect(results, f"{case}: no Arthas port, no arthas- thread, same processes",
           not post.get("listening") and post.get("arthas_threads") == 0 and post.get("procs_same"),
           f"listening {post.get('listening')}, arthas threads {post.get('arthas_threads')}, procs_same {post.get('procs_same')}")


def jvm_cpu_series(path, t0, t1):
    """[(seconds after t0, JVM CPU %)] from metrics.jsonl (100 is one CPU)."""
    rows = [r for r in load(path) if "ticks" in r]
    out = []
    for p, q in zip(rows, rows[1:]):
        if t0 - 2 <= q["t"] <= t1 + 2:
            out.append((round(q["t"] - t0, 1), round((q["ticks"] - p["ticks"]) / (q["t"] - p["t"]), 0)))
    return out


def func(a):
    root = OUT / "l2func" / a.svc
    root.mkdir(parents=True, exist_ok=True)
    results = []
    set_env(a.mem)
    for other in JDKS:
        if other != a.svc:
            Target(other).down()
    for case in a.cases.split(","):
        d = root / case
        remove(d)
        d.mkdir(parents=True)
        t = Target(a.svc).up()
        ip = t.ip()
        col = Collector(t, d / "metrics.jsonl")
        col.start()
        lg = start_loadgen(t, d, 150, LOAD_PROFILES["p1k"])
        time.sleep(30)  # warm-up
        for _ in range(50):
            http_get(f"http://{ip}:8080/l2/overloads?x=3")
        state = fresh_state(f"func-{a.svc}-{case}")
        steady = MODES["steady"]
        if case == "affect2":
            args = (["watch"], ["-class", "demo.L2Overloads", "-method", "calc", "-max-methods", "1"])
        elif case == "affect6":
            args = (["trace"], ["-class", "demo.L2Overloads", "-method", "many"])
        elif case == "cpu":
            http_get(f"http://{ip}:8080/l2/burn?threads=3&seconds=20")
            time.sleep(2)
            args = (["watch"], steady)
        elif case == "guard":
            http_get(f"http://{ip}:8080/l2/burn?threads=1&seconds=60")
            time.sleep(2)
            args = (["watch"], steady + ["-guard-cpu", "80"])
        else:
            raise SystemExit(f"unknown case {case}")
        p = ja_call(a.svc, d / "calls.jsonl", f"func-{a.svc}-{case}", args[0], state=str(state), extra=args[1], evidence=d / "calls")
        (d / "ja-call.err").write_text(p.stderr)
        time.sleep(3)
        col.stop_ev.set()
        col.join(timeout=5)
        lg.send_signal(signal.SIGINT)  # ja-loadgen writes the seconds still open on SIGINT only; sudo passes it on
        lg.wait(timeout=30)
        drop_state(state)
        keep_logs(t, a.svc, d)
        recs = load(d / "calls.jsonl") if (d / "calls.jsonl").exists() else []
        if not recs:
            expect(results, f"{case}: ja-call wrote a record", False, p.stderr[-500:])
            continue
        rec = recs[0]
        c = f"{a.svc} {case}"
        if case == "affect2":
            expect(results, f"{c}: failed, check affect, 2 methods over max_methods 1",
                   rec["status"] == "failed" and rec.get("check") == "affect" and "affected 2 methods, the limit is 1" in (rec.get("reason") or ""),
                   f"status {rec['status']}, check {rec.get('check')}, reason {rec.get('reason')}, affect {rec.get('affect')}")
            expect(results, f"{c}: reset restored the class", rec.get("enhanced_classes") == "0 (reset restored 1)", rec.get("enhanced_classes"))
        elif case == "affect6":
            expect(results, f"{c}: failed, check affect, 6 methods over the default max_methods 5",
                   rec["status"] == "failed" and rec.get("check") == "affect" and "affected 6 methods, the limit is 5" in (rec.get("reason") or ""),
                   f"status {rec['status']}, check {rec.get('check')}, reason {rec.get('reason')}, affect {rec.get('affect')}")
            expect(results, f"{c}: reset restored the class", rec.get("enhanced_classes") == "0 (reset restored 1)", rec.get("enhanced_classes"))
        elif case == "cpu":
            expect(results, f"{c}: refused by cpu_usage before the attach",
                   rec["status"] == "refused" and rec.get("check") == "cpu_usage" and not rec["steps"].get("attach") and not rec.get("attach"),
                   f"status {rec['status']}, check {rec.get('check')}, cpu_before {rec.get('cpu_before')}, reason {rec.get('reason')}, "
                   f"attach step {rec['steps'].get('attach')}")
        elif case == "guard":
            # The JVM uses more than 80% from the start of the enhancement on (one busy thread alone is about 100%): an abort at
            # 5 s or later shows that the first 5 s are not evaluated.
            j0, dur, end = job_times(rec)
            start = rec["start"] + (j0 or 0)
            cpu = jvm_cpu_series(d / "metrics.jsonl", start, start + 12)
            early = [x for x in cpu if 0 <= x[0] < 5 and x[1] > 80]
            expect(results, f"{c}: aborted_by_guard by cpu, not within 5 s of the start of the enhancement",
                   rec["status"] == "aborted_by_guard" and rec.get("check") == "cpu" and dur is not None and dur >= 5.0 and bool(early),
                   f"status {rec['status']}, check {rec.get('check')}, reason {rec.get('reason')}, async_exec to {end} {dur} s, "
                   f"cpu_before {rec.get('cpu_before')}, JVM CPU % per second from the start of the enhancement {cpu}")
        clean_after(results, c, rec)
    (root / "results.json").write_text(json.dumps(results, indent=2))
    failed = [r for r in results if not r["pass"]]
    log(f"func {a.svc}: {len(results) - len(failed)} of {len(results)} passed")
    return 1 if failed else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    rp = sub.add_parser("run")
    rp.add_argument("--svc", default="jdk17", choices=JDKS)
    rp.add_argument("--profile", default="p1k", choices=sorted(LOAD_PROFILES))
    rp.add_argument("--mode", default="steady", choices=sorted(MODES))
    rp.add_argument("--rep", type=int, default=1)
    rp.add_argument("--order", default=",".join(ORDER), help="commands in the order of repetition 1")
    rp.add_argument("--every", type=float, default=70, help="seconds from the start of one call to the start of the next")
    rp.add_argument("--offset", type=float, default=5, help="seconds from the start of the during window to the first call")
    rp.add_argument("--warm", type=int, default=60)
    rp.add_argument("--phase", type=int, default=60, help="length of the before window")
    rp.add_argument("--after", type=int, default=60)
    rp.add_argument("--mem", default="2g")
    rp.add_argument("--burn", default="", help="threads,duty: busy threads of /l2/burn for the whole run, each busy duty %% of the time")
    rp.add_argument("--variant", default="", help="name of the run variant, appended to the mode in the directory name (with --burn)")
    fp = sub.add_parser("func")
    fp.add_argument("--svc", default="jdk17", choices=JDKS)
    fp.add_argument("--cases", default="affect2,affect6,cpu,guard")
    fp.add_argument("--mem", default="2g")
    sub.add_parser("host")
    a = ap.parse_args()
    # The defaults of compose.yaml start the JVM on the cpus and with the project name of other copies of the environment.
    if "compose.s3d.yaml" not in os.environ.get("COMPOSE_FILE", "") or not os.environ.get("COMPOSE_PROJECT_NAME") or not os.environ.get("APP_CPUS"):
        sys.exit("set COMPOSE_FILE (with compose.s3d.yaml), COMPOSE_PROJECT_NAME and APP_CPUS, see scripts/run_s3_l2.sh")
    if a.cmd == "run":
        l2run(a)
    elif a.cmd == "func":
        sys.exit(func(a))
    else:
        print(json.dumps(host_sample(), indent=1))


if __name__ == "__main__":
    main()
