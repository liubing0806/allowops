#!/usr/bin/env python3
"""Per-second latency of the hot flow around the Arthas calls of one benchmark run (the retransform / attach transients of item 5).

Usage: transitions.py <run dir> [seconds-after=6] [kinds=attach,job,reset,stop]
For the first call of each kind: one line per second from 1 s before the call to `seconds-after` seconds after its start,
with p50 / p99 / max of the hot flow, the JVM CPU in that second and the safepoint operations that began in it.

       transitions.py --table <bench root>
One markdown row per run that enhances a class (l2*, l2stuck*): how many seconds after the enhancement started the hot flow's p99 stayed above
max(10 ms, 3 x the typical p99 of the before window), the worst second, and the safepoints (redefine, other non-GC) of the first 5 seconds.
"""
import collections
import datetime as dt
import json
import pathlib
import re
import sys

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


def per_second_hist(d, flow="hot"):
    per = collections.defaultdict(collections.Counter)
    for ln in open(d / "load.jsonl"):
        r = json.loads(ln)
        if r["flow"] == flow:
            c = per[int(r["t"])]
            for b, n in r["h"].items():
                c[int(b)] += n
    return per


def table(root):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    import analyze
    print("| svc | scenario | profile | rep | typical p99 before ms | enhancement start | seconds above threshold (first 10 s) | worst second p50 / p99 / max ms | JVM CPU % in worst second | redefine STW (count, max ms) in first 5 s | other STW max ms in first 5 s | reset: worst p99 / max ms in first 3 s |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|")
    for done in sorted(pathlib.Path(root).rglob("done")):
        d = done.parent
        meta = json.load(open(d / "meta.json"))
        if not meta["scenario"].startswith("l2"):
            continue
        calls = [json.loads(x) for x in open(d / "calls.jsonl")]
        starts = [c for c in calls if c["kind"] in ("job", "async_exec")]
        if not starts:
            continue
        s0 = int(starts[0]["start"])
        per = per_second_hist(d)
        b0, b1 = meta["windows"]["before"]
        typ = sorted(pct(per[x], .99) for x in range(b0, b1) if x in per)
        typ = typ[len(typ) // 2]
        thr = max(10.0, 3 * typ)
        secs = [(x, per[x]) for x in range(s0, s0 + 10) if x in per]
        bad = [x for x, h in secs if pct(h, .99) > thr]
        worst = max(secs, key=lambda xh: pct(xh[1], .99))
        cpu = {}
        prev = None
        for ln in open(d / "metrics.jsonl"):
            r = json.loads(ln)
            if "ticks" not in r:
                continue
            if prev is not None:
                cpu[int(r["t"])] = (r["ticks"] - prev["ticks"]) / (r["t"] - prev["t"])
            prev = r
        java_major = 8
        m = re.search(r"java major=(\d+)", (d / "stdout.log").read_text(errors="ignore"))
        if m:
            java_major = int(m.group(1))
        sps = analyze.safepoints(d, java_major)
        first5 = [e for e in sps if s0 <= e[0] < s0 + 6]
        red = [e for e in first5 if "redefine" in e[1].lower()]
        other = [e for e in first5 if not analyze.GC_OPS.match(e[1]) and "redefine" not in e[1].lower()]
        resets = [c for c in calls if c["kind"] == "reset"]
        rtxt = "-"
        if resets:
            r0 = int(resets[0]["start"])
            rs = [(x, per[x]) for x in range(r0, r0 + 3) if x in per]
            if rs:
                w = max(rs, key=lambda xh: pct(xh[1], .99))
                rtxt = f"{pct(w[1], .99):.1f} / {val(max(w[1])):.1f}"
        print(f"| {meta['svc']} | {meta['scenario']} | {meta['profile']} | {meta['rep']} | {typ:.2f} | +{s0 - b0}s | {len(bad)} | {pct(worst[1], .5):.1f} / {pct(worst[1], .99):.1f} / {val(max(worst[1])):.1f} | {cpu.get(worst[0], 0):.0f} | "
              f"{len(red)}, {max((e[2] for e in red), default=0):.1f} | {max((e[2] for e in other), default=0):.1f} | {rtxt} |")


def main():
    if sys.argv[1] == "--table":
        return table(sys.argv[2])
    d = pathlib.Path(sys.argv[1])
    after = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    kinds = (sys.argv[3] if len(sys.argv) > 3 else "attach,job,reset,stop").split(",")
    per = collections.defaultdict(collections.Counter)
    for ln in open(d / "load.jsonl"):
        r = json.loads(ln)
        if r["flow"] == "hot":
            c = per[int(r["t"])]
            for b, n in r["h"].items():
                c[int(b)] += n
    cpu = {}
    prev = None
    for ln in open(d / "metrics.jsonl"):
        r = json.loads(ln)
        if "ticks" not in r:
            continue
        if prev is not None:
            cpu[int(r["t"])] = (r["ticks"] - prev["ticks"]) / (r["t"] - prev["t"])
        prev = r
    sps = collections.defaultdict(list)
    sp = d / "safepoint.log"
    if sp.exists():
        pat = re.compile(r'^\[([^\]]+)\]\[[^\]]+\] Safepoint "([^"]+)".*Total: (\d+) ns')
        for ln in sp.read_text(errors="ignore").splitlines():
            m = pat.match(ln)
            if m:
                sps[int(ts(m.group(1)))].append(f"{m.group(2)} {int(m.group(3)) / 1e6:.1f}ms")
    calls = [json.loads(x) for x in open(d / "calls.jsonl")]
    seen = set()
    for c in calls:
        if c["kind"] not in kinds or c["kind"] in seen:
            continue
        seen.add(c["kind"])
        t0 = int(c["start"])
        print(f"--- {c['kind']} starts at second {t0} ({c['ms']} ms)")
        for sec in range(t0 - 1, t0 + after + 1):
            h = per.get(sec)
            if not h:
                continue
            print(f"  {sec - t0:+3d}s  n={sum(h.values()):5d}  p50={pct(h, .5):8.2f}  p99={pct(h, .99):8.2f}  max={val(max(h)):8.2f} ms  jvm_cpu={cpu.get(sec, 0):6.1f}%  {'; '.join(sps.get(sec, []))[:120]}")


if __name__ == "__main__":
    main()
