#!/usr/bin/env python3
"""Summary of the JVM pause runs (bench.py --watch and exp_logstall.py) for docs/arthas-jvm-pause-report.md.

For each run directory:
- episodes: runs of consecutive seconds in which the p99 of every flow (hot, ping, work, db) is above --ms (default 200), with
  the largest latency, the JVM cpu over the episode (ticks of the metrics rows that span it) and what overlaps it: a device
  stall (exp_logstall.py), the first 4 s of an Arthas job (bench.py, the enhancement start), a JVM thread blocked in a write
  (pause_watch.py), a slow write of the host probe (host_io_probe.py, natural runs);
- safepoint log lines after which 100 ms or more went missing (pause_logwrite.py);
- JVM threads that pause_watch.py saw in a write-type system call or in state D for 100 ms or more, with the top of their stack.
Times are seconds from the start of the before window (bench.py) or from the start of the run (exp_logstall.py).

Usage: pause_summary.py [--ms 200] [--host <host_io.jsonl>] <run dir>...
"""
import argparse
import collections
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import pause_logwrite  # noqa: E402

BASE = 1.01
FLOWS = ("hot", "ping", "work", "db")


def val_ms(b):
    return (BASE ** (int(b) + 0.5) - 1) / 1000.0


def pct(c, q):
    n = sum(c.values())
    if not n:
        return 0.0
    k, acc = q * n, 0
    for b in sorted(c):
        acc += c[b]
        if acc >= k:
            return val_ms(b)
    return val_ms(max(c))


def jl(path):
    if not path.exists():
        return []
    out = []
    for ln in open(path):
        ln = ln.strip()
        if ln:
            try:
                out.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    return out


def frames(stack, n=6):
    return " < ".join(x.split()[1].split("+")[0] for x in stack.splitlines()[:n] if len(x.split()) > 1)


def summarize(d, ms, host):
    meta = json.load(open(d / "meta.json"))
    t0 = meta["windows"]["before"][0] if "windows" in meta else meta["start"]
    per = collections.defaultdict(lambda: collections.defaultdict(collections.Counter))
    for r in jl(d / "load.jsonl"):
        c = per[int(r["t"])][r["flow"]]
        for b, n in r["h"].items():
            c[int(b)] += n
    slow = sorted(s for s, f in per.items() if all(fl in f and pct(f[fl], 0.99) > ms for fl in FLOWS))
    eps = []
    for s in slow:
        if eps and s == eps[-1][1] + 1:
            eps[-1][1] = s
        else:
            eps.append([s, s])
    rows = [r for r in jl(d / "metrics.jsonl") if "ticks" in r]
    stalls = [(r["suspended"], r["resumed"]) for r in jl(d / "stalls.jsonl")]
    jobs = [(c["start"], c["start"] + 4) for c in jl(d / "calls.jsonl") if c.get("kind") == "job"]
    watch = jl(d / "watch.jsonl")
    blocked = {}
    for r in watch:
        if r["kind"] == "blocked":
            k = (r["tid"], r["since"])
            if k not in blocked:
                blocked[k] = {"since": r["since"], "comm": r["comm"], "call": r["call"], "state": r["state"], "wchan": r["wchan"],
                              "stack": frames(r["stack"]), "seconds": r["for_s"]}
            else:
                blocked[k]["seconds"] = max(blocked[k]["seconds"], r["for_s"])
        elif r["kind"] == "blocked_end" and (r["tid"], r["since"]) in blocked:
            blocked[(r["tid"], r["since"])]["seconds"] = r["seconds"]
    hostw = [(r["t"], r["t"] + r["seconds"], r) for r in host if r["kind"] == "write" and r["seconds"] >= 0.1]
    hostd = [(r["t"], r["t"] + r["seconds"], r) for r in host if r["kind"] == "disk_stall"]
    end = max(per) if per else t0

    def overlaps(a, b, ivs):
        return [iv for iv in ivs if iv[0] < b and iv[1] > a]

    name = meta.get("scenario") or meta.get("case")
    print(f"== {d}  ({meta['svc']} {name} rep{meta['rep']}; {meta.get('java_version', '')[:80]})")
    if stalls:
        print("   device stalls:", ", ".join(f"+{a - t0:.1f}..+{b - t0:.1f}" for a, b in stalls))
    if jobs:
        print("   Arthas jobs start:", ", ".join(f"+{a - t0:.1f}" for a, _ in jobs))
    hw = [h for h in hostw if t0 - 70 <= h[0] <= end]
    hd = [h for h in hostd if t0 - 70 <= h[0] <= end]
    if host:
        print(f"   host probe during the run: {len(hw)} writes >= 100 ms (max {max([h[2]['seconds'] for h in hw], default=0):.2f} s), "
              f"{len(hd)} disk stalls >= 100 ms (max {max([h[2]['seconds'] for h in hd], default=0):.2f} s)")
        for a, b, r in hw:
            print(f"     host write +{a - t0:.2f} {r['seconds']:.2f} s {pathlib.Path(r['dir']).name}")
    print(f"   episodes (all four flows p99 > {ms:.0f} ms): {len(eps)}")
    for a, b in eps:
        mx = max((val_ms(max(per[s][fl])) for s in range(a, b + 1) for fl in FLOWS if per[s][fl]), default=0)
        span = [r for r in rows if a - 1 <= r["t"] <= b + 2]
        cpu = (span[-1]["ticks"] - span[0]["ticks"]) / (span[-1]["t"] - span[0]["t"]) if len(span) > 1 else float("nan")
        tags = []
        if overlaps(a - 1, b + 1, stalls):
            tags.append("device stall")
        if overlaps(a - 0.5, b + 1, jobs):
            tags.append("first 4 s of a job")
        bl = [v for v in blocked.values() if v["since"] < b + 1 and v["since"] + v["seconds"] > a - 1]
        if bl:
            tags.append("blocked: " + "; ".join(f"{v['comm']} {v['call']} {v['seconds']:.2f}s" for v in bl[:3]))
        if overlaps(a - 1, b + 1, hw):
            tags.append("host write stall")
        print(f"     +{a - t0:.0f}..+{b - t0 + 1:.0f} s  max {mx:.0f} ms  JVM cpu {cpu:.0f}%  {' | '.join(tags)}")
    lw = pause_logwrite.scan(d / "safepoint.log", 100) if (d / "safepoint.log").exists() else []
    print(f"   safepoint log gaps >= 100 ms: {len(lw)}")
    for _, up, op, where, lost, figures, before in lw:
        print(f"     uptime {up:.3f}s {op} {where}: {lost} ms ({figures}); line before: {before}")
    print(f"   JVM threads >= 100 ms in a write or in D: {len(blocked)}")
    for v in sorted(blocked.values(), key=lambda v: v["since"]):
        print(f"     +{v['since'] - t0:.2f} {v['comm']!r} {v['call']} {v['state']} {v['seconds']:.2f}s  {v['stack']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ms", type=float, default=200)
    ap.add_argument("--host")
    ap.add_argument("dirs", nargs="+")
    a = ap.parse_args()
    host = jl(pathlib.Path(a.host)) if a.host else []
    for x in a.dirs:
        p = pathlib.Path(x)
        for d in ([p] if (p / "meta.json").exists() else sorted(q.parent for q in p.rglob("meta.json"))):
            summarize(d, a.ms, host)


if __name__ == "__main__":
    main()
