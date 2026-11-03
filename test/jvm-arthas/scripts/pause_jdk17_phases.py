#!/usr/bin/env python3
"""JDK 17 and 21 safepoint logs of all bench.py runs under a directory: safepoints longer than a threshold, with their phases.

Usage: pause_jdk17_phases.py <bench root> <threshold ms>
"""
import sys, json, pathlib, re, datetime as dt
root = pathlib.Path(sys.argv[1]); thr = float(sys.argv[2])
def ts(s): return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
pat = re.compile(r'^\[([^\]]+)\]\[[^\]]+\] Safepoint "([^"]+)", Time since last: (\d+) ns, Reaching safepoint: (\d+) ns, Cleanup: (\d+) ns, At safepoint: (\d+) ns,(?: Leaving safepoint: (\d+) ns,)? Total: (\d+) ns')
for done in sorted(root.rglob("done")):
    d = done.parent; m = json.load(open(d/"meta.json"))
    if m["svc"] not in ("jdk17", "jdk21"): continue
    t0 = m["windows"]["before"][0]
    for ln in open(d/"safepoint.log", errors="ignore"):
        x = pat.match(ln)
        if x and int(x.group(8)) / 1e6 >= thr:
            since, reach, clean, at, leave, tot = [(int(v) / 1e6 if v else 0.0) for v in x.groups()[2:]]
            end = ts(x.group(1)) - t0
            print(f"{m['svc']} | {m['scenario']} {m['profile']} rep{m['rep']} | starts +{end - tot / 1000:.1f}s | {x.group(2)} | reaching {reach:.1f} cleanup {clean:.1f} at {at:.1f} total {tot:.1f} ms")
