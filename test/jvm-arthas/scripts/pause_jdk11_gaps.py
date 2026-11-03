#!/usr/bin/env python3
"""JDK 11 safepoint logs of all bench.py runs under a directory: safepoints whose wall time (from the "Application time" line to the
"Total time for which application threads were stopped" line) exceeds the stop time that the JVM reports by more than a threshold.

Usage: pause_jdk11_gaps.py <bench root> <threshold ms>      prints (scenario, profile, repeat, start in s since the before window, wall ms, reported ms)
"""
import sys, json, pathlib, re, datetime as dt
root = pathlib.Path(sys.argv[1]); thr = float(sys.argv[2])
def ts(s): return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
tot = 0; hits = []
for done in sorted(root.rglob("done")):
    d = done.parent; m = json.load(open(d/"meta.json"))
    if m["svc"] != "jdk11": continue
    t0 = m["windows"]["before"][0]
    app = None; n = 0
    for ln in open(d/"safepoint.log", errors="ignore"):
        a = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Application time: ([0-9.]+) seconds", ln)
        if a: app = ts(a.group(1)); continue
        s = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Total time for which application threads were stopped: ([0-9.]+) seconds", ln)
        if s and app is not None:
            n += 1; wall = (ts(s.group(1)) - app) * 1000; rep = float(s.group(2)) * 1000
            if wall - rep > thr: hits.append((m["scenario"], m["profile"], m["rep"], round(app - t0, 1), round(wall, 1), round(rep, 1)))
            app = None
    tot += n
print("jdk11 safepoints", tot)
for h in hits: print(h)
