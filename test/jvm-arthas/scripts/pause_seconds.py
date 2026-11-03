#!/usr/bin/env python3
"""Seconds of one bench.py run whose p99 of the hot flow is above a threshold, with the JVM cpu and run delay of that second.

Usage: pause_seconds.py <run dir> [threshold ms = 100]      e.g. .../bench/jdk11/l2_watch__p10k/rep4
The metrics collector (bench.py) writes a row late when the JVM does not answer /diag (timeout 2 s): "metrics_interval" is the length of the
sampling period that ends in that second, 0.00 when no row ended in it.
"""
import sys, json, pathlib, re
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import transitions as T
d = pathlib.Path(sys.argv[1]); thr = float(sys.argv[2]) if len(sys.argv) > 2 else 100
per = T.per_second_hist(d); meta = json.load(open(d/"meta.json"))
calls = [json.loads(x) for x in open(d/"calls.jsonl")]
t0 = int(meta["windows"]["before"][0])
rows = [json.loads(l) for l in open(d/"metrics.jsonl")]
rows = [r for r in rows if "ticks" in r]
cpu, rd, gap = {}, {}, {}
for a, b in zip(rows, rows[1:]):
    s = int(b["t"]); dt = b["t"] - a["t"]
    cpu[s] = (b["ticks"]-a["ticks"])/dt; rd[s] = (b["rundelay_ns"]-a["rundelay_ns"])/1e9/dt; gap[s] = dt
print("jobs", [(round(c["start"]-t0,1), round(c["end"]-t0,1)) for c in calls if c["kind"]=="job"])
for s in sorted(per):
    p99 = T.pct(per[s], .99)
    if p99 > thr:
        print(f"+{s-t0} p99={p99:.1f} max={T.val(max(per[s])):.1f} n={sum(per[s].values())} jvmcpu={cpu.get(s,0):.0f}% rundelay={rd.get(s,0):.2f}s/s metrics_interval={gap.get(s,0):.2f}s")
