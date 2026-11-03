#!/usr/bin/env python3
"""Summary of host_io_probe.py records (docs/arthas-jvm-pause-report.md).

- every probe write of --ms or more (default 200): time, file system, length, the jbd2 thread's top frame and the writer's frame
  while it was stuck, and the disk load of the seconds around it (MB written, writes completed, cache flushes completed and the
  milliseconds they took, the cgroups that wrote the most);
- seconds in which the disk's cache flushes took --flush-ms or more in total (default 500), and how many of them have a probe
  write of --ms or more within 2 s.

Usage: host_io_summary.py [--ms 200] [--flush-ms 500] <host_io.jsonl>...
"""
import argparse
import json
import pathlib
import time


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ms", type=float, default=200)
    ap.add_argument("--flush-ms", type=float, default=500)
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    recs = []
    for f in a.files:
        for ln in open(f):
            try:
                recs.append(json.loads(ln))
            except json.JSONDecodeError:
                pass
    recs.sort(key=lambda r: r["t"])
    starts = [r for r in recs if r["kind"] == "start"]
    fs = {}
    for s in starts:
        fs.update(s["dirs"])
    writes = [r for r in recs if r["kind"] == "write" and r["seconds"] * 1000 >= a.ms]
    stuck = [r for r in recs if r["kind"] == "write_stuck"]
    loads = [r for r in recs if r["kind"] == "load"]
    span = (recs[0]["t"], recs[-1]["t"]) if recs else (0, 0)
    print(f"records {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(span[0]))} .. {time.strftime('%H:%M:%S', time.localtime(span[1]))}"
          f" ({(span[1] - span[0]) / 60:.0f} min); load records {len(loads)}")
    print(f"probe writes >= {a.ms:.0f} ms: {len(writes)}")
    for w in writes:
        st = [s for s in stuck if s["dir"] == w["dir"] and w["t"] <= s["t"] <= w["t"] + w["seconds"]]
        jf = sorted({s["jbd2_stack"].splitlines()[0].split()[1] for s in st if s.get("jbd2_stack")})
        wf = sorted({s["stack"].splitlines()[0].split()[1] for s in st if s.get("stack")})
        print(f"  {time.strftime('%H:%M:%S', time.localtime(w['t']))} {fs.get(w['dir'], '?'):10} {w['seconds']:.2f} s  writer {wf}  jbd2 {jf}")
        for r in loads:
            if w["t"] - 2.5 <= r["t"] <= w["t"] + w["seconds"] + 0.5:
                top = ", ".join(f"{k.rsplit('/', 1)[-1][:40]} {v}" for k, v in list(r["cgroups_mb"].items())[:3])
                print(f"      {r['t'] - w['t']:+.1f} s: {r['mb_written']} MB, {r['writes']} writes, flushes {r.get('flushes')} ({r.get('flush_ms')} ms); {top}")
    slow = [r for r in loads if r.get("flush_ms", 0) >= a.flush_ms]
    hit = [r for r in slow if any(abs(w["t"] - r["t"]) <= 2 or (w["t"] <= r["t"] <= w["t"] + w["seconds"] + 2) for w in writes)]
    print(f"seconds with cache flushes >= {a.flush_ms:.0f} ms in total: {len(slow)}; with a probe write >= {a.ms:.0f} ms within 2 s: {len(hit)}")
    with_w = [w for w in writes if any(r["t"] - 2 <= w["t"] <= r["t"] + r["seconds"] + 2 for r in slow)]
    print(f"probe writes >= {a.ms:.0f} ms during the load records: {len([w for w in writes if loads and loads[0]['t'] <= w['t'] <= loads[-1]['t']])};"
          f" with flushes >= {a.flush_ms:.0f} ms within 2 s: {len(with_w)}")


if __name__ == "__main__":
    main()
