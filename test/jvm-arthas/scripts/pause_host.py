#!/usr/bin/env python3
"""Compares the JVM pauses of docs/arthas-stage0-report.md, section 3.5.6, with other activity on the host (needs `sudo -n journalctl`).

Usage: pause_host.py gaps <since> <until> <threshold s>     gaps between consecutive system journal entries, e.g. "2026-10-24 04:30:00" "2026-10-24 04:50:00" 3.8
       pause_host.py jvm <run dir> <jdk11|jdk21>            the JVM pauses of one bench.py run (JDK 11: safepoint wall time minus reported stop time > 20 ms;
                                                            JDK 21: safepoints > 200 ms) and the journal gaps > 1.5 s that overlap them
       pause_host.py probe <tripwire run dir>...            slow fsync probes (>= 0.3 s) of stall_tripwire.py runs and the journal gaps > 1.5 s that overlap them
       pause_host.py k3s <since>                            k3s "Slow SQL" entries (SQL statements that took one second or longer) since a time
Times in the output are local time (UTC+8).
"""
import datetime as dt
import json
import pathlib
import re
import subprocess
import sys

TZ = dt.timezone(dt.timedelta(hours=8))


def fmt(t):
    return dt.datetime.fromtimestamp(t, TZ).strftime("%H:%M:%S.%f")[:-3]


def stamp(t):
    return dt.datetime.fromtimestamp(t, TZ).strftime("%Y-%m-%d %H:%M:%S")


def ts(s):
    return dt.datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()


def journal_times(since, until):
    out = subprocess.run(["sudo", "-n", "journalctl", "--since", since, "--until", until, "--no-pager", "-o", "short-unix"], capture_output=True, text=True).stdout
    return [float(ln.split()[0]) for ln in out.splitlines() if ln[:1].isdigit()]


def gaps_between(times, thr):
    return [(a, b) for a, b in zip(times, times[1:]) if b - a > thr]


def cmd_gaps(since, until, thr):
    g = gaps_between(journal_times(since, until), float(thr))
    print(f"{len(g)} gaps > {thr} s")
    for a, b in g:
        print(f"{fmt(a)} -> {fmt(b)} ({b - a:.2f} s)")


def jvm_pauses(d, kind):
    ev = []
    lines = open(d / "safepoint.log", errors="ignore").read().splitlines()
    if kind == "jdk11":
        for i, ln in enumerate(lines):
            m = re.match(r"^\[([^\]]+)\]\[[^\]]+\] Application time", ln)
            if not m:
                continue
            for j in range(i + 1, min(i + 14, len(lines))):
                t = re.match(r"^\[([^\]]+)\].*Total time for which application threads were stopped: ([0-9.]+) seconds", lines[j])
                if t:
                    wall, rep = ts(t.group(1)) - ts(m.group(1)), float(t.group(2))
                    if wall - rep > 0.02:
                        ev.append((ts(m.group(1)), ts(m.group(1)) + wall - rep))
                    break
    else:
        pat = re.compile(r'^\[([^\]]+)\]\[[^\]]+\] Safepoint "([^"]+)".*Total: (\d+) ns')
        for ln in lines:
            x = pat.match(ln)
            if x and int(x.group(3)) / 1e9 > 0.2:
                end = ts(x.group(1))
                ev.append((end - int(x.group(3)) / 1e9, end))
    episodes = []
    for s, e in sorted(ev):  # merge pauses that are less than 1 s apart
        if episodes and s - episodes[-1][1] < 1.0:
            episodes[-1] = (episodes[-1][0], max(episodes[-1][1], e))
        else:
            episodes.append((s, e))
    return episodes


def cmd_jvm(run, kind):
    ep = jvm_pauses(pathlib.Path(run), kind)
    if not ep:
        print("no pauses")
        return
    gaps = gaps_between(journal_times(stamp(ep[0][0] - 30), stamp(ep[-1][1] + 30)), 1.5)
    for s, e in ep:
        near = [(fmt(a), fmt(b), round(b - a, 2)) for a, b in gaps if a <= e + 1 and b >= s - 1]
        print(f"JVM pause {fmt(s)} - {fmt(e)} ({e - s:.2f} s) | journal gaps > 1.5 s overlapping: {near}")


def cmd_probe(runs):
    for run in runs:
        rows = [json.loads(x) for x in open(pathlib.Path(run) / "tripwire.jsonl")]
        fs = [r for r in rows if r["kind"] == "fsync" and r["seconds"] >= 0.3]
        print("==", run, f"{len(fs)} fsync probes >= 0.3 s")
        if not fs:
            continue
        a, b = min(r["t"] for r in fs) - 10, max(r["t"] + r["seconds"] for r in fs) + 10
        gaps = gaps_between(journal_times(stamp(a), stamp(b)), 1.5)
        for r in fs:
            s, e = r["t"], r["t"] + r["seconds"]
            near = [(fmt(x), fmt(y), round(y - x, 2)) for x, y in gaps if x <= e + 0.5 and y >= s - 0.5]
            print(f"{r['dir']}: fsync {fmt(s)} +{r['seconds']:.2f} s | journal gaps > 1.5 s overlapping: {near}")


def cmd_k3s(since):
    out = subprocess.run(["sudo", "-n", "journalctl", "-u", "k3s", "--since", since, "--no-pager", "-o", "short-iso"], capture_output=True, text=True).stdout
    for ln in out.splitlines():
        m = re.search(r'Slow SQL.*duration=(\S+) name=(\S+) started="([^"]+)"', ln)
        if m:
            print(m.group(3), m.group(1), m.group(2))


if __name__ == "__main__":
    {"gaps": lambda a: cmd_gaps(*a), "jvm": lambda a: cmd_jvm(*a), "probe": cmd_probe, "k3s": lambda a: cmd_k3s(a[0])}[sys.argv[1]](sys.argv[2:])
