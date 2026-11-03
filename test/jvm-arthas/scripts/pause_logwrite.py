#!/usr/bin/env python3
"""Safepoints whose time is not spent in any timed step of the JVM, from the safepoint logs (-Xlog:safepoint*) of JDK 11, 17 and 21.

Each log line carries the uptime at which the JVM formatted it; the write to the file comes after that. When the time between two
lines is not covered by the duration that the later line (or the safepoint summary) reports, the JVM spent it between formatting
the earlier line and the next timed step, which in the code paths below is only the write of the earlier line:
  JDK 11  RuntimeService::record_safepoint_begin() logs "Application time" and then starts the safepoint timer. The gap between the
          "Application time" line and the "Entering safepoint region" line, minus "Stopping threads took", is not in the stop time
          that the JVM reports ("Total time for which application threads were stopped").
  JDK 17, 21  The cleanup phase (SafepointSynchronize::do_cleanup_tasks) logs one line per cleanup step ("updating inline caches",
          ...) and one for the whole phase ("safepoint cleanup tasks"). Cleanup phase minus the steps' own durations is the time
          between the steps, which is the writes of their lines.
"Reaching safepoint" longer than the threshold is listed separately: it is the time until the last Java thread stops, not a write.

Usage: pause_logwrite.py <threshold ms> <safepoint.log | directory>...     (directories are searched for safepoint.log)
Output: one line per safepoint over the threshold: file, uptime, cause, unexplained ms, the JVM's own figures, the line before the gap.
"""
import pathlib
import re
import sys

LINE = re.compile(r"^\[[^\]]+\]\[([0-9.]+)s\] (.*)$")
APP = re.compile(r"^Application time: ([0-9.]+) seconds")
ENTER = re.compile(r"^Entering safepoint region: (\S+)")
TOTAL11 = re.compile(r"^Total time for which application threads were stopped: ([0-9.]+) seconds, Stopping threads took: ([0-9.]+) seconds")
STEP = re.compile(r"^(.+), ([0-9.]+) secs$")
SUM17 = re.compile(r'^Safepoint "([^"]+)", Time since last: (\d+) ns, Reaching safepoint: (\d+) ns, Cleanup: (\d+) ns, At safepoint: (\d+) ns,'
                   r'(?: Leaving safepoint: (\d+) ns,)? Total: (\d+) ns')


def lines(path):
    for ln in open(path, errors="ignore"):
        m = LINE.match(ln.rstrip("\n"))
        if m:
            yield float(m.group(1)), m.group(2)


def scan(path, thr_ms, ends=None):
    """ends, when a list, gets the uptime at which each listed gap's safepoint ended (one entry per output line)."""
    out = []
    block = []          # lines of the current safepoint (JDK 17/21: since the previous summary line)
    app = None          # JDK 11: the "Application time" line of the current safepoint
    enter = None
    for up, text in lines(path):
        if APP.match(text):
            app, enter, block = (up, text), None, []
            continue
        m = ENTER.match(text)
        if m and app is not None:
            enter = (up, m.group(1))
            continue
        m = TOTAL11.match(text)
        if m:
            if app is not None and enter is not None:
                stop_ms, sync_ms = float(m.group(1)) * 1000, float(m.group(2)) * 1000
                gap_ms = (enter[0] - app[0]) * 1000
                lost = gap_ms - sync_ms
                if lost >= thr_ms:
                    out.append((path, app[0], enter[1], "after the 'Application time' line", round(lost, 1),
                                f"reported stop {stop_ms:.1f} ms, stopping threads {sync_ms:.1f} ms", app[1]))
                    if ends is not None:
                        ends.append(enter[0] + stop_ms / 1000)
            app = enter = None
            continue
        m = SUM17.match(text)
        if m:
            op = m.group(1)
            reach, clean = int(m.group(3)) / 1e6, int(m.group(4)) / 1e6
            at, total = int(m.group(5)) / 1e6, int(m.group(7)) / 1e6
            steps = [(u, t, float(STEP.match(t).group(2)) * 1000) for u, t in block if STEP.match(t)]
            inner = [s for s in steps if not s[1].startswith("safepoint cleanup tasks")]
            lost = clean - sum(s[2] for s in inner)
            if lost >= thr_ms:
                # the line after which the time went missing: the one before the largest gap among the cleanup lines
                prev = None
                for a, b in zip(steps, steps[1:]):
                    g = (b[0] - a[0]) * 1000 - (b[2] if b in inner else 0)
                    if prev is None or g > prev[0]:
                        prev = (g, a[1])
                out.append((path, block[0][0] if block else 0.0, op, "in the cleanup phase", round(lost, 1),
                            f"reaching {reach:.1f} ms, cleanup {clean:.1f} ms, at safepoint {at:.1f} ms, total {total:.1f} ms",
                            prev[1] if prev else ""))
                if ends is not None:
                    ends.append(up)
            if reach >= thr_ms:
                out.append((path, block[0][0] if block else 0.0, op, "reaching safepoint", round(reach, 1),
                            f"reaching {reach:.1f} ms, cleanup {clean:.1f} ms, at safepoint {at:.1f} ms, total {total:.1f} ms", ""))
                if ends is not None:
                    ends.append(up)
            block = []
            continue
        block.append((up, text))
    return out


def spans(path, thr_ms):
    """The log write gaps of scan() as wall-clock intervals: [(epoch start, epoch end, operation, where, lost ms)]. The uptime
    decoration is turned into epoch seconds with the time decoration of the first line ([<time>][<uptime>s])."""
    first = None
    for ln in open(path, errors="ignore"):
        m = re.match(r"^\[([^\]]+)\]\[([0-9.]+)s\]", ln)
        if m:
            first = m
            break
    if not first:
        return []
    from datetime import datetime
    offset = datetime.strptime(first.group(1), "%Y-%m-%dT%H:%M:%S.%f%z").timestamp() - float(first.group(2))
    ends = []
    rows = scan(path, thr_ms, ends)
    return [(r[1] + offset, e + offset, r[2], r[3], r[4]) for r, e in zip(rows, ends) if r[3] != "reaching safepoint"]


def main():
    thr = float(sys.argv[1])
    files = []
    for a in sys.argv[2:]:
        p = pathlib.Path(a)
        files += sorted(p.rglob("safepoint.log")) if p.is_dir() else [p]
    n = 0
    for f in files:
        for path, up, op, where, lost, figures, before in scan(f, thr):
            n += 1
            print(f"{path} | {up:.3f}s | {op} | {where} | {lost} ms | {figures} | {before}")
    print(f"# {len(files)} files, {n} safepoints at or over {thr} ms", file=sys.stderr)


if __name__ == "__main__":
    main()
