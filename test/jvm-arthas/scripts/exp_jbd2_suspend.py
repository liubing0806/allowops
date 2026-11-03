#!/usr/bin/env python3
"""One writer that appends like the JVM's safepoint log, on the stall file system while its device is suspended
(docs/arthas-jvm-pause-report.md, 4.2). Run with sudo: the jbd2 thread's kernel stack needs root.

The writer appends three lines once a second (one write() per line, no fsync), the way the VM thread writes the safepoint log
at a quiet safepoint rate. A sampler reads the top frame of the jbd2 thread of the file system every 100 ms. The device is
suspended for 6 s, <tries> times, 7.3 s apart (scripts/stallfs.sh stall 6). For every suspension it prints the appends that took
more than 50 ms in it and the jbd2 frames seen in it.

Usage: sudo python3 exp_jbd2_suspend.py <file on run/stallfs> <pid of jbd2/dm-N> <tries> <path of scripts/stallfs.sh>
"""
import json
import os
import subprocess
import sys
import threading
import time

LINE = b"[2026-10-25T00:00:00.000+0000][1.000s] Application time: 1.0000567 seconds\n"


def main():
    path, jpid, tries, stallfs = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    stop = threading.Event()
    slow, frames = [], []

    def writer():
        while not stop.is_set():
            for _ in range(3):
                t0 = time.time()
                os.write(fd, LINE)
                d = time.time() - t0
                if d > 0.05:
                    slow.append((round(t0, 2), round(d, 2)))
            time.sleep(1.0)

    def sampler():
        while not stop.is_set():
            with open(f"/proc/{jpid}/stack") as f:
                st = f.read().splitlines()
            frames.append((round(time.time(), 2), st[0].split()[1] if st else "-"))
            time.sleep(0.1)

    threading.Thread(target=writer, daemon=True).start()
    threading.Thread(target=sampler, daemon=True).start()
    for i in range(tries):
        time.sleep(7.3)
        r = subprocess.run([stallfs, "stall", "6"], capture_output=True, text=True).stdout.strip()
        s = json.loads(r.splitlines()[-1])
        in_win = [x for x in slow if s["suspended"] - 0.1 <= x[0] <= s["resumed"]]
        fr = sorted({f for t, f in frames if s["suspended"] <= t <= s["resumed"]})
        print(f"suspension {i + 1}: appends > 50 ms in it: {in_win}; jbd2 frames: {fr}", flush=True)
    stop.set()


if __name__ == "__main__":
    main()
