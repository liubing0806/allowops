#!/usr/bin/env python3
"""Once a second, the columns of /proc/stat for the given cpus, until <seconds> are over or <stop file> contains <stop text>.
Busy time without the double count of guest time: /proc/stat counts the time of virtual machine CPUs in both user and guest,
so bench.Collector's host_cpu (all columns but idle and iowait) counts it twice. Used by s3_l2_analyze.py for the CPU that
other processes take on the JVM's cpus.
usage: cpu_stat.py <cpus, e.g. 4-9> <seconds> <out.jsonl> [<stop file> <stop text>]"""
import json, sys, time

spec, seconds, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
stop = sys.argv[4:6]
want = {f"cpu{c}" for part in spec.split(",") for c in range(int(part.split("-")[0]), int(part.split("-")[-1]) + 1)}
COLS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal", "guest", "guest_nice")


def stopped():
    try:
        with open(stop[0]) as f:
            return stop[1] in f.read()
    except OSError:
        return False


end = time.time() + seconds
with open(out, "a") as w:
    while time.time() < end and not (stop and stopped()):
        row = {"t": round(time.time(), 3)}
        with open("/proc/stat") as f:
            for ln in f:
                p = ln.split()
                if p and p[0] in want:
                    row[p[0]] = dict(zip(COLS, map(int, p[1:])))
        w.write(json.dumps(row) + "\n")
        w.flush()
        time.sleep(1 - time.time() % 1)
