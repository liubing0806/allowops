#!/usr/bin/env python3
"""Samples the threads of one process from /proc at about 10 Hz (needs root: run it with sudo).

Usage: stall_sampler.py <pid> <out.jsonl> <seconds>
One JSON line per sample: {"t": epoch seconds, "threads": [[comm, state, wchan, voluntary ctx switches], ...]}.
state is the third field of /proc/<pid>/task/<tid>/stat (R running, S interruptible sleep, D uninterruptible sleep, ...),
wchan the kernel function the thread sleeps in ("0" when it does not sleep).
"""
import json
import os
import sys
import time


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def main():
    pid, out, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    end = time.time() + seconds
    with open(out, "w") as f:
        while time.time() < end:
            t0 = time.time()
            rows = []
            try:
                tids = os.listdir(f"/proc/{pid}/task")
            except OSError:
                break
            for tid in tids:
                base = f"/proc/{pid}/task/{tid}"
                stat = read(base + "/stat")
                if not stat:
                    continue
                comm = stat[stat.index("(") + 1:stat.rindex(")")]
                state = stat[stat.rindex(")") + 2:].split()[0]
                status = read(base + "/status")
                vol = 0
                for ln in status.splitlines():
                    if ln.startswith("voluntary_ctxt_switches"):
                        vol = int(ln.split()[1])
                rows.append([comm, state, read(base + "/wchan").strip() or "-", vol])
            f.write(json.dumps({"t": t0, "threads": rows}) + "\n")
            f.flush()
            time.sleep(max(0.0, 0.1 - (time.time() - t0)))


if __name__ == "__main__":
    main()
