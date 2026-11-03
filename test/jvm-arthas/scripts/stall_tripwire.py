#!/usr/bin/env python3
"""Records what the kernel says about a frozen JVM (needs root: run it with sudo).

Polls the cpu ticks of one process (/proc/<pid>/stat) every 20 ms. While the process makes no progress for 200 ms or more, it records
for every thread the state, the kernel function it sleeps in (wchan) and the system call it is in, plus the kernel stack of the threads
in uninterruptible sleep, of the JVM's own threads (VM, GC, compiler, ...) and of the threads that sleep in an unusual place (not futex, epoll, accept, socket receive, nanosleep),
at the start of the freeze and every 250 ms after. Every 500 ms it also records the host's
pressure stall counters (/proc/pressure) and the dirty / writeback page counts. It reads /proc only, it does not touch the JVM.

With --probe-dir <dir> (repeatable) it also writes 4 KB and fsyncs it in each directory every 200 ms and records every fsync that takes 50 ms or more
("kind": "fsync", with the directory and the duration), to see whether the storage under the JVM's log files stalls at the same time as the JVM.

Usage: stall_tripwire.py <pid> <out.jsonl> <seconds> [--probe-dir <dir>]...
Records ("kind"): "psi" (every 500 ms), "freeze" (snapshot while frozen), "freeze_end" (ticks progress again; "frozen_s" is the length),
"fsync" (a probe write that took 50 ms or more).
"""
import collections
import json
import os
import sys
import threading
import time


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def ticks(pid):
    stat = read(f"/proc/{pid}/stat")
    if not stat:
        return None
    fields = stat[stat.rindex(")") + 2:].split()
    return int(fields[11]) + int(fields[12])


def psi():
    r = {"kind": "psi", "t": time.time()}
    for res in ("io", "memory", "cpu"):
        for ln in read(f"/proc/pressure/{res}").splitlines():
            kind, *kv = ln.split()
            for item in kv:
                k, v = item.split("=")
                if k == "total":
                    r[f"{res}_{kind}_us"] = int(v)
    for ln in read("/proc/meminfo").splitlines():
        if ln.startswith(("Dirty:", "Writeback:")):
            r[ln.split(":")[0].lower() + "_kb"] = int(ln.split()[1])
    return r


JVM_THREADS = ("VM ", "G1 ", "GC ", "C1 ", "C2 ", "Service Thread", "Sweeper", "Signal Dispatcher", "Reference Handler", "Finalizer")
BENIGN_WCHAN = {"futex_do_wait", "do_epoll_wait", "inet_csk_accept", "__skb_wait_for_more_packets", "do_nanosleep", "hrtimer_nanosleep", "do_sigtimedwait.isra.0", "-"}


def snapshot(pid):
    summary = collections.Counter()
    deep = []
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return {}, []
    for tid in tids:
        base = f"/proc/{pid}/task/{tid}"
        stat = read(base + "/stat")
        if not stat:
            continue
        comm = stat[stat.index("(") + 1:stat.rindex(")")]
        state = stat[stat.rindex(")") + 2:].split()[0]
        wchan = read(base + "/wchan").strip() or "-"
        sysc = (read(base + "/syscall").split() or ["?"])[0]
        summary[f"{state} {wchan} syscall={sysc}"] += 1
        if state == "D" or comm.startswith(JVM_THREADS) or wchan not in BENIGN_WCHAN:
            deep.append({"comm": comm, "tid": tid, "state": state, "wchan": wchan, "syscall": read(base + "/syscall").strip(), "stack": read(base + "/stack")})
    return dict(summary), deep


def probe(dirs, out, lock, end):
    """Writes and fsyncs 4 KB to a file in each directory every 200 ms; records the slow ones."""
    fds = []
    for d in dirs:
        os.makedirs(d, exist_ok=True)
        fds.append((d, os.open(os.path.join(d, "probe"), os.O_WRONLY | os.O_CREAT | os.O_TRUNC)))
    block = b"x" * 4096
    while time.time() < end:
        for d, fd in fds:
            t0 = time.time()
            os.lseek(fd, 0, os.SEEK_SET)
            os.write(fd, block)
            os.fsync(fd)
            dur = time.time() - t0
            if dur >= 0.05:
                with lock:
                    out.write(json.dumps({"kind": "fsync", "t": t0, "dir": d, "seconds": round(dur, 3)}) + "\n")
                    out.flush()
        time.sleep(0.2)
    for _, fd in fds:
        os.close(fd)


def main():
    pid, out, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    dirs = [sys.argv[i + 1] for i, a in enumerate(sys.argv) if a == "--probe-dir"]
    end = time.time() + seconds
    last_ticks, last_change, last_psi, last_snap, frozen_since = ticks(pid), time.time(), 0.0, 0.0, None
    with open(out, "w") as f:
        lock = threading.Lock()
        if dirs:
            threading.Thread(target=probe, args=(dirs, f, lock, end), daemon=True).start()
        while time.time() < end:
            now = time.time()
            tk = ticks(pid)
            if tk is None:
                break
            if tk != last_ticks:
                if frozen_since is not None:
                    with lock:
                        f.write(json.dumps({"kind": "freeze_end", "t": now, "frozen_s": round(now - last_change, 3), "since": last_change}) + "\n")
                    frozen_since = None
                last_ticks, last_change = tk, now
            elif now - last_change >= 0.2:
                if frozen_since is None:
                    frozen_since = now
                if now - last_snap >= 0.25:
                    summary, deep = snapshot(pid)
                    with lock:
                        f.write(json.dumps({"kind": "freeze", "t": now, "frozen_for_s": round(now - last_change, 3), "threads": summary, "deep": deep}) + "\n")
                    last_snap = time.time()
            if now - last_psi >= 0.5:
                with lock:
                    f.write(json.dumps(psi()) + "\n")
                last_psi = now
            with lock:
                f.flush()
            time.sleep(0.02)


if __name__ == "__main__":
    main()
