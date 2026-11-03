#!/usr/bin/env python3
"""What the kernel says while the threads of one JVM sit in a slow system call or in uninterruptible sleep (run with sudo: the kernel
stacks need root). It reads /proc only, it does not touch the JVM.

Every 20 ms it reads, for every thread of the process, the state (/proc/<pid>/task/<tid>/stat) and the system call it is in
(/proc/<pid>/task/<tid>/syscall). A thread that stays in the same write-type system call (write, pwrite64, writev, fsync,
fdatasync, msync) or in state D for 100 ms or more is recorded once with its name, system call, wchan and kernel stack, and again
every 500 ms while it stays there; when it leaves, a "blocked_end" record gives the total time. While some thread has been
there for 200 ms or more, a "snapshot" record (at most every 500 ms) gives the state and wchan of every thread of the process,
and the kernel stack of the threads that sleep somewhere else than the usual waits (futex, epoll, accept, socket receive,
nanosleep). The process's cpu ticks are recorded with every record, so a pause of the whole JVM shows up as ticks that do not
change.

Usage: pause_watch.py <pid> <out.jsonl> <seconds>
Records ("kind"): "blocked" (a thread over 100 ms), "blocked_end" (it left; "seconds" is the time in that state), "snapshot", "psi"
(every 500 ms: /proc/pressure io and memory totals, Dirty and Writeback from /proc/meminfo).
"""
import json
import os
import sys
import time

WRITE_SYSCALLS = {1: "write", 18: "pwrite64", 20: "writev", 74: "fsync", 75: "fdatasync", 26: "msync"}
BENIGN_WCHAN = {"futex_do_wait", "do_epoll_wait", "inet_csk_accept", "__skb_wait_for_more_packets", "do_nanosleep", "hrtimer_nanosleep",
                "do_sigtimedwait.isra.0", "do_sigtimedwait", "-", "0"}


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def ticks(pid):
    s = read(f"/proc/{pid}/stat")
    if not s:
        return None
    f = s[s.rindex(")") + 2:].split()
    return int(f[11]) + int(f[12])


def psi():
    r = {"kind": "psi", "t": time.time()}
    for res in ("io", "memory"):
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


def snapshot(pid, tk):
    threads, deep = {}, []
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return None
    for tid in tids:
        base = f"/proc/{pid}/task/{tid}"
        st = read(base + "/stat")
        if not st:
            continue
        comm = st[st.index("(") + 1:st.rindex(")")]
        state = st[st.rindex(")") + 2:].split()[0]
        wchan = read(base + "/wchan").strip() or "-"
        key = f"{state} {wchan}"
        threads[key] = threads.get(key, 0) + 1
        if state not in ("R",) and wchan not in BENIGN_WCHAN:
            deep.append({"tid": tid, "comm": comm, "state": state, "wchan": wchan, "syscall": " ".join(read(base + "/syscall").split()[:1]),
                         "stack": read(base + "/stack")})
    return {"kind": "snapshot", "t": time.time(), "ticks": tk, "threads": threads, "deep": deep}


def main():
    pid, out, seconds = sys.argv[1], sys.argv[2], float(sys.argv[3])
    end = time.time() + seconds
    since = {}        # tid -> (key, first seen, last recorded)
    last_psi = last_snap = 0.0
    with open(out, "w") as f:
        while time.time() < end:
            now = time.time()
            tk = ticks(pid)
            if tk is None:
                break
            try:
                tids = os.listdir(f"/proc/{pid}/task")
            except OSError:
                break
            seen = set()
            for tid in tids:
                base = f"/proc/{pid}/task/{tid}"
                st = read(base + "/stat")
                if not st:
                    continue
                state = st[st.rindex(")") + 2:].split()[0]
                sc = read(base + "/syscall").split()
                nr = int(sc[0]) if sc and sc[0].lstrip("-").isdigit() else None
                if nr in WRITE_SYSCALLS or state == "D":
                    key = (WRITE_SYSCALLS.get(nr, f"syscall {nr}" if nr is not None and nr >= 0 else "no syscall"), state if state == "D" else "")
                    seen.add(tid)
                    prev = since.get(tid)
                    if prev is None or prev[0][0] != key[0]:
                        since[tid] = (key, now, 0.0)
                        continue
                    first, rec = prev[1], prev[2]
                    if now - first >= 0.1 and now - rec >= 0.5:
                        comm = st[st.index("(") + 1:st.rindex(")")]
                        f.write(json.dumps({"kind": "blocked", "t": now, "since": first, "for_s": round(now - first, 3), "tid": tid, "comm": comm,
                                            "call": key[0], "state": state, "wchan": read(base + "/wchan").strip(), "syscall": " ".join(sc[:3]),
                                            "stack": read(base + "/stack"), "ticks": tk}) + "\n")
                        f.flush()
                        since[tid] = (key, first, now)
            if now - last_snap >= 0.5 and any(now - v[1] >= 0.2 for t_, v in since.items() if t_ in seen):
                snap = snapshot(pid, tk)
                if snap:
                    f.write(json.dumps(snap) + "\n")
                    f.flush()
                last_snap = now
            for tid in list(since):
                if tid not in seen:
                    key, first, rec = since.pop(tid)
                    if rec:
                        f.write(json.dumps({"kind": "blocked_end", "t": now, "since": first, "seconds": round(now - first, 3), "tid": tid,
                                            "call": key[0], "ticks": tk}) + "\n")
                        f.flush()
            if now - last_psi >= 0.5:
                f.write(json.dumps({**psi(), "ticks": tk}) + "\n")
                f.flush()
                last_psi = now
            time.sleep(max(0.0, 0.02 - (time.time() - now)))


if __name__ == "__main__":
    main()
