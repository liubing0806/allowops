#!/usr/bin/env python3
"""Stalls of the host's storage, seen the way a JVM's log file sees them (run with sudo: the kernel stacks need root).

- For every --dir, one thread appends a 120-byte line to <dir>/io-probe.log every 10 ms with one write() and no fsync, the way the
  JVM's unified logging writes a line (fprintf + fflush). A write that takes 50 ms or more is recorded ("kind": "write").
  While a write has been running for 100 ms, a watchdog records the writer's kernel stack and the stack of the jbd2 thread of
  the file system ("kind": "write_stuck"), again every 500 ms while it stays stuck.
- Every 10 ms it reads /proc/diskstats for --disk (default nvme0n1) and records each interval of 100 ms or more during which
  requests are in flight and none completes ("kind": "disk_stall", with the number in flight).
- Every second: /proc/pressure/io totals, Dirty and Writeback from /proc/meminfo ("kind": "psi"); and the load on --disk over
  that second: sectors written, writes completed, cache flushes completed and the milliseconds spent flushing (fields 18 and 19
  of /proc/diskstats), requests in flight, and the cgroups that wrote the most to it (io.stat of
  every cgroup up to three levels below /sys/fs/cgroup, the 8 largest, nested cgroups included) ("kind": "load").

Usage: host_io_probe.py <out.jsonl> <seconds> --dir <directory> [--dir <directory>]... [--disk nvme0n1]
"""
import argparse
import json
import os
import threading
import time


def read(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


class Out:
    def __init__(self, path):
        self.f, self.lock = open(path, "w"), threading.Lock()

    def put(self, rec):
        with self.lock:
            self.f.write(json.dumps(rec) + "\n")
            self.f.flush()


def jbd2_threads():
    """jbd2 kernel threads by device name, e.g. {"nvme0n1p6-8": pid}."""
    out = {}
    for p in os.listdir("/proc"):
        if p.isdigit():
            c = read(f"/proc/{p}/comm").strip()
            if c.startswith("jbd2/"):
                out[c[5:]] = p
    return out


def dev_of(path):
    """Block device name (nvme0n1p6) of the file system that holds path, from /proc/self/mountinfo."""
    st = os.stat(path)
    want = f"{os.major(st.st_dev)}:{os.minor(st.st_dev)}"
    for ln in read("/proc/self/mountinfo").splitlines():
        f = ln.split()
        if f[2] == want:
            src = ln.split(" - ")[1].split()[1]
            return os.path.basename(os.path.realpath(src))
    return "?"


def writer(d, out, end, state):
    os.makedirs(d, exist_ok=True)
    fd = os.open(os.path.join(d, "io-probe.log"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    state["tid"] = threading.get_native_id()
    n = 0
    while time.time() < end:
        line = f"[{time.strftime('%Y-%m-%dT%H:%M:%S')}][{n}] io probe line {'x' * 64}\n".encode()[:120]
        t0 = time.time()
        state["t0"] = t0
        os.write(fd, line)
        state["t0"] = None
        dur = time.time() - t0
        if dur >= 0.05:
            out.put({"kind": "write", "t": t0, "dir": d, "seconds": round(dur, 3)})
        n += 1
        if n % 100000 == 0:
            os.ftruncate(fd, 0)
        time.sleep(max(0.0, 0.01 - (time.time() - t0)))
    os.close(fd)


def watchdog(d, out, end, state, dev):
    last = 0.0
    while time.time() < end:
        t0 = state.get("t0")
        now = time.time()
        if t0 and now - t0 >= 0.1 and now - last >= 0.5:
            tid = state["tid"]
            jbd = jbd2_threads()
            jpid = next((p for k, p in jbd.items() if k.startswith(dev + "-")), None)
            out.put({"kind": "write_stuck", "t": now, "dir": d, "for_s": round(now - t0, 3),
                     "wchan": read(f"/proc/{tid}/wchan").strip(), "stack": read(f"/proc/{tid}/stack"),
                     "jbd2": f"jbd2/{dev}", "jbd2_state": read(f"/proc/{jpid}/stat").split(")")[-1].split()[:1] if jpid else None,
                     "jbd2_stack": read(f"/proc/{jpid}/stack") if jpid else ""})
            last = now
        time.sleep(0.02)


def diskstats(disk):
    for ln in read("/proc/diskstats").splitlines():
        f = ln.split()
        if len(f) > 13 and f[2] == disk:
            done = int(f[3]) + int(f[7]) + (int(f[14]) if len(f) > 14 else 0) + (int(f[18]) if len(f) > 18 else 0)
            return done, int(f[11])
    return None


def disk_watch(disk, out, end):
    prev, stall_since, stall_max = diskstats(disk), None, 0
    last_psi = 0.0
    while time.time() < end:
        time.sleep(0.01)
        now = time.time()
        cur = diskstats(disk)
        if cur is None:
            continue
        if cur[1] > 0 and cur[0] == prev[0]:
            if stall_since is None:
                stall_since = now
            stall_max = max(stall_max, cur[1])
        else:
            if stall_since is not None and now - stall_since >= 0.1:
                out.put({"kind": "disk_stall", "t": stall_since, "seconds": round(now - stall_since, 3), "disk": disk, "in_flight_max": stall_max})
            stall_since, stall_max = None, 0
        prev = cur
        if now - last_psi >= 1.0:
            r = {"kind": "psi", "t": now}
            for ln in read("/proc/pressure/io").splitlines():
                kind, *kv = ln.split()
                for item in kv:
                    k, v = item.split("=")
                    if k == "total":
                        r[f"io_{kind}_us"] = int(v)
            for ln in read("/proc/meminfo").splitlines():
                if ln.startswith(("Dirty:", "Writeback:")):
                    r[ln.split(":")[0].lower() + "_kb"] = int(ln.split()[1])
            out.put(r)
            last_psi = now


def cgroup_wbytes(devno):
    out = {}
    root = "/sys/fs/cgroup"
    for depth in ("*", "*/*", "*/*/*"):
        for p in __import__("glob").glob(f"{root}/{depth}/io.stat"):
            for ln in read(p).splitlines():
                if ln.startswith(devno + " "):
                    for kv in ln.split()[1:]:
                        if kv.startswith("wbytes="):
                            out[p[len(root) + 1:-len("/io.stat")]] = int(kv[7:])
    return out


def load_watch(disk, out, end):
    devno = read(f"/sys/block/{disk}/dev").strip()

    def disk_now():
        for ln in read("/proc/diskstats").splitlines():
            f = ln.split()
            if len(f) > 13 and f[2] == disk:
                return int(f[7]), int(f[9]), int(f[11]), int(f[18]) if len(f) > 19 else 0, int(f[19]) if len(f) > 19 else 0
        return 0, 0, 0, 0, 0
    pd, pc, pt = disk_now(), cgroup_wbytes(devno), time.time()
    while time.time() < end:
        time.sleep(max(0.0, 1.0 - (time.time() - pt)))
        cd, cc, ct = disk_now(), cgroup_wbytes(devno), time.time()
        top = sorted(((v - pc.get(k, v), k) for k, v in cc.items()), reverse=True)[:8]
        out.put({"kind": "load", "t": pt, "seconds": round(ct - pt, 3), "writes": cd[0] - pd[0], "mb_written": round((cd[1] - pd[1]) * 512 / 2**20, 1),
                 "in_flight": cd[2], "flushes": cd[3] - pd[3], "flush_ms": cd[4] - pd[4], "cgroups_mb": {k: round(v / 2**20, 1) for v, k in top if v > 0}})
        pd, pc, pt = cd, cc, ct


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("seconds", type=float)
    ap.add_argument("--dir", action="append", default=[])
    ap.add_argument("--disk", default="nvme0n1")
    a = ap.parse_args()
    out, end = Out(a.out), time.time() + a.seconds
    for d in a.dir:
        os.makedirs(d, exist_ok=True)
    out.put({"kind": "start", "t": time.time(), "dirs": {d: dev_of(d) for d in a.dir}, "disk": a.disk})
    ths = [threading.Thread(target=disk_watch, args=(a.disk, out, end), daemon=True),
           threading.Thread(target=load_watch, args=(a.disk, out, end), daemon=True)]
    for d in a.dir:
        st = {}
        ths.append(threading.Thread(target=writer, args=(d, out, end, st), daemon=True))
        ths.append(threading.Thread(target=watchdog, args=(d, out, end, st, dev_of(d)), daemon=True))
    for t in ths:
        t.start()
    for t in ths:
        t.join()


if __name__ == "__main__":
    main()
