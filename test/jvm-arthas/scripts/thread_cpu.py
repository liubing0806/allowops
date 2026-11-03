#!/usr/bin/env python3
"""CPU of the threads of the JVM in a container, grouped by thread name (C2 and C1 compiler threads, Tomcat's http-nio
threads, GC threads, Arthas threads, the rest by name without the trailing number), once a second, in % of one CPU, from
/proc/<pid>/task/*/stat on the host. It waits for the container's java process and ends after <seconds> or when the process
is gone.
usage: thread_cpu.py <container> <seconds> <out.jsonl>"""
import json, os, re, subprocess, sys, time

container, seconds, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
HZ = os.sysconf("SC_CLK_TCK")


def java_pid():
    while time.time() < end:
        p = subprocess.run(["docker", "top", container, "-eo", "pid,comm"], capture_output=True, text=True)
        for ln in p.stdout.splitlines()[1:]:
            f = ln.split()
            if len(f) >= 2 and f[1] == "java":
                return f[0]
        time.sleep(1)
    sys.exit(0)


def group(name):
    if name.startswith("C2 Compiler"):
        return "C2"
    if name.startswith("C1 Compiler"):
        return "C1"
    if name.startswith("http-nio"):
        return "http-nio"
    if name.startswith(("GC Thread", "G1 ")):
        return "GC"
    if "arthas" in name.lower():
        return "arthas"
    return re.sub(r"[-#]?\d+$", "", name)


def sample(pid):
    r = {}
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        return r
    for tid in tids:
        try:
            with open(f"/proc/{pid}/task/{tid}/stat") as f:
                s = f.read()
            with open(f"/proc/{pid}/task/{tid}/comm") as f:
                name = f.read().strip()
        except OSError:
            continue
        rest = s[s.rindex(")") + 2:].split()
        r[tid] = (name, int(rest[11]) + int(rest[12]))
    return r


end = time.time() + seconds
pid = java_pid()
prev, pt = sample(pid), time.time()
with open(out, "w") as w:
    while time.time() < end:
        time.sleep(1 - (time.time() - pt) % 1)
        if not os.path.isdir(f"/proc/{pid}/task"):
            break
        cur, ct = sample(pid), time.time()
        g = {}
        for tid, (name, ticks) in cur.items():
            d = ticks - prev[tid][1] if tid in prev else ticks
            g[group(name)] = g.get(group(name), 0) + d
        dt = ct - pt
        w.write(json.dumps({"t": round(ct, 3), "threads": len(cur),
                            "cpu": {k: round(v / HZ / dt * 100) for k, v in sorted(g.items(), key=lambda kv: -kv[1]) if v}}) + "\n")
        w.flush()
        prev, pt = cur, ct
