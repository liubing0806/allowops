#!/usr/bin/env python3
"""Stage-0 item 3 and the first half of item 7: what is left in the JVM after `stop`, and what do 50 attach/stop cycles cost?

Usage: exp_stop.py [svc ...]      (default jdk8 jdk11 jdk17 jdk21, run in parallel)
"""
import concurrent.futures
import sys

from ja import *

EXP = "item3-stop"
CYCLES = int(os.environ.get("CYCLES", "50"))
L1_SAMPLE = ["version", "jvm", "thread -n 5", "sc -d demo.HotService", "classloader -t", "memory"]


def snap(t, label, histogram=False):
    d = t.diag()
    p = t.probe(secret=False)
    s = {"label": label, "t": time.time(), "diag": d, "listeners": [(x["addr"], x["port"]) for x in p["listeners"]],
         "arthas_threads": p["arthas_threads"], "arthas_fds": p["arthas_fds"], "arthas_maps": p["arthas_maps"],
         "threads_proc": p["status"]["threads"], "java_sockets": p["java_sockets"],
         "cgroup_mem_current": int((t.cgroup() / "memory.current").read_text())}
    if histogram:
        s["histogram"] = class_histogram(t)
        s["loader_stats"] = loader_stats(t)
    return s


def class_histogram(t):
    """Live-object class histogram (this forces a full GC). Counts what remains of the Arthas class loader."""
    pid = t.pid()
    nspid = t.inspect()["nspid"]
    r = t.docker_exec("sh", "-c", f"jcmd {nspid} GC.class_histogram 2>&1", user="10001" if "root" not in t.svc else "0", timeout=120)
    keep = {}
    for ln in r.stdout.splitlines():
        low = ln.lower()
        if "arthas" in low:
            parts = ln.split()
            if len(parts) >= 4:
                keep[parts[3]] = {"instances": int(parts[1]), "bytes": int(parts[2])}
    return {"arthas_classes_with_live_instances": len(keep),
            "arthas_loader_instances": keep.get("com.taobao.arthas.agent.ArthasClassloader", {}).get("instances", 0),
            "total_arthas_instances": sum(v["instances"] for v in keep.values()),
            "sample": dict(list(sorted(keep.items(), key=lambda kv: -kv[1]["instances"]))[:8])}


def loader_stats(t):
    """ArthasClassloader instances known to the JVM, from jcmd VM.classloader_stats (JDK 9+) or jmap -clstats (JDK 8)."""
    nspid = t.inspect()["nspid"]
    user = "0" if "root" in t.svc else "10001"
    cmd = f"jmap -clstats {nspid} 2>&1" if re.search(r"8$", t.svc) else f"jcmd {nspid} VM.classloader_stats 2>&1"
    r = t.docker_exec("sh", "-c", cmd, user=user, timeout=180)
    rows = [ln.split() for ln in r.stdout.splitlines() if "ArthasClassloader" in ln]
    alive = 0
    classes = 0
    for f in rows:
        if "dead" not in f:
            alive += 1
        for x in f[1:4]:
            if x.isdigit():
                classes += int(x)
                break
    return {"loaders": len(rows), "loaders_not_dead": alive, "classes_sum_first_numeric_column": classes, "sample": [" ".join(f)[:160] for f in rows[:3]],
            "tool_output_tail": r.stdout.splitlines()[-3:] if not rows else []}


def wait_gone(t, timeout=30):
    """Polls once a second until no Arthas thread and no Arthas listener is left; returns seconds taken or None."""
    t0 = time.time()
    seen = []
    while time.time() - t0 < timeout:
        p = t.probe(secret=False)
        ports = [x["port"] for x in p["listeners"] if x["port"] == t.arthas_port]
        seen.append({"dt": round(time.time() - t0, 1), "threads": len(p["arthas_threads"]), "listening": bool(ports)})
        if not p["arthas_threads"] and not ports:
            return round(time.time() - t0, 1), seen
        time.sleep(1)
    return None, seen


def one(svc):
    t = Target(svc).up()
    res = {"svc": svc, "java": t.diag().get("uptimeMillis") and None}
    res["s0_before"] = snap(t, "before attach", histogram=True)
    a = t.attach()
    res["attach_first"] = a
    time.sleep(1)
    # a typical L1 session
    cmds = {}
    for c in L1_SAMPLE:
        cmds[c] = short(t.exec(c, exec_timeout=30000))
    res["l1_commands"] = cmds
    res["s1_during"] = snap(t, "attached, after L1 commands")
    st = t.exec("stop", exec_timeout=20000)
    res["stop_response"] = short(st)
    res["stop_raw"] = st
    gone_after, series = wait_gone(t)
    res["gone_after_s"] = gone_after
    res["gone_series"] = series
    res["s2_after_stop"] = snap(t, "after stop", histogram=True)
    # port really closed? and API unreachable?
    res["api_after_stop"] = t.api("exec", cmd="version").get("error")
    res["stdout_tail_after_stop"] = t.logs().splitlines()[-12:]

    # attach/stop cycles; a container that is killed half way (OOM) still leaves what was measured so far
    cyc = []
    res["cycles"] = cyc
    try:
        for i in range(1, CYCLES + 1):
            c = {"i": i}
            cyc.append(c)
            a = t.attach(port=18563 + (i % 7))  # a different port now and then: nothing may stay bound
            c["attach_ok"] = a["ok"]
            c["attach_ms"] = a.get("request_to_reply_ms")
            c["socket_reused"] = a.get("socket_reused")
            if not a["ok"]:
                c["attach_reply"] = a.get("reply")
                c["error"] = a.get("error")
                continue
            c["version"] = short(t.exec("version"))["state"]
            c["thread"] = short(t.exec("thread -n 5", exec_timeout=30000))["state"]
            t.exec("stop", exec_timeout=20000)
            g, _ = wait_gone(t, 20)
            c["gone_s"] = g
            d = t.diag()
            c.update({k: d.get(k) for k in ("threads", "classesLoaded", "classesTotalLoaded", "classesUnloaded", "metaspaceUsed",
                                             "metaspaceCommitted", "classSpaceUsed", "classSpaceCommitted", "heapUsed", "gcCount")})
            c["cgroup_mem"] = int((t.cgroup() / "memory.current").read_text())
            c["rss_kb"] = next((int(x.split()[1]) for x in open(f"/proc/{t.pid()}/status") if x.startswith("VmRSS")), None)
            if i in (1, 2, 5, 10, 25, 50):
                log(svc, "cycle", i, "attach_ms", c["attach_ms"], "metaspace", c.get("metaspaceUsed"), "threads", c.get("threads"))
    except Exception as e:
        res["cycles_aborted"] = repr(e)[:400]
        res["container_state"] = run(["docker", "inspect", "-f", "{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}", t.container], check=False).stdout.strip()
        log(svc, "cycles aborted", res["container_state"], res["cycles_aborted"][:100])
        write_json(EXP, f"{svc}.json", res)
        return svc
    res["s3_after_cycles"] = snap(t, "after cycles (before explicit GC)")
    res["s4_after_gc"] = snap(t, "after cycles + class histogram (full GC)", histogram=True)
    time.sleep(3)
    res["s5_after_gc_settled"] = snap(t, "settled", histogram=True)
    # more full GCs: does metaspace go back to the level before the first attach, and after how many collections?
    user = "0" if "root" in t.svc else "10001"
    nspid = t.inspect()["nspid"]
    extra = []
    for k in range(1, 9):
        t.docker_exec("sh", "-c", f"jcmd {nspid} GC.run 2>&1 | tail -1", user=user, timeout=120)
        time.sleep(1)
        d = t.diag()
        extra.append({"extra_full_gc": k, "metaspaceUsed": d["metaspaceUsed"], "metaspaceCommitted": d["metaspaceCommitted"],
                      "classesLoaded": d["classesLoaded"], "classesUnloaded": d["classesUnloaded"], "heapUsed": d["heapUsed"],
                      "cgroup_mem": int((t.cgroup() / "memory.current").read_text())})
        if k >= 2 and extra[-1]["classesLoaded"] == extra[-2]["classesLoaded"]:
            break
    res["s6_extra_full_gcs"] = extra
    res["s7_final"] = snap(t, "after the extra full GCs", histogram=True)
    write_json(EXP, f"{svc}.json", res)
    return svc


if __name__ == "__main__":
    which = sys.argv[1:] or ["jdk8", "jdk11", "jdk17", "jdk21"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(which)) as ex:
        for r in ex.map(one, which):
            log("done", r)
