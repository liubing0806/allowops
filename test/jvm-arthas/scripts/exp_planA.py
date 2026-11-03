#!/usr/bin/env python3
"""Stage-0 item 8: how much container memory does plan A (arthas-boot inside the container) add, compared with
loading Arthas through the attach socket from the host? Also: does a tight memory limit make plan A kill the application?"""
import threading

from ja import *

EXP = "item8-planA"


class Sampler(threading.Thread):
    def __init__(self, t, interval=0.05):
        super().__init__(daemon=True)
        self.t, self.interval = t, interval
        self.stop_ev = threading.Event()
        self.samples = []      # (seconds, memory.current)
        self.max_procs = 0
        self.max_jvms = 0
        self.cg = t.cgroup()

    def run(self):
        t0 = time.time()
        last_top = 0
        while not self.stop_ev.is_set():
            try:
                self.samples.append((round(time.time() - t0, 3), int((self.cg / "memory.current").read_text())))
            except OSError:
                pass
            if time.time() - last_top > 0.5:
                last_top = time.time()
                procs = [p for p in (self.cg / "cgroup.procs").read_text().split()]
                self.max_procs = max(self.max_procs, len(procs))
                jv = 0
                for p in procs:
                    try:
                        if b"java" in open(f"/proc/{p}/cmdline", "rb").read(64):
                            jv += 1
                    except OSError:
                        pass
                self.max_jvms = max(self.max_jvms, jv)
            time.sleep(self.interval)

    def result(self):
        vals = [v for _, v in self.samples]
        return {"min": min(vals), "max": max(vals), "n": len(vals), "max_processes": self.max_procs, "max_java_processes": self.max_jvms}


def mem(t):
    cg = t.cgroup()
    st = {}
    for ln in (cg / "memory.stat").read_text().splitlines():
        k, v = ln.split()
        if k in ("anon", "file", "kernel", "slab", "shmem", "file_mapped"):
            st[k] = int(v)
    return {"current": int((cg / "memory.current").read_text()), "peak": int((cg / "memory.peak").read_text()), "stat": st,
            "limit": (cg / "memory.max").read_text().strip(), "oom_kill": [ln for ln in (cg / "memory.events").read_text().splitlines() if ln.startswith("oom_kill")]}


def reset_peak(t):
    try:
        (t.cgroup() / "memory.peak").write_text("0")   # needs root; may not be permitted
    except OSError:
        run(["sudo", "sh", "-c", f"echo 0 > {t.cgroup()}/memory.peak"], check=False)


def settle(t, seconds=8):
    time.sleep(seconds)


def plan_a(t, limit=None):
    """Runs plan A step 1 (attach + one command through arthas-boot) and step 2 (stop through arthas-client)."""
    r = {}
    nspid = t.inspect()["nspid"]
    reset_peak(t)
    r["before"] = mem(t)
    s = Sampler(t)
    s.start()
    t0 = time.time()
    p = t.docker_exec("sh", "-c", f"timeout 90 java -jar /opt/arthas-stock/arthas-boot.jar {nspid} --arthas-home /opt/arthas-stock -c 'version' 2>&1 | tail -6", user="10001", timeout=150)
    r["step1_seconds"] = round(time.time() - t0, 1)
    r["step1_output"] = p.stdout.strip().splitlines()[-6:]
    s.stop_ev.set()
    s.join()
    r["step1_sampler"] = s.result()
    r["after_step1"] = mem(t)
    r["java_processes_after_step1"] = run(["docker", "top", t.container, "-eo", "pid,rss,args"]).stdout.strip().splitlines()
    settle(t)
    r["settled_after_step1"] = mem(t)
    # step 2: stop with arthas-client
    reset_peak(t)
    s = Sampler(t)
    s.start()
    t0 = time.time()
    p = t.docker_exec("sh", "-c", "timeout 60 java -jar /opt/arthas-stock/arthas-client.jar 127.0.0.1 3658 -c stop 2>&1 | tail -4", user="10001", timeout=100)
    r["step2_seconds"] = round(time.time() - t0, 1)
    r["step2_output"] = p.stdout.strip().splitlines()[-4:]
    s.stop_ev.set()
    s.join()
    r["step2_sampler"] = s.result()
    settle(t)
    r["settled_after_stop"] = mem(t)
    r["container_state"] = run(["docker", "inspect", "-f", "{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}", t.container]).stdout.strip()
    r["app_alive"] = None
    try:
        r["app_alive"] = http_get(f"http://{t.ip()}:8080/ping", 3)
    except Exception as e:
        r["app_alive"] = f"down: {e}"
    return r


def go_attach(t):
    r = {}
    reset_peak(t)
    r["before"] = mem(t)
    s = Sampler(t)
    s.start()
    a = t.attach(flavor="minlog")
    for c in ("version", "thread -n 5", "dashboard -n 1"):
        t.exec(c, exec_timeout=30000)
    s.stop_ev.set()
    s.join()
    r["attach"] = {"ok": a["ok"], "ms": a.get("request_to_reply_ms")}
    r["sampler"] = s.result()
    r["after_attach"] = mem(t)
    settle(t)
    r["settled_attached"] = mem(t)
    t.exec("stop", exec_timeout=20000)
    settle(t)
    r["settled_after_stop"] = mem(t)
    try:
        r["app_alive"] = http_get(f"http://{t.ip()}:8080/ping", 3)
    except Exception as e:
        r["app_alive"] = f"down: {e}"
    return r


if __name__ == "__main__":
    # LIMITS="700m,650m" runs only the tight-limit part (JDK 17) and writes result-tight.json
    tight = os.environ.get("LIMITS")
    res = {}
    for svc in ([] if tight else ["jdk17", "jdk8"]):
        t = Target(svc).up()
        settle(t, 10)
        res[f"{svc}_baseline"] = mem(t)
        res[f"{svc}_plan_a_1g"] = plan_a(t)
        t = Target(svc).up()
        settle(t, 10)
        res[f"{svc}_go_attach_1g"] = go_attach(t)
        log("planA", svc, "done 1g")
    # tight limit: baseline working set is about 510-525 MB with the 512m heap
    for svc in ["jdk17"]:
        for limit in (tight or "900m,800m").split(","):
            t = Target(svc).up()
            settle(t, 10)
            run(["docker", "update", "--memory", limit, "--memory-swap", limit, t.container])
            settle(t, 5)
            res[f"{svc}_baseline_{limit}"] = mem(t)
            try:
                res[f"{svc}_plan_a_{limit}"] = plan_a(t)
            except OSError as e:
                # the container was killed during plan A: its cgroup is gone
                res[f"{svc}_plan_a_{limit}"] = {"killed": True, "error": str(e), "container_state": run(["docker", "inspect", "-f", "{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}", t.container]).stdout.strip()}
                log("planA", svc, limit, "container killed:", res[f"{svc}_plan_a_{limit}"]["container_state"])
            write_json(EXP, "result-tight.json" if tight else "result.json", res)
            t = Target(svc).up()
            settle(t, 10)
            run(["docker", "update", "--memory", limit, "--memory-swap", limit, t.container])
            settle(t, 5)
            res[f"{svc}_go_attach_{limit}"] = go_attach(t)
            log("planA", svc, "done", limit)
    write_json(EXP, "result-tight.json" if tight else "result.json", res)
