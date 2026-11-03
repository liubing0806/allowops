#!/usr/bin/env python3
"""Stage-0 item 4: what happens to watch/trace jobs and to the enhanced bytecode when the session ends in different ways?

State of the bytecode is read with /diag/live (a counting spy; never triggers a retransform) and, where the
JVM can log it, from -Xlog:redefine+class (JDK 9+) or the probe agent's retransform log (JDK 8).

Usage: exp_session.py [svc ...]    (default probe8 jdk11 probe17 jdk21, in parallel)
"""
import concurrent.futures
import subprocess
import threading
import sys

from ja import *

EXP = "item4-session"
WATCH_FOREVER = "watch demo.HotService work '{params,returnObj}' '#cost>1000000' -n 5"   # never fires, keeps the job running
WATCH_N3 = "watch demo.HotService work '{params}' -n 3"
SESSION_TIMEOUT = 20


class Traffic(threading.Thread):
    """~100 requests/s to /hot so that watch has something to see."""

    def __init__(self, t):
        super().__init__(daemon=True)
        self.url = f"http://{t.ip()}:8080/hot?calls=1"
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            try:
                http_get(self.url, 2)
            except Exception:
                pass
            time.sleep(0.01)


def live(t):
    try:
        return json.loads(http_get(f"http://{t.ip()}:8080/diag/live", 10))
    except Exception as e:
        return {"error": str(e)}


def redefine_log(t):
    f = RUN / t.svc / "logs"
    out = []
    for name in ("redefine.log", "probe.log"):
        p = f / name
        if p.exists():
            out += [f"{name}: {ln}" for ln in p.read_text(errors="ignore").splitlines()]
    return out


def state(t, label):
    p = t.probe(secret=False)
    return {"label": label, "at": time.strftime("%H:%M:%S"), "live": {k: v for k, v in live(t).items() if k in ("enhanced", "atEnter", "spyApi", "previousSpyWasNop")},
            "arthas_threads": len(p["arthas_threads"]), "listening": any(x["port"] == t.arthas_port for x in p["listeners"]),
            "redefine_events": len([ln for ln in redefine_log(t) if "RETRANSFORM" in ln or "redefin" in ln.lower()])}


def sess(t):
    r = t.api("init_session")
    b = r["body"]
    return b["sessionId"], b.get("consumerId")


def affect(resp):
    for r in results_of(resp)[1]:
        if r.get("type") == "enhancer":
            return {k: r.get(k) for k in ("success", "effect")}
    return None


def attach(t):
    a = t.attach(enabled=L2_COMMANDS, session_timeout=SESSION_TIMEOUT)
    if not a["ok"]:
        raise RuntimeError(a)
    time.sleep(1)
    return a


def fresh(svc):
    t = Target(svc).up()
    attach(t)
    return t


def scenario_a(t, tr, res):
    """watch ends by itself (-n 3). The job is over; is the class still enhanced?"""
    r = t.exec(WATCH_N3, exec_timeout=20000)
    res["a_watch_n3"] = {"short": short(r), "affect": affect(r)}
    res["a_after_job"] = state(t, "after watch -n 3 finished")
    r = t.exec("reset", exec_timeout=20000)
    res["a_reset"] = short(r)
    res["a_after_reset"] = state(t, "after reset")


def scenario_b(t, tr, res):
    """sync exec hits execTimeout (5 s): the server interrupts the job."""
    r = t.exec(WATCH_FOREVER, exec_timeout=5000)
    res["b_exec_timeout"] = {"short": short(r), "timeExpired": (results_of(r)[2] or {}).get("timeExpired"), "affect": affect(r)}
    res["b_after_timeout"] = state(t, "after execTimeout interrupt")
    t.exec("reset", exec_timeout=20000)
    res["b_after_reset"] = state(t, "after reset")


def scenario_c(t, tr, res):
    """The client process is killed (kill -9) while a sync exec is running. Is the job still alive, and until when?"""
    sid, _ = sess(t)
    args = ["sudo", str(BIN), "api", "-pid", str(t.pid()), "-port", str(t.arthas_port), "-pass-file", str(t.pw_file),
            "-action", "exec", "-cmd", WATCH_FOREVER, "-session", sid, "-exec-timeout", "40000", "-timeout", "120s"]
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)
    run(["sudo", "pkill", "-9", "-f", "[j]a-attach api .*-action exec"], check=False)
    p.wait()
    t_kill = time.time()
    probes = []
    for _ in range(11):
        r = t.api("exec", cmd="version", session=sid)
        probes.append({"dt": round(time.time() - t_kill, 1), "state": (r.get("body") or {}).get("state"),
                       "message": (r.get("body") or {}).get("message")})
        if probes[-1]["state"] == "SUCCEEDED":
            break
        time.sleep(5)
    res["c_probes_same_session"] = probes
    res["c_after"] = state(t, "after the killed client's job ended")
    t.exec("reset", exec_timeout=20000)
    res["c_after_reset"] = state(t, "after reset")
    t.api("close_session", session=sid)


def scenario_d(t, tr, res):
    """async_exec, then the client never comes back. sessionTimeout is 20 s, the reaper runs every 60 s."""
    sid, cid = sess(t)
    r = t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    res["d_async_exec"] = short(r)
    res["d_during"] = state(t, "async watch running")
    t.api("pull_results", session=sid, consumer=cid)
    probes = []
    t0 = time.time()
    for _ in range(14):
        time.sleep(10)
        r = t.api("session_info", session=sid)
        probes.append({"dt": round(time.time() - t0), "info_state": (r.get("body") or {}).get("state"),
                       "message": (r.get("body") or {}).get("message")})
    res["d_session_info_every_10s"] = probes
    res["d_after_140s"] = state(t, "140 s later, nobody polled")
    r = t.api("close_session", session=sid)
    res["d_close_session"] = short(r)
    res["d_after_close"] = state(t, "after close_session")
    t.exec("reset", exec_timeout=20000)
    res["d_after_reset"] = state(t, "after reset")


def scenario_e(t, tr, res):
    """A session without any job: when is it evicted, and does the server stop?"""
    sid, _ = sess(t)
    t0 = time.time()
    res["e_session_start"] = state(t, "idle session created")
    gone = None
    for _ in range(20):
        time.sleep(5)
        r = t.api("session_info", session=sid)
        if (r.get("body") or {}).get("state") != "SUCCEEDED":
            gone = round(time.time() - t0)
            break
    res["e_session_evicted_after_s"] = gone
    res["e_after"] = state(t, "after the idle session was evicted")


def scenario_f(t, tr, res):
    """stop while a watch job runs."""
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(2)
    res["f_during"] = state(t, "async watch running")
    r = t.exec("stop", exec_timeout=20000)
    res["f_stop"] = short(r)
    time.sleep(6)
    res["f_after_stop"] = state(t, "6 s after stop")


def scenario_g(t, tr, res):
    """reset while a watch job runs."""
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(2)
    res["g_during"] = state(t, "async watch running")
    r = t.exec("reset", exec_timeout=20000)
    res["g_reset"] = short(r)
    res["g_after_reset"] = state(t, "after reset, job still registered?")
    pr = t.api("pull_results", session=sid, consumer=cid)
    res["g_pull_after_reset"] = short(pr)
    t.api("close_session", session=sid)


def one(svc):
    res = {"svc": svc, "session_timeout_s": SESSION_TIMEOUT}
    for name, fn in [("a", scenario_a), ("b", scenario_b), ("c", scenario_c), ("d", scenario_d), ("e", scenario_e),
                     ("g", scenario_g), ("f", scenario_f)]:
        if os.environ.get("ONLY") and name not in os.environ["ONLY"]:
            continue
        t = fresh(svc)
        res.setdefault("baseline", state(t, "attached, no command yet"))
        tr = Traffic(t)
        tr.start()
        log(svc, "scenario", name)
        try:
            fn(t, tr, res)
        except Exception as e:  # keep what was measured
            res[f"{name}_error"] = repr(e)
        tr.stop.set()
        res[f"{name}_redefine_log"] = redefine_log(t)
    write_json(EXP, f"{svc}.json", res)
    return svc


if __name__ == "__main__":
    which = sys.argv[1:] or ["probe8", "jdk11", "probe17", "jdk21"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(which)) as ex:
        for r in ex.map(one, which):
            log("done", r)
