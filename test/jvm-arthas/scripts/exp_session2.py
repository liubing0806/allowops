#!/usr/bin/env python3
"""Stage-0 item 4, second round. exp_session.py polled the session every few seconds, which refreshes its last-access time and
makes "was the session evicted?" unanswerable. Here a session is touched exactly once at the end. Also the cleanup orders:

  d2  async watch that never fires, nobody touches the session for 150 s (sessionTimeout=20): evicted? job running? class enhanced?
  e2  idle sessions, each touched once at 30 s / 65 s / 130 s: when is an idle session evicted?
  h   the watch ends by itself, then `stop` without `reset`:  is the class restored?
  i   async watch running -> close_session -> `stop` without `reset`
  j   async watch running -> close_session -> reset
  k   async watch running -> reset -> close_session -> reset
  m   state of k, then `reset demo.HotService` (explicit class pattern): is the class restored?
  n   async watch running -> stop (class stays enhanced), attach again, `reset demo.HotService`: is the class restored?

Usage: exp_session2.py [svc ...]    (default probe8 jdk11 probe17 jdk21, in parallel)
"""
import concurrent.futures
import sys
import threading

from ja import *
from exp_session import (EXP, WATCH_FOREVER, WATCH_N3, SESSION_TIMEOUT, Traffic, state, sess, fresh, redefine_log, attach, affect)

HOLD_S = 150


def scenario_d2(t, tr, res):
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(3)
    res["d2_running"] = state(t, "async watch running (3 s after start)")
    time.sleep(HOLD_S)
    res["d2_after_hold_untouched"] = state(t, f"{HOLD_S} s without any call to the session")
    info = t.api("session_info", session=sid)
    res["d2_session_info_after_hold"] = {"state": (info.get("body") or {}).get("state"), "message": (info.get("body") or {}).get("message")}
    pr = t.api("pull_results", session=sid, consumer=cid)
    res["d2_pull_after_hold"] = short(pr)
    t.api("close_session", session=sid)
    res["d2_after_close"] = state(t, "after close_session")
    t.exec("reset", exec_timeout=20000)
    res["d2_after_reset"] = state(t, "after reset")


def scenario_e2(t, tr, res):
    sids = [sess(t)[0] for _ in range(3)]
    t0 = time.time()
    out = []
    for sid, at in zip(sids, (30, 65, 130)):
        time.sleep(max(0, t0 + at - time.time()))
        r = t.api("session_info", session=sid)
        out.append({"touched_after_s": round(time.time() - t0), "state": (r.get("body") or {}).get("state"), "message": (r.get("body") or {}).get("message")})
    res["e2_idle_sessions"] = out
    res["e2_after"] = state(t, "after the idle sessions")


def scenario_h(t, tr, res):
    r = t.exec(WATCH_N3, exec_timeout=20000)
    res["h_watch"] = short(r)
    res["h_before_stop"] = state(t, "job finished, not reset")
    r = t.exec("stop", exec_timeout=20000)
    res["h_stop"] = short(r)
    time.sleep(6)
    res["h_after_stop"] = state(t, "6 s after stop")


def scenario_i(t, tr, res):
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(2)
    t.api("close_session", session=sid)
    res["i_after_close"] = state(t, "watch running -> close_session")
    t.exec("stop", exec_timeout=20000)
    time.sleep(6)
    res["i_after_stop"] = state(t, "6 s after stop")


def scenario_j(t, tr, res):
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(2)
    t.api("close_session", session=sid)
    res["j_after_close"] = state(t, "watch running -> close_session")
    t.exec("reset", exec_timeout=20000)
    res["j_after_reset"] = state(t, "reset after close_session")


def scenario_k(t, tr, res):
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(2)
    t.exec("reset", exec_timeout=20000)
    res["k_after_reset_1"] = state(t, "reset while the watch runs")
    t.api("close_session", session=sid)
    res["k_after_close"] = state(t, "close_session")
    t.exec("reset", exec_timeout=20000)
    res["k_after_reset_2"] = state(t, "second reset")


def scenario_m(t, tr, res):
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(2)
    t.exec("reset", exec_timeout=20000)
    t.api("close_session", session=sid)
    t.exec("reset", exec_timeout=20000)
    res["m_stuck"] = state(t, "reset while the watch ran, close_session, reset")
    r = t.exec("reset demo.HotService", exec_timeout=20000)
    res["m_reset_class"] = short(r)
    res["m_after_reset_class"] = state(t, "reset demo.HotService")
    # enhance the class once more (the watch registers it with Arthas again) and reset
    r = t.exec(WATCH_N3.replace("-n 3", "-n 1"), exec_timeout=20000)
    res["m_recover_watch"] = {"short": short(r), "affect": affect(r)}
    res["m_after_recover_watch"] = state(t, "new watch -n 1 finished")
    t.exec("reset", exec_timeout=20000)
    res["m_after_recover_reset"] = state(t, "reset after the new watch")


def scenario_n(t, tr, res):
    sid, cid = sess(t)
    t.api("async_exec", cmd=WATCH_FOREVER, session=sid)
    time.sleep(2)
    t.exec("stop", exec_timeout=20000)
    time.sleep(6)
    res["n_after_stop"] = state(t, "stop while the watch runs")
    a = attach(t)
    res["n_reattach"] = {"ok": a["ok"], "ms": a.get("request_to_reply_ms")}
    res["n_after_reattach"] = state(t, "attached again, nothing else")
    r = t.exec("reset demo.HotService", exec_timeout=20000)
    res["n_reset_class"] = short(r)
    res["n_after_reset_class"] = state(t, "reset demo.HotService")
    r = t.exec(WATCH_N3.replace("-n 3", "-n 1"), exec_timeout=20000)
    res["n_recover_watch"] = {"short": short(r), "affect": affect(r)}
    t.exec("reset", exec_timeout=20000)
    res["n_after_recover_reset"] = state(t, "new watch -n 1, then reset")
    t.exec("stop", exec_timeout=20000)
    time.sleep(6)
    res["n_after_final_stop"] = state(t, "final stop")


def one(svc):
    res = {"svc": svc, "session_timeout_s": SESSION_TIMEOUT, "hold_s": HOLD_S}
    for name, fn in [("d2", scenario_d2), ("e2", scenario_e2), ("h", scenario_h), ("i", scenario_i), ("j", scenario_j), ("k", scenario_k), ("m", scenario_m), ("n", scenario_n)]:
        if os.environ.get("ONLY") and name not in os.environ["ONLY"].split(","):
            continue
        t = fresh(svc)
        tr = Traffic(t)
        tr.start()
        log(svc, "scenario", name)
        try:
            fn(t, tr, res)
        except Exception as e:
            res[f"{name}_error"] = repr(e)
        tr.stop.set()
        res[f"{name}_redefine_log"] = redefine_log(t)
    write_json(EXP, f"{svc}-round2{os.environ.get('SUFFIX', '')}.json", res)
    return svc


if __name__ == "__main__":
    which = sys.argv[1:] or ["probe8", "jdk11", "probe17", "jdk21"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(which)) as ex:
        for r in ex.map(one, which):
            log("done", r)
