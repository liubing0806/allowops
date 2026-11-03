#!/usr/bin/env python3
"""Stage-0 follow-up of item 1: the HotSpot attach `load` command takes the agent argument as one string.
How long may `<agent.jar>=<core.jar>;<options>` be on JDK 8 / 11 / 17 / 21, and what does the failure look like?

Pads the Arthas option string with an unused key (`pad=xxxx`) until the whole argument has the wanted length.

Usage: exp_args.py [svc ...]      (default jdk8 jdk11 jdk17 jdk21, in parallel)
"""
import concurrent.futures
import sys

from ja import *
from exp_stop import wait_gone

EXP = "item1-params"
LENGTHS = [452, 900, 1000, 1023, 1024, 1025, 1100, 2000, 4000, 8000]


def one(svc):
    t = Target(svc).up()
    rows = []
    base_len = None
    for want in LENGTHS:
        pw = t.new_secret()
        plain = (f"telnetPort=-1;httpPort=18563;ip=127.0.0.1;password={pw};localConnectionNonAuth=false;"
                 f"mcpEndpoint=;disabledCommands={disabled_for(L1_COMMANDS)};sessionTimeout=300")
        a0 = len("/opt/arthas-minlog/arthas-agent.jar") + 1 + len("/opt/arthas-minlog/arthas-core.jar") + 1
        pad = max(0, want - (a0 + len(plain)) - len(";pad="))
        opts = plain + (f";pad={'x' * pad}" if pad else "")
        a = t.attach(raw_opts=opts.replace(pw, "@PW@"), wait="6s")
        row = {"want": want, "arg_len": a.get("agent_arg_len"), "ok": a["ok"], "stage": a["stage"], "reply": (a.get("reply") or "")[:200],
               "error": a.get("error")}
        if a["ok"]:
            r = short(t.exec("version"))
            row["version"] = r["state"]
            t.exec("stop", exec_timeout=20000)
            row["gone_s"] = wait_gone(t, 20)[0]
        rows.append(row)
        log(svc, want, row["arg_len"], row["ok"], row["stage"], row["reply"][:60].replace("\n", " "), row.get("version"))
    out = t.logs()
    res = {"svc": svc, "rows": rows, "thread_dumps_in_stdout": out.count("Full thread dump")}
    write_json(EXP, f"arglen-{svc}.json", res)
    return svc


if __name__ == "__main__":
    which = sys.argv[1:] or ["jdk8", "jdk11", "jdk17", "jdk21"]
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(which)) as ex:
        for r in ex.map(one, which):
            log("done", r)
