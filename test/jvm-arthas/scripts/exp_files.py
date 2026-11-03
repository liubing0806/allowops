#!/usr/bin/env python3
"""Stage-0 item "attach files": where the attach files/sockets live, which uid combinations the JVM accepts
(JDK 8 vs 11+, target running as root or not), what happens with -Xrs / -XX:+DisableAttachMechanism /
java as PID 1, and what sun.rt.jvmCapabilities says.

Usage: exp_files.py [matrix|special]
"""
import concurrent.futures
import sys

from hsperf import read_hsperf
from ja import *

EXP = "item9-attach-files"
COMBOS = [("cwd", "root", "root"), ("cwd", "target", "root"), ("cwd", "root", "target"), ("cwd", "target", "target"),
          ("tmp", "root", "root"), ("tmp", "target", "root"), ("tmp", "root", "target"), ("tmp", "target", "target"),
          ("none", "root", "root")]


def thread_dumps(t):
    return t.logs().count("Full thread dump")


def stat_files(t):
    r = t.docker_exec("sh", "-c", "ls -ln /tmp/.java_pid* /app/.attach_pid* /tmp/.attach_pid* 2>&1; ls -ldn /tmp /app", user="0")
    return r.stdout.strip().splitlines()


def matrix(svc):
    out = []
    for file_dir, file_owner, conn_user in COMBOS:
        t = Target(svc).up()
        before = thread_dumps(t)
        insp = t.inspect()
        hs = read_hsperf(t.pid(), insp["nspid"])
        a = t.attach(file_dir=file_dir, file_owner=file_owner, conn_user=conn_user, wait="6s")
        time.sleep(1)
        row = {"svc": svc, "file_dir": file_dir, "file_owner": file_owner, "conn_user": conn_user,
               "target_uid": insp["uid"], "ok": a["ok"], "stage": a["stage"], "error": a.get("error"), "reply": a.get("reply"),
               "attach_ms": a.get("request_to_reply_ms"), "signal_to_socket_ms": a.get("signal_to_socket_ms"),
               "thread_dump_printed_to_stdout": thread_dumps(t) - before,
               "files_after": stat_files(t), "sun.rt.jvmCapabilities": (hs or {}).get("sun.rt.jvmCapabilities"),
               "java.property.java.version": (hs or {}).get("java.property.java.version")}
        log(svc, file_dir, file_owner, conn_user, "->", a["ok"], a["stage"], a.get("error"))
        out.append(row)
    write_json(EXP, f"matrix-{svc}.json", out)
    return svc


def special():
    res = {}
    # hsperfdata of ordinary JVMs, for the "attach allowed" check of plan 3.2
    for svc in ["jdk8", "jdk11", "jdk17", "jdk21", "noattach8", "noattach17", "jre17", "jlink17"]:
        t = Target(svc).up()
        insp = t.inspect()
        hs = read_hsperf(t.pid(), insp["nspid"]) or {}
        keep = {k: v for k, v in hs.items() if k in ("sun.rt.jvmCapabilities", "java.property.java.version", "java.property.java.vm.name",
                                                       "sun.rt.javaCommand", "java.property.java.vm.version", "sun.rt.jvmVersion",
                                                       "java.property.java.runtime.version", "java.property.sun.boot.library.path",
                                                       "sun.rt.jvmVersion", "java.rt.vmFlags", "java.rt.vmArgs") or k == "_prologue"}
        keep["n_counters"] = len(hs)
        a = t.attach(file_dir="cwd", wait="6s", flavor="minlog") if svc.startswith(("noattach",)) else None
        res[svc] = {"inspect": insp, "hsperf": keep, "attach_attempt": a,
                    "thread_dumps_in_stdout": thread_dumps(t)}
        log("special", svc, keep.get("sun.rt.jvmCapabilities"))
    # java as PID 1
    t = Target("pid1-17").up()
    insp = t.inspect()
    a = t.attach(file_dir="cwd", wait="6s")
    res["pid1-17"] = {"inspect": insp, "attach": a, "pid_of_java_in_container": insp["nspid"]}
    # -Xrs: the JVM does not catch SIGQUIT. Record the signal masks first, then send the attach signal once.
    for svc in ["xrs8", "xrs17"]:
        t = Target(svc).up()
        insp = t.inspect()
        a = t.attach(file_dir="cwd", wait="6s")
        time.sleep(2)
        st = run(["docker", "inspect", "-f", "{{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}}", t.container]).stdout.strip()
        res[svc] = {"inspect": insp, "attach": a, "container_state_after": st, "stdout_tail": t.logs().splitlines()[-6:]}
        log("special", svc, st)
    write_json(EXP, "special.json", res)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    if mode in ("matrix", "all"):
        svcs = ["jdk8", "jdk11", "jdk17", "jdk21", "root8", "root17"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(svcs)) as ex:
            for r in ex.map(matrix, svcs):
                log("done", r)
    if mode in ("special", "all"):
        special()
