#!/usr/bin/env python3
"""Stage-0 item 6: attach and run Arthas in containers with a read-only root file system and/or no HOME.
Records what Java thinks user.home is, where Arthas managed to write, and what it printed."""
from ja import *

EXP = "item6-rofs"
L1 = ["version", "jvm", "thread -n 5", "sc -d demo.HotService", "classloader -t", "sysprop user.home"]


def env_facts(t):
    sh = ("id; echo HOME=${HOME-<unset>}; "
          "for d in / /app /tmp /home/app; do (touch $d/.w 2>/dev/null && rm -f $d/.w && echo writable:$d) || echo readonly-or-missing:$d; done; "
          "java -XshowSettings:properties -version 2>&1 | grep -E 'user.home|java.io.tmpdir|user.dir|user.name'; "
          "mount | grep -E ' / | /tmp ' | cut -c1-120")
    return t.docker_exec("sh", "-c", sh, user=None).stdout.strip().splitlines()


def written_files(t):
    # everything that is newer than the application jar on writable file systems and tmpfs
    r = t.docker_exec("sh", "-c", "find / -xdev -newer /app/app.jar \\( -type f -o -type d \\) 2>/dev/null | grep -v -E '^/(proc|sys|dev)' | head -60; "
                                  "echo ---tmpfs; find /tmp -type f -o -type d 2>/dev/null | grep -v hsperfdata | head -40", user="0")
    return r.stdout.strip().splitlines()


def one(svc):
    t = Target(svc).up()
    r = {"svc": svc, "env": env_facts(t), "inspect": t.inspect()}
    before_stdout = len(t.logs().splitlines())
    attempts = {}
    for file_dir in ("cwd", "tmp"):
        a = t.attach(file_dir=file_dir, wait="6s", flavor="minlog")
        attempts[file_dir] = {"ok": a["ok"], "stage": a["stage"], "error": a.get("error"), "reply": a.get("reply")}
        if a["ok"]:
            break
    r["attach_attempts"] = attempts
    time.sleep(1)
    if t.arthas_port and any(v["ok"] for v in attempts.values()):
        r["l1"] = {c: short(t.exec(c, exec_timeout=30000)) for c in L1}
        r["user_home_seen_by_arthas"] = [x.get("value") for x in results_of(t.exec("sysprop user.home"))[1] if x.get("type") == "sysprop"]
        r["written_files"] = written_files(t)
        t.exec("stop", exec_timeout=20000)
    out = t.logs().splitlines()
    r["stdout_new_lines"] = out[before_stdout:][:60]
    r["target_still_serves"] = http_get(f"http://{t.ip()}:8080/ping")
    r["docker_diff"] = run(["docker", "diff", t.container], check=False).stdout.strip().splitlines()[:40]
    return r


if __name__ == "__main__":
    res = {}
    for svc in ["jdk17", "rofs17", "rofs8", "nohome17", "nohome8", "rofsnotmp17"]:
        res[svc] = one(svc)
        log("rofs", svc, {k: v["ok"] for k, v in res[svc]["attach_attempts"].items()})
    write_json(EXP, "result.json", res)
