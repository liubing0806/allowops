#!/usr/bin/env python3
"""Stage-0 item 2: can arthas-core run in a JVM that comes from a JRE-only image (no jdk.attach, no jcmd)
or from a jlink runtime without java.instrument? Plan A (arthas-boot inside the container) is tried in the same images."""
from ja import *

EXP = "item2-jre"
L1 = ["version", "jvm", "memory", "dashboard -n 1", "thread -n 5", "thread -b", "sc -d demo.HotService", "sm -d demo.HotService work",
      "classloader -t", "classloader -l", "logger", "sysprop java.version", "session"]


def modules(t):
    r = t.docker_exec("sh", "-c", "java --list-modules 2>/dev/null | grep -E 'attach|instrument|management'; "
                                  "ls /opt/java/openjdk/lib/tools.jar 2>&1 | head -1; which jcmd jstat jps jattach 2>&1 | head -5; "
                                  "java -version 2>&1 | head -1")
    return r.stdout.strip().splitlines()


def main():
    res = {}
    for svc in ["jre8", "jre17", "jlink17"]:
        t = Target(svc).up()
        r = {"modules_and_tools": modules(t), "inspect": t.inspect()}
        a = t.attach()
        r["attach"] = a
        time.sleep(1)
        if a["ok"]:
            r["l1"] = {c: short(t.exec(c, exec_timeout=30000)) for c in L1}
            p = t.probe()
            r["probe"] = {"arthas_threads": p["arthas_threads"], "listeners": [x["port"] for x in p["listeners"]]}
            r["stop"] = short(t.exec("stop", exec_timeout=20000))
        else:
            r["target_still_serves"] = http_get(f"http://{t.ip()}:8080/ping")
            r["stdout_tail"] = t.logs().splitlines()[-8:]
            r["thread_dumps_in_stdout"] = t.logs().count("Full thread dump")
        # plan A inside the same container
        pid = t.inspect()["nspid"]
        pa = t.docker_exec("sh", "-c", f"timeout 60 java -jar /opt/arthas-stock/arthas-boot.jar {pid} --arthas-home /opt/arthas-stock -c version 2>&1 | tail -15",
                           user="10001", timeout=120)
        r["plan_a_in_this_image"] = pa.stdout.strip().splitlines()[-12:]
        res[svc] = r
        log("jre", svc, "attach ok:", a["ok"], a.get("reply"))
    # control: the same plan A in the full JDK image
    t = Target("jdk17").up()
    pid = t.inspect()["nspid"]
    pa = t.docker_exec("sh", "-c", f"timeout 90 java -jar /opt/arthas-stock/arthas-boot.jar {pid} --arthas-home /opt/arthas-stock -c version 2>&1 | tail -15",
                       user="10001", timeout=150)
    res["jdk17_plan_a_control"] = pa.stdout.strip().splitlines()[-12:]
    write_json(EXP, "result.json", res)


if __name__ == "__main__":
    main()
