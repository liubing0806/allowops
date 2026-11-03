#!/usr/bin/env python3
"""Why the class loader of Arthas stays after `logger` (docs/arthas-logger-classloader-report.md).

Per service and command kind, a new JVM: warm-up requests, 3 Full GCs, a few jvm_arthas calls of one kind through
bin/ja-call, more Full GCs, then the class loaders and, with --dump, a heap dump for the offline analysis
(scripts/hprof_paths.py). Raw data goes to $JA_OUT/<name>/<svc>/<kind>/.

Run from test/jvm-arthas with COMPOSE_FILE=compose.yaml:compose.logger.yaml, a COMPOSE_PROJECT_NAME of its own and
JA_PORT_PREFIX at 32 or lower, for example:

  scripts/logger_leak.py --svcs jdk8,jdk17 --kinds logger,version --calls 2 --dump
  scripts/logger_leak.py --svcs log4j2-8,log4j2-17 --kinds logger --calls 2 --dump
  scripts/logger_leak.py --svcs jdk8,jdk17 --kinds logger --calls 2 --flavor patched --name logger-patched

--flavor patched uses run/arthas-patched (scripts/patch-arthas-pd.sh) instead of run/arthas-minlog.

Before the first run: `make app probe arthas tools prepare`, the log4j2 build of app/pom-log4j2.xml,
scripts/patch-arthas-pd.sh, `mkdir -p run/log4j2-8/logs run/log4j2-17/logs` (mode 0777, as `make prepare` does) and
`docker compose build jdk8 jdk17` with the COMPOSE_FILE above. Afterwards:
`docker compose --profile jre --profile variants --profile log4j2 down -v --remove-orphans`.
"""
import argparse
import shutil

from accept import full_gc, ja_call, jvm_pid_in_container, set_env, snapshot
from ja import *


def loaders(t, svc):
    pid = jvm_pid_in_container(t)
    if svc == "jdk8" or svc.endswith("-8"):
        # JDK 8 has no VM.classloaders; GC.class_stats needs -XX:+UnlockDiagnosticVMOptions, which entrypoint.sh sets.
        stats = t.docker_exec("jcmd", pid, "VM.classloader_stats", timeout=120).stdout
        classes = t.docker_exec("jcmd", pid, "GC.class_stats", "ClassLoader,ClassName", timeout=300).stdout
        return {"VM.classloader_stats": stats, "GC.class_stats": classes}
    return {"VM.classloaders": t.docker_exec("jcmd", pid, "VM.classloaders", "show-classes=true", "verbose=true", timeout=120).stdout}


def one(svc, kind, a):
    d = OUT / a.name / svc / kind
    if (d / "steps.json").exists():
        log("skip", d)
        return
    d.mkdir(parents=True, exist_ok=True)
    t = Target(svc).up()
    ip = t.ip()
    steps = []
    step = lambda what, **kw: steps.append({"t": time.time(), "what": what, "diag": json.loads(http_get(f"http://{ip}:8080/diag")), **kw})
    for path in ("/ping", "/hot?calls=10", "/work", "/db?id=3"):
        for _ in range(200):
            http_get(f"http://{ip}:8080{path}")
    for i in range(3):
        full_gc(t)
        time.sleep(2)
    step("baseline", snap=snapshot(svc))
    (d / "loaders-baseline.json").write_text(json.dumps(loaders(t, svc), indent=2))
    flavor = ["-files", str(RUN / f"arthas-{a.flavor}"), "-arthas-dir", f"/opt/arthas-{a.flavor}"]
    p = ja_call(svc, d / "calls.jsonl", f"{svc}-logger-{kind}", [kind], calls=a.calls, evidence=d / "calls", extra=flavor)
    (d / "ja-call.err").write_text(p.stderr)
    step("after calls", rc=p.returncode)
    for i in range(a.gcs):
        gc = full_gc(t)
        time.sleep(2)
        step(f"after full gc {i + 1}", gc=gc, snap=snapshot(svc))
    pid = jvm_pid_in_container(t)
    hist = t.docker_exec("jcmd", pid, "GC.class_histogram", timeout=120).stdout.splitlines()
    step("histogram", arthas=[ln for ln in hist if "arthas" in ln.lower()])
    (d / "loaders-after.json").write_text(json.dumps(loaders(t, svc), indent=2))
    if a.dump:
        # GC.heap_dump without -all dumps the live objects only, after one more Full GC.
        name = f"{svc}-{kind}.hprof"
        r = t.docker_exec("jcmd", pid, "GC.heap_dump", f"/logs/{name}", timeout=600)
        step("heap dump", rc=r.returncode, out=r.stdout.strip())
        t.docker_exec("chmod", "0644", f"/logs/{name}")  # the JVM writes it with mode 0600
        shutil.move(str(RUN / svc / "logs" / name), str(d / name))
    (d / "steps.json").write_text(json.dumps(steps, indent=2))
    (d / "stdout.log").write_text(run(["docker", "logs", "--timestamps", t.container], check=False).stdout)
    t.down()
    log("finished", svc, kind)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--svcs", default="jdk8,jdk17")
    ap.add_argument("--kinds", default="logger,version")
    ap.add_argument("--calls", type=int, default=2)
    ap.add_argument("--gcs", type=int, default=5)
    ap.add_argument("--mem", default="2g")
    ap.add_argument("--dump", action="store_true", help="write a heap dump after the Full GCs")
    ap.add_argument("--flavor", default="minlog", choices=["minlog", "patched"], help="Arthas files: run/arthas-<flavor>")
    ap.add_argument("--name", default="logger", help="directory under JA_OUT")
    a = ap.parse_args()
    set_env(a.mem)
    for svc in a.svcs.split(","):
        for kind in a.kinds.split(","):
            one(svc, kind, a)
