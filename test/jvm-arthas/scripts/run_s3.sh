#!/bin/sh
# Stage-3 measurements (docs/arthas-stage3-acceptance-report.md), one after the other: the latency runs need an otherwise idle
# cpuset 4-9. Environment of its own: compose.stage3.yaml (JVM logs and /tmp on tmpfs, -Xlog:async on JDK 17 and 21),
# COMPOSE_PROJECT_NAME=jvm-arthas-s3m, ports 27xxx, images jvmarthas/app-s3:*. Every latency run also runs host_io_probe.py,
# pause_watch.py and a sampler of the other processes (accept.py latency --probe).
#   JA_OUT=<raw data dir> scripts/run_s3.sh [set ...]
# Sets: envcheck noise-l1 threads oldgen metaspace interval (default: all, in this order). Finished runs (a `done` file) are
# skipped, so an interrupted set can be started again.
cd "$(dirname "$0")/.." || exit 1
: "${JA_OUT:?set JA_OUT to the directory for the raw data}"
export COMPOSE_FILE="${COMPOSE_FILE:-compose.yaml:compose.stage3.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-jvm-arthas-s3m}"
export JA_PORT_PREFIX="${JA_PORT_PREFIX:-27}"
export JA_LOGDIR_TMPFS=/logs-tmpfs
mkdir -p "$JA_OUT"

others() {
  # other copies of the environment, the load of the host and what runs on the measuring cpus, before each run
  { date +%s; uptime; docker ps --format '{{.Names}} {{.Status}}' | grep -E '^jvm-arthas' || true
    ps -eo psr,pcpu,pid,comm --sort=-pcpu | awk '($1>=4 && $1<=9 || $1>=12 && $1<=15) && $2>=5' | head -20; echo; } >> "$JA_OUT/others.txt"
}
# A failed run is reported and the next one starts. The driver itself runs on the cpus of the calls.
A() { others; taskset -c 12-15 python3 scripts/accept.py "$@" || echo "FAILED: accept.py $*" >&2; }
S() { others; taskset -c 12-15 python3 scripts/s3.py "$@" || echo "FAILED: s3.py $*" >&2; }
# The 12 L1 command kinds other than logger (suspended by A69), thread -b twice; dashboard first because it takes longest.
L1=dashboard,thread_top,thread_blocking,thread_info,memory,jvm,class_info,method_info,classloader_tree,thread_blocking,classloader_list,sysprop,version
TB="--kinds thread_blocking --calls 4 --every 14 --phase 60 --blocked 50 --probe"
DEEP="--depth 40 --holders 300 --locks 4"
OG="--kinds jvm,thread_top,memory,dashboard --reps 3"

for set in ${*:-envcheck noise-l1 threads oldgen metaspace interval}; do
  case "$set" in
  envcheck) S envcheck ;;
  noise-l1)
    # noop and l1all alternate, so that both see the same host
    for rep in 1 2 3; do
      for svc in jdk8 jdk11 jdk17 jdk21; do
        A latency --svc "$svc" --scenario noop --kinds none --blocked 5 --rep "$rep" --probe
        A latency --svc "$svc" --scenario l1all --kinds "$L1" --every 11 --blocked 5 --rep "$rep" --probe
      done
    done
    ;;
  threads)
    # about 995 live threads, 40 frames deep, 300 of them holding 4 monitors each, 50 blocked on a monitor (the default limit is 1000)
    for rep in 1 2 3; do
      for svc in jdk17 jdk21 jdk8 jdk11; do
        A latency --svc "$svc" --scenario tbdeep $TB $DEEP --threads-total 995 --rep "$rep"
      done
    done
    # beyond the limit: 1500 threads; the checks are told 990
    for svc in jdk17 jdk21; do
      A latency --svc "$svc" --scenario tbdeep1500 $TB $DEEP --threads-total 1500 --threads-live 990
    done
    ;;
  oldgen)
    S oldgen --svc jdk8 --case jdk8-parallel --gc=-XX:+UseParallelGC $OG
    S oldgen --svc jdk8 --case jdk8-cms --gc=-XX:+UseConcMarkSweepGC $OG
    S oldgen --svc jdk8 --case jdk8-serial --gc=-XX:+UseSerialGC $OG
    S oldgen --svc jdk11 --case jdk11-g1 $OG
    S oldgen --svc jdk17 --case jdk17-g1 $OG
    S oldgen --svc jdk21 --case jdk21-g1 $OG
    S oldgen --svc jdk17 --case jdk17-zgc --gc=-XX:+UseZGC $OG
    S oldgen --svc jdk21 --case jdk21-zgc --gc=-XX:+UseZGC $OG
    S oldgen --svc jdk17 --case jdk17-shenandoah --gc=-XX:+UseShenandoahGC $OG
    S oldgen --svc jdk21 --case jdk21-shenandoah --gc=-XX:+UseShenandoahGC $OG
    ;;
  metaspace)
    for m in 128 150 175 200 260; do S metaspace --case "jdk17-max${m}m" --java-extra="-XX:MaxMetaspaceSize=${m}m"; done
    S metaspace --svc jdk8 --case jdk8-max150m --java-extra=-XX:MaxMetaspaceSize=150m
    S metaspace --svc jdk21 --case jdk21-max150m --java-extra=-XX:MaxMetaspaceSize=150m
    ;;
  interval)
    S interval --svc jdk17 --case jdk17
    S interval --svc jdk8 --case jdk8
    ;;
  *) echo "unknown set $set" >&2; exit 2 ;;
  esac
done
