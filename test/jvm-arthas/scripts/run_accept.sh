#!/bin/sh
# Stage-2 acceptance: the measurements of docs/arthas-stage2-acceptance-report.md, one after the other (the latency
# runs need an otherwise idle cpuset 4-9, so nothing runs in parallel with them).
#   JA_OUT=<raw data dir> scripts/run_accept.sh [set ...]
# Sets: cycles leak limits metaspace latency threads oldgen extra (default: all, in this order). Finished latency runs
# (a `done` file) are skipped, so an interrupted set can be started again.
cd "$(dirname "$0")/.." || exit 1
: "${JA_OUT:?set JA_OUT to the directory for the raw data}"
export COMPOSE_FILE="${COMPOSE_FILE:-compose.yaml:compose.accept.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-jvm-arthas-accept}"
export JA_PORT_PREFIX="${JA_PORT_PREFIX:-26}"
# A failed run is reported and the next one starts.
A() { python3 scripts/accept.py "$@" || echo "FAILED: accept.py $*" >&2; }
# The 13 L1 command kinds, thread -b twice; dashboard first because it takes longest.
L1=dashboard,thread_top,thread_blocking,thread_info,memory,jvm,class_info,method_info,classloader_tree,thread_blocking,classloader_list,logger,sysprop,version
# The 12 kinds other than logger (the Full GCs do not unload the class loaders that logger leaves, report section 3.4).
NOLOG=dashboard,thread_top,thread_blocking,thread_info,memory,jvm,class_info,method_info,classloader_tree,classloader_list,sysprop,version
TB="--kinds thread_blocking --calls 4 --every 14 --phase 60 --blocked 10"
OG="--kinds dashboard,thread_top,jvm,memory --every 10 --phase 45 --after 30"

for set in ${*:-cycles leak limits metaspace latency threads oldgen extra}; do
  case "$set" in
  cycles) A cycles ;;
  leak) A leak ;;
  limits) A limits ;;
  metaspace)
    for m in 96 128 160; do A metaspace --case jdk17-max${m}m --java-extra="-XX:MaxMetaspaceSize=${m}m"; done
    A metaspace --case jdk17-max128m-defaults --java-extra=-XX:MaxMetaspaceSize=128m --keep-state --calls 5 --gap 61
    A metaspace --svc jdk8 --case jdk8-max128m --java-extra=-XX:MaxMetaspaceSize=128m
    # The overlay starts jdk17 without entrypoint.sh, so that the option can come from one of the two variables.
    (export COMPOSE_FILE="$COMPOSE_FILE:compose.accept-env.yaml" JA_JAVA_TOOL_OPTIONS="-XX:MaxMetaspaceSize=96m"
      A metaspace --case jdk17-java-tool-options-max96m --calls 2)
    (export COMPOSE_FILE="$COMPOSE_FILE:compose.accept-env.yaml" JA_JDK_JAVA_OPTIONS="-XX:MaxMetaspaceSize=96m"
      A metaspace --case jdk17-jdk-java-options-max96m --calls 2)
    ;;
  latency)
    for rep in 1 2 3; do
      for svc in jdk8 jdk11 jdk17 jdk21; do
        A latency --svc "$svc" --scenario l1all --kinds "$L1" --every 11 --blocked 5 --rep "$rep"
      done
    done
    ;;
  threads)
    for svc in jdk17 jdk8 jdk11 jdk21; do
      A latency --svc "$svc" --scenario tb470 $TB --threads-total 470
      A latency --svc "$svc" --scenario tb1000 $TB --threads-total 1000 --threads-live 400
    done
    A latency --svc jdk17 --scenario tb470 $TB --threads-total 470 --rep 2
    A latency --svc jdk17 --scenario tb1000 $TB --threads-total 1000 --threads-live 400 --rep 2
    # Retained small objects: thread -b also reports the locked synchronizers, which HotSpot finds by walking the heap.
    A latency --svc jdk17 --scenario tb-heap250x64 $TB --retain 250 --retain-size 64
    ;;
  oldgen)
    for svc in jdk17 jdk8; do
      A latency --svc "$svc" --scenario og0 $OG
      for mb in 300 400 450; do A latency --svc "$svc" --scenario "og$mb" $OG --retain "$mb"; done
    done
    ;;
  extra)
    # Follow-ups of the first results: 50 calls without logger; the class loaders after logger; the l1all windows without
    # a call (noise reference) and two more l1all runs on JDK 21, where one call met a 166 ms safepoint.
    A cycles --name cycles-nologger --kinds "$NOLOG"
    A leak --name leak-loaders --kinds logger,version
    for rep in 1 2; do A latency --svc jdk21 --scenario noop --kinds none --rep "$rep"; done
    for rep in 4 5; do A latency --svc jdk21 --scenario l1all --kinds "$L1" --every 11 --blocked 5 --rep "$rep"; done
    ;;
  *) echo "unknown set $set" >&2; exit 2 ;;
  esac
done
