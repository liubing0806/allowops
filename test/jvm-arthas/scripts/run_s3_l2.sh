#!/bin/sh
# Stage-3 L2 measurements (docs/arthas-stage3-acceptance-report.md) through the product code: scripts/s3_l2.py, one run after the
# other. Environment of its own: compose.stage3.yaml (JVM logs and /tmp on tmpfs, -Xlog:async on JDK 17 and 21) plus
# compose.s3d.yaml (images jvmarthas/app-s3d:*), COMPOSE_PROJECT_NAME=jvm-arthas-s3d, ports 23xxx. Every run also runs
# host_io_probe.py, pause_watch.py and a sampler of the other processes, and records the load of the host before and after.
#   JA_OUT=<raw data dir> scripts/run_s3_l2.sh [set ...]
# Sets (default: steady plain):
#   build   the sample application, the probe, the Arthas files, the tools and the four images jvmarthas/app-s3d:*
#   steady  4 JDKs x p1k, p10k x 3 repetitions; each run a new JVM and the five commands 70 s apart, watch, trace, stack and
#           monitor with the unmet condition #cost>10000 (about 9.6 min per run, 3.9 h)
#   plain   the transient of the calls without condition, count 1: 4 JDKs x p10k x 1 repetition, watch, trace, stack and
#           monitor, the first command turning with the JDK (about 8.5 min per run, 34 min)
#   cpuload the JVM already uses about 40% of its CPU limit (2 busy threads of /l2/burn at 70% duty, 1.4 CPUs, plus the load),
#           under the 50% of the CPU check: JDK 17 x p1k, p10k x 1 repetition, as steady (about 20 min)
#   func    the functional checks of s3_l2.py func on the four JDKs (about 4 min per JDK)
#   down    remove the containers and the temporary directories of Tomcat that uid 10001 left in run/*/logs
# Finished runs (a `done` file) are skipped, so an interrupted set can be started again. CPUs: the JVM on 4-7 (APP_CPUS), the
# load on 8-9 (LOAD_CPUS), ja-call, the probes and this driver on 12-15 (CALL_CPUS); the measurement needs them otherwise idle.
cd "$(dirname "$0")/.." || exit 1
: "${JA_OUT:?set JA_OUT to the directory for the raw data}"
export COMPOSE_FILE="${COMPOSE_FILE:-compose.yaml:compose.stage3.yaml:compose.s3d.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-jvm-arthas-s3d}"
export JA_PORT_PREFIX="${JA_PORT_PREFIX:-23}"
export JA_LOGDIR_TMPFS=/logs-tmpfs
export APP_CPUS="${APP_CPUS:-4-7}" LOAD_CPUS="${LOAD_CPUS:-8-9}" CALL_CPUS="${CALL_CPUS:-12-15}"
mkdir -p "$JA_OUT"

# A failed run is reported and the next one starts.
R() { taskset -c "$CALL_CPUS" python3 scripts/s3_l2.py "$@" || echo "FAILED: s3_l2.py $*" >&2; }

for set in ${*:-steady plain}; do
  case "$set" in
  build)
    make app probe arthas prepare tools && docker compose build jdk8 jdk11 jdk17 jdk21 || exit 1
    ;;
  steady)
    # The repetitions are the outer loop, so that a change of the host's load spreads over the JDKs and the rates.
    for rep in 1 2 3; do
      for svc in jdk8 jdk11 jdk17 jdk21; do
        for profile in p1k p10k; do
          R run --mode steady --svc "$svc" --profile "$profile" --rep "$rep"
        done
      done
    done
    ;;
  plain)
    # The first command turns with the JDK: the first enhancement of a JVM takes longer (report, section 7), and so each
    # of the four commands is the first one once.
    for o in jdk8:watch,trace,stack,monitor jdk11:trace,stack,monitor,watch jdk17:stack,monitor,watch,trace \
      jdk21:monitor,watch,trace,stack; do
      R run --mode plain --svc "${o%%:*}" --profile p10k --rep 1 --order "${o#*:}"
    done
    ;;
  cpuload)
    for profile in p1k p10k; do
      R run --mode steady --variant cpu40 --burn 2,70 --svc jdk17 --profile "$profile" --rep 1
    done
    ;;
  func)
    for svc in jdk8 jdk11 jdk17 jdk21; do R func --svc "$svc"; done
    ;;
  down)
    docker compose --profile jre --profile variants down -v --remove-orphans
    sudo -n find run -maxdepth 3 -path 'run/*/logs/tomcat*' -user 10001 -exec rm -rf {} +
    ;;
  *) echo "unknown set $set" >&2; exit 2 ;;
  esac
done
