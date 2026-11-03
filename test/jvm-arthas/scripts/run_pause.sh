#!/bin/sh
# JVM pause measurements (docs/arthas-jvm-pause-report.md), one run after the other: the latency runs need an otherwise idle
# cpuset 4-9. Environment of its own: COMPOSE_PROJECT_NAME=jvm-arthas-pause, ports 25xxx, images jvmarthas/app-pause:*.
#   JA_OUT=<raw data dir> scripts/run_pause.sh natural   bench.py l2:watch@p10k as in stage 0 (JVM logs on the host's root
#                                                        file system), JDK 11 and 21 three times, JDK 17 once, JDK 11 noop once;
#                                                        pause_watch.py on every JVM and host_io_probe.py on / and /data
#   JA_OUT=<raw data dir> scripts/run_pause.sh stall     exp_logstall.py: a device that is stopped for 6 s three times per run
#                                                        under the JVM's log files, under nothing of the JVM's, or under its
#                                                        /tmp (scripts/stallfs.sh setup first)
#   JA_OUT=<raw data dir> scripts/run_pause.sh freeze    the same cases with the file system frozen for 4 s (fsfreeze), plus
#                                                        tmpfs and hsperf for all three JDKs
#   JA_OUT=<raw data dir> scripts/run_pause.sh stall2    JDK 17 and 21, log files on the device, 6 suspensions per run
# Finished runs (a `done` file) are skipped.
cd "$(dirname "$0")/.." || exit 1
: "${JA_OUT:?set JA_OUT to the directory for the raw data}"
export COMPOSE_FILE="${COMPOSE_FILE:-compose.yaml:compose.pause.yaml}"
export COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-jvm-arthas-pause}"
export JA_PORT_PREFIX="${JA_PORT_PREFIX:-25}"
export APP_MEM="${APP_MEM:-2g}"

others() {
  # other copies of the environment and what runs on the measuring cpus, before each run
  { date +%s; docker ps --format '{{.Names}} {{.Status}}' | grep -E '^jvm-arthas' || true
    ps -eo psr,pcpu,pid,comm --sort=-pcpu | awk '$1>=4 && $1<=9 && $2>=5' | head -20; echo; } >> "$JA_OUT/others.txt"
}

case "$1" in
natural)
  mkdir -p "$JA_OUT/natural" run/io-probe-root "$JA_OUT/io-probe-data"
  sudo -n taskset -c 12-15 python3 scripts/host_io_probe.py "$JA_OUT/natural/host_io.jsonl" 3600 \
    --dir "$PWD/run/io-probe-root" --dir "$JA_OUT/io-probe-data" --disk nvme0n1 &
  probe=$!
  B="python3 scripts/bench.py --phase 60 --warm 60 --watch"
  export JA_OUT="$JA_OUT/natural"
  for step in "jdk11 l2:watch@p10k 1" "jdk21 l2:watch@p10k 1" "jdk17 l2:watch@p10k 1" "jdk11 l2:watch@p10k 2" \
              "jdk21 l2:watch@p10k 2" "jdk11 noop 1 p10k" "jdk11 l2:watch@p10k 3" "jdk21 l2:watch@p10k 3"; do
    set -- $step
    others
    $B --svc "$1" --scenario "$2" --rep "$3" ${4:+--profile $4} || echo "FAILED: $step" >&2
  done
  sudo -n kill "$probe" 2>/dev/null
  ;;
stall)
  E="python3 scripts/exp_logstall.py"
  for step in "jdk11 disk" "jdk17 disk" "jdk21 disk" "jdk11 tmpfs" "jdk21 tmpfs" "jdk17 async" "jdk21 async" \
              "jdk17 hsperf" "jdk17 hsperf-off" "jdk11 hsperf"; do
    set -- $step
    others
    $E --svc "$1" --case "$2" || echo "FAILED: $step" >&2
  done
  ;;
freeze)
  # the same cases with the file system frozen (fsfreeze) for 4 s instead of the device suspended
  E="python3 scripts/exp_logstall.py --how freeze --stall 4"
  for step in "jdk11 disk" "jdk17 disk" "jdk21 disk" "jdk11 tmpfs" "jdk17 tmpfs" "jdk21 tmpfs" "jdk17 async" "jdk21 async" \
              "jdk11 hsperf" "jdk17 hsperf" "jdk21 hsperf" "jdk17 hsperf-off" "jdk21 hsperf-off"; do
    set -- $step
    others
    $E --svc "$1" --case "$2" || echo "FAILED: $step" >&2
  done
  ;;
stall2)
  # more device suspensions with the log files on the device: 6 per run, JDK 17 and 21
  for svc in jdk17 jdk21; do
    others
    python3 scripts/exp_logstall.py --svc "$svc" --case disk --rep 2 --count 6 || echo "FAILED: $svc" >&2
  done
  ;;
*)
  echo "usage: $0 natural | stall | freeze | stall2" >&2
  exit 2
  ;;
esac
