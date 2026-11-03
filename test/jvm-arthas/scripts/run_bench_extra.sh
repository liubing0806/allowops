#!/bin/sh
# Stage-0 item 5: second runs of the measurements whose first run was disturbed by other processes on the host or whose result needs a repeat.
#   scripts/run_bench_extra.sh extra17        output: $JA_OUT/bench/jdk17/<scenario>__<profile>/rep<k>/
# Finished runs (a `done` file) are skipped. Run it after run_bench.sh, with nothing else using the cpusets.
set -e
cd "$(dirname "$0")/.."
: "${JA_OUT:?set JA_OUT to the directory for the raw data}"
export APP_MEM="${APP_MEM:-2g}"
P="--phase ${PHASE:-60} --warm ${WARM:-60}"
B="python3 scripts/bench.py $P"

case "$1" in
extra17)
  $B --svc jdk17 --scenario attach_hold --rep 2
  $B --svc jdk17 --scenario attach_hold --rep 3
  $B --svc jdk17 --scenario "l1c:thread -n 5" --rep 2
  $B --svc jdk17 --scenario "l1s:thread -b" --rep 2
  $B --svc jdk17 --scenario "l1s:classloader -t" --rep 2
  $B --svc jdk17 --scenario "l2:watch@p1k" --rep 2
  $B --svc jdk17 --scenario "l2:watch@p10k" --rep 2
  $B --svc jdk17 --scenario "l2:trace@p10k" --rep 2
  $B --svc jdk17 --scenario noop --rep 4
  ;;
*)
  echo "usage: $0 extra17" >&2
  exit 2
  ;;
esac
