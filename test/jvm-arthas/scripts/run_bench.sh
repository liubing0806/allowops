#!/bin/sh
# Stage-0 item 5: the whole latency matrix, one run after the other (nothing else may use the cpusets in between).
#   scripts/run_bench.sh main17 | jdk8 | jdk11 | jdk21        output: $JA_OUT/bench/<svc>/<scenario>__<profile>/rep<k>/
# Finished runs (a `done` file) are skipped, so an interrupted set can be started again.
set -e
cd "$(dirname "$0")/.."
: "${JA_OUT:?set JA_OUT to the directory for the raw data}"
export APP_MEM="${APP_MEM:-2g}"   # attach/stop cycles add about 10 MB of metaspace each; 1 GB would end in an OOM kill (item 3)
P="--phase ${PHASE:-60} --warm ${WARM:-60}"
B="python3 scripts/bench.py $P"

case "$1" in
main17)
  $B --svc jdk17 --scenario noop --rep 1
  $B --svc jdk17 --scenario attach_hold,attach_cycle
  for c in "dashboard -n 1" "thread -n 5" "thread -b" "jvm" "memory" "sc -d demo.HotService" "sm -d demo.HotService work" "classloader -t"; do
    $B --svc jdk17 --scenario "l1c:$c"
  done
  $B --svc jdk17 --scenario noop --rep 2
  for c in "thread -n 5" "thread -b" "classloader -t"; do
    $B --svc jdk17 --scenario "l1s:$c"
  done
  for k in watch trace stack monitor; do
    $B --svc jdk17 --scenario "l2:$k@p1k,l2:$k@p10k"
  done
  $B --svc jdk17 --scenario "l2keep:watch@p1k,l2stuck:watch@p1k"
  $B --svc jdk17 --scenario noop --rep 3
  ;;
jdk8)
  $B --svc jdk8 --scenario noop --rep 1
  $B --svc jdk8 --scenario "attach_cycle,l1c:thread -n 5,l1c:thread -b,l1c:classloader -t,l2:watch@p1k,l2:watch@p10k"
  $B --svc jdk8 --scenario noop --rep 2
  ;;
jdk11|jdk21)
  $B --svc "$1" --scenario "noop,attach_cycle,l1c:thread -b,l2:watch@p10k"
  ;;
*)
  echo "usage: $0 main17|jdk8|jdk11|jdk21" >&2
  exit 2
  ;;
esac
