#!/bin/sh
# Chooses the JVM flags for the JDK that is installed, then replaces the shell with the JVM.
#   HEAP        heap size, default 512m
#   JAVA_EXTRA  extra JVM flags, e.g. "-XX:+DisableAttachMechanism" or "-Xrs"
#   MINI=1      run MiniServer instead of the Spring Boot sample (runtime without java.instrument)
#   PROBE=1     load /app/probe.jar (records retransformations; not used in latency runs)
#   LOGDIR      where JVM logs go, default /logs
#   GC          garbage collector flags, default -XX:+UseG1GC (for example -XX:+UseParallelGC)
#   UNSET_HOME=1  remove HOME from the environment (the no-HOME variant)
set -eu
if [ "${UNSET_HOME:-0}" = "1" ]; then unset HOME; fi
HEAP="${HEAP:-512m}"
LOGDIR="${LOGDIR:-/logs}"
GC="${GC:--XX:+UseG1GC}"

ver="$(java -version 2>&1 | sed -n '1s/.*version "\([^"]*\)".*/\1/p')"
case "$ver" in
  1.*) major="$(echo "$ver" | cut -d. -f2)" ;;
  *)   major="$(echo "$ver" | cut -d. -f1)" ;;
esac

flags="-Xms$HEAP -Xmx$HEAP $GC -Djava.security.egd=file:/dev/./urandom -Dspring.main.banner-mode=off"
if [ "$major" -ge 9 ]; then
  flags="$flags -Xlog:safepoint*=info:file=$LOGDIR/safepoint.log:uptime,time"
  flags="$flags -Xlog:gc*=info:file=$LOGDIR/gc.log:uptime,time"
  flags="$flags -Xlog:redefine+class*=info:file=$LOGDIR/redefine.log:uptime,time"
else
  # JDK 8: safepoint statistics go to stdout (docker logs), GC and stopped time to a file.
  flags="$flags -XX:+PrintGCDetails -XX:+PrintGCDateStamps -XX:+PrintGCApplicationStoppedTime -Xloggc:$LOGDIR/gc.log"
  flags="$flags -XX:+UnlockDiagnosticVMOptions -XX:+PrintSafepointStatistics -XX:PrintSafepointStatisticsCount=1"
fi
if [ "${PROBE:-0}" = "1" ]; then
  flags="$flags -javaagent:/app/probe.jar=$LOGDIR/probe.log"
fi
echo "entrypoint: java major=$major flags=$flags ${JAVA_EXTRA:-}"
# shellcheck disable=SC2086
if [ "${MINI:-0}" = "1" ]; then
  exec java $flags ${JAVA_EXTRA:-} -cp /app/mini MiniServer
fi
exec java $flags ${JAVA_EXTRA:-} -jar /app/app.jar
