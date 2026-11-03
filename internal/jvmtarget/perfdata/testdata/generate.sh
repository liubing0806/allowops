#!/bin/sh
# Regenerates the *.hsperf samples from eclipse-temurin containers.
# Only needs Docker and network access to pull the images; run it from any directory.
#
# Each sample is the unmodified /tmp/hsperfdata_root/1 file of a JVM that runs
# src/com/example/sample/Sample.java with these arguments:
#   java -Xms64m -Xmx256m [GC flag] -cp /app com.example.sample.Sample --note=hello
# The program holds no secrets, so the samples contain none.
set -eu

here="$(cd "$(dirname "$0")" && pwd)"
work="$(mktemp -d)"
trap 'docker rm -f $(docker ps -aq --filter "name=hsperf-sample-") >/dev/null 2>&1 || true; rm -rf "$work"' EXIT

mkdir -p "$work/classes"
docker run --rm -v "$here/src:/src:ro" -v "$work/classes:/out" maven:3.9.9-eclipse-temurin-21 \
	javac --release 8 -Xlint:-options -d /out /src/com/example/sample/Sample.java
chmod -R a+rX "$work/classes"

sample() {
	name="$1"; image="$2"; shift 2
	docker run -d --name "hsperf-sample-$name" -v "$work/classes:/app:ro" "$image" \
		java -Xms64m -Xmx256m "$@" -cp /app com.example.sample.Sample --note=hello >/dev/null
}

sample jdk8-parallel eclipse-temurin:8-jre -XX:+UseParallelGC
sample jdk8-g1 eclipse-temurin:8-jre -XX:+UseG1GC
sample jdk11-g1 eclipse-temurin:11-jre
sample jdk17-g1 eclipse-temurin:17-jre
sample jdk17-serial eclipse-temurin:17-jre -XX:+UseSerialGC
sample jdk17-parallel eclipse-temurin:17-jre -XX:+UseParallelGC
sample jdk21-g1 eclipse-temurin:21-jre
sample jdk21-zgc eclipse-temurin:21-jre -XX:+UseZGC

sleep 8
for name in jdk8-parallel jdk8-g1 jdk11-g1 jdk17-g1 jdk17-serial jdk17-parallel jdk21-g1 jdk21-zgc; do
	docker exec "hsperf-sample-$name" cat /tmp/hsperfdata_root/1 >"$here/$name.hsperf"
done
