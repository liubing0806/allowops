#!/bin/sh
# Test-only Arthas variant for docs/arthas-logger-classloader-report.md, never for a real JVM:
#   run/arthas-patched   run/arthas-minlog with one class of arthas-core.jar replaced
# The replaced class is com.taobao.arthas.common.ReflectUtils, compiled from the arthas-common 4.3.5 sources with one
# change: defineClass passes a null ProtectionDomain on to ClassLoader.defineClass instead of the ProtectionDomain
# of ReflectUtils itself. ClassLoader.defineClass then uses the default domain of the target class loader.
# Needs run/arthas-minlog (scripts/fetch-arthas.sh) and a JDK with javac and javap.
set -eu
VERSION=4.3.5
SHA256=e53d40869df719b6580e95305350f8e290b66f7e9e5b9d7f39bf94530f92d896
URL="https://repo.maven.apache.org/maven2/com/taobao/arthas/arthas-common/$VERSION/arthas-common-$VERSION-sources.jar"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$HERE/run"
SRC="$RUN/dl/arthas-common-$VERSION-sources.jar"
if [ ! -f "$SRC" ]; then curl -fsSL -o "$SRC" "$URL"; fi
echo "$SHA256  $SRC" | sha256sum -c -
WORK="$RUN/patch-pd"
rm -rf "$WORK" "$RUN/arthas-patched"
mkdir -p "$WORK/src" "$WORK/classes"
(cd "$WORK/src" && unzip -q "$SRC" com/taobao/arthas/common/ReflectUtils.java)
F="$WORK/src/com/taobao/arthas/common/ReflectUtils.java"
perl -0777 -pi -e 's/\n\s*if \(protectionDomain == null\) \{\n\s*protectionDomain = PROTECTION_DOMAIN;\n\s*\}//g' "$F"
if grep -q "protectionDomain = PROTECTION_DOMAIN" "$F"; then echo "patch did not apply" >&2; exit 1; fi
javac -nowarn -encoding UTF-8 --release 8 -cp "$RUN/arthas-minlog/arthas-core.jar" -d "$WORK/classes" "$F" 2>&1 | grep -v "^Note:" || true
# The compiled class must have the same members as the shipped one.
javap -p -cp "$RUN/arthas-minlog/arthas-core.jar" com.taobao.arthas.common.ReflectUtils > "$WORK/members-shipped.txt"
javap -p -cp "$WORK/classes" com.taobao.arthas.common.ReflectUtils > "$WORK/members-patched.txt"
diff "$WORK/members-shipped.txt" "$WORK/members-patched.txt"
cp -r "$RUN/arthas-minlog" "$RUN/arthas-patched"
chmod u+w "$RUN/arthas-patched/arthas-core.jar"
(cd "$WORK/classes" && jar uf "$RUN/arthas-patched/arthas-core.jar" com/taobao/arthas/common/ReflectUtils*.class)
chmod -R a+rX "$RUN/arthas-patched"
echo "defineClass reads of PROTECTION_DOMAIN: shipped $(javap -c -p -cp "$RUN/arthas-minlog/arthas-core.jar" com.taobao.arthas.common.ReflectUtils | grep -c 'getstatic.*PROTECTION_DOMAIN'), patched $(javap -c -p -cp "$RUN/arthas-patched/arthas-core.jar" com.taobao.arthas.common.ReflectUtils | grep -c 'getstatic.*PROTECTION_DOMAIN')"
(cd "$RUN/arthas-patched" && sha256sum arthas-agent.jar arthas-core.jar arthas-spy.jar)
