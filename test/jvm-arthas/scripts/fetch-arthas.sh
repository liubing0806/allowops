#!/bin/sh
# Downloads Arthas from Maven Central, checks the SHA-256 and unpacks it into run/.
#   run/arthas-stock   everything in the release zip (arthas.properties as shipped)
#   run/arthas-min     the three jars plus arthas.properties without the MCP keys (plan section 6)
#   run/arthas-minlog  arthas-min plus the shipped logback.xml (without it Arthas logs DEBUG to the target's stdout)
set -eu
VERSION=4.3.5
SHA256=2f75ea954ead5d02c4a743ecd783fd92f546a44ef3aee437ea5066eb30ad07bf
URL="https://repo.maven.apache.org/maven2/com/taobao/arthas/arthas-packaging/$VERSION/arthas-packaging-$VERSION-bin.zip"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
RUN="$HERE/run"
mkdir -p "$RUN/dl"
ZIP="$RUN/dl/arthas-packaging-$VERSION-bin.zip"
if [ ! -f "$ZIP" ]; then curl -fsSL -o "$ZIP" "$URL"; fi
echo "$SHA256  $ZIP" | sha256sum -c -
rm -rf "$RUN/arthas-stock" "$RUN/arthas-min" "$RUN/arthas-minlog"
mkdir -p "$RUN/arthas-stock" "$RUN/arthas-min" "$RUN/arthas-minlog"
unzip -q "$ZIP" -d "$RUN/arthas-stock"
for f in arthas-agent.jar arthas-core.jar arthas-spy.jar; do cp "$RUN/arthas-stock/$f" "$RUN/arthas-min/$f"; done
grep -v -E '^arthas\.mcp(Endpoint|Protocol)=' "$RUN/arthas-stock/arthas.properties" > "$RUN/arthas-min/arthas.properties"
cp "$RUN/arthas-min/"* "$RUN/arthas-minlog/"
cp "$RUN/arthas-stock/logback.xml" "$RUN/arthas-minlog/logback.xml"
chmod -R a+rX "$RUN/arthas-stock" "$RUN/arthas-min" "$RUN/arthas-minlog"
(cd "$RUN/arthas-stock" && sha256sum arthas-agent.jar arthas-core.jar arthas-spy.jar arthas.properties arthas-boot.jar) | tee "$RUN/arthas-stock.sha256"
