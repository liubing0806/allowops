#!/bin/sh
set -eu
image=${1:?usage: verify.sh IMAGE EXPECTED_VERSION}
expected=${2:?usage: verify.sh IMAGE EXPECTED_VERSION}
actual=$(docker run --rm --network none "$image" --version)
if [ "$actual" != "$expected" ]; then
    printf 'Gateway version mismatch: expected <%s>, actual <%s>\n' "$expected" "$actual" >&2
    exit 1
fi
architecture=$(docker image inspect "$image" --format '{{.Architecture}}')
if [ "$architecture" != amd64 ]; then
    printf 'Gateway architecture mismatch: expected <amd64>, actual <%s>\n' "$architecture" >&2
    exit 1
fi
user=$(docker image inspect "$image" --format '{{.Config.User}}')
if [ "$user" != '65532:65532' ]; then
    printf 'Gateway image user mismatch: expected <65532:65532>, actual <%s>\n' "$user" >&2
    exit 1
fi
echo 'Gateway version, amd64 architecture and non-root image user passed.'
