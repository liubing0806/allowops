#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
dist=$(realpath "${1:-$repo/dist}")
shopt -s nullglob
debs=("$dist"/*.deb)
rpms=("$dist"/*.rpm)
archives=("$dist"/*.tar.gz)
if [[ ${#debs[@]} != 1 || ${#rpms[@]} != 1 || ${#archives[@]} != 1 ]]; then
    echo 'Expected one deb, one rpm and one tar.gz; run make package first.' >&2
    exit 1
fi

# Refuse a remote Docker endpoint: this test only installs into local containers.
if [[ -n ${DOCKER_CONTEXT:-} ]]; then
    endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{(index .Endpoints "docker").Host}}')
else
    endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')}
fi
[[ $endpoint == unix://* ]]

(cd "$dist" && sha256sum -c checksums.txt)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
tar -xzf "${archives[0]}" -C "$tmp"
version=$("$tmp/allowops" --version)
[[ -n $version && $version != dev ]]
for binary in allowops allowops-gateway allowops-agent allowops-exec; do
    if [[ $binary == allowops-exec ]]; then
        if "$tmp/$binary" --version > "$tmp/exec-version.log" 2>&1; then
            echo 'allowops-exec accepted command-line arguments' >&2
            exit 1
        fi
        grep -qx ARGUMENTS_FORBIDDEN "$tmp/exec-version.log"
    else
        [[ $("$tmp/$binary" --version) == "$version" ]]
    fi
    metadata=$(go version -m "$tmp/$binary")
    for setting in CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1; do
        grep -Eq "build[[:space:]]+$setting$" <<< "$metadata"
    done
done
test -f "$tmp/LICENSE"
test -s "$tmp/THIRD_PARTY_NOTICES"

# Every archive and Linux package has a parseable SPDX SBOM.
python3 - "$repo" "${archives[0]}" "${debs[0]}" "${rpms[0]}" <<'PY'
import json
import sys
from pathlib import Path

repo = Path(sys.argv[1])
section = (repo / "docs/design.md").read_text().split("\n## 5. 主机端\n", 1)[1]
expected = section.split("```\n", 1)[1].split("```", 1)[0]
actual = (repo / "deploy/packaging/allowops.sudoers").read_text()
assert actual == expected, (expected, actual)

for artifact in sys.argv[2:]:
    with open(artifact + ".sbom.json") as stream:
        sbom = json.load(stream)
    assert sbom["spdxVersion"].startswith("SPDX-"), artifact
    assert sbom["packages"], artifact
PY

pids=()
for image in centos:7 rockylinux:9 ubuntu:20.04 debian:12; do
    case "$image" in
        centos:*|rockylinux:*) package=${rpms[0]}; format=rpm ;;
        *) package=${debs[0]}; format=deb ;;
    esac
    (
        echo "Testing $image ($version)"
        if docker run --rm --platform linux/amd64 \
            --mount "type=bind,src=$dist,dst=/packages,readonly" \
            --mount "type=bind,src=$repo/test/packaging,dst=/tests,readonly" \
            --mount "type=bind,src=$repo/deploy/packaging,dst=/packaging,readonly" \
            "$image" /bin/bash /tests/container.sh "$(basename "$package")" "$format" "$version"; then
            echo "PASS $image"
        else
            echo "FAIL $image" >&2
            exit 1
        fi
    ) &
    pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
    wait "$pid" || status=1
done
exit "$status"
