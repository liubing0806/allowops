#!/usr/bin/env bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
if [[ -n ${DOCKER_CONTEXT:-} ]]; then
    endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{(index .Endpoints "docker").Host}}')
else
    endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')}
fi
[[ $endpoint == unix://* ]] || { echo 'Only a local Docker daemon is allowed.' >&2; exit 1; }
if ! docker info > /dev/null; then
    echo 'SKIP root tests: local Docker daemon is unavailable; setuid, environment and sudo cancellation were not verified.' >&2
    exit 77
fi

scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
cd "$repo"
CGO_ENABLED=0 go build -o "$scratch/allowops-exec" ./cmd/allowops-exec
CGO_ENABLED=0 go build -o "$scratch/fixture" ./test/agent/fixture
CGO_ENABLED=0 go test -tags agentcontainer -c -o "$scratch/root-tests" ./test/agent
CGO_ENABLED=0 go test -c -o "$scratch/agent-tests" ./internal/agent
cp test/agent/Dockerfile "$scratch/Dockerfile"
cp test/agent/run.sh "$scratch/run.sh"
cp deploy/packaging/allowops.sudoers "$scratch/allowops.sudoers"
docker build -t allowops-p3-agent-test "$scratch"
docker run --rm --network none allowops-p3-agent-test
