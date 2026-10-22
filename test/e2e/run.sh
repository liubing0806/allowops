#!/bin/sh
set -eu
umask 077
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo"
if [ -n "${DOCKER_CONTEXT:-}" ]; then
    endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{(index .Endpoints "docker").Host}}')
else
    endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')}
fi
case "$endpoint" in
    unix://*) ;;
    *) echo 'E2E requires a local Docker Unix socket.' >&2; exit 1 ;;
esac
docker info >/dev/null
stage=$(mktemp -d /tmp/allowops-p10b-runtime.XXXXXXXX)
export ALLOWOPS_E2E_ARTIFACTS=$(mktemp -d /tmp/allowops-p10b-evidence.XXXXXXXX)
export COMPOSE_PROJECT_NAME=allowops-p10b-$(basename "$stage" | tr '[:upper:]' '[:lower:]' | cut -d . -f 2)
export ALLOWOPS_GATEWAY_IMAGE=$COMPOSE_PROJECT_NAME-gateway:local
export ALLOWOPS_HOST_IMAGE=$COMPOSE_PROJECT_NAME-host:local
export ALLOWOPS_DEMO_UID=$(id -u) ALLOWOPS_DEMO_GID=$(id -g)
compose_dir=$stage/deploy/compose
compose() {
    docker compose --project-directory "$compose_dir" -f "$compose_dir/compose.yaml" -f "$compose_dir/e2e.yaml" "$@"
}
cleanup() {
    result=$?
    trap - EXIT HUP INT TERM
    if [ -f "$compose_dir/e2e.yaml" ]; then
        compose --profile demo --profile auth-tools --profile e2e down --volumes --remove-orphans >>"$ALLOWOPS_E2E_ARTIFACTS/cleanup.log" 2>&1 || result=1
    fi
    for image in "$ALLOWOPS_GATEWAY_IMAGE" "$ALLOWOPS_HOST_IMAGE"; do
        if docker image inspect "$image" >/dev/null 2>&1; then
            docker image rm "$image" >>"$ALLOWOPS_E2E_ARTIFACTS/cleanup.log" 2>&1 || result=1
        fi
    done
    rm -rf "$stage"
    echo "E2E evidence: $ALLOWOPS_E2E_ARTIFACTS"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
echo "E2E project: $COMPOSE_PROJECT_NAME"
echo "E2E evidence: $ALLOWOPS_E2E_ARTIFACTS"
pnpm --dir web install --frozen-lockfile
pnpm --dir test/e2e install --frozen-lockfile
python3 test/e2e/prepare.py copy "$repo" "$stage"
pnpm --dir "$stage/web" build
(cd "$compose_dir" && GOFLAGS="${GOFLAGS:-} -buildvcs=false" ./prepare.sh) >"$ALLOWOPS_E2E_ARTIFACTS/prepare.log" 2>&1 || {
    echo "Environment build failed; see $ALLOWOPS_E2E_ARTIFACTS/prepare.log" >&2
    exit 1
}
python3 test/e2e/prepare.py fixtures "$repo" "$stage" "$ALLOWOPS_E2E_ARTIFACTS"
compose up -d
compose wait ready
compose run --rm --no-deps admin-tool
compose --profile demo up -d --no-deps --wait demo-1
export ALLOWOPS_E2E_URL=$(cat "$compose_dir/.local/browser-url")
# Verify the running image by its content digest, independent of version/SHA fields.
container=$(compose ps -q gateway)
running_image=$(docker inspect --format '{{.Image}}' "$container")
built_image=$(docker image inspect --format '{{.Id}}' "$ALLOWOPS_GATEWAY_IMAGE")
test "$running_image" = "$built_image"
printf 'commit=%s\ngateway_image=%s\nurl=%s\nproject=%s\n' \
    "$(git rev-parse HEAD)" "$running_image" "$ALLOWOPS_E2E_URL" "$COMPOSE_PROJECT_NAME" \
    >"$ALLOWOPS_E2E_ARTIFACTS/provenance.txt"
result=0
compose --profile e2e run --rm --no-deps browser || result=$?
(cd "$compose_dir" && python3 verify-secrets.py) || result=1
exit "$result"
