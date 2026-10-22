#!/bin/sh
set -eu
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-allowops-fx2-local}
case "$COMPOSE_PROJECT_NAME" in
    allowops-fx2-*) ;;
    *) echo 'COMPOSE_PROJECT_NAME must start with allowops-fx2-.' >&2; exit 1 ;;
esac
export ALLOWOPS_GATEWAY_IMAGE=${ALLOWOPS_GATEWAY_IMAGE:-$COMPOSE_PROJECT_NAME-gateway:local}
export ALLOWOPS_HOST_IMAGE=${ALLOWOPS_HOST_IMAGE:-$COMPOSE_PROJECT_NAME-host:local}
export ALLOWOPS_DEMO_UID=$(id -u)
export ALLOWOPS_DEMO_GID=$(id -g)
python3 verify-config.py
./prepare.sh
docker compose up -d
docker compose wait ready
docker compose run --rm --no-deps admin-tool
docker compose --profile demo up -d --wait demo-1 demo-2
python3 verify.py
docker compose run --rm --no-deps admin-tool verify-job
python3 verify-secrets.py
