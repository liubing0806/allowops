#!/bin/sh
# Stop the persistent local test environment (P13), keeping data volumes.
set -eu
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-allowops-local}
export ALLOWOPS_LOCAL_PORT=${ALLOWOPS_LOCAL_PORT:-8443}
docker compose -f compose.yaml -f local.yaml --profile demo --profile auth-tools down --remove-orphans
cat <<EOF
Stopped $COMPOSE_PROJECT_NAME containers; data volumes kept.
Restart with make local-up (or ./deploy/compose/local-up.sh).
Full reset (deletes volumes and generated files; same COMPOSE_PROJECT_NAME as local-up):
  COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME docker compose -f compose.yaml -f local.yaml --profile demo --profile auth-tools down -v --remove-orphans && rm -rf .local
EOF
