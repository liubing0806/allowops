#!/bin/sh
# Persistent local test environment (P13): gateway, PostgreSQL, SeaweedFS,
# LDAPS and three demo hosts. The gateway TLS port is published on the host
# loopback interface only. Reuses .local/ and data volumes when present.
set -eu
umask 077
cd "$(dirname "$0")"
export COMPOSE_PROJECT_NAME=${COMPOSE_PROJECT_NAME:-allowops-local}
case "$COMPOSE_PROJECT_NAME" in
    allowops-fx2-*|allowops-p10b-*)
        echo 'COMPOSE_PROJECT_NAME must not collide with quickstart (allowops-fx2-*) or e2e (allowops-p10b-*).' >&2
        exit 1
        ;;
esac
export ALLOWOPS_GATEWAY_IMAGE=${ALLOWOPS_GATEWAY_IMAGE:-$COMPOSE_PROJECT_NAME-gateway:local}
export ALLOWOPS_HOST_IMAGE=${ALLOWOPS_HOST_IMAGE:-$COMPOSE_PROJECT_NAME-host:local}
export ALLOWOPS_DEMO_UID=$(id -u)
export ALLOWOPS_DEMO_GID=$(id -g)
export ALLOWOPS_LOCAL_PORT=${ALLOWOPS_LOCAL_PORT:-8443}
export ALLOWOPS_LOCAL_BIND=${ALLOWOPS_LOCAL_BIND:-127.0.0.1}
case "$ALLOWOPS_LOCAL_BIND" in
    0.0.0.0|::|'[::]'|'')
        echo 'ALLOWOPS_LOCAL_BIND must be one address, not a wildcard.' >&2
        exit 1
        ;;
esac
if [ "$ALLOWOPS_LOCAL_BIND" = 127.0.0.1 ]; then
    console_host=localhost
else
    console_host=$ALLOWOPS_LOCAL_BIND
fi
export ALLOWOPS_DEMO_HOSTS=${ALLOWOPS_DEMO_HOSTS:-demo-1,demo-2,demo-3}
export ALLOWOPS_TLS_KEY_ALG=${ALLOWOPS_TLS_KEY_ALG:-rsa}
if [ -n "${DOCKER_CONTEXT:-}" ]; then
    endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{(index .Endpoints "docker").Host}}')
else
    endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')}
fi
case "$endpoint" in
    unix://*) ;;
    *) echo 'Only a local Docker Unix socket is allowed.' >&2; exit 1 ;;
esac
python3 verify-config.py
python3 verify-local.py
if [ ! -e .local ]; then
    ./prepare.sh
fi
# Bootstrap (catalog publication and join tokens) is gated on its own marker,
# not on whether .local was just created: a run interrupted after prepare.sh and
# before bootstrap finished must bootstrap on the next run. Environments that
# completed bootstrap before the marker existed hold join token files, which
# only bootstrap writes; record them instead of running bootstrap again, since
# it creates the demo-publisher account and would conflict.
if [ ! -e .local/bootstrap.done ] && [ -n "$(find .local/joins -name '*.token' -size +0c 2>/dev/null)" ]; then
    : > .local/bootstrap.done
fi
origin_changed=$(python3 local-origin.py "$console_host" "$ALLOWOPS_LOCAL_PORT")
if [ "$console_host" != localhost ] && ! grep -qx "subjectAltName=.*,IP:$console_host" .local/secrets/tls.ext; then
    # Reissue the gateway certificate with the LAN address; prepare-volumes
    # copies it into the credentials volume on the next start.
    sed -i "s/^subjectAltName=.*/subjectAltName=DNS:gateway,DNS:localhost,IP:127.0.0.1,IP:$console_host/" .local/secrets/tls.ext
    openssl x509 -req -in .local/secrets/tls.csr -CA .local/secrets/tls-ca.crt \
      -CAkey .local/secrets/tls-ca.key -CAcreateserial -days 30 \
      -extfile .local/secrets/tls.ext -out .local/secrets/tls.crt
    cat .local/secrets/tls-ca.crt >> .local/secrets/tls.crt
    origin_changed=changed
fi
# Pre-create the token file before any admin-tool container starts: Docker
# bind-mounts a missing source as a directory, which would break the helper.
if [ -e .local/mcp-token ] && [ ! -f .local/mcp-token ]; then
    rm -rf .local/mcp-token
fi
if [ ! -e .local/mcp-token ]; then
    : > .local/mcp-token
    chmod 0600 .local/mcp-token
fi
docker compose -f compose.yaml -f local.yaml up -d
if [ "$origin_changed" = changed ]; then
    docker compose -f compose.yaml -f local.yaml up -d --force-recreate prepare-volumes gateway
fi
docker compose -f compose.yaml -f local.yaml wait ready
if [ ! -e .local/bootstrap.done ]; then
    docker compose -f compose.yaml -f local.yaml run --rm --no-deps \
        -e ALLOWOPS_DEMO_HOSTS="$ALLOWOPS_DEMO_HOSTS" admin-tool
    : > .local/bootstrap.done
fi
docker compose -f compose.yaml -f local.yaml --profile demo up -d --wait demo-1 demo-2 demo-3
if [ ! -s .local/mcp-token ]; then
    docker compose -f compose.yaml -f local.yaml run --rm --no-deps admin-tool ensure-mcp
fi
export COMPOSE_FILE=compose.yaml:local.yaml
python3 verify.py
docker compose -f compose.yaml -f local.yaml run --rm --no-deps \
    -e ALLOWOPS_DEMO_HOSTS="$ALLOWOPS_DEMO_HOSTS" admin-tool verify-job
python3 verify-secrets.py
cat <<EOF
Persistent local environment ready (project $COMPOSE_PROJECT_NAME).
Console: https://$console_host:$ALLOWOPS_LOCAL_PORT
Gateway CA certificate: deploy/compose/.local/secrets/tls-ca.crt
Administrator login: provider demo, username demo-admin; password in deploy/compose/.local/auth/login-password (0600, not printed).
CLI login example:
  ./deploy/compose/.local/bin/allowops login --gateway https://$console_host:$ALLOWOPS_LOCAL_PORT --ca-file deploy/compose/.local/secrets/tls-ca.crt --provider demo --username demo-admin --password-stdin < deploy/compose/.local/auth/login-password
CLI run example (needs the login session above):
  ./deploy/compose/.local/bin/allowops run disk_usage --selector environment=demo --expected-count 3 --reason 'local verification'
MCP endpoint: https://$console_host:$ALLOWOPS_LOCAL_PORT/mcp
MCP token: create a service account token on the console Service Accounts page; this environment already stores one in deploy/compose/.local/mcp-token (0600, not printed). Example client configuration:
  {"mcpServers": {"allowops": {"type": "http", "url": "https://$console_host:$ALLOWOPS_LOCAL_PORT/mcp", "headers": {"Authorization": "Bearer \${ALLOWOPS_MCP_TOKEN}"}}}}
Full reset (deletes volumes and generated files; same COMPOSE_PROJECT_NAME as local-up):
  COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME docker compose -f compose.yaml -f local.yaml --profile demo --profile auth-tools down -v --remove-orphans && rm -rf .local
EOF
