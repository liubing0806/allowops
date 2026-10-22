#!/bin/sh
set -eu
umask 077
repo=$(cd "$(dirname "$0")/../.." && pwd)
cd "$repo/deploy/compose"
# Gateway TLS key algorithm for browser compatibility. The default Ed25519 keeps
# the one-shot quickstart unchanged; the persistent local environment exports
# ALLOWOPS_TLS_KEY_ALG=rsa because Chromium fails the Ed25519 TLS handshake
# (the e2e runner applies the same substitution to a temporary copy).
: "${ALLOWOPS_TLS_KEY_ALG:=ed25519}"
if [ -n "${DOCKER_CONTEXT:-}" ]; then
    endpoint=$(docker context inspect "$DOCKER_CONTEXT" --format '{{(index .Endpoints "docker").Host}}')
else
    endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{(index .Endpoints "docker").Host}}')}
fi
case "$endpoint" in
    unix://*) ;;
    *) echo 'Only a local Docker Unix socket is allowed.' >&2; exit 1 ;;
esac
if [ -e .local ]; then
    echo '.local already exists. Keep it to reuse identity; remove it only after compose down -v.' >&2
    exit 1
fi
mkdir -p .local/bin .local/secrets .local/joins .local/host-context .local/cli
for binary in allowops allowops-agent allowops-exec; do
    (cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOAMD64=v1 \
      go build -trimpath -ldflags '-s -w -X main.version=0.1.0' \
      -o "deploy/compose/.local/bin/$binary" "./cmd/$binary")
done
for name in tls-ca host-ca; do
    if [ "$ALLOWOPS_TLS_KEY_ALG" = rsa ] && [ "$name" = tls-ca ]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ".local/secrets/$name.key"
    else
        openssl genpkey -algorithm ED25519 -out ".local/secrets/$name.key"
    fi
    openssl req -new -x509 -key ".local/secrets/$name.key" -days 3650 \
      -subj "/CN=Allowops local $name" -addext 'basicConstraints=critical,CA:TRUE' \
      -addext 'keyUsage=critical,keyCertSign,cRLSign' -out ".local/secrets/$name.crt"
done
if [ "$ALLOWOPS_TLS_KEY_ALG" = rsa ]; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .local/secrets/tls.key
else
    openssl genpkey -algorithm ED25519 -out .local/secrets/tls.key
fi
openssl req -new -key .local/secrets/tls.key -subj /CN=gateway -out .local/secrets/tls.csr
cat > .local/secrets/tls.ext <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:gateway,DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -in .local/secrets/tls.csr -CA .local/secrets/tls-ca.crt \
  -CAkey .local/secrets/tls-ca.key -CAcreateserial -days 30 \
  -extfile .local/secrets/tls.ext -out .local/secrets/tls.crt
cat .local/secrets/tls-ca.crt >> .local/secrets/tls.crt
.local/bin/allowops catalog keygen --private-key .local/secrets/catalog.key \
  --public-key .local/secrets/catalog.pub.pem
commit=$(git -C "$repo" rev-parse HEAD)
.local/bin/allowops catalog validate "$repo/examples/catalog"
.local/bin/allowops catalog build --dir "$repo/examples/catalog" \
  --git-commit "$commit" --out .local/catalog.json
.local/bin/allowops catalog sign --in .local/catalog.json \
  --key .local/secrets/catalog.key --out .local/catalog.dsse.json
pin=$(openssl x509 -in .local/secrets/tls-ca.crt -outform DER | openssl dgst -sha256 -r | cut -d ' ' -f 1)
printf 'sha256:%s\n' "$pin" > .local/ca-pin
printf 'upstream: https://gateway:8443\nca_pin: sha256:%s\nreported_labels:\n  environment: demo\n' "$pin" > .local/host-context/agent.yaml
cp .local/bin/allowops-agent .local/bin/allowops-exec .local/host-context/
cp .local/secrets/catalog.pub.pem demo-host.sh .local/host-context/
chmod 0644 .local/host-context/agent.yaml .local/host-context/catalog.pub.pem .local/secrets/tls-ca.crt
openssl rand -hex 24 > .local/secrets/postgres-password
python3 ../generate-secrets.py .local/secrets
password=$(cat .local/secrets/postgres-password)
printf 'ALLOWOPS_DATABASE_URL=postgres://allowops:%s@postgres:5432/allowops?sslmode=disable\n' "$password" > .local/gateway.env
unset password
cat > .local/gateway.yaml <<'EOF'
address: ':8443'
tls_certificate: /run/allowops/credentials/tls.crt
tls_key: /run/allowops/credentials/tls.key
ca_certificate: /run/allowops/credentials/ca.crt
ca_key: /run/allowops/credentials/ca.key
catalog_keys: /run/allowops/credentials/catalog-keys
gateway:
  shutdown_grace: 10s
identity:
  origin: https://gateway:8443
output:
  bucket: allowops-demo
  region: us-east-1
  endpoint: http://seaweedfs:8333
audit:
  cursor_key_file: /run/allowops/credentials/audit-cursor-key
  export:
    enabled: true
  export_directory: /var/lib/allowops/audit
  cursor_name: compose-demo
  max_file_bytes: 16777216
EOF
printf 'management:\n  upstream: https://gateway:8443\n  ca_pin: sha256:%s\n' "$pin" >> .local/gateway.yaml
chmod 0644 .local/gateway.yaml
python3 prepare-auth.py
docker build --network host --platform linux/amd64 --build-arg VERSION=0.1.0 \
  --build-arg HTTP_PROXY --build-arg HTTPS_PROXY \
  -f "$repo/deploy/docker/Dockerfile" -t "${ALLOWOPS_GATEWAY_IMAGE:-allowops-gateway:fx2}" "$repo"
docker compose --profile demo build demo-1
echo 'Local certificates, signing key, signed catalog and images prepared.'
echo 'Use the real P4B CLI/API for authentication, join tokens and publication; see README.md.'
