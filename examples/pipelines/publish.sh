#!/bin/sh
# Called only by a protected-branch CI publishing job with credential bindings.
set +x
set -eu
umask 077

test "${ALLOWOPS_PUBLISH_BRANCH:-}" = main || {
    echo 'Publication requires the protected main branch.' >&2
    exit 1
}
: "${ALLOWOPS_GATEWAY:?gateway origin required}"
: "${ALLOWOPS_GATEWAY_CA_FILE:?trusted TLS CA file required}"
: "${ALLOWOPS_PUBLISHER_TOKEN:?publisher credential binding required}"

catalog_dir=${ALLOWOPS_CATALOG_DIR:-examples/catalog}
allowops catalog validate "$catalog_dir"
publish_dir=$(mktemp -d)
trap 'rm -rf "$publish_dir"' EXIT
trap 'exit 1' HUP INT TERM

if [ -n "${ALLOWOPS_SIGNING_KEY_FILE:-}" ]; then
    signing_key=$ALLOWOPS_SIGNING_KEY_FILE
else
    : "${ALLOWOPS_SIGNING_KEY_PEM:?signing credential binding required}"
    signing_key=$publish_dir/signing-key.pem
    printf '%s\n' "$ALLOWOPS_SIGNING_KEY_PEM" > "$signing_key"
    unset ALLOWOPS_SIGNING_KEY_PEM
fi

allowops catalog build --dir "$catalog_dir" --out "$publish_dir/catalog.json"
allowops catalog sign --in "$publish_dir/catalog.json" \
    --out "$publish_dir/catalog.dsse.json" --key "$signing_key"
allowops catalog publish -f "$publish_dir/catalog.dsse.json" \
    --gateway "$ALLOWOPS_GATEWAY" --ca-file "$ALLOWOPS_GATEWAY_CA_FILE" \
    --token-env ALLOWOPS_PUBLISHER_TOKEN
