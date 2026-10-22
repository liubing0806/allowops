# Signing and publishing

Catalogs use Ed25519 signatures in a Dead Simple Signing Envelope (DSSE).
Distribute public keys to the gateway and each host independently. The gateway
cannot add or revoke keys in a host's trust directory.

## Prepare a signing identity

On a controlled machine, create a keypair once:

```sh
allowops catalog keygen --private-key catalog-key.pem --public-key catalog.pub.pem
```

The private key is PKCS8 PEM with mode 0600; the public key is PKIX PEM.
Move the private key into the CI credential store. Do not commit it or distribute
it with the catalog. Install the public key as a root-owned file in each host's
`/etc/allowops/catalog-keys/` and in the gateway's configured key directory.

## Validate, build, sign, publish

The following is the publishing sequence. In CI, `ALLOWOPS_SIGNING_KEY_FILE`
is a credential-store file binding, `ALLOWOPS_PUBLISHER_TOKEN` is a secret
environment binding and `ALLOWOPS_GATEWAY_CA_FILE` is the trusted TLS CA file.

```sh
allowops catalog validate examples/catalog
allowops catalog build --dir examples/catalog --out catalog.json
allowops catalog sign --in catalog.json --out catalog.dsse.json \
  --key "$ALLOWOPS_SIGNING_KEY_FILE"
allowops catalog publish -f catalog.dsse.json \
  --gateway https://gateway.example.org \
  --ca-file "$ALLOWOPS_GATEWAY_CA_FILE" --token-env ALLOWOPS_PUBLISHER_TOKEN
```

Build records the Git commit, UTC `YYYYMMDDHHMMSS` version, creation time and
expiry. `--git-commit` supplies a source commit explicitly. `--ttl` defaults to
2160h (90 days) from **build time**. Signing does not extend expiry. The gateway,
agent and privileged helper verify signatures and expiry. Published versions
must increase; rollbacks require a new version containing the reviewed prior
content. Action names must be unique across current catalogs.

Publication uses staged, digest-checked upload and an atomic publish. The gateway
notifies hosts, which pull and verify the signed bytes before reporting a load.
After publishing, inspect catalog distribution and unsupported actions in the
console. A publish response alone is not evidence that every host loaded it.

## CI boundary

Use the [pipeline examples](https://github.com/liubing0806/allowops/tree/main/examples/pipelines)
for GitHub Actions, Jenkins and Flow. Protect the publishing branch with review.
Restrict credential access to that branch through the CI platform's permissions,
not merely a condition in repository code. Forks and pull requests must not receive
signing credentials. Pin the installed CLI release and verify its artifacts.
Use an isolated runner and serialize publishers for each catalog to avoid version
collisions. Do not log environments or archive private key files.

The publisher account needs only `publish_catalog`; it does not need execution
access. Publish uses a token environment variable and never a token value in
command arguments. If a response reports an audit failure after a possible
commit, query catalog history before deciding whether to retry.

## Rotate catalog signing keys

1. Distribute the new public key to the gateway and all hosts.
2. Sign a new package with both keys by repeating `--key`.
3. Verify publication and host load reports for the dual-signed package.
4. After every required host trusts the new key, remove the old public key and
   disable the old CI credential.

If a private key leaks, remove its public key from host trust through the operator's
host-management channel. Gateway-side revocation alone cannot revoke host trust.
