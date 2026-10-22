# Local Docker Compose quick start

Run this from a Linux amd64 checkout with Docker Compose, Go 1.27.3, OpenSSL,
Git and Python 3 with PyYAML installed. Docker must use a local Unix socket.
Builds and image pulls may obtain public build resources. Runtime services use
an internal Docker network and publish no host ports. Nothing is deployed to
a cluster or pushed to a registry. The Linux build uses host networking and
forwards existing HTTP proxy settings for public Go build dependencies.

```sh
cd deploy/compose
export COMPOSE_PROJECT_NAME=allowops-fx2-local
./quickstart-local.sh
```

The default Compose file includes the gateway, PostgreSQL, SeaweedFS and a
separate demonstration LDAPS directory. The script generates credentials,
builds images, waits for storage and gateway readiness, authenticates the
administrator, publishes the example catalog and registers two real P3 agents.
It exits successfully after both hosts load the signed catalog, a read-only
`disk_usage` job succeeds on both, both tasks report `output_stored=true`,
and the CLI reads demo-1 complete stdout/stderr from object storage and checks
their SHA-256 against the job summary. Generated secrets are scanned against
Compose logs in memory before successful exit. No additional Compose files are needed.

`prepare.sh` builds the gateway image and agent binaries. It generates separate
local TLS and host identity certificate authorities (CAs), a full-chain gateway
certificate and Ed25519 catalog signing keys. It validates `examples/catalog`,
builds the catalog and signs its DSSE (Dead Simple Signing Envelope) package.
Database passwords, S3 credentials, SeaweedFS SSE and audit cursor keys,
and LDAPS passwords are random local values.
All credentials, certificates, binaries and signed packages are in ignored
`.local/`. Do not commit or share that directory. The script refuses to
overwrite it. Keep it when restarting existing volumes so host identities and
service credentials remain valid.

The `migrate` service completes before gateway startup. `prepare-volumes`
copies the gateway credentials into a named volume as ordinary 0600 files
owned by UID 65532 and makes the audit volume writable by that UID. It copies
the S3 configuration into a separate volume readable only by SeaweedFS UID
1000. The gateway receives only its AWS credentials file and shared audit
cursor key as private 0600 files; the SSE key is supplied only to SeaweedFS. The gateway has a
read-only root filesystem, no Linux capabilities, and a 20-second stop grace
period for its 10-second ShutdownGrace plus the command's additional 5-second
timeout. The gateway healthcheck calls `allowops-gateway health` against
`/health/ready`, verifying TLS with the generated CA. The separate `ready`
service also verifies PostgreSQL and object storage are healthy before the
demo starts. Readiness degrades with HTTP 200 when storage is unavailable;
PostgreSQL or migration mismatch returns HTTP 503. Helm uses HTTPS probes on
the same port; `/health/live` remains independent of storage and PostgreSQL.

## S3 storage and bucket initialization (A25 / A29)

The public image is `chrislusf/seaweedfs:4.46`, pinned to
`sha256:08d516132314207d10c8e37cbffc1f32b147d870169688734cc61c6231625b62`.
[SeaweedFS is Apache-2.0 licensed](https://github.com/seaweedfs/seaweedfs/blob/4.46/LICENSE).
It is an independent service and is not included in the gateway or its Go
dependencies. The image entrypoint switches the server to UID 1000. Master,
volume server, filer and S3 gateway run together for this local demonstration.
Data and filer metadata persist in the `seaweedfs` volume. Master telemetry is
disabled. The S3 endpoint is `http://seaweedfs:8333` on the internal network.
It requires the generated credentials and has no anonymous identity.

`storage-init.py` runs in the non-root `storage-init` container. It reads the
private generated S3 configuration, waits for the signed ListBuckets API,
and explicitly creates `allowops-demo` through the S3 CreateBucket API.
Automatic bucket creation on upload is disabled. The script signs requests
with AWS Signature Version 4 using Python's standard library. It uploads a
test object, reads it back, compares the exact bytes and deletes it. The
bucket remains available for the demonstration. Repeat this check with:

```sh
export ALLOWOPS_DEMO_UID=$(id -u) ALLOWOPS_DEMO_GID=$(id -g)
docker compose run --rm --no-deps storage-init
```

Gateway output config uses bucket `allowops-demo`, region `us-east-1` and
endpoint `http://seaweedfs:8333`. `AWS_SHARED_CREDENTIALS_FILE` selects the
generated AWS credential file. `WEED_S3_SSE_KEY` enables AES256 server-side
encryption in SeaweedFS; the gateway never receives that key. Keep all these
files and the audit cursor key when reusing volumes. Bucket lifecycle rules
are operator-managed; this quickstart does not configure retention or test
expiration. P6 integration tests cover SDK checksums and encryption.
PostgreSQL uses a superuser only for this isolated demonstration.
Production deployments use separate migration/runtime roles as documented
in `docs/audit.md` and the Helm chart README. The Helm chart requires externally
provided PostgreSQL and object storage.

## Demonstration identity source (G47 / A28)

The default `ldap` service and `prepare-auth.py` form an independent identity
source that can be removed or replaced. They use `osixia/openldap:1.5.0` pinned
to `sha256:18742e9c449c9c1afe129d3f2f3ee15fb34cc43e5f940a20f3399728f41d7c28`.
The container project is MIT licensed. OpenLDAP uses the OpenLDAP Public
License 2.8; the base distribution has its own package licenses. This service
is not included in the gateway or its Go dependencies.

`demo-admin` and all directory credentials are only for this local
demonstration. Passwords and certificates are generated locally by
`prepare-auth.py`. The directory contains no real credentials and publishes
no host ports. Its CA private key and the user's login password are not mounted
in the directory container. LDAP login uses LDAPS with certificate and hostname
verification. The generated provider configuration is in
`.local/gateway-auth.yaml`, its CA in `.local/auth/ca.crt`, and its bind secret
in `.local/auth/gateway-ldap.env`.

To replace it with another **local** identity source, replace the `ldap`
service, the initialization script, the provider YAML, CA and bind secret.
Update the gateway's dependency and `bootstrap.py` provider/user arguments to
match that source. Authentication and publishing continue to use the real
CLI/API; there is no built-in password account or direct database seeding.
The helper does not reuse or discover real credentials.

## Authentication, registration and publication (G41 / G47)

`quickstart-local.sh` uses `allowops login --password-stdin` to authenticate
`demo-admin` against the directory. `bootstrap.py` uses the authenticated
ServiceAccountService API to create a publisher account and a one-day token.
It runs in an ephemeral non-root `admin-tool` container at
`https://gateway:8443`, without host port routing or a Docker socket mount.
Its bind mounts contain only required CLI inputs and output directories;
signing and CA private keys are excluded.

The helper calls `allowops catalog publish` with the publisher token in a
child process environment. It then calls `allowops jointoken create` twice to
generate single-use registration tokens. It does not write to PostgreSQL
directly. CLI session files and join tokens use mode 0600. Publisher tokens
remain in memory and secret values are not printed. The gateway explicitly
sets `management.ca_pin` to the TLS root CA DER fingerprint and returns the
container-reachable upstream `https://gateway:8443` (G35).

To inspect agent state and repeat the authenticated verification:

```sh
docker compose exec --user 65532:65532 demo-1 allowops-agent status
docker compose exec --user 65532:65532 demo-2 allowops-agent status
python3 verify.py
docker compose run --rm --no-deps admin-tool verify-job
python3 verify-secrets.py
```

Each host reads its generated token with `--token-file`, joins once and drops to the `allowops` account for
`allowops-agent run`. Its named volume preserves the identity. Catalog public
keys are root-owned image files. Verification checks two distinct host IDs,
server-side online state, `running=true`, `connected=true`, the published
catalog ID/version in `loaded_catalogs`, and both hosts' catalog load reports.
A loaded catalog does not prove all actions are executable on the demo image.
External tools such as Docker, kubectl and database clients are not installed.
The helper binary is present, but sudo is not installed. Privileged jobs are
outside this demonstration.

## Persistent local environment

For interactive use (browser console, CLI, MCP client), keep one command up
and one down from the repository root. It uses its own Compose project
`allowops-local`, so it does not disturb the one-shot quickstart
(`allowops-fx2-*`) or `make e2e` (`allowops-p10b-*`):

```sh
make local-up
make local-down
```

`local-up` generates credentials once, builds the images, starts the gateway,
PostgreSQL, SeaweedFS and LDAPS, publishes the example catalog and registers
three demo hosts (`demo-1`, `demo-2`, `demo-3`). A second run reuses `.local/`
and the data volumes without regenerating credentials. `local-down` stops the
containers and keeps the volumes. A complete reset deletes volumes and
generated files:

```sh
cd deploy/compose
COMPOSE_PROJECT_NAME=allowops-local docker compose -f compose.yaml -f local.yaml --profile demo --profile auth-tools down -v --remove-orphans && rm -rf .local
```

Use the same `COMPOSE_PROJECT_NAME` (and `ALLOWOPS_LOCAL_PORT`) as the
`local-up` run being reset; the default project is `allowops-local`.

Only one environment can use `deploy/compose/.local` at a time: park or
remove it before switching between `make local-up` and `quickstart-local.sh`.

Differences from the one-shot quickstart above:

- The gateway TLS port is published on the host loopback only, default
  `127.0.0.1:8443` (`ALLOWOPS_LOCAL_PORT` changes the host port). No service
  binds `0.0.0.0`. Docker does not map host ports for containers attached only
  to an internal network, so the overlay file `local.yaml` additionally joins
  the gateway to a project-scoped `host-access` bridge. Inter-service traffic
  keeps using the internal network; only the gateway has the extra interface.
- Gateway TLS keys use RSA-2048 (`ALLOWOPS_TLS_KEY_ALG=rsa`) because Chromium
  fails the default Ed25519 TLS handshake. The certificate still covers
  `localhost` and `127.0.0.1`.
- The gateway identity origin becomes `https://localhost:<port>` so the
  browser console can log in; the container-reachable management upstream
  stays `https://gateway:8443`.
- On success the script prints the console URL, the CA path, the administrator
  login (the password stays in its 0600 file and is never printed), a CLI
  login/run example and an MCP client example. It also stores one 365-day
  `local-mcp` service account token in `.local/mcp-token` (0600).

## Cleanup

```sh
docker compose --profile demo down -v --remove-orphans
# After deleting all demo volumes, remove only the generated files:
rm -rf .local
```

`down -v` deletes this project's database, objects, directory, audit exports,
credentials and host identities. Test images may be retained. New setup
creates new CAs; keeping old volumes while replacing `.local/` is unsupported.

The quickstart defaults to `allowops-fx2-local` and requires an
`allowops-fx2-*` project name. Image tags are derived from that name to avoid
concurrent workers replacing each other's test images. Export the same project
name for all follow-up commands.
