# Installation

Gateway and host artifacts target Linux amd64. Use the CLI, gateway, agent and
helper from the same verified release. Verify release checksums and signatures
against a separately trusted release key before installation. Review the
software bill of materials and third-party notices supplied with the release.

## Local Compose demonstration

Prerequisites are Docker Compose using a local Unix socket, Go 1.27.3, OpenSSL,
Git and Python 3 with PyYAML on Linux amd64. From a source checkout:

```sh
cd deploy/compose
export COMPOSE_PROJECT_NAME=allowops-fx2-local
./quickstart-local.sh
```

The script prepares separate gateway TLS and host identity CAs, catalog signing
keys and random local credentials. It builds the services, initializes storage,
authenticates the demonstration administrator through LDAPS, publishes the
example catalog and registers two host agents. Verification checks online
state and signed catalog load reports, runs a read-only `disk_usage` job on
both hosts, waits for `output_stored=true`, reads demo-1's complete stdout/stderr
and compares their SHA-256 hashes with the job summary. Generated secrets are
scanned against Compose logs in memory before successful exit.

The Compose network is internal and publishes no host ports. Its `.local/`
directory is ignored by Git and contains private generated material, including
S3 credentials, the SeaweedFS encryption key and the shared audit cursor key.
Preserve it when restarting the existing volumes. Do not copy demonstration
credentials into another deployment. The demonstration is not an execution test for every
action; external tools and privileged-action dependencies are not all installed.

```sh
docker compose exec --user 65532:65532 demo-1 allowops-agent status
docker compose exec --user 65532:65532 demo-2 allowops-agent status
python3 verify.py
docker compose run --rm --no-deps admin-tool verify-job
python3 verify-secrets.py
```

Keep the same Compose project name for follow-up commands. This quickstart
requires an `allowops-fx2-` prefix and defaults to `allowops-fx2-local`.

The [repository Compose guide](https://github.com/liubing0806/allowops/blob/main/deploy/compose/README.md)
describes generated files, service boundaries and destructive cleanup.

### Persistent local environment

For a resident setup reachable from a browser, CLI and MCP client on this
machine, use the separate `allowops-local` Compose project instead:

```sh
make local-up
make local-down
```

By default, the gateway TLS port is published only on the host's IPv4 loopback
interface on port `8443` (`ALLOWOPS_LOCAL_PORT` changes the host port). It uses a
browser-compatible certificate, and three demo hosts register on first start.
`local-up` prints the console URL, the CA path, the
administrator login, CLI examples and an MCP client example. Reruns reuse the
generated credentials and data volumes; `local-down` stops the containers and
keeps the volumes. The repository Compose guide above describes the overlay,
the reset procedure and service boundaries.

## Gateway on Kubernetes

Use the chart in `deploy/helm/allowops`. Provide PostgreSQL and S3-compatible
object storage independently. The chart uses a Layer 4 TCP Service on port 443.
TLS and Application-Layer Protocol Negotiation (ALPN) must reach the gateway
unchanged. An HTTP Ingress that terminates TLS cannot serve the host protocol.

Provision gateway TLS certificates including the full CA chain, the separate
host CA, catalog public keys, runtime database credentials and a separate
migration database credential through existing Kubernetes Secrets. Also provision
`allowops-output` with an `aws-credentials` file and `allowops-audit-cursor` with
`audit-cursor-key` containing exactly 32 raw random bytes, shared by all gateway
instances. Keep secrets out of Helm values and release history.
Configure the identity provider (give an OIDC `client_secret_env` or LDAP
`bind_password_env` variable a Secret through `gateway.providerSecretEnv`), public
HTTPS origin, output bucket/region/endpoint and S3 credential delivery according
to the chart's values and Secret contract. The TLS certificate name must match
the public upstream address. Apply the required runtime database grants before
starting a fresh gateway installation.

Set `output.bucket`, `output.region` and `output.endpoint` in Helm values.
An empty endpoint uses the AWS regional S3 endpoint. `output.existingSecret` /
`output.credentialsKey` select the credential file; `audit.cursorKeySecret` /
`audit.cursorKeyKey` select the audit cursor key. The chart copies those files
to ordinary mode-0600 files and sets `AWS_SHARED_CREDENTIALS_FILE` for the gateway.

```sh
helm lint deploy/helm/allowops
helm template allowops deploy/helm/allowops -f gateway-values.yaml
helm upgrade --install allowops deploy/helm/allowops \
  --namespace allowops --create-namespace -f gateway-values.yaml
```

`gateway-values.yaml` is an operator-supplied file containing non-secret settings
and references to pre-provisioned Secrets, not a file shipped in this repository.
The migration hook runs before installation/upgrade. Use distinct maintenance
and runtime database roles. The runtime role must not own the audit tables or
inherit maintenance privileges. Preserve the dedicated export instance's volume.
See the [chart guide](https://github.com/liubing0806/allowops/blob/main/deploy/helm/allowops/README.md)
for the exact values and database prerequisites.

## Gateway process

For a deployment that manages the binary directly, deliver database credentials
through `ALLOWOPS_DATABASE_URL`. The gateway YAML refers to TLS files, host CA
files and a catalog public-key directory. It also supplies identity and output
storage settings. S3 credentials use the AWS SDK's credential chain rather than
command-line arguments or credential values in YAML.

```sh
allowops-gateway migrate
allowops-gateway serve --config /etc/allowops/gateway.yaml
```

Run migration with the maintenance role, then start the service with the runtime
role. CA private keys must be ordinary files with mode 0600. Gateway instances
share the same host CA. Enable output encryption on the object store; SeaweedFS
requires an operator-provided encryption key for AES256 uploads.

Provide `output.bucket` and `output.region`, and optionally `output.endpoint`,
in gateway YAML. Deliver AWS credentials through `AWS_SHARED_CREDENTIALS_FILE`
or another supported AWS SDK credential source. Set `audit.cursor_key_file` to
a private file containing exactly 32 raw random bytes; use the same key on all
instances and preserve it across restarts. See [audit](audit.md).

## Health checks

The gateway exposes HTTPS GET `/health/live` and `/health/ready` on its normal
TLS listener. `/health/live` returns HTTP 200 while the server handles requests
and is independent of PostgreSQL and output storage. `/health/ready` returns
HTTP 503 for PostgreSQL connection or schema failures. Output storage failure
returns HTTP 200 with `degraded: true` and `output: unavailable`; execution can
continue while full-output persistence is unavailable.

```sh
allowops-gateway health --url https://gateway.example.org/health/ready \
  --ca-file /absolute/path/gateway-tls-ca.crt
```

This command verifies TLS and succeeds for HTTP 200, including degraded storage.
It does not inspect the response body's degradation flag. Monitor that flag
separately. Helm startup/liveness probes use `/health/live`; readiness uses
`/health/ready` on the pod's TLS port 8443. Kubernetes HTTPS probes do not verify
the serving certificate. Compose's CLI health check verifies TLS with the
generated CA. Its separate ready service checks storage before the demo starts.

## Host packages

Install verified local files. Debian/Ubuntu packages are `.deb`; RHEL-family
packages are `.rpm`. Install systemd, account-management utilities and sudo
before installing from local media.

```sh
sudo dpkg -i /absolute/path/allowops-agent_0.1.0_amd64.deb
# Or, on an RPM-based system:
sudo rpm -Uvh /absolute/path/allowops-agent-0.1.0-1.x86_64.rpm
sudo install -o root -g root -m 0644 /absolute/path/catalog.pub.pem \
  /etc/allowops/catalog-keys/catalog.pub.pem
sudo install -o root -g root -m 0644 /absolute/path/agent.yaml \
  /etc/allowops/agent.yaml
```

Replace the example version with the verified release's filename. Packages
enable the service without starting it. Supply the upstream and pinned gateway
TLS CA in `/etc/allowops/agent.yaml`. Obtain a bounded registration token from
your gateway administrator in a privately delivered mode-0600 file. Compute the
pin from the supplied gateway TLS CA certificate, not the host identity CA:

```sh
ca_pin=$(openssl x509 -in /absolute/path/gateway-tls-ca.crt -outform DER \
  | openssl dgst -sha256 -r | cut -d ' ' -f 1)
sudo allowops-agent join --upstream https://gateway.example.org \
  --token-file /absolute/path/join-token.txt --ca-pin "sha256:$ca_pin"
```

The configured upstream and pin must match registration. Alternatively, pass
the privately delivered token through stdin with `--token-stdin`. Exactly one
of `--token-file`, `--token-stdin` or legacy `--token` is required. All sources
accept at most 4 KiB, trim surrounding whitespace and reject empty input.
Prefer file/stdin to keep the token value out of process arguments.
After registration:

```sh
sudo systemctl start allowops-agent
sudo -u allowops allowops-agent status
```

The agent runs as the `allowops` account without supplementary groups. Give
actions that need additional privilege an explicit `run_as`. Inspect
`/etc/sudoers.d/allowops` with `visudo` after installation.

## Host tar archive

The `.tar.gz` release contains the binaries, license and notices; it is not a
package-manager installer. Extract the verified archive into a staging directory:

```sh
mkdir -p staging
tar -xzf /absolute/path/allowops_0.1.0_linux_amd64.tar.gz -C staging
```

From the matching source tag, provision the dedicated account if it does not
already exist, then install the files. These commands assume the binaries are
at the staging root; inspect the verified archive layout first.

```sh
sudo useradd --system --user-group --home-dir /var/lib/allowops \
  --no-create-home --shell "$(command -v nologin)" allowops
sudo install -d -o allowops -g allowops -m 0700 /var/lib/allowops
sudo install -d -o root -g root -m 0700 /var/lib/allowops-exec
sudo install -d -o root -g root -m 0755 /usr/libexec/allowops /etc/allowops/catalog-keys
sudo install -o root -g root -m 0755 staging/allowops-agent /usr/bin/allowops-agent
sudo install -o root -g root -m 0755 staging/allowops-exec /usr/libexec/allowops/allowops-exec
sudo install -o root -g root -m 0644 deploy/packaging/allowops-agent.service \
  /usr/lib/systemd/system/allowops-agent.service
sudo install -o root -g root -m 0440 deploy/packaging/allowops.sudoers /etc/sudoers.d/allowops
sudo visudo -cf /etc/sudoers.d/allowops
sudo systemctl daemon-reload
sudo systemctl enable allowops-agent
```

Install the administrator-supplied public key and agent YAML using the package
section's commands, complete registration, then start the service. Retain LICENSE
and THIRD_PARTY_NOTICES from the archive. Do not run the agent as root.

| Path | Ownership / mode |
|---|---|
| `/usr/bin/allowops-agent` | root, 0755 |
| `/usr/libexec/allowops/allowops-exec` | root, 0755 |
| `/usr/lib/systemd/system/allowops-agent.service` | root, 0644 |
| `/etc/sudoers.d/allowops` | root, 0440 |
| `/etc/allowops/agent.yaml` | root, 0644 |
| `/etc/allowops/catalog-keys/` | root, 0755; public keys root, 0644 |
| `/var/lib/allowops/` | allowops, 0700 |
| `/var/lib/allowops-exec/` | root, 0700 |

The intended OS range includes CentOS/RHEL 7, Rocky/Alma/RHEL 8+, Ubuntu 20.04+
and Debian 11+. This guide does not establish a successful VM test for each OS.
Use the release's platform verification evidence when selecting a version.
