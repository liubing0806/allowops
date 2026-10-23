# Allowops Helm chart

This chart installs two or more gateway replicas, an L4 TCP Service on port
443, a migration hook, a PodDisruptionBudget and, by default, one audit export
StatefulSet. PostgreSQL and object storage are supplied by the operator.
All containers use amd64 nodes. No Ingress or HTTP/TLS termination proxy is
included: mutual TLS and Application-Layer Protocol Negotiation (ALPN) must
reach the gateway process unchanged. Set the cloud-specific Service
annotations for an L4 TCP load balancer.

Supply an image tag in `image.repository` / `image.tag`. Build locally with:

```sh
docker build --platform linux/amd64 -f deploy/docker/Dockerfile \
  --build-arg VERSION=0.1.0 -t allowops-gateway:0.1.0 .
./deploy/docker/verify.sh allowops-gateway:0.1.0 0.1.0
helm lint deploy/helm/allowops
helm template allowops deploy/helm/allowops > /tmp/allowops.yaml
python3 deploy/helm/verify.py /tmp/allowops.yaml  # local PyYAML dependency
kubeconform -strict -summary -kubernetes-version 1.32.0 /tmp/allowops.yaml
helm package deploy/helm/allowops --destination /tmp
```

OCI (Open Container Initiative) publication settings are in
`../oci.env.example`. Packaging and rendering do not upload the chart.
Registry login and publication require a separate release action.
GoReleaser's snapshot build also builds a local gateway image, with
`skip_push: true`. Its legacy Docker configuration is retained for this
explicit load-only behavior; GoReleaser 2.18.3 reports a deprecation warning.
The image build emits assembly dependency inspection warnings from
go-licenses; these do not replace inspection of non-Go dependencies.

## Secrets and migration

Provision these Secrets in the target namespace before installation:

* `allowops-credentials`: `ca.crt`, `ca.key` (PKCS8 host identity CA),
  `tls.crt` (server certificate and full chain), `tls.key`,
  `catalog.pub.pem` (PKIX Ed25519 public key).
* `allowops-audit-cursor`: `audit-cursor-key`, exactly 32 raw random bytes,
  shared across API and export instances and retained across restarts.
* `allowops-output`: `aws-credentials`, an AWS shared credentials file.
* `allowops-database`: `url`, the runtime PostgreSQL connection string.
* `allowops-migration-database`: `url`, a separate PostgreSQL maintenance
  connection string. It must exist before `pre-install` runs.

The chart can create the credentials and runtime database Secrets using
`credentials.create` / `database.create` and the corresponding data values.
Use existing Secrets to keep secrets out of Helm values and release history.
The migration Secret is always provisioned independently. The pre-install /
pre-upgrade Job runs `allowops-gateway migrate`; failed migrations prevent
the release from starting or upgrading. Successful hook Jobs are deleted.

Identity providers in `gateway.providers` read their secrets from environment
variables (`client_secret_env` for OIDC, `bind_password_env` for LDAP). Map each
variable to a pre-provisioned Secret with `gateway.providerSecretEnv`, a list of
`{name, secretName, key}` entries rendered as `secretKeyRef` variables in the
gateway Deployment and the export StatefulSet. The gateway does not start when a
referenced variable is empty. Names reserved by the chart (`ALLOWOPS_DATABASE_URL`,
`AWS_SHARED_CREDENTIALS_FILE`, `AWS_EC2_METADATA_DISABLED`) are rejected. Secret
values never enter the ConfigMap. `python3 deploy/helm/verify-provider-secrets.py`
renders the chart with an LDAP and an OIDC provider and checks this contract
(needs helm and PyYAML). The chart does not mount provider CA files; `ca_file`
paths must already exist in the image.

G35 requires either a self-signed root CA in `tls.crt`'s full chain or an
explicit `gateway.management.ca_pin` (SHA-256 of the TLS root CA DER).
The host identity CA is a different CA. `gateway.management.upstream` defaults
to `gateway.identity.origin`; it must match the public TLS certificate name
and use the Service's public port 443. Without a usable pin, CreateJoinToken
is disabled by the gateway.
The P3 pinned TLS client also requires the TLS root CA in the presented server
chain. Include it in `tls.crt` even when a pin is configured explicitly.

The migration role needs the privileges described in `docs/audit.md`.
The runtime role must not be a superuser, the audit table owner, or a member
of the maintenance role. After migration, the database administrator grants
`allowops_audit_writer` and the required non-audit table privileges to the
runtime role. On a fresh installation, this must be done before the runtime
gateway starts successfully. Chart validation does not validate these grants.
Partition maintenance and backups remain operator responsibilities.

Kubernetes Secret projections contain symlinks. The gateway rejects symlinks
and requires the CA private key to have mode 0600. A short non-root init
container reads the group-readable Secret projection (0440, fsGroup 65532),
copies credentials into its own subdirectory of a memory-backed emptyDir,
and sets mode 0600. The gateway and init container run without capabilities,
as UID/GID 65532, with read-only root filesystems. No container receives a
service account token. The pinned Alpine utility image is independently distributed
and contains BusyBox (GPL-2.0); it is not part of the scratch gateway image
or its Go dependencies. The gateway ships its license, Go dependency notices
and the Mozilla CA bundle notice (MPL-2.0).

Secret changes supplied outside Helm require restarting the workloads,
because credentials are copied at pod startup. Chart-owned ConfigMap and
Secret changes update the pod template checksum.

## Shutdown and audit export

`gateway.shutdownGraceSeconds` sets the gateway's `shutdown_grace`.
`terminationGracePeriodSeconds` is computed as that value plus 10 seconds,
covering the gateway command's additional 5-second shutdown timeout. SIGTERM
reaches the gateway directly. Startup and liveness probes use HTTPS GET `/health/live` on port 8443.
Readiness uses `/health/ready` on the same port. PostgreSQL connection or
migration mismatch returns 503; unavailable output storage returns 200 with
`degraded:true`. Kubernetes HTTPS probes do not verify the serving certificate.
The gateway's shared audit cursor key is copied from its Secret as a 0600 file.

`audit.enabled=true` selects the single `*-export-0` instance for file export.
The API Deployment has no export directory. The export StatefulSet has one
ReadWriteOnce persistent volume claim (PVC), a stable cursor name, and no
client traffic from the public Service. It still runs the gateway because
there is no separate exporter-only command. Do not increase its replicas.
The exporter config explicitly sets `audit.export.enabled=true`; API replicas
set it to false. A directory and cursor alone do not enable export.
The StatefulSet preserves the volume across replacement and serializes pod
updates, so its files remain available when the export instance recovers.
Export pauses during its downtime. PostgreSQL advisory locking and fsync
before cursor advancement are implemented by the existing P7 exporter.
Keep the cursor name bound to the same persisted directory. PVCs remain after
chart removal; retention, collection, delivery and backups are operator duties.
Consumers deduplicate files by sequence number and check equal hashes.

## Output storage and local secret generation

Set `output.bucket`, `output.region` and `output.endpoint` for your external
S3-compatible service. An empty endpoint uses the AWS regional S3 endpoint.
`output.existingSecret` / `output.credentialsKey` select the credential file;
`audit.cursorKeySecret` / `audit.cursorKeyKey` select the shared cursor key.
PostgreSQL and object storage are operator-provided services.

Generate local demonstration secrets without placing values in arguments:

```sh
python3 deploy/generate-secrets.py /tmp/allowops-fx2-secrets
# These commands print manifests only; no cluster write is performed.
kubectl create secret generic allowops-audit-cursor \
  --from-file=audit-cursor-key=/tmp/allowops-fx2-secrets/audit-cursor-key \
  --dry-run=client -o yaml
kubectl create secret generic allowops-output \
  --from-file=aws-credentials=/tmp/allowops-fx2-secrets/aws-credentials \
  --dry-run=client -o yaml
```

Generated files use mode 0600. Secret manifests contain private values;
keep them out of source control and logs. Provision them through your approved
Secret workflow before installation. The generator also writes `s3.json` and
`seaweedfs.env`; provide them only to the external SeaweedFS service.
`seaweedfs.env` contains the generated `WEED_S3_SSE_KEY` required for AES256
server-side encryption. The chart does not mount that key in the gateway.
See [protocol.md](../../../docs/protocol.md) for storage encryption and retention.
