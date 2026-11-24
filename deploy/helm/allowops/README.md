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
  --build-arg VERSION=0.2.0 -t allowops-gateway:0.2.0 .
./deploy/docker/verify.sh allowops-gateway:0.2.0 0.2.0
helm lint deploy/helm/allowops
helm template allowops deploy/helm/allowops > /tmp/allowops.yaml
python3 deploy/helm/verify.py  # renders and checks default and production values, requires PyYAML
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
  `tls.crt` (server certificate and full chain), `tls.key`, and at least one
  PKIX Ed25519 public key named `catalog*.pub.pem` (typically `catalog.pub.pem`).
* `allowops-audit-cursor`: `audit-cursor-key`, exactly 32 raw random bytes,
  shared across API and export instances and retained across restarts.
* `allowops-output`: `aws-credentials`, an AWS shared credentials file.
* `allowops-database`: `url`, the runtime PostgreSQL connection string.
* `allowops-migration-database`: `url`, a separate PostgreSQL maintenance
  connection string. It must exist before `pre-install` runs.

For a private registry, set `imagePullSecrets` to a list such as
`[{name: allowops-registry}]`. The gateway, exporter, and migration Job
use the list. Provision the registry Secret before installing the chart so
the migration hook can pull its image.

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

Use a maintenance role that owns the application tables for the migration
Secret. The runtime login requires the least-privilege grants in
[the PostgreSQL operations guide](../../../docs/audit.md).
Apply those grants after migration, including
`GRANT allowops_audit_writer, allowops_job_writer TO your_gateway_login;`.
The runtime login must have no superuser privileges, application table
ownership, maintenance role membership, or CREATE privilege on the
application schema. On a fresh installation, apply the grants before the
gateway starts.

Migrations provision partitions for the current UTC month and the next two
months. Schedule these commands monthly using the maintenance credentials.

```sql
SELECT audit_create_partitions(now(), 3);
SELECT tasks_create_partitions(now(), 3);
```

If `RunJob` returns `UNAVAILABLE` with reason `TASK_PARTITION_MISSING`, run the
task partition maintenance command and retry the job submission.

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

To rotate a catalog signing key, add the new public key to
`credentials.existingSecret` under a distinct name such as
`catalog-2026.pub.pem`. Keep the old key during the transition. The init
container copies all `catalog*.pub.pem` files as regular files with mode
0600. Roll out the gateway and exporter (if enabled) after updating the Secret.
Distribute the new key to hosts and verify dual-signed publication and host
load reports before removing the old key. Roll out the workloads again to
remove the old key from gateway trust. Any matching filename can be the
remaining key. See the [catalog publishing guide](../../../website/publishing.md#rotate-catalog-signing-keys).

## Identity providers and runtime settings

`extraEnv` and `envFrom` use Kubernetes container environment entries and
sources. Use Secret references for OpenID Connect (OIDC) client secrets and
Lightweight Directory Access Protocol (LDAP) bind passwords. Use
`extraVolumes` and `extraVolumeMounts` to mount a private certificate
authority (CA) bundle, then reference its path with `gateway.providers[].ca_file`.
These settings apply to both the gateway and exporter.

~~~yaml
extraEnv:
  - name: OIDC_CLIENT_SECRET
    valueFrom:
      secretKeyRef:
        name: allowops-oidc
        key: client-secret
envFrom:
  - secretRef:
      name: allowops-ldap  # Contains the LDAP_BIND_PASSWORD key.
extraVolumes:
  - name: provider-ca
    secret:
      secretName: allowops-provider-ca  # Contains the ca.crt key.
extraVolumeMounts:
  - name: provider-ca
    mountPath: /etc/allowops-provider-ca
    readOnly: true
gateway:
  certificateTTL: "12h"
  jobs:
    wait_seconds: 15
    max_wait_seconds: 60
    batch_size: 10
    max_failures: 2
  providers:
    - id: workforce-oidc
      display_name: Workforce OIDC
      kind: oidc
      issuer_url: https://sso.example.com
      client_id: allowops
      client_secret_env: OIDC_CLIENT_SECRET
      ca_file: /etc/allowops-provider-ca/ca.crt
    - id: workforce-ldap
      display_name: Workforce LDAP
      kind: ldap
      url: ldaps://ldap.example.com
      user_base_dn: ou=users,dc=example,dc=com
      group_base_dn: ou=groups,dc=example,dc=com
      bind_dn: cn=allowops,ou=services,dc=example,dc=com
      bind_password_env: LDAP_BIND_PASSWORD
      ca_file: /etc/allowops-provider-ca/ca.crt
~~~

`gateway.certificateTTL` controls the host identity certificate lifetime for
issuance and renewal. Use a positive Go duration such as `12h` or `1h30m`.
An empty value uses the gateway default of `24h`. Set any of the four
`gateway.jobs` fields to override the corresponding gateway defaults
(`30`, `120`, `20` and `5`, respectively). Keep `wait_seconds` at or below
`max_wait_seconds`.

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
