# Operations

## Backups and restoration

Back up PostgreSQL, S3 output objects and lifecycle configuration, gateway TLS
and host CA material, catalog public keys, identity configuration and the
designated audit export volume. Preserve the export cursor with its matching
files and the shared `audit.cursor_key_file` key across gateway instances.
Protect private keys and credentials through your secret-management
backup process. Keep audit checkpoints in a separate trust domain.

Test restoration in an isolated environment. Check schema compatibility,
database privileges, identity login, host connection, catalog distribution and
audit verification. Restore object references and objects from compatible backup
points. Missing or expired objects must be reported as unavailable; a valid
audit chain does not restore their contents.

Backups of hosts include `/var/lib/allowops/` (private identity and catalog state)
and `/var/lib/allowops-exec/` (root-owned highest versions). Never clone one host's
identity to another. Preserving only catalog bytes while losing highest-version
state weakens rollback detection. Treat such restoration as a reviewed trust
recovery, not a routine file copy.

## Upgrade order

Upgrade the gateway first, then hosts using verified artifacts from the intended
release. A gateway supports its own and previous major host versions (only major
zero for a major-zero gateway), but rejects a host with a newer full SemVer.
Do not introduce a new host version before the gateway supports it.

Run the release migration with the maintenance database role. Helm uses a
pre-install/pre-upgrade migration hook; deployments that manage binaries run
`allowops-gateway migrate` separately. Preserve the runtime role's restricted
audit privileges. Review migration compatibility before rolling back binaries;
do not edit migration history or assume a newer schema works with an older gateway.

SIGTERM stops new work, drains in-flight work up to the configured grace period
and asks hosts to reconnect. Allow sufficient container termination time.
Disconnects terminate active task process groups and do not replay tasks.
Cancellation and disconnect do not reverse side effects already made.

After an upgrade, verify the running image digest or behavior unique to the new
code, then check authenticated login, inventory, an authorized test action, its
output and audit. A reported version or commit alone does not establish that
the new executable is serving requests. Host package installation enables but
does not start the service; operators control the restart.

## Update check

The gateway can remind operators that a newer release exists. The check is off
by default. Enable it with `update_check.enabled: true`.

`update_check.url` defaults to `https://liubing0806.github.io/allowops/version.json`.
An intranet deployment can host the same file internally and point the setting
at it. The manifest has two fields:

```json
{"version":"0.1.0","published_at":"2026-10-22T00:00:00Z"}
```

`version` is the latest SemVer release and `published_at` is its UTC date. The
documentation build generates the file from the first release heading of
`CHANGELOG.md`.

The gateway requests the manifest every 24 hours with a random delay. The
request carries only the header `User-Agent: allowops-gateway/<version>`. The
gateway only shows a reminder when the manifest version is newer than the running
one. It never downloads or installs a release; follow [Upgrade order](#upgrade-order)
with verified artifacts.

## Key and token rotation

Catalog key rotation is described in [publishing](publishing.md): distribute the
new public key, publish a dual-signed package, confirm host loading, then remove
the old key. Revoke compromised keys on hosts, not only at the gateway.

For service tokens, issue a replacement, update one client, validate access and
revoke the old token. Separate accounts for different clients simplify revocation.
Keep passwords and tokens out of process arguments and shell tracing.

The gateway TLS CA pin is distinct from the host identity CA. Renew gateway TLS
certificates with the expected names and full chain. Changing the pinned TLS
CA requires a coordinated operator update of every host's configured pin.
Secret changes copied by Helm init containers require workload restarts.
Do not replace the host identity CA as a routine rotation: in-place host CA
rotation is outside the MVP. Plan a controlled re-registration if that trust
must change.

## Storage and retention

Use an existing S3 bucket, configure the output region/endpoint and deliver
credentials through the AWS SDK credential chain. Configure encryption support:
output uploads request AES256 server-side encryption. SeaweedFS needs its SSE key
configured independently. Retention belongs to the bucket lifecycle policy;
the gateway does not set it automatically. The intended default is one year.

SeaweedFS lifecycle configuration APIs and compressed output operations have
local integration coverage. Actual delayed expiry deletion requires operator
verification over the configured retention interval. Check the selected storage
version and its encryption/lifecycle behavior before relying on deletion.
Full output writes are asynchronous; monitor failed persistence even when jobs
succeed. The `output_stored` flag distinguishes execution from persistence.

## Monitoring and recovery

Use HTTPS GET `/health/live` for liveness and `/health/ready` for readiness.
PostgreSQL connection/schema failure returns HTTP 503. Output storage failure
keeps readiness at HTTP 200 with `degraded: true`; monitor the body and output
persistence rather than interpreting HTTP 200 as proof that every dependency
is healthy. The `allowops-gateway health` command checks status and TLS but does
not fail on the degradation flag. Health endpoints do not verify user login
or action authorization.

Synchronize clocks. Catalog activation allows five minutes of skew; excessive
skew can break certificate or catalog validation. Monitor offline hosts, failed
catalog loading, unsupported actions, output persistence, audit export lag and
dependency health. Catalog expiry and token expiry require renewal before use
ends. Inventory load reports reflect the last complete report, including for
offline hosts; they do not prove the host's present execution environment.

Use short join-token lifetimes and bounded uses. Set authorization labels only
after checking the registered host identity. Deletion invalidates certificates;
a same-name replacement has a new immutable ID. No host credential is an API
identity.

If publication or management returns an audit-result error after a possible
commit, read the resource before retrying. If an execution response is lost,
inspect jobs before submitting again. There is no general exactly-once side-effect
guarantee. A gateway-instance loss can require task reconciliation without replay.
