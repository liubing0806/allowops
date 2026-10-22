# Audit

Audit events record authenticated actors, operations, decisions, policy versions,
job/task identifiers and output object references with SHA-256 hashes. They do
not store command output bodies or raw action parameters. Keep reasons free of
credentials and other sensitive data because reasons are audit metadata.

PostgreSQL stores a continuous hash chain. Each event hashes the preceding hash
and its authoritative canonical payload bytes. Sequence allocation is transactional;
failed appends do not leave sequence gaps. A checkpoint event is added about every
five minutes while the gateway is running. Event queries with filters are not
necessarily a continuous chain.

## Runtime and maintenance privileges

Run migrations with a separate maintenance role. The runtime gateway role must
not be a superuser, the audit table owner, or a member of the maintenance role.
Its audit event permissions are INSERT and SELECT, not UPDATE/DELETE. The export
cursor has separate update privileges. A database administrator provisions the
required runtime grants after migration.

Monthly partition creation and retention are maintenance responsibilities.
Migrations create the current and next two UTC months. Schedule maintenance
before those partitions run out. Retention defaults to approximately one year
at monthly boundaries. Deletion records a retained boundary hash and refuses
to pass a registered export cursor that has not advanced far enough.
There is no general partition-maintenance CLI command in this release.

## Durable export

Enable file export on one designated gateway instance with a persistent volume:

```yaml
audit:
  export:
    enabled: true
  export_directory: /var/lib/allowops/audit
  cursor_name: primary-export
  max_file_bytes: 16777216
```

Other instances keep export disabled. Files and the directory are synchronized
before the database cursor advances. If a crash occurs before cursor advancement,
delivery can repeat; collectors must deduplicate by sequence number and reject
different hashes for the same sequence. Only collect published `.jsonl` files.
Hidden temporary files are not complete exports.

The designated instance's downtime pauses export. Restore its original volume
and cursor together. Moving export to another instance requires stopping the
old exporter and transferring both; do not start a new cursor on an empty volume
and treat it as a continuation. Filesystem persistence does not prove delivery
to an independent archive. Monitor and verify the collector separately.

## Export and verify with the CLI

The CLI uses `ALLOWOPS_DATABASE_URL` for database access, not a saved gateway
session. Deliver a least-privilege database credential through the process
environment. These commands do not run migrations.

```sh
allowops audit export --from 2026-01-01T00:00:00Z \
  --to 2026-02-01T00:00:00Z --output audit.jsonl
allowops audit verify --file audit.jsonl --from-seq 1 --to-seq 100
```

Export times are RFC3339, from inclusive and to exclusive. `--output -` writes
JSON Lines to stdout. Verification requires inclusive `--from-seq`/`--to-seq`
and accepts `--file -` for stdin. Without `--file`, it reads PostgreSQL.
Single verification ranges are limited to 10000 events; split longer ranges and
carry a verified boundary between them. Invalid chains return a nonzero exit
and the first invalid sequence/reason.

Use `--expected-preceding-hash` or `--expected-final-hash` with a 64-character
hex SHA-256 obtained from an independent trusted system to compare an external
anchor. Internal hash consistency alone does not prove a database administrator
has not rewritten the whole chain. `externally_anchored` describes comparison
to a supplied anchor; the caller is responsible for its trustworthiness.
Deleted history is unavailable for verification, not silently treated as valid.

Configure `audit.cursor_key_file` with a private file containing exactly 32 raw
random bytes. All API and export instances must use the same key and retain it
across restarts. Helm supplies it through `audit.cursorKeySecret` /
`audit.cursorKeyKey`; Compose generates and preserves it with the other private
material. Changing the key invalidates existing API pagination cursors.
If the setting is omitted, the gateway warns and uses a process-local random
key; cursors then become invalid after restart or a replica change. Restart
such queries without the stale cursor. This does not change the persisted chain.
