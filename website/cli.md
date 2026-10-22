# CLI reference

Use the binaries from one release. `allowops --help` and each subcommand's
`--help` are the authoritative interface for that release. The gateway uses a
different command parser. Serve checks `ALLOWOPS_DATABASE_URL` before parsing
flags, so set that environment variable before checking `serve --help`.
Both `allowops-gateway serve --help` and `health --help` print their flags but
exit nonzero. The helper accepts no arguments, including `--help`.

## Authentication

```sh
allowops login --gateway https://gateway.example.org --provider identity
allowops login --gateway https://gateway.example.org \
  --provider directory --username operator
```

Login flags are `--gateway`, `--provider`, `--ca-file`, `--no-browser`,
`--username` and `--password-stdin`. Jobs and policies use saved CLI credentials.
Host and join-token commands also accept `--gateway`, `--ca-file` and
`--token-env` for a service account. Publish requires an explicit token
environment variable. See [identity](identity.md).

## Catalog commands

| Command | Important flags |
|---|---|
| `allowops catalog keygen` | `--private-key`, `--public-key`; creates new files. |
| `allowops catalog validate [directory]` | `--dir` if no positional directory is supplied. |
| `allowops catalog build` | `--dir`, `--out`, `--git-commit`, `--ttl` (2160h default). |
| `allowops catalog sign` | `--in`, `--out`, repeated `--key` for multiple signatures. |
| `allowops catalog publish` | `-f`/`--file`, `--gateway`, `--ca-file`, `--token-env`, `--json`. |
| `allowops catalog try <action>` | `--dir`, repeated `--param name=value`; executes locally as the current user. |

Build expiry starts at build time; sign preserves it. `--out -` writes to stdout.
Private keys are read from files. See [publishing](publishing.md).
There is currently no `allowops actions list` or `actions describe` command;
inspect catalogs in the console or discover MCP tools.

## Hosts and registration tokens

```sh
allowops hosts list --selector env=test --json
allowops hosts label host-a --set env=test --set team=ops --remove temporary
allowops hosts label --selector env=test --expected-count 2 --set team=ops
allowops hosts delete host-a
allowops jointoken create --uses 1 --ttl 1h
```

Selectors are comma-separated `key=value` conjunctions. `reported.` keys filter
reported attributes; they never grant authorization. Label changes set/remove
explicit keys, preserve others, and verify revisions and target counts atomically.
Deleting a host invalidates its identity. Join-token creation displays the secret
once: send it through a private delivery channel and avoid logging its output.
These command groups support `--json` and the remote flags described above.

## Run and jobs

```sh
allowops run systemd_service_status --selector env=test,team=ops \
  --expected-count 2 --param service=nginx --reason 'check service state' \
  --wait-seconds 30 --batch-size 2 --max-failures 0 --json
allowops jobs list --page-size 50 --json
allowops jobs get job-20261014-0001 --wait-seconds 30 --response-format detailed --json
allowops jobs output job-20261014-0001 --host host-a --stream stdout \
  --offset 0 --limit 16384 --json
allowops jobs cancel job-20261014-0001 --json
```

Run chooses `--hosts` (comma-separated names) or `--selector`; selectors require
`--expected-count`. `--reason` is required. Action inputs use repeated `--param`;
integers/booleans are typed and arrays use JSON. Supplying parameters also requires
`view_catalog` so the CLI can read the action schema. Run supports
`--response-format concise|detailed`, wait, batch and failure controls. It does
not expose separate output-filter flags; use MCP for top-level output filters.

`run` exits 1 when the returned job is failed, partially failed, cancelled or
denied. It exits 0 when the returned job succeeded. A queued or running response
also exits 0 and prints a notice to stderr that the job has not completed. This
can occur with `--wait-seconds 0` or when the response wait ends before completion;
exit 0 alone does not establish task success. An unspecified or unknown job
status, or a response without a job, exits 1 and reports the unknown status
on stderr. The text or JSON response remains
on stdout, including for a failed job. Submission, RPC and output errors remain
nonzero. These exit rules apply to `run`; use `jobs get` to inspect later progress.

`jobs list` pages with `--page-token`; use JSON to obtain the next token.
Output requires `--step` for a composite action's zero-based step index; omit
it for single-step actions. Read each declared step separately, resetting the
offset when changing step or stream. Omitting a composite step or supplying an
invalid index returns `INVALID_OUTPUT_STEP`. For example:

```sh
allowops jobs output job-20261014-0002 --host host-a --step 0 --stream stdout --json
allowops jobs output job-20261014-0002 --host host-a --step 1 --stream stdout --json
```

Output also supports `--stream stdout|stderr`, `--offset` and `--limit` (default
16384, maximum 24576 bytes). JSON uses ProtoJSON:
bytes are Base64, 64-bit integers are strings. Continue at `next_offset` until
`eof`. The table output includes raw output bytes; treat them as untrusted data.

MCP action tools use the same job service. Their inputs are JSON with action
parameters inside `params`; `jobs_get` with `host` reads output and uses
`step_index` for composite actions. MCP returns `data_base64` and numeric
`next_offset`; CLI JSON returns ProtoJSON `data` and a string `next_offset`.
See [MCP tools](mcp.md) for summary fields, output pages and reading hints.

## Policy and audit

```sh
allowops policy get > rules.yaml
allowops policy test -f rules.yaml
allowops policy apply -f rules.yaml --reason 'update policy'
allowops audit export --from 2026-01-01T00:00:00Z \
  --to 2026-02-01T00:00:00Z --output audit.jsonl
allowops audit verify --file audit.jsonl --from-seq 1 --to-seq 100
```

Policy get defaults to editable YAML; `--json` includes version metadata.
Apply replaces the full rule set and performs simulation before save.
Audit export and database verification read `ALLOWOPS_DATABASE_URL` directly;
they do not use gateway login credentials. Local file verification does not
need a database. Audit flags are detailed in [audit](audit.md).

## Gateway and host binaries

```sh
allowops-gateway migrate
allowops-gateway serve --config /etc/allowops/gateway.yaml
allowops-gateway health --url https://gateway.example.org/health/ready \
  --ca-file /absolute/path/gateway-tls-ca.crt
sudo allowops-agent join --upstream https://gateway.example.org \
  --token-file /absolute/path/join-token.txt --ca-pin "sha256:$ca_pin"
allowops-agent run
allowops-agent status
```

Migrate takes no flags and uses the maintenance database credential. Serve uses
the runtime credential and requires `--config`. `allowops-agent run` loads the
fixed `/etc/allowops/agent.yaml` and must run as the dedicated user; systemd
normally invokes it. `status` reports public identity and connection/catalog
state. Registration is an administrator-controlled operation using the gateway
TLS CA pin; obtain `$ca_pin` as described in [installation](installation.md).
Join requires `--upstream`, `--ca-pin` and exactly one of `--token-file`,
`--token-stdin` or legacy `--token`. File/stdin input is bounded to 4 KiB and
surrounding whitespace is trimmed; empty input is rejected. Prefer file/stdin
because the legacy option exposes the token in process arguments.

`health` accepts `--url` and optional `--ca-file`, verifies TLS, rejects redirects
and succeeds only for HTTP 200. Its URL must use HTTPS with `/health/live` or
`/health/ready`. Storage degradation still returns 200, so inspect the endpoint's
body separately. Health does not need a database credential or login session.
Never invoke `allowops-exec` as an interactive command; it is a fixed-path,
stdin-only privileged protocol endpoint.
