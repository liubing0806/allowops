# Release notes

## Unreleased

Changes on `main` since v0.1.0. They are not in a release yet.

### Upgrade notes

- The gateway applies three schema migrations on start:
  `00007_jobs_created_index`, `00008_task_output_instance` and
  `00009_gateway_update_check`.
- Building from source needs Go 1.27.3 (GO-2026-6809).
- Command runners are treated as interpreters. A catalog action that passes
  caller-supplied program text to a command runner is refused; the program
  text must be fixed in the signed catalog.
- The example actions `docker_stop` and `process_signal` are removed.
- `k8s_configmap_view` prints each key as `### <key>=<value>` instead of a
  `### <key>` line followed by the value.

### Gateway and console

- Gateway update notice: with `update_check.enabled` (default `false`) the
  gateway reads a release manifest once every 24 hours, and the console shows a
  newer release in the sidebar, the overview and the system page. The sidebar
  shows the gateway build version.
- The jobs list is paged on the server.
- Authorization labels are edited one `key=value` per line. Labels that this
  format cannot represent are refused instead of being changed.
- The job output dialog stays bound to the job it was opened for.
- MCP job options that the caller omits take the defaults and limits of the
  gateway jobs configuration. Tool input schemas no longer use root-level
  combinators.
- A database failure during authentication is reported as unavailable.
- Agent version rejections are logged by the gateway and in the agent journal.

### Reliability

- Jobs: task event transactions are retried on transient SQL errors. Replay
  accepts the state written by a COMMIT whose acknowledgement was lost, and
  starts output persistence when it finds its own terminal result. Pending
  output of a lost gateway instance is marked unavailable.
- Host connections: a failed catalog report write is retried, pending
  mailboxes left by another instance are reconciled, and an interrupted CA
  creation can finish.
- API: host writes lock only the hosts they change and use one pool
  connection. Policy rules and catalog rows are loaded only when needed.
- Executor:
  - exit 0 is kept when a detached descendant holds the output pipes;
  - the output wait after the process exits is bounded;
  - tail filter memory is bounded by the output limit, and a tail is marked
    truncated only when a requested line is lost;
  - path parameters are refused when a path component can be written by an
    untrusted user.
- Built-in actions: `mysql_query` result bytes are bounded by
  `max_response_bytes`; Redis `GET`, `MGET` and `HGET` reads are bounded;
  `log_search` `path_glob` expansion is bounded and can be cancelled.
- CLI: SIGINT and SIGTERM cancel the running command, including a password
  prompt.
- Deployment: the Helm chart injects provider secrets from Kubernetes Secrets.
  Compose `local-up` bootstraps again after an interrupted first run.

### Example catalog

- `agent_upgrade` (`risk: dangerous`) upgrades a host agent online from the
  package repository through a signed catalog action.
- 41 new read-only actions for configuration, files, JAR entries, Dubbo QoS,
  MySQL, Redis and Kubernetes. The catalog now has 91 actions: 90 read and
  1 dangerous.
- Redaction: the built-in secret rules cover more URL credential, DSN, query
  parameter, `NAME=value`, `NAME: value`, command-line password and SQL text
  forms, including URL passwords with escaped quotes. A skipped part of a line
  is no longer scanned again, so redaction time grows linearly with the line
  length.
- Custom redaction rules accept `before_builtin` to run before the built-in
  rules.
- The built-in MySQL actions redact by row; `redis_slowlog` summarizes
  `SLOWLOG GET`.

### Documentation

- The website allowops.com serves English and Chinese documentation.

## v0.1.0 — 2026-10-22 (pre-release)

First pre-release of the MVP: central gateway (MCP, console, CLI API, ABAC,
batch scheduling, audit hash chain), host agent and privileged execution helper,
CLI, and the example catalog with 51 actions. Host side is linux/amd64 only.

Release assets: binaries archive, `.deb` and `.rpm` for allowops-agent, the
gateway container image as a `docker save` archive, SPDX SBOMs, `checksums.txt`
with a detached GPG signature, and the release signing public key.

### Known limitations

- When a gateway instance is declared lost, a surviving instance finalizes its
  unfinished jobs. Pending tasks become `skipped`; running tasks become `failed`
  with reason `GATEWAY_INSTANCE_LOST`. Batches that have not been dispatched are
  not automatically resumed by another gateway instance.
- Cross-instance continuation of undispatched batches is on the
  [Roadmap](docs/design.md#17-roadmap).
- Wrapped-command checks have the limits listed in
  [website/execution.md](website/execution.md).
- Deferred minor findings are listed in [docs/roadmap.md](docs/roadmap.md).
