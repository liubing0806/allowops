# Release notes

## v0.2.0 — 2026-10-23 (pre-release)

Adds online agent upgrades through a signed catalog action, the gateway version
in the console with an opt-in newer release notice, server-side paging of the
jobs list, and fixes from two external code reviews.

### Upgrade notes

- Run `allowops-gateway migrate` before starting the new gateway. Three
  migrations are added (`00007_jobs_created_index`, `00008_task_output_instance`,
  `00009_gateway_update_check`); the schema version goes from 6 to 9.
- Path parameters are now refused unless every component is owned by root or
  the run-as user, is not a symlink, and is not group- or world-writable
  (sticky directories excepted). Paths under group-writable directories, such
  as `/var/log` owned by `root:syslog` with mode 0775 on some distributions, are
  refused with `PATH_NOT_TRUSTED`; the gateway currently shows
  `EXECUTION_FAILED`.
- Catalog templates that pass a parameter to a program that runs commands
  (`sh -c`, `watch`, `ssh`, `su`, `setsid`, `find -exec`,
  `tar --to-command`, and others) now need `allow_interpreter`, and placeholders
  may no longer supply interpreter options or program text. See D10 in
  [docs/architecture-decisions.md](docs/architecture-decisions.md).
- The audit writer uses its own connection pool, which takes 6 more database
  connections per gateway instance.
- Page tokens issued by v0.1.0 for listing jobs are rejected with
  `INVALID_PAGE_TOKEN`.

### New

- Host agents can be upgraded online through a signed catalog action that
  installs the package with yum or apt and restarts the agent about 5 seconds
  after the task result is sent.
- The gateway logs agent version rejections with host ID, hostname and both
  versions; the agent logs the rejection to its journal.
- The console shows the gateway version under the sidebar brand.
- Opt-in newer release check (`update_check`, off by default): the gateway
  fetches `version.json` over HTTPS at most once per interval across the
  cluster, and the console shows a newer release in the sidebar, the overview
  and the system page. With the check off, the gateway sends no outbound
  requests.
- The jobs list is paged on the server, 10 jobs per page in the console. The
  overview shows the latest 50 jobs.
- Helm: `gateway.providerSecretEnv` injects identity provider secrets from
  Kubernetes Secrets.
- Console authorization labels are edited one `key=value` per line.
- MySQL `mysql_query` result size is bounded by `max_response_bytes`
  (default 64 KiB).
- allowops.com landing page; the documentation is served under `/docs/`.

### Fixes

- MCP action tools no longer use `allOf` at the input schema root, which made
  Claude Code skip every action tool.
- Database errors during authentication return `Unavailable` instead of sending
  console users to the login page.
- Output, memory and wait limits: tail filtering, Redis `GET`/`MGET`/`HGET`,
  log `path_glob` expansion, and the wait for output after a process exits are
  now bounded. A detached descendant holding the output pipes no longer turns
  exit 0 into a failure.
- Gateway: host writes lock only the hosts they change and no longer need a
  second pool connection; policy rules and catalog versions are read only when
  needed; task events are retried on transient database errors; pending output
  of a lost gateway instance is marked unavailable; MCP job option defaults
  follow the gateway jobs configuration.
- Host connections: CA files are staged so an interrupted creation can finish;
  pending mailboxes and failed catalog report writes are reconciled on the
  maintenance tick; ignored database write failures are logged.
- CLI: SIGINT and SIGTERM cancel the running command, including the password
  prompt.
- Compose: an interrupted first `local-up` bootstraps again.
- Console: the job output dialog no longer keeps the previous job's state, and
  jobs paging resets when the filter changes.

### Known limitations

- The limitations listed for v0.1.0 still apply.
- The console still reads every page of the hosts and audit lists.

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
