# Release notes

## Unreleased

Changes on `main` since v0.2.0. They are not in a release yet.

### Upgrade notes

- Building from source needs Go 1.27.4 (GO-2026-6859).
- **Catalog metadata (`toolset`, `tags`, `entity_kinds`)**: `allowops-agent`
  and `allowops-exec` parse signed catalogs strictly and reject packages
  containing unknown fields (`CATALOG_REJECTED`). Upgrade in order before
  publishing catalogs that use these fields:
  1. Upgrade `allowops-gateway` (defaults to `mcp.mode: flat`, preserving
     existing tool names).
  2. Upgrade `allowops-agent` and `allowops-exec` on target hosts and verify
     their reported `features` include `action_metadata`.
  3. Upgrade the `allowops` CLI used in CI pipelines.
  4. Sign and publish the updated catalog.
- **New authoring/publish reserved action names**: `actions_search`,
  `actions_invoke_read`, `actions_invoke_write`, and
  `actions_invoke_dangerous` are now reserved on catalog authoring
  (`allowops catalog validate` / `build`) and publication (`PublishCatalog`).
  Reading previously stored historical catalogs remains compatible. Before
  upgrading and publishing new catalog versions, inspect your current
  catalog's action names on the web console Catalog page (or via
  `CatalogService.ListActions`) and rename any action that uses one of these
  four names.
- `exact` mode job summaries now default to deterministic Anomaly-First ranking
  (`failure` → `anomaly` → `normal`) instead of task insertion order, and
  terminal tasks without output hashes (such as `skipped`, `cancelled`, or
  dispatch-failure tasks) are included as Tier 0 failure groups rather than
  omitted.
- **Reserved MCP tool names (`jobs_diff`, `changes_list`, `runbooks_search`, `runbooks_read`)**:
  before upgrading gateway binaries, rename, re-sign, and publish any active
  catalog action using these names; otherwise catalog verification rejects the
  catalog and `/mcp` returns HTTP 503.
- **New authorization operations (`view_changes`, `view_knowledge`)**: defaults
  grant both to `admin`, `operator`, and `viewer` only on first initialization.
  Existing database policies are preserved on upgrade. Follow the rolling
  upgrade order: (1) migrate any conflicting catalog action names, (2) upgrade
  all `allowops-gateway` instances first, (3) export the policy with
  `allowops policy get > rules.yaml`, add `view_changes` / `view_knowledge` to
  the appropriate roles, run `allowops policy test -f rules.yaml`, and apply
  with `allowops policy apply`. Before rolling back to an older gateway binary,
  remove `view_changes` and `view_knowledge` from the active policy first.
- **Experimental `plugin.Host` API change (PL2)**: `plugin.Host` adds
  `HTTPClient()`, `Credential(ref)`, `Cache()`, and `Now()`, and adds optional
  `Validator`, `Cleaner`, and `ControlPlaneChangeReader` interfaces. Custom
  out-of-tree plugins and test doubles implementing `plugin.Host` must be
  updated to match.

### New

- MCP progressive disclosure and catalog action metadata for large catalogs:
  - Signed catalog actions now support optional `toolset`, `tags`, and
    `entity_kinds` metadata fields (included in the action digest and DSSE
    signature). Omitting them keeps existing catalog digests unchanged. All
    136 actions in `examples/catalog/actions/` are annotated across 16
    toolsets, and the web console displays these fields in the Catalog action
    detail panel.
  - `gateway.yaml` adds an optional `mcp` section with `mode` (`flat` default,
    `progressive`, or `auto`) and `auto_threshold` (default `40`, range
    `1..1000`). Clients can also scope their view with `X-Allowops-Toolsets`
    (up to 16 toolsets) and `X-Allowops-MCP-Mode` (`flat` or `progressive`)
    headers; `/mcp` continues to reject URL query parameters.
  - In `progressive` mode, `tools/list` exposes `actions_search` (keyword,
    exact `names`, `toolset`, `tag`, `risk`, `entity_kind`, and single-host
    `hostname` ABAC precheck with optional `include_schema` and 32 KiB paged
    results) and risk-split invocation tools (`actions_invoke_read`,
    `actions_invoke_write`, `actions_invoke_dangerous`) only for the risk
    levels visible to the caller. Each call verifies the action's current
    signed risk and runs through the same parameter, `expected_count`,
    `max_targets`, per-host ABAC, and audit pipeline as flat tools.
  - `entities_search` now includes per-kind `recommended_actions` (up to 10
    visible actions per returned entity kind, packed within the remaining
    32 KiB budget with a separate `recommended_actions_truncated` marker).
  - MCP caching uses a two-tier design: verified catalogs and projected policy
    are shared across identities, the per-identity LRU holds one slot per
    identity, and header-narrowed servers are built per request without
    evicting cached identities.
- Fleet output normalized clustering, Anomaly-First ranking, and cross-job
  baseline comparison:
  - Action tools, `jobs_get`, `allowops run`, and `allowops jobs get` accept
    `grouping` (`exact` by default, or `normalized`). Normalized mode clusters
    volatile output noise (timestamps, PIDs, IP addresses, hostnames, and
    numbers) into shared templates while preserving version numbers and semantic
    status/exit codes, and computes per-cluster numeric distributions
    (`min`/`p50`/`p95`/`max` and MAD outlier hosts).
  - Job summaries expose severity (`failure`/`anomaly`/`normal`),
    `anomaly_reason`, template metadata, `variances`, and strict
    host-conservation counters (`total_groups`, `omitted_groups`,
    `omitted_hosts`, `folded_normal_hosts`, `unfinished_hosts_count`), using
    linear `O(G)` 32 KiB budget trimming.
  - Added read-only MCP tool `jobs_diff`, `JobService.DiffJobs` RPC, and
    `allowops jobs diff <base-job-id> <target-job-id>` CLI subcommand
    (defaulting to `grouping=normalized`). Aligns two finished, non-denied jobs
    of the same action by immutable `host_id`, reporting added/removed/replaced
    hosts, degradation-first status transitions, anomaly-first pattern changes
    with bounded line diffs, and significant numeric metric drifts under a
    strict 32 KiB response budget with per-host `view_jobs` and `view_output`
    authorization and dual-job audit attribution.
- Composite `steps` actions now support controlled output extraction
  (`steps[].extract`), whole-element step variable references
  (`{steps.<step_name>.<var>}`), and declarative conditional branching
  (`steps[].when`):
  - Extractors support single-capture-group Go RE2 (`regex`, `match: first |
    exactly_one`), strict `$`-rooted `json_path` (rejecting duplicate keys and
    nesting past depth 32), and `tsv` (`line`, `column`, `tab | whitespace`)
    with bounded scan (`max_bytes`, default `64KB`, max `1MB`). Extraction runs
    after redaction and before caller output filters or budget truncation,
    rejects redaction-modified lines or JSON documents, and re-redacts decoded
    JSON values.
  - Every extracted value must satisfy an explicit `as` type (`int` with
    required `min`/`max` and `min >= 0` in `exec`, non-dash `enum`, anchored
    `string` with `regex` + `max_len`, `path` with `allowed_roots` and pre-exec
    `PATH_NOT_TRUSTED` check, or `bool`). `{steps.*}` is statically restricted
    to ordinary arguments of the final command and forbidden with
    `allow_interpreter: true`.
  - `when` evaluates a bounded YAML AST (max depth 4, max 32 nodes, forbidden on
    step 0) using Kleene three-valued logic so missing values fail closed.
    Skipped steps report explicit `CONDITION_FALSE` or `STOPPED` reasons.
  - Agents report `step_extract` and `step_when` in `features`. Upgrade both
    `allowops-agent` and `allowops-exec` before publishing catalogs that use
    these fields; older binaries reject unknown fields with `CATALOG_REJECTED`
    or `REQUEST_REJECTED`.
  - Added three read-only example actions: `disk_pressure_diagnose`,
    `top_process_diagnose`, and `docker_container_diagnose`.
- Investigation context plugin loop (stages A–D, see
  [docs/plugin-stage0203-design.md](docs/plugin-stage0203-design.md)):
  - **Plugin host security foundation & `plugin/plugintest`**: instance-scoped
    `egress` allowlist with single-resolution pinned-IP dialing, IPv4/IPv6 IMDS
    and NAT64/tunnel prefix blocking, cross-origin redirect decision table,
    strict private `ca_file` pinning, startup-pinned `dirFD` credential reader
    (supporting both `O_NOFOLLOW` regular files and Linux `openat2(RESOLVE_IN_ROOT)`
    Kubernetes projected volume rotation for UID 65532), bounded instance LRU
    TTL cache, per-instance `max_concurrency` semaphore, reference-counted
    graceful shutdown (`Close`), redacting logger, and `plugin/plugintest`
    contract suite with AST network-bypass guardrails.
  - **Dynamic Inventory & multi-source merging**: adds `inventory.k8s`,
    `inventory.prometheus_targets`, and `inventory.cmdb_http`. `entities_search`
    now audits before and after plugin calls, filters visible hosts per source
    first, propagates cross-source secrets within visible groups, merges
    matching entities across sources with `sources`, `conflicts`, and
    `selector_conflicts`, and degrades oversized entities cleanly under 32 KiB.
  - **Changes extension point (`plugin/changes`)**: adds `changes.allowops`
    (read-only catalog publication and policy version history via isolated
    `ControlPlaneChangeReader`), `changes.k8s_rollout`, `changes.http`, fixed
    MCP tool `changes_list` (max 7-day window, cross-field redaction,
    pre/post audit, 32 KiB budget), and `view_changes` operation.
  - **Knowledge extension point (`plugin/knowledge`) & MCP Resources**: adds
    `knowledge.git_markdown` (local `dir` mode via `openat(O_NOFOLLOW|O_NONBLOCK)`
    and `scratch`-compatible `archive_url` `.tar.gz` in-memory mode with full
    decompression stream limits), fixed MCP tools `runbooks_search` and
    `runbooks_read` (full-document `Redactor.Stream` PEM redaction, snapshot
    `revision`, unique section slicing, lossless UTF-8 paging), MCP Resources
    (`resources/list`, `resources/templates/list`, `resources/read` for
    `allowops://runbooks/{source}/{+id}`), and `view_knowledge` operation.
- The web console is redesigned (#27). The design handoff and prototypes are
  in [docs/console-redesign/](docs/console-redesign/README.md). The change is
  frontend only: no API, schema, or policy change, and no upgrade step.
  - A complete dark theme and self-hosted Geist and Geist Mono fonts. The
    console loads no external resources.
  - The sidebar groups pages into run, govern, and manage, and shows the
    current user and gateway health. Ctrl+K or ⌘K opens a command palette that
    jumps to a host by name, to a page, or to the unlabeled and outdated host
    filters.
  - Hosts: hostname search and label selector input, status filters for online,
    offline, unlabeled, and outdated hosts, and a detail side panel that keeps
    the list in view. Selected hosts can get labels through a per-host diff
    preview that is applied with the expected revisions, or be copied as MCP
    `targets` with `expected_count`.
  - Jobs: list and detail side by side, task progress per job, and an output
    viewer with stdout and stderr, steps of composite actions, and paged reads.
  - Policies: simulation for all subjects or for one subject, operation,
    action, and selector, with each host's decision before and after the change
    and the matching rules. Version history and rollback use the same
    simulate-and-save flow.
  - Catalog: envelope size, expiry, the catalog version loaded on hosts, a risk
    filter for actions, and a copyable publish command.
  - Service accounts show a running-job indicator. Join tokens show when they
    were created. The one-time secret dialogs list the next steps.
  - Audit: matched rules in the table, and an event side panel with the
    previous, current, and next hash as recorded.
  - Overview: a summary built from gateway numbers, and a list of items that
    need attention, including unlabeled hosts, agents older than the gateway,
    and a newer gateway release.

### Fixes

- The console reads the output of composite actions step by step. Before,
  opening the output of a composite action failed with `INVALID_OUTPUT_STEP`.
- The sidebar shows the username when a directory user has no display name.

## v0.2.0 — 2026-11-03 (pre-release)

Adds JVM diagnostics, log queries, monitoring and SQL actions, gateway inventory
plugins, and online agent upgrades. Also adds gateway update notices and job
paging, and fixes execution, redaction, and recovery errors since v0.1.0.

### Upgrade notes

- Run `allowops-gateway migrate` before starting the new gateway. Three
  migrations are added: `00007_jobs_created_index`,
  `00008_task_output_instance`, and `00009_gateway_update_check`. The schema
  version goes from 6 to 9. `serve` exits when the schema is older than the
  binary requires. The Helm chart runs the migration in its pre-upgrade hook.
- Set `gateway.version` in `gateway.yaml` to `0.2.0` or remove it; without the
  key the gateway uses its build version. The gateway refuses agents newer than
  this value. With `gateway.version: '0.1.0'`, an agent upgraded to 0.2.0 is
  refused with `agent version unsupported` and cannot reconnect.
- With a separate runtime database role, grant it `SELECT`, `INSERT`, and
  `UPDATE` on `gateway_update_check` before enabling `update_check`.
- Building from source needs Go 1.27.3 (GO-2026-6809).
- Path parameters are now refused unless every component is owned by root or
  the run-as user, is not a symlink, and is not group- or world-writable
  (sticky directories excepted). Paths under group-writable directories, such
  as `/var/log` owned by `root:syslog` with mode 0775 on some distributions, are
  refused with `PATH_NOT_TRUSTED`; the gateway currently shows
  `EXECUTION_FAILED`.
- Catalog templates that pass a parameter to a program that runs commands
  (`sh -c`, `watch`, `ssh`, `su`, `setsid`, `find -exec`,
  `tar --to-command`, and others) now need `allow_interpreter`. Placeholders
  may no longer supply interpreter options or program text. Command runners
  are treated as interpreters; program text must be fixed in the signed
  catalog. See D10 in
  [docs/architecture-decisions.md](docs/architecture-decisions.md).
- The audit writer uses its own connection pool. Allow 6 additional database
  connections per gateway instance.
- Page tokens issued by v0.1.0 for listing jobs are rejected with
  `INVALID_PAGE_TOKEN`.
- The example actions `docker_stop` and `process_signal` are removed.
- `k8s_configmap_view` prints each key as `### <key>=<value>` instead of a
  `### <key>` line followed by the value.
- The example `log_search` action now uses the `log_query` builtin. It accepts
  a named source and time range and returns paged JSON records. The old action
  definition is available as `log_grep`; the `log_search` builtin remains
  available. Update callers that depend on the old parameters or output.
  Configure `builtin_config.sources`, timestamp layouts, and allowed roots for
  your logs before signing and publishing the catalog. Container and Pod
  sources also need the configured container or namespace and local log access.
  See [docs/log-search-design.md](docs/log-search-design.md).
- To use `jvm_perfdata` or `jvm_arthas`, set `builtin_config.targets` to the
  systemd units or Docker containers and main classes to allow. To use Arthas,
  install the optional `allowops-arthas` package on each agent host. For a
  container target, also copy or mount its files into the container at the
  configured `arthas_dir`, by default `/usr/share/allowops/arthas/4.3.5`.
  Keep the five `builtin_config.sha256` values in the signed catalog consistent
  with those files. Without the package, Arthas actions are `unsupported`.
  See the [guide](website/installation.md#optional-package-allowops-arthas).
- All `jvm_arthas_*` actions require `risk: write`, `run_as: root`,
  `idempotent: false`, `batch_size: 1`, `max_failures: 1`, and `max_targets: 1`.
  Grant `execute_action` and `view_output` by action name. Authorize
  instrumentation and decompilation actions (L2: `watch`, `trace`, `stack`,
  `monitor`, and `jad`) separately from inspection actions (L1).
  L2 actions also need `builtin_config.class_prefixes`, explicit `secrets` and
  `pii` redaction, and timeouts that include cleanup. The examples use 90s for
  enhancement commands. Merge the required rules into your existing policy;
  [examples/policy/java-diagnostics.yaml](examples/policy/java-diagnostics.yaml)
  is a full replacement example. Configuration limits are in
  [docs/builtin-config.md](docs/builtin-config.md#jvm_arthas).
- Before enabling StarRocks or Dremio actions, set the endpoint and credential
  path in `builtin_config`. StarRocks uses `address`; Dremio uses `url`.
  Credentials are host-local JSON files owned by root with mode 0600; actions
  run as root. Use a SELECT-only StarRocks query account. Configure a separate
  StarRocks diagnostic account with the required `OPERATE` and audit-table
  SELECT grants; never use that account for `starrocks_query`. Configure Dremio
  data sources with read-only accounts. See
  [docs/builtin-starrocks.md](docs/builtin-starrocks.md) and
  [docs/builtin-dremio.md](docs/builtin-dremio.md).
- Before enabling Prometheus or Alertmanager actions, set
  `builtin_config.address` to the service endpoint. Optional `credential` files
  support a bearer token or a username and password. They must be root-owned
  with mode 0600 and require `run_as: root`. Use `ca_file` for a private
  HTTPS CA.
- Grant `view_inventory` to the roles that need `entities_search`. Defaults
  include admin, operator, and viewer only on first initialization. Upgrades do
  not change stored policies. Export the current policy with
  `allowops policy get > rules.yaml`, add the operation to the appropriate
  rules, retain the other rules, then run
  `allowops policy test -f rules.yaml` and
  `allowops policy apply -f rules.yaml --reason 'grant inventory access'`.
  You can also edit, simulate, and save the policy in the console.
- Rename any catalog action named `entities_search`, then sign and publish the
  updated catalog. This name is now reserved and catalog validation rejects it.
- Configure inventory instances under `plugins` in `gateway.yaml` and restart
  the gateway. Static topology file changes also require a restart. Without an
  available inventory instance, the MCP tool list is unchanged. See
  [examples/gateway.yaml](examples/gateway.yaml) and
  [examples/topology.yaml](examples/topology.yaml).

### New

- `jvm_perfdata` reads heap, garbage collection, class, and thread figures from
  an allowlisted JVM's hsperfdata file. It does not attach, send signals, or
  write target files. Targets can be systemd services or Docker JVMs.
- `jvm_arthas` runs one fixed Arthas command in an allowlisted JVM per action.
  Twelve L1 commands inspect threads, memory, JVM state, classes, methods,
  class loaders, selected system properties, and the Arthas version. Five L2
  commands provide `watch`, `trace`, `stack`, `monitor`, and `jad`. Enhancement
  commands are limited to one class and a bounded number of methods and reset
  the enhancement after the call. Caller-supplied command text is refused.
- Arthas calls verify file hashes in the target's mount namespace and check
  JVM support, memory headroom, attach count, and attach interval before
  attaching. L2 calls also check CPU use. Defaults allow at most five attaches
  per JVM lifetime, at least 60 seconds apart. Optional CPU, garbage collection,
  and health checks can abort a running command. Cleanup interrupts the job,
  resets enhancements, and stops Arthas. Session records support recovery after
  an interrupted call. The separate `allowops-arthas` deb and rpm packages carry
  Arthas 4.3.5; installation and execution do not download Arthas files.
- Signed catalog actions can set `max_targets`. The gateway rejects a request
  whose resolved host count exceeds this limit with `MAX_TARGETS_EXCEEDED`.
  An action without this field keeps the previous behavior.
- `log_query` supports named log sources, time ranges, multiline records,
  ascending or descending search, and cursor paging. It reads plain and gzip
  files, Docker standard output, container files, and node-local Kubernetes Pod
  logs. File, scan, time-window, record, and output limits bound each call.
- Log queries also provide source discovery, level filtering, time-bucket
  statistics, pattern clustering, and text export. `jobs_get encoding=text`
  returns UTF-8 output pages for reading exports without base64 decoding.
- `prometheus_query` supports instant and range PromQL queries, series and label
  discovery, alerts, rules, and targets. `alertmanager_alerts` lists alerts,
  including optional silenced and inhibited alerts. Requests and result sizes
  are bounded; text fields and individual labels are redacted.
- `starrocks_query` and `dremio_query` run a single SQL statement and return
  redacted TSV. Both default to at most 500 rows, 1 MiB of result text, and a
  10-second timeout. The shared SQL guard checks dialect-specific statement
  allowlists before reading credentials or connecting. It rejects writes,
  multiple statements, unsafe comments, hints, and blocked functions.
  StarRocks `EXPLAIN ANALYZE` is disabled unless explicitly enabled.
- `starrocks_diag` reads cluster state, running and slow queries, and query
  profiles. Profile summaries include operator metrics and rule findings.
  `profile_run` executes a guarded query to collect a profile and is off by
  default. `dremio_diag` reads nodes, memory, jobs, reflections, and job profile
  summaries through fixed requests. See
  [SQL guard documentation](docs/builtin-sqlguard.md) for the boundary.
- The experimental gateway plugin API in `plugin/` adds the Inventory extension
  point. Before 1.0, API changes may be incompatible and will be recorded here.
  `inventory.static` reads a local topology YAML file;
  `inventory.host_labels` derives entities from active host labels.
- The read-only MCP tool `entities_search` appears when at least one inventory
  instance is available. Results include source IDs, visible hosts, and
  selectors. Access requires `view_inventory`, and host visibility is filtered
  by policy. The gateway redacts secrets and limits the complete result to 32KB.
- System dependencies show configured plugin provisioning health. An optional
  plugin that fails provisioning makes system status DEGRADED. A required plugin
  that fails provisioning prevents startup. The readiness check is unchanged.
- Host agents can be upgraded online with the `agent_upgrade` example action
  (`risk: dangerous`, `run_as: root`). It installs the selected
  `allowops-agent` version from the host's configured apt or yum repository and
  restarts the agent from a transient systemd timer about 5 seconds after the
  task result is sent. A host already at the requested version is not changed;
  a version mismatch after install fails without a restart; downgrades are
  refused.
- The gateway logs agent version rejections with host ID, hostname, and both
  versions; the agent logs the rejection to its journal.
- The console shows the gateway build version under the sidebar brand.
  With `update_check.enabled` (default `false`), the gateway fetches
  `version.json` over HTTPS at most once per interval across the cluster
  (24 hours by default). The console shows a newer release in the sidebar,
  overview, and system page. With the check off, it sends no update requests.
- The jobs list is paged on the server, 10 jobs per page in the console. The
  overview shows the latest 50 jobs.
- Console authorization labels are edited one `key=value` per line. Labels
  that this format cannot represent are refused instead of being changed.
- Helm: `gateway.providerSecretEnv` injects identity provider secrets from
  Kubernetes Secrets.
- allowops.com has English and Chinese landing pages and documentation under
  `/docs/`. The website publishes `version.json` from the release notes.

### Fixes

- MCP action tools no longer use root-level schema combinators such as `allOf`,
  which made Claude Code skip every action tool. Omitted job options use the
  defaults and limits of the gateway jobs configuration.
- Database errors during authentication return `Unavailable` instead of sending
  console users to the login page.
- Jobs: task event transactions retry transient SQL errors. Replay accepts the
  state written by a COMMIT whose acknowledgement was lost and starts output
  persistence when it finds its own terminal result. Pending output of a lost
  gateway instance is marked unavailable.
- API: host writes lock only the hosts they change and no longer need a second
  pool connection. Policy rules are loaded only when the stored version changes;
  catalog reads decode only the versions they return.
- Host connections: CA files are staged so an interrupted creation can finish.
  Pending mailboxes and failed catalog report writes are reconciled on the
  maintenance tick. Ignored database write failures are logged.
- Executor: the output wait after a process exits is bounded. A detached
  descendant holding the output pipes no longer turns exit 0 into a failure.
  Tail filter memory is bounded by the output limit, and a tail is marked
  truncated only when a requested line is lost.
- Built-in failures preserve recognized log-query reason codes through the
  agent and MCP output groups. MCP summaries include a reason and gateway hint.
  Handler error text is included in stderr and passes through output redaction.
- MySQL `mysql_query` result size is bounded by `max_response_bytes`
  (default 64 KiB). Redis `GET`, `MGET`, and `HGET` reads are bounded before
  oversized values can be allocated. Legacy `log_search` `path_glob` expansion
  is bounded, can be cancelled, and skips non-regular files.
- Redaction covers more URL credentials, DSNs, query parameters, `NAME=value`,
  `NAME: value`, command-line passwords, and SQL text forms, including URL
  passwords with escaped quotes and passwords in JSON argument arrays.
  A skipped part of a line is no longer scanned again, so redaction time grows
  linearly with the line length. Bank card and identity card rules respect token
  boundaries.
- Custom redaction rules accept `before_builtin` to run before built-in rules.
  Built-in MySQL actions redact by row; `redis_slowlog` returns entry metadata
  without command arguments. `mysql_show` accepts a LIKE pattern for
  SHOW STATUS. `mysql_slow_log` reads trailing lines instead of a
  caller-supplied pattern.
- Prometheus formatting respects output limits and cancellation. An explicit
  range-query step of `0s` is refused. Metric and label names outside the legacy
  syntax are quoted. Alertmanager decoding retains at most `max_alerts` alerts;
  alerts with invalid start times sort after valid times.
- Arthas recovery keeps session records while a load command is unanswered and
  records the load attempt before sending it, so a later call can recover it.
- CLI: SIGINT and SIGTERM cancel the running command, including the password
  prompt. Compose: an interrupted first `local-up` bootstraps again.
- Console: the job output dialog stays bound to the job it was opened for, and
  jobs paging resets when the filter changes. Update notices refresh, hide
  omitted versions, and do not report an up-to-date gateway after a failed
  check.
  The embedded console includes the `OutputGroup.reason` protocol update.
- Update checks refuse a release manifest whose `published_at` is outside the
  year 1 to 9999 range.

### Example catalog

- The catalog has 133 actions: 115 read, 17 write, and 1 dangerous. Compared
  with v0.1.0's 51 actions, 84 are added and `docker_stop` and `process_signal`
  are removed. All 17 write actions are `jvm_arthas_*`; `agent_upgrade` is
  dangerous.
- The 66 new read actions cover configuration, files, JAR entries and Java class
  members, Dubbo QoS, MySQL, Redis, Kubernetes, log queries, Prometheus,
  Alertmanager, StarRocks, Dremio, and JVM performance data.
- The 17 Arthas actions include 12 L1 inspection actions and 5 L2 actions.
  All attach to a JVM and therefore have `risk: write`.

### Known limitations

- Cross-instance continuation of undispatched job batches remains unavailable.
  A surviving gateway finalizes unfinished jobs after an instance is lost, as
  described in v0.1.0. See the [Roadmap](docs/design.md#17-roadmap).
- Wrapped-command checks retain the limits in
  [website/execution.md](website/execution.md). Deferred review findings are
  tracked in [docs/roadmap.md](docs/roadmap.md).
- The console still reads every page of the hosts and audit lists.
- Arthas supports HotSpot 8, 11, 17, and 21 on linux/amd64. Other JVMs and
  architectures are refused. PerfData must be available. Docker targets need
  PID namespace information that CentOS 7's 3.10 kernel does not provide.
  The `logger` command is paused because its Arthas class loader remains loaded
  after cleanup. See the
  [Arthas logger report](docs/arthas-logger-classloader-report.md).
- Attaching and enhancing classes can pause the JVM and increase CPU and memory
  use. The checks do not prevent every pause. Enhancement calls can outlast the
  default MCP wait; retrieve the result with `jobs_get`. `jad` leaves class dump
  files in the JVM user's Arthas log directory and needs that directory to be
  writable. See the
  [stage 3 acceptance report](docs/arthas-stage3-acceptance-report.md) and
  [L2 report](docs/arthas-stage3-l2-report.md).
- The SQL guard is a lexical allowlist. It does not inspect view definitions or
  side effects of server plugins and user-defined functions, or restrict table
  access. Account permissions remain part of the boundary. Dremio 24.1 Community
  Edition accounts have administrator access; read-only data-source credentials
  are required. The dialects are designed for StarRocks 3.3 and Dremio 24.1;
  other versions are unverified. Dremio query results stop at 500 rows, and
  cancellation does not guarantee that a query at the data source stops.
- Container file log queries support bind mounts, volumes, and overlay2 paths;
  paths outside mounts with the containerd snapshot store are unsupported.
  Kubernetes log queries read node-local files and select Pods by name prefix.
  They do not search other nodes or select Pods by labels.

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
