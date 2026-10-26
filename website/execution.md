# Execution capabilities

The [catalog format](catalogs.md) supports fixed command arrays and bounded
alternatives to common shell workflows. Each capability is part of the signed
action; a caller cannot add it dynamically.

## Output filters

Declare `filters: [match, exclude, tail, head, count]` to allow those inputs.
`match` and `exclude` are RE2 patterns of at most 200 characters. `tail` and
`head` are positive line counts; `count` is a boolean. `tail`, `head` and `count`
are mutually exclusive by field presence, including `count: false`.
MCP filters are top-level inputs, separate from `params`.

Filters apply to each step's stdout after redaction. `max_scan` counts the raw
stdout bytes for each step; scan-limit and output-truncation flags describe
different limits. There is no hidden unredacted output to retrieve later.

## Sequential steps and fallback paths

`steps` runs a list of named, fixed `exec` arrays sequentially. `on_error` is
`continue` or `stop`. One action timeout and output budget cover all steps;
the final exit code is the first failed step's code, or zero. Skipped steps
remain visible. `exec_fallbacks` supplies alternative absolute executable paths
when the primary executable does not exist; it is not a retry for command failure.

```yaml
name: host_snapshot
description: Read uptime and memory in separate steps.
risk: read
params: {}
steps:
  - name: uptime
    exec: [/usr/bin/uptime]
  - name: memory
    exec: [/usr/bin/free, -m]
on_error: continue
timeout: 10s
max_output: 64KB
filters: [head, count]
redact:
  builtin: [secrets]
```

## Signed scripts and interpreter exceptions

`script: {file, interpreter}` names a script within the catalog and an absolute
interpreter path. Its bytes and digest are signed with the action. `args` uses
the same whole-element placeholders and optional groups as `exec`. The host
writes the script in a private temporary directory and removes it afterward;
Python runs with `-I` isolation. Scripts execute on hosts, not in the gateway.

Ordinary exec actions reject interpreters and shebang scripts by default.
`allow_interpreter: true` is an explicit per-action exception and emits a warning.
Review it as permission to run the signed interpreter program. It does not make
arbitrary interpreter input from an AI agent safe. Wrapped commands are also
checked; interactive TTY execution is prohibited.

Known limits of the wrapped-command check:

- A target started by a wrapper (`env`, `timeout`, `nice`, `ionice`, `stdbuf`,
  `xargs`, `nsenter`, `chroot`) is checked only for the ELF magic bytes
  (`\x7fELF`). A non-ELF file without `#!` is rejected unless
  `allow_interpreter` is set.
- A file that starts with `\x7fELF` but is not a valid ELF executable is
  accepted. On a host where `/bin/sh` is `dash`, `execvp` can run such an
  executable text file through `sh` after an `ENOEXEC` error. This requires an
  attacker who can already write an executable file on the host.
- `nsenter` without a directory (`-r`, `--root`), and `-a`, `-m`, `--mount[=file]`,
  enter a root or mount namespace that the host cannot inspect. Only the command
  name is checked in these cases. `-r<dir>` and `--root=<dir>` are inspected on
  the host when `<dir>` is the host's own root directory.

## Builtins

| Builtin | Behavior and boundary |
|---|---|
| `log_search` | Search allowed plain/gzip logs with bounded files, scan bytes, matches and context; path globs stay within allowed roots. |
| `log_query` | List named log sources (`mode: sources`) or search one source within a time range (`mode: search`): multiline records, paginated JSON with cursors, fixed error reason codes. Sources and allowed roots are declared in `builtin_config`. |
| `mysql_query` | One SELECT/SHOW/DESC/EXPLAIN statement, read-only transaction, bounded rows, result bytes and timeout. Host credentials stay in root-owned mode-0600 files. |
| `redis_command` | Read-only allowlist: GET, MGET, HGET, HLEN, TTL, TYPE, EXISTS, STRLEN, LLEN, SCARD, ZCARD, SCAN and INFO. |
| `http_get` | GET within signed URL prefixes; no redirects; bounded response. |
| `prometheus_query` | Read-only Prometheus HTTP API v1 query. `builtin_config.api` fixes one of query, query_range, series, labels, label_values, alerts, rules and targets; GET only, no redirects; bounded time range, step, points, series and response size; TSV output. A host credential (bearer token or basic auth) requires `run_as: root`. |
| `alertmanager_alerts` | Read-only `GET /api/v2/alerts` against one configured Alertmanager; no redirects; bounded alert count and response; TSV output sorted by start time. An action that sets a credential file (root-owned, mode 0600) must declare `run_as: root`. |
| `starrocks_query` | One SELECT, SHOW, DESC or EXPLAIN statement sent to a StarRocks frontend over the MySQL protocol (`tcp://host:port`). The read-only boundary has three parts: a database account that holds SELECT only, a lexical SQL guard, and a session timeout with row and byte limits (at most 500 rows, 1 MiB, 10 s; configuration can only lower them). StarRocks has no read-only transaction, so the guard does not replace the account's grants. Readable tables are set by those grants. Profile statements are always rejected; `EXPLAIN ANALYZE` is rejected unless `allow_explain_analyze` is set. |
| `starrocks_diag` | Fixed diagnostics for a StarRocks frontend: cluster status, running queries, slow queries from the audit table, profile list, `ANALYZE PROFILE` and a profile summary with rule findings. The handler builds every statement; the caller chooses an `op` and bounded parameters. The account needs SYSTEM-level OPERATE, so use a separate account from `starrocks_query`. The optional `profile_run` op runs a caller's SELECT, is off by default and passes the SQL guard first. |
| `dremio_query` | One SELECT, SHOW, DESCRIBE or EXPLAIN PLAN statement run as a Dremio job through the REST API (`http(s)://host:port`): login, submit, poll, read the first page (at most 500 rows, 1 MiB, 10 s), then cancel and log out. Dremio 24.1 has no permission boundary: every account is an administrator. The lexical SQL guard is the only write restriction on the Dremio side, and each data source behind Dremio must use a read-only account. |
| `dremio_diag` | Fixed Dremio requests: nodes and memory, job list, one job, a job profile summary with rule findings, and reflections. The caller supplies no SQL; `builtin_config.ops` can pin an action to a single `op`. Dremio has no permission boundary, so the fixed requests are the write restriction. |

Use `builtin_config` to narrow the handler's defined limits and resource
allowlists. Database handlers (`mysql_query`, `redis_command`, `starrocks_query`,
`starrocks_diag`, `dremio_query` and `dremio_diag`) use the privileged helper to
read host-local credentials even if `run_as` is omitted. `log_search`, `http_get` and
`alertmanager_alerts` without `run_as` run directly as the agent. `log_search` with no matches and `http_get`
with a non-success HTTP status can return exit code zero; inspect the result
and HTTP status, not just the process exit code.

Unsupported executables or features are reported as `unsupported` on the host.
A successful catalog load does not prove every action is executable.
Review the [example catalog](https://github.com/liubing0806/allowops/tree/main/examples/catalog)
and the builtin configuration references in the source repository before use.
