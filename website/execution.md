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
| `mysql_query` | One SELECT/SHOW/DESC/EXPLAIN statement, read-only transaction, bounded rows and timeout. Host credentials stay in root-owned mode-0600 files. |
| `redis_command` | Read-only allowlist: GET, MGET, HGET, HLEN, TTL, TYPE, EXISTS, STRLEN, LLEN, SCARD, ZCARD, SCAN and INFO. |
| `http_get` | GET within signed URL prefixes; no redirects; bounded response. |

Use `builtin_config` to narrow the handler's defined limits and resource
allowlists. Database handlers use the privileged helper to read host-local
credentials even if `run_as` is omitted. `log_search` and `http_get` without
`run_as` run directly as the agent. `log_search` with no matches and `http_get`
with a non-success HTTP status can return exit code zero; inspect the result
and HTTP status, not just the process exit code.

Unsupported executables or features are reported as `unsupported` on the host.
A successful catalog load does not prove every action is executable.
Review the [example catalog](https://github.com/liubing0806/allowops/tree/main/examples/catalog)
and the builtin configuration references in the source repository before use.
