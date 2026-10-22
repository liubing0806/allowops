# Action catalogs

Keep operational catalogs in a reviewed repository. The public examples are
templates: review executable paths, available programs, privileges and allowed
resources for your hosts before publishing.

```text
catalog.yaml
actions/systemd_service_status.yaml
scripts/                         # only when using signed script actions
```

The catalog configuration identifies the catalog and shared limits:

```yaml
catalog_id: generic-ops
schema_version: 1
defaults:
  timeout: 10s
  max_output: 64KB
  batch_size: 20
  max_failures: 5
redact:
  builtin: [secrets]
```

## An action

```yaml
name: systemd_service_status
description: Read the status of an allowed systemd service.
risk: read
params:
  service:
    type: enum
    description: Service selected from the signed allowlist.
    values: [nginx, api]
exec: [/usr/bin/systemctl, status, '{service}', --no-pager]
timeout: 10s
max_output: 64KB
filters: [match, exclude, tail, head, count]
max_scan: 256MB
redact:
  builtin: [secrets]
```

Names match `^[a-z][a-z0-9_]{0,63}$`. Action names are globally unique across
current catalogs and cannot use the fixed MCP tool names. Descriptions are
required. Risk is `read`, `write` or `dangerous`; it is a policy attribute, not
a proof that the operation has no side effects. Optional `idempotent` supplies
the MCP idempotency annotation. Omitted `run_as` uses the low-privilege account
for ordinary commands. Set `run_as` to the reviewed execution identity when needed.

Use exactly one of `exec`, `steps`, `script` or `builtin`.
`exec[0]` is an absolute executable path. Do not put sudo in an action; use
`run_as`. Only an argv element equal to `{parameter_name}` is substituted.
Everything else is literal text. An optional group such as
`["--since", "{since}"]` is omitted in full if its parameter is absent.

## Parameter types

Every parameter has a description. `default` supplies an omitted value and
`optional: true` permits absence. Unknown fields, unknown parameters, missing
required values and incorrect types are rejected.

| Type | Constraints |
|---|---|
| `enum` | `values` is the allowlist. |
| `int` | `min`, `max`; preserve integer values. |
| `string` | `regex`, `max_len`; Go RE2 patterns. |
| `duration` | `max`; `format: go` by default, or `seconds`. |
| `path` | Required `allowed_roots`; the path must exist on the host. |
| `url` | Required `allowed_prefixes`; used by HTTP probes. |

Builtins also define `bool` and `string_array` inputs. Their schemas are owned
by allowops; follow the builtin definition rather than inventing arbitrary
handler parameters. CLI arrays use JSON string arrays; MCP uses JSON arrays.

String and path values beginning with `-` are rejected. Path resolution and
symlink checks happen on the host. Gateway validation cannot establish that a
path exists on a remote filesystem. Size suffixes KB and MB use powers of 1024.

Immediately before a command starts, the process that runs it (the root helper
when `run_as` is used, otherwise the agent itself) walks every component of each
resolved path value from `/` to the final entry without following links. Each
component must be owned by root or by the user the command runs as, must not be
a symbolic link, and must not be writable by group or other. A directory with
the sticky bit (such as `/tmp`) may be group or other writable, because other
users cannot replace entries they do not own; its child entries are still
checked. Otherwise the action is rejected with `PATH_NOT_TRUSTED`, without the
path in the message. This keeps a user who can write inside an allowed root
from swapping a component for a symbolic link after the check. Consequence: a
path under a directory that applications write with a different owner or with
group/other write permission, such as a log directory owned by a service user
and group-writable, is rejected. Make the directory and files writable only by
root or the run_as user, or choose a different `allowed_roots`. ACLs and mount
options are not examined.

## Limits and redaction

Set a timeout, `max_output` and, where scanning is involved, `max_scan`. Combined
actions share a total stdout/stderr output budget. Runtime callers can tighten
batch/failure limits, not increase the signed limits. stdout is redacted,
filtered and truncated in that order. stderr is redacted before truncation.

`secrets` is enabled by default; `pii` is optional. Custom rules use
`redact.custom: [{name, regex}]`. Action-level redaction overrides global rules,
so explicitly retain `secrets` when adding an override. Redaction is imperfect.
Do not define actions that intentionally expose credentials.

Validate before review and build:

```sh
allowops catalog validate examples/catalog
allowops catalog try systemd_service_status --dir examples/catalog --param service=nginx
```

`try` executes unsigned content on the current machine as the current user.
It does not apply gateway policy or elevate to `run_as`. Use a controlled test
host with suitable permissions. Continue with [execution capabilities](execution.md)
and [signing and publishing](publishing.md).
