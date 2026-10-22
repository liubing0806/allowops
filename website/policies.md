# Policies

The gateway embeds Open Policy Agent (OPA) with a fixed Rego program. Operators
provide structured rule data, not arbitrary Rego. A deny wins over an allow;
no match and evaluation errors deny. Execution also requires at least one
gateway-managed authorization label on every target.

Rules use authenticated role/team/owner attributes, operations, action names or
risks, host authorization labels, optional time windows and source networks.
Reported labels are never policy attributes. Lists within a condition match by
OR; different subject, host, time and network conditions combine by AND.
`actions` and `risks` are alternatives: if both are supplied, either can match.
To restrict an exact action list, do not add a broader `risks: [read]` allowlist
to the same rule.

## Defaults

| Role | Initial permissions |
|---|---|
| `admin` | Management and reading, plus all actions on labeled hosts, including dangerous actions. |
| `operator` | Host management/reading, join tokens, job metadata and system status. |
| `auditor` | Audit, job metadata and output. |
| `viewer` | Host/catalog/job metadata. |
| `publisher` | Publish catalogs. |

Only admin has default execution access. The other roles need explicit action
rules. Configuration `bootstrap_admins` preserves policy modification access as
a recovery path; it is not an unrestricted execution identity.

## Rule shape

Policy YAML has a `rules` list. Rules use `name`, `effect: allow|deny`, required
`roles` and `operations`, and optional `teams`, `owners`, `actions`, `risks`,
`host_labels`, `hours` and `source_cidrs`. `roles: ['*']` matches any role.
Action wildcard syntax is exact names or `'*'`; it is not a general glob pattern.

```yaml
rules:
  - name: readers-on-test
    effect: allow
    roles: [ops-reader]
    operations: [execute_action]
    risks: [read]
    host_labels:
      env: test
      team: ops
```

This fragment alone is not a replacement for an installation's management
rules. The [example policy](https://github.com/liubing0806/allowops/blob/main/examples/policy/read-only.yaml)
includes administrator recovery permissions and a separate output rule.
`hours` uses `from`, `to`, `timezone`; it is a half-open same-day interval with
`0 <= from < to <= 24`. Use two rules for an overnight window. Supply explicit
IANA timezones. Source-network rules use CIDR notation; choose your own networks
without copying deployment addresses into a public policy repository.

Operation names are `execute_action`, `modify_policy`, `manage_service_accounts`,
`manage_hosts`, `create_join_token`, `manage_user_roles`, `publish_catalog`,
`view_hosts`, `view_catalog`, `view_jobs`, `view_output`, `view_audit` and `view_system`.

## Review and apply

```sh
allowops policy get > rules.yaml
# Edit rules.yaml and retain the required management rules.
allowops policy test -f rules.yaml
allowops policy apply -f rules.yaml --reason 'restrict reader access to test hosts'
```

`apply` replaces the full policy, not just the rules in the file. It reads the
current version, simulates the candidate, displays changes and saves with an
optimistic concurrency check. Review the separate `test` result first; `apply`
does not prompt for interactive approval. Snapshot, version or permission changes
require a new simulation. Policies that leave no subject able to modify policy
are rejected. Historical rollback in the console also simulates and creates a
new version; it does not lower the policy version.

Reading a job summary and reading its output are separate permissions. Service
accounts can read/cancel only their own jobs. User cancellation rechecks execution
permission on every original target. A selector count is a safety check, not a
permission grant. See [MCP](mcp.md) for the request shape.
