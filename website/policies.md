# Policies

The gateway embeds Open Policy Agent (OPA) with a fixed Rego program. Operators
provide structured rule data, not arbitrary Rego. Precedence is strictly
`deny > require_approval > allow > default deny`; no match and evaluation errors
deny. Execution also requires at least one gateway-managed authorization label
on every target.

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
| `admin` | Management and reading (including inventory, changes, knowledge, `view_approvals` and `approve_jobs`), plus all actions on labeled hosts, including dangerous actions. |
| `operator` | Host management/reading, join tokens, inventory, changes, knowledge, job metadata and system status. |
| `auditor` | Audit, job metadata and output. |
| `viewer` | Host/catalog/job metadata, inventory, changes and knowledge. |
| `publisher` | Publish catalogs. |

Only admin has default execution access. The other roles need explicit action
rules. Configuration `bootstrap_admins` preserves policy modification access as
a recovery path; it is not an unrestricted execution identity.

## Context plugin access after an upgrade

`entities_search` requires `view_inventory`, `changes_list` requires
`view_changes`, and `runbooks_search`, `runbooks_read` and MCP runbook
resources require `view_knowledge`. New installations grant all three to admin,
operator and viewer. Upgrades preserve the stored policy, so existing roles do
not gain these permissions automatically.

Follow this upgrade order to avoid disruption in rolling deployments:

1. Before upgrading binaries, rename, re-sign and publish any active catalog
   action named `entities_search`, `changes_list`, `runbooks_search` or
   `runbooks_read` (these names are reserved; catalog verification rejects them
   and serves HTTP 503 on `/mcp`).
2. Upgrade all `allowops-gateway` instances to the new binary first so every
   instance recognizes `view_changes` and `view_knowledge`.
3. Export the current policy with `allowops policy get > rules.yaml`, add
   `view_inventory`, `view_changes` and/or `view_knowledge` to the rules for
   the roles that need them, retain all other rules, run
   `allowops policy test -f rules.yaml`, then run
   `allowops policy apply -f rules.yaml --reason 'grant context plugin access'`.
   You can also edit, simulate and save the policy in the console.
4. Before rolling back to an older gateway binary, remove `view_changes` and
   `view_knowledge` from the active policy first.

`view_inventory`, `view_changes` and `view_knowledge` are global operations. A
rule with `host_labels` does not match them. Hostnames in inventory results
still require `view_hosts` for each host. Entities whose associated hosts are
all hidden are removed before cross-source merging. Entities configured without
hosts remain visible to callers with `view_inventory`. Passing a returned
selector to an action checks execution permission on each target.

## Rule shape

Policy YAML has a `rules` list. Rules use `name`, `effect: allow|deny|require_approval`,
required `roles` and `operations`, and optional `teams`, `owners`, `actions`,
`risks`, `host_labels`, `hours`, `source_cidrs` and (for `require_approval`)
`approval`. `roles: ['*']` matches any role. Action wildcard syntax is exact
names or `'*'`; it is not a general glob pattern.

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
  - name: prod-write-needs-approval
    effect: require_approval
    roles: [ops-agent]
    operations: [execute_action]
    risks: [write]
    host_labels:
      env: prod
    approval:
      approver_roles: [sre-approver, admin]
      min_approvals: 1
      ttl_seconds: 1800
      allow_owner_approve: false
```

`effect: require_approval` is allowed only on `operations: [execute_action]`
and requires non-empty `approval.approver_roles`. When multiple
`require_approval` rules or hosts match a single job, the gateway aggregates
constraints strictly: `min_approvals` takes the maximum, `ttl_seconds` takes
the minimum, `allow_owner_approve` combines by AND, and
`required_approver_role_sets` requires satisfying every matched rule's role set
(AND of OR-sets). If any target host matches `deny`, the whole job is denied
without creating an approval request.

See the [HITL approval policy example](https://github.com/liubing0806/allowops/blob/main/examples/policy/hitl-approval.yaml)
for a complete policy with `require_approval`, `view_approvals`, and `approve_jobs`.
New installations grant `view_approvals` and `approve_jobs` only to `admin`;
upgrades preserve existing database policies without silent mutation.

This fragment alone is not a replacement for an installation's management
rules. The [example policy](https://github.com/liubing0806/allowops/blob/main/examples/policy/read-only.yaml)
includes administrator recovery permissions and a separate output rule. The
[Java diagnostics example](https://github.com/liubing0806/allowops/blob/main/examples/policy/java-diagnostics.yaml)
grants the Arthas L2 actions, which enhance classes or decompile them, to one
role in a time window, separately from the Arthas L1 actions.
`hours` uses `from`, `to`, `timezone`; it is a half-open same-day interval with
`0 <= from < to <= 24`. Use two rules for an overnight window. Supply explicit
IANA timezones. Source-network rules use CIDR notation; choose your own networks
without copying deployment addresses into a public policy repository.

Operation names are `execute_action`, `approve_jobs`, `modify_policy`,
`manage_service_accounts`, `manage_hosts`, `create_join_token`,
`manage_user_roles`, `publish_catalog`, `view_hosts`, `view_inventory`,
`view_changes`, `view_knowledge`, `view_catalog`, `view_jobs`, `view_approvals`,
`view_output`, `view_audit` and `view_system`.

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
