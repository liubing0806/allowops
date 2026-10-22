# Concepts

An **action** is a named operation with a fixed execution definition, typed
parameters, a risk classification and resource limits. A **catalog** is a
versioned, signed collection of actions. The host obtains commands from that
catalog, not from a command string supplied by an AI agent or the gateway.

```text
MCP client / CLI / console → gateway → PostgreSQL and S3-compatible storage
                               ▲
                               │ outbound mutual-TLS connection
                            host agent
                               │ privileged helper when required
                            signed action
```

The gateway authenticates people and service accounts, validates requests,
selects hosts, evaluates attribute-based access control (ABAC), schedules jobs
and records audit events. The low-privilege `allowops-agent` maintains the host
connection and verifies catalogs. `allowops-exec` independently verifies the
catalog before privileged operations and applies the signed execution identity.
The helper is invoked through a fixed sudo rule with no command-line arguments.
Database builtins that read root-owned credentials also use the helper.

## Hosts, labels and identities

Hosts initiate connections to the gateway; no inbound host port is required.
Gateway TLS and the host identity certificate authority (CA) are separate trust
systems. Registration pins the gateway TLS CA. Subsequent host RPCs use mutual
TLS and a short-lived host certificate with an immutable host ID.

Authorization labels are set by operators at the gateway. Reported labels such
as operating system information can filter inventory, but never grant access.
New hosts have no authorization labels and cannot execute actions, including
for an admin. Hostnames are globally unique. Deleting a host invalidates its
identity; registering that hostname again creates a new host ID.

## Jobs and targets

A **job** is one action invocation over a target set. A **task** is the execution
on one host. Select explicit hostnames or comma-separated `key=value` conditions
that all must match. Selectors require an exact `expected_count`. A count mismatch
or denial on any target rejects the whole request before dispatch.

Tasks run in batches. `batch_size` and `max_failures` may tighten the signed
limits. Failed, timed-out and unsupported tasks count toward the failure limit;
offline tasks do not. Remaining tasks are skipped when failures exceed the
threshold. `wait_seconds` controls how long the response waits, not the action
timeout. An offline host is not queued for later execution. A disconnect stops
the task's process group; execution and output are not replayed.

Job states are `queued`, `running`, `succeeded`, `partially_failed`, `failed`,
`cancelled` and `denied`. Denied submissions do not create an executable job.
Task states are `pending`, `running`, `succeeded`, `failed`, `timeout`, `offline`,
`skipped`, `cancelled` and `unsupported`.

MCP action tools submit jobs to the same service used by the CLI. Action calls
and `jobs_get` return authorized job summaries with counts, output groups and
offline hosts. Detailed MCP summaries list hostnames within each group. Use
`jobs_get` with `host` for stored output; see [MCP tools](mcp.md).

## Output and audit

Output is redacted on the host before it leaves the host. stdout can then be
filtered and both streams are bounded. Summaries group matching exit codes and
output hashes. Full output is stored asynchronously in S3-compatible storage;
storage failure does not turn a successful action into a failed action.
Reading previews or full output requires separate output authorization.

A composite action has ordered, named steps with separate output streams.
Read stored output one step at a time: MCP `jobs_get` requires `step_index` with
`host`, and CLI `jobs output` requires `--step`. Both use zero-based indexes.
Omitting the index for composite output is an `INVALID_OUTPUT_STEP` parameter
error; MCP also returns a hint to read each step separately. Omit the index for
single-step actions. Summary requests do not select an output step.

Output remains untrusted data and may contain prompt injection. Redaction can
miss sensitive data. Audit events contain decisions, identifiers and output
references/hashes rather than output bodies. See [audit](audit.md) and
[security](security.md) for the limits of those guarantees.
