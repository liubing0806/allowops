# Example policies

[read-only.yaml](read-only.yaml) grants `ops-reader` read-risk actions and output
on hosts with both `env=test` and `team=ops`, and explicitly denies write/dangerous
actions. [maintenance.yaml](maintenance.yaml) grants `ops-maintainer` on team
`ops` two exact actions on those hosts between 08:00 and 18:00 UTC. It denies
dangerous actions even if a named action later changes risk.
[java-diagnostics.yaml](java-diagnostics.yaml) separates the Arthas actions of
the example catalog: `java-reader` and `java-diagnostician` may run the twelve
`jvm_arthas_*` L1 actions (attach and run a command, no class is enhanced) and
read their output on those hosts at any hour. Only `java-diagnostician` may run
the five L2 actions `jvm_arthas_watch`, `jvm_arthas_trace`, `jvm_arthas_stack`,
`jvm_arthas_monitor` and `jvm_arthas_jad`, which enhance classes or decompile
them, and only between 09:00 and 17:00 UTC. These are independent full-policy
examples, not fragments to apply together.

In the Java example, the L2 output (method arguments, return values,
decompiled source) has its own `view_output` rule without a time window, so a
diagnostician can read a result after the window closes. Other roles have no
allow rule for the L2 actions and are denied. `java-reader` also has an
explicit deny for executing them and reading their output, so a broader allow
added later, such as `risks: [write]`, does not grant L2. Because a deny takes
precedence, an identity that holds both `java-reader` and `java-diagnostician`
is denied the L2 actions; give such a person only `java-diagnostician`, which
also grants L1. A user's cancellation of a job rechecks the execution
permission, including the time window: after 17:00 a diagnostician cannot
cancel an L2 job, and the action's own timeout ends it.

All three retain admin management permissions and publisher publication permissions.
They deliberately do not give admin unrestricted action execution. Review this
difference from the gateway's initial default before applying. Assign the example
roles to actual identities and set authorization labels at the gateway. Reported
labels cannot satisfy policy conditions; unlabeled hosts always deny execution.

`actions` and `risks` match by OR. The maintenance example omits a read-risk allow
condition so it does not accidentally authorize every read action. A deny takes
precedence. No match denies. Time intervals are half-open and use an explicit
timezone.

From the repository root, after login:

```sh
allowops policy get > current-rules.yaml
allowops policy test -f examples/policy/read-only.yaml
allowops policy apply -f examples/policy/read-only.yaml --reason 'apply reviewed test policy'
```

`apply` replaces the whole rule set and automatically runs another simulation
before saving. Review `test` first; it does not prompt for confirmation. Retain
an operator-controlled `bootstrap_admins` recovery identity. These templates are
not a recommendation to replace an existing production policy unchanged.
See the [policy guide](../../website/policies.md).
