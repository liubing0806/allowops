# Example policies

[read-only.yaml](read-only.yaml) grants `ops-reader` read-risk actions and output
on hosts with both `env=test` and `team=ops`, and explicitly denies write/dangerous
actions. [maintenance.yaml](maintenance.yaml) grants `ops-maintainer` on team
`ops` two exact actions on those hosts between 08:00 and 18:00 UTC. It denies
dangerous actions even if a named action later changes risk. These are independent
full-policy examples, not fragments to apply together.

Both retain admin management permissions and publisher publication permissions.
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
