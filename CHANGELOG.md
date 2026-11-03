# Release notes

## Unreleased

- Add the experimental gateway plugin API in `plugin/` and the Inventory
  extension point. Before 1.0, API changes may be incompatible and will be
  recorded here.
- Add `inventory.static` for a local topology YAML file and
  `inventory.host_labels` for entities derived from active host labels.
  Configure instances in `gateway.yaml` under `plugins`; see
  [the configuration example](examples/gateway.yaml) and
  [the topology example](examples/topology.yaml). Configuration and static file
  changes require a gateway restart.
- Add the read-only MCP tool `entities_search` when at least one inventory
  instance is available. Results include source IDs, visible hosts and selectors.
  The gateway redacts secrets and limits the complete tool result to 32KB.
- Show configured plugin provisioning health in system dependencies. An optional
  plugin that fails provisioning makes system status DEGRADED. A required plugin
  that fails provisioning prevents startup. The readiness check is unchanged.

### Upgrade steps

1. Grant `view_inventory` to the roles that need `entities_search`. Defaults
   include admin, operator and viewer only on first initialization. Upgrades do
   not change stored policies. Export the current policy with
   `allowops policy get > rules.yaml`, add the operation to the appropriate rules,
   retain the other rules, then run `allowops policy test -f rules.yaml` and
   `allowops policy apply -f rules.yaml --reason 'grant inventory access'`.
   You can also edit, simulate and save the policy in the console.
2. Rename any catalog action named `entities_search`, then sign and publish the
   updated catalog. This name is now reserved and catalog validation rejects it.
3. Configure inventory instances and restart the gateway. Without an available
   inventory instance, the MCP tool list is unchanged.


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
