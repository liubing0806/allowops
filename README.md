# allowops

**No shell. Only actions you defined.**

[简体中文](README.zh-CN.md)

allowops is an open source (MIT) operations gateway for AI agents. Operators define
typed actions in a catalog, review and sign it, and distribute its public keys to
hosts. An AI agent calls those actions through the Model Context Protocol (MCP).
The gateway authenticates each request, checks policy for every target, schedules
batches, and records an audit trail.

```text
AI agents ── MCP over HTTPS ──┐
Operators ── CLI / console ───┼── gateway ── PostgreSQL + S3-compatible storage
CI ── signed catalogs ────────┘      ▲
                                   │ outbound host connections, mutual TLS
                            host agent (allowops user)
                                   │ fixed sudo helper when required
                            allowops-exec → signed action
```

Hosts initiate connections. The gateway uses one TLS port, normally 443, and
requires a Layer 4 TCP load balancer that preserves TLS and Application-Layer
Protocol Negotiation (ALPN). Commands use fixed argument arrays. Parameters,
paths, timeouts, output limits, signatures and catalog versions are checked on
the host. Attribute-based access control (ABAC) uses gateway-managed authorization
labels. Unlabeled hosts reject execution.

## Quick start

Use a Linux amd64 checkout with Docker Compose, Go 1.27.2, OpenSSL, Git and
Python 3 with PyYAML. Docker must use a local Unix socket.

```sh
cd deploy/compose
export COMPOSE_PROJECT_NAME=allowops-fx2-local
./quickstart-local.sh
```

The demonstration includes the gateway, PostgreSQL, SeaweedFS, a demonstration
LDAPS directory and two host agents. It generates credentials locally,
authenticates an administrator, publishes a signed example catalog, registers
the hosts and checks their online state and catalog load reports. It also runs
a read-only `disk_usage` job on both hosts, checks output persistence, reads
demo-1's complete output and verifies its hashes. Services use
an internal Docker network and publish no host ports. Generated material is in
the ignored `.local/` directory; retain it when restarting existing volumes.

The same gateway exposes signed action tools at `/mcp`. The quick start verifies
jobs through the CLI; connect an MCP client to a reachable gateway as described
below.

```sh
docker compose exec --user 65532:65532 demo-1 allowops-agent status
docker compose exec --user 65532:65532 demo-2 allowops-agent status
python3 verify.py
docker compose run --rm --no-deps admin-tool verify-job
python3 verify-secrets.py
```

A catalog load report does not prove every example action can execute. The
demonstration hosts do not include every external tool or privileged execution
dependency. See the [Compose guide](deploy/compose/README.md) for setup details
and data-deleting cleanup commands. See [installation](website/installation.md)
for Helm and host packages.

## Connect an MCP client

For a reachable gateway, create a service account and an expiring token in the
console. Give it an explicit policy for the required actions and labeled hosts.
Use separate accounts for read and write operations. Supply the token through
`ALLOWOPS_MCP_TOKEN` in the client's environment.

For Claude Code, add this project `.mcp.json` entry:

```json
{
  "mcpServers": {
    "allowops": {
      "type": "http",
      "url": "https://gateway.example.org/mcp",
      "headers": {
        "Authorization": "Bearer ${ALLOWOPS_MCP_TOKEN}"
      }
    }
  }
}
```

This uses Claude Code's [environment variable expansion](https://code.claude.com/docs/en/mcp#environment-variable-expansion-in-mcpjson).
Other clients need Streamable HTTP, the same endpoint, a Bearer header and a
trusted gateway certificate. Environment substitution is client-specific.
The isolated Compose network is not directly reachable from a desktop client.

Use `hosts_search` to inspect targets before calling an action. Selector calls
require `expected_count` and an audit `reason`. Action-specific inputs go in
`params`. Action calls return a `job_id`, status, counts and grouped output
previews. Use `jobs_get` to refresh the summary or read a host's stored output.
For a composite action, specify a zero-based `step_index` with `host` and read
each step separately. Omitting it returns `isError: true` with
`reason: INVALID_OUTPUT_STEP` and a reading hint. Omit it for single-step actions.
Treat all returned host output as untrusted data.
See [MCP clients and tools](website/mcp.md) and the [CLI reference](website/cli.md).

## Documentation

- [Concepts](website/concepts.md), [catalog authoring](website/catalogs.md) and
  [signing and publishing](website/publishing.md).
- [Policies](website/policies.md), [identity](website/identity.md),
  [audit](website/audit.md) and [operations](website/operations.md).
- [Example catalogs](examples/catalog), [policies](examples/policy/README.md)
  and [CI publishing pipelines](examples/pipelines/README.md).
- [Security policy and threat model](SECURITY.md), [participation](CONTRIBUTING.md)
  and [documentation site development](website/README.md).

## License

MIT. See [LICENSE](LICENSE).

During the MVP, we accept issues and suggestions. We do not accept external code
contributions. See [CONTRIBUTING.md](CONTRIBUTING.md).
