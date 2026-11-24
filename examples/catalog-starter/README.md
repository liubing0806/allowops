# Starter Production Action Catalog (`starter-ops`)

This directory is a standalone starter subset of [`examples/catalog`](../catalog) designed for initial internal rollout.

## Scope & Safety Properties

- **19 read-only actions (`risk: read`)**: all actions run directly as the unprivileged `allowops` service user without `run_as: root`, `allowops-exec` elevation, or custom scripts.
- **Standalone replacement for initial rollout**: AllowOps enforces globally unique action names across simultaneously published catalogs. Publish `examples/catalog-starter` **instead of** `examples/catalog` during Phase 1 rollout, then expand to additional privileged/database/JVM actions later as needed.

## Included Actions (19)

| Category | Action | Description |
| --- | --- | --- |
| System & Resources | `system_load` | Read uptime and load averages. |
| System & Resources | `memory_usage` | Read memory and swap usage in megabytes. |
| System & Resources | `disk_usage` | Read filesystem capacity excluding temporary filesystems. |
| System & Resources | `disk_usage_paths` | Read filesystem capacity for an allowed path. |
| Process & Service | `process_find` | Find process identifiers by an allowed exact process name. |
| Process & Service | `process_top` | Read processes sorted by CPU consumption. |
| Process & Service | `systemd_service_status` | Read the status of an allowed systemd service. |
| Network & Local HTTP | `dns_lookup` | Resolve one host name through the host resolver. |
| Network & Local HTTP | `hosts_entries` | Read `/etc/hosts` with optional match filtering. |
| Network & Local HTTP | `http_get_local` | Probe an allowed local health endpoint with a bounded GET request. |
| Dubbo QoS (Local HTTP) | `dubbo_qos_get_address` | Show available provider addresses of one Dubbo service (credentials redacted). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_get_config` | Dump effective Dubbo configuration (credentials redacted). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_live` | Check Dubbo liveness (`GET /live`). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_logger_info` | Show Dubbo logger adapter and level (`GET /loggerInfo`). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_ls` | List Dubbo provider and consumer services (`GET /ls`). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_ps` | List Dubbo server ports (`GET /ps`). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_ready` | Check Dubbo readiness (`GET /ready`). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_startup` | Check Dubbo startup state (`GET /startup`). |
| Dubbo QoS (Local HTTP) | `dubbo_qos_version` | Show Dubbo framework version (`GET /version`). |

## Validate & Smoke-Test Locally

```bash
./bin/allowops catalog validate --dir examples/catalog-starter
./bin/allowops catalog try system_load --dir examples/catalog-starter
./bin/allowops catalog try disk_usage --dir examples/catalog-starter
./bin/allowops catalog try memory_usage --dir examples/catalog-starter
```

> Note: Before publishing to production, review parameter allowlists in `actions/disk_usage_paths.yaml`, `actions/http_get_local.yaml`, `actions/process_find.yaml`, and `actions/systemd_service_status.yaml` (and remove the `dubbo_qos_*` actions if your fleet does not run Dubbo).
