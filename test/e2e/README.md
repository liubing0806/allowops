# Console end-to-end tests

Run `make e2e` from a Linux amd64 checkout with local Docker Compose, Go
(the version in `go.mod`), Node 24.19.0+, pnpm 10.33.2, OpenSSL, Git, and
Python 3 with PyYAML installed. The runner installs the locked packages and
pulls the fixed official Playwright Chromium image:

```sh
make e2e
```

Playwright is pinned to **1.62.1**, including its transitive browser package
in `pnpm-lock.yaml`. Tests run with one worker and no retries.

The runner reuses `deploy/compose` instead of introducing a second
testcontainers environment. That environment already provides TLS-verified
LDAPS, real CLI authentication, signed catalog publication, migrations,
PostgreSQL, SeaweedFS S3 storage, and the real host agent. Sources and Compose
scripts are copied to a fresh `/tmp` directory. The console is rebuilt there
before the gateway image is built, so tests exercise the current React code
through the gateway's embedded assets without changing tracked build output.
Go VCS stamping is disabled for the temporary non-checkout build. The running
gateway image ID must equal the newly built image's content digest.
Temporary gateway TLS certificates use RSA-2048 because Chromium fails the
demo's Ed25519 TLS handshake (`no suitable signature algorithm`). Host
identity and catalog signing keep the existing Ed25519 keys. The original
Compose configuration and preparation script are unchanged.

Each run gets its own random Compose project, image tags, volumes, and
internal network. No host ports are published. The browser runs in its own
container on that network at `https://gateway:8443`, avoiding host Chromium's
`ERR_NETWORK_CHANGED` during concurrent Docker tests. The official image is
pinned to version 1.62.1 and its Linux amd64 SHA-256 digest in `prepare.py`.
It runs as the current UID/GID without capabilities, with a read-only root
filesystem and writable temporary storage. It receives only test files,
evidence storage, and the two generated login passwords, with no Docker socket.
The runner rejects remote Docker endpoints. Gateway readiness verifies the
generated CA, PostgreSQL, and object storage; Chromium accepts that local
certificate with `ignoreHTTPSErrors`. No shared environment, SSH, or existing
application credentials are used. Builds and
dependency installation may download public dependencies and images.

The directory has one LDAP provider with generated administrator and viewer
credentials. The viewer is mapped to the default `viewer` role, which can
inspect jobs but cannot read output. Fixtures are created through the real
LDAP directory and management APIs; no database rows are inserted by tests.
Only `demo-1` starts. It loads the signed example catalog and executes the
read-only `disk_usage` action through the actual job service and agent.

Scenarios cover:

- LDAP login, secure session cookies, logout, and protected routes.
- Overview metrics and the actual completed job.
- Host list, authorization-label persistence, and selector filtering.
- Join-token creation, CSRF, and one-time secret handling.
- Catalog and `disk_usage` (exec), `host_snapshot` (steps),
  `nginx_access_stats` (script), and `mysql_query_readonly` (builtin) details.
- Policy rules and history.
- Jobs, task status, persisted stdout/stderr, and untrusted-output notice.
- Viewer output button, HTTP permission rejection, and translated notices (A34).
- Audit filtering and internal hash-chain verification.
- Chinese/English navigation and page labels.

Evidence is printed as `/tmp/allowops-p10b-evidence.<random>/`. It contains
page screenshots, the Playwright HTML report, build/cleanup logs, and commit,
image digest, URL, and project provenance. Join secrets and installation
commands are masked in screenshots. Network traces, videos, and persisted
browser sessions are disabled. Treat evidence as local test data. Inspect
screenshots manually for layout and readability; screenshot capture alone
does not establish visual correctness.

Exit and signal handlers remove this run's containers, volumes, network,
images, and temporary credentials. Evidence remains in `/tmp` for inspection.
Page defects should be recorded as failing tests and reported separately;
do not change gateway or console behavior in this test task.

G69 sets output pages to a 16 KiB default and 24 KiB maximum, within the
32 KiB JSON response budget. The Jobs page uses the system-reported default,
capped by its reported maximum, and omits the limit when system information
is unavailable. The administrator output and viewer permission tests retain
their HTTP 200 and 403 assertions without skips or expected-failure markers.

`.github/workflows/e2e-nightly.yml` runs daily at 18:00 UTC (02:00 Asia/Taipei)
and supports manual execution before a release. It uploads evidence for seven
days. The existing push/pull-request workflow is unchanged.
