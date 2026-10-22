"""Check the default demo's storage, identity and isolation boundaries."""
from pathlib import Path

import yaml

root = Path(__file__).resolve().parent
config = yaml.safe_load((root / "compose.yaml").read_text())
services = config["services"]
assert "seaweedfs" in services, "Default Compose must provide the SeaweedFS S3 service"
storage = services["seaweedfs"]
assert storage["image"] == (
    "chrislusf/seaweedfs:4.46@sha256:"
    "08d516132314207d10c8e37cbffc1f32b147d870169688734cc61c6231625b62"
)
assert "-s3" in storage["command"]
assert "-master.telemetry=false" in storage["command"]
assert "-s3.autoCreateBucket=false" in storage["command"]
assert "ldap" in services and "admin-tool" in services
assert services["gateway"]["depends_on"]["ldap"]["condition"] == "service_healthy"
assert services["ready"]["depends_on"]["storage-init"]["condition"] == "service_completed_successfully"
assert config["networks"]["default"]["internal"] is True
assert all(not service.get("ports") for service in services.values())
for name in ("ldap", "admin-tool", "storage-init"):
    mounts = services[name]["volumes"]
    assert not any("ca.key" in mount or "/secrets:" in mount for mount in mounts), name
assert "compose.local-" not in (root / "quickstart-local.sh").read_text()
print("Default S3 storage, LDAPS, initialization and network isolation checks passed.")

health = services["gateway"]["healthcheck"]["test"]
assert health == ["CMD", "/usr/bin/allowops-gateway", "health", "--url",
                  "https://localhost:8443/health/ready", "--ca-file",
                  "/run/allowops/credentials/tls-ca.crt"]
assert services["seaweedfs"]["env_file"] == "./.local/secrets/seaweedfs.env"
assert services["gateway"]["environment"]["AWS_SHARED_CREDENTIALS_FILE"] == "/run/allowops/credentials/aws-credentials"
assert "WEED_S3_SSE_KEY" not in services["gateway"]["environment"]
assert "--token-file" in (root / "demo-host.sh").read_text()
assert '--token "' not in (root / "demo-host.sh").read_text()
assert "verify-job" in (root / "quickstart-local.sh").read_text()
print("Gateway healthcheck, file-only secret delivery and real job verification configured.")

postgres_probe = services["postgres"]["healthcheck"]["test"]
assert "-h 127.0.0.1" in postgres_probe[-1], (
    f"PostgreSQL healthcheck must wait for TCP, not the init Unix socket: {postgres_probe!r}"
)
print("PostgreSQL readiness waits for the final TCP listener before migration.")
