"""Check deployment boundaries in a rendered Allowops chart (local tool)."""
import sys
from pathlib import Path

import yaml

documents = [item for item in yaml.safe_load_all(Path(sys.argv[1]).read_text()) if item]
config = next(item for item in documents if item["kind"] == "ConfigMap")["data"]
gateway = yaml.safe_load(config["gateway.yaml"])
exporter = yaml.safe_load(config["exporter.yaml"])
enabled = exporter.get("audit", {}).get("export", {}).get("enabled")
assert enabled is True, f"Exporter audit.export.enabled: expected True, actual {enabled!r}"
enabled = gateway.get("audit", {}).get("export", {}).get("enabled")
assert enabled is False, f"API gateway audit.export.enabled: expected False, actual {enabled!r}"

deployment = next(item for item in documents if item["kind"] == "Deployment")
pod = deployment["spec"]["template"]["spec"]
assert deployment["spec"]["replicas"] >= 2
assert pod["securityContext"]["runAsUser"] == 65532
assert pod["securityContext"]["runAsNonRoot"]
assert pod["containers"][0]["securityContext"]["capabilities"]["drop"] == ["ALL"]
assert all(mount["name"] != "audit" for mount in pod["containers"][0]["volumeMounts"])
assert pod["terminationGracePeriodSeconds"] >= int(gateway["gateway"]["shutdown_grace"][:-1]) + 5

states = [item for item in documents if item["kind"] == "StatefulSet"]
if states:
    assert len(states) == 1
    assert states[0]["spec"]["replicas"] == 1
    assert states[0]["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"] == ["ReadWriteOnce"]
service = next(item for item in documents if item["kind"] == "Service" and item["spec"].get("type"))
assert service["spec"]["selector"]["app.kubernetes.io/component"] == "gateway"
assert service["spec"]["ports"][0]["port"] == 443
assert service["spec"]["ports"][0]["protocol"] == "TCP"
job = next(item for item in documents if item["kind"] == "Job")
assert job["metadata"]["annotations"]["helm.sh/hook"] == "pre-install,pre-upgrade"
assert job["spec"]["template"]["spec"]["containers"][0]["args"] == ["migrate"]
print("Audit export, replicas, security, shutdown, L4 service and migration boundaries passed.")

assert gateway["audit"]["cursor_key_file"] == exporter["audit"]["cursor_key_file"]
assert gateway["output"] == exporter["output"]
assert gateway["output"]["bucket"] and gateway["output"]["region"]
for workload in [deployment, *states]:
    spec = workload["spec"]["template"]["spec"]
    container = spec["containers"][0]
    assert container["ports"] == [{"name": "tls", "containerPort": 8443}]
    for probe, path in (("startupProbe", "/health/live"),
                        ("livenessProbe", "/health/live"),
                        ("readinessProbe", "/health/ready")):
        assert container[probe]["httpGet"] == {"scheme": "HTTPS", "path": path, "port": "tls"}
        assert container[probe]["timeoutSeconds"] >= 5
    environment = {item["name"]: item for item in container["env"]}
    assert environment["AWS_SHARED_CREDENTIALS_FILE"]["value"] == "/run/allowops/credentials/aws-credentials"
    volumes = {volume["name"]: volume for volume in spec["volumes"]}
    assert volumes["audit-secret"]["secret"]["secretName"] == next(volume["secret"]["secretName"] for volume in pod["volumes"] if volume["name"] == "audit-secret")
    assert volumes["output-secret"]["secret"]["secretName"]
    assert "WEED_S3_SSE_KEY" not in environment
print("HTTPS probes, shared audit key and output credential/configuration boundaries passed.")
