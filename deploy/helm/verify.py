"""Check deployment boundaries in a rendered Allowops chart (local tool)."""
import argparse
import stat
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml


def verify(rendered, values=None, catalog_keys=(), partitions_disabled=False):
    documents = [item for item in yaml.safe_load_all(rendered) if item]
    config = next(item for item in documents if item["kind"] == "ConfigMap")["data"]
    gateway = yaml.safe_load(config["gateway.yaml"])
    exporter = yaml.safe_load(config["exporter.yaml"])
    for cfg, expected in ((gateway, False), (exporter, True)):
        enabled = cfg.get("audit", {}).get("export", {}).get("enabled")
        assert enabled is expected, f"audit.export.enabled: expected {expected}, actual {enabled!r}"

    deployment = next(item for item in documents if item["kind"] == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    audit_secret = next(volume["secret"] for volume in pod["volumes"] if volume["name"] == "audit-secret")
    assert deployment["spec"]["replicas"] >= 2
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
    migration_pod = job["spec"]["template"]["spec"]
    migration_container = migration_pod["containers"][0]
    assert migration_container["args"] == ["migrate"]

    cronjobs = [item for item in documents if item["kind"] == "CronJob"]
    if partitions_disabled:
        assert not cronjobs, "Expected partition maintenance CronJob to be disabled"
    else:
        assert len(cronjobs) == 1, f"Expected one partition maintenance CronJob, found {len(cronjobs)}"
        cronjob = cronjobs[0]
        assert cronjob["apiVersion"] == "batch/v1"
        assert len(cronjob["metadata"]["name"]) <= 52
        assert "helm.sh/hook" not in cronjob["metadata"].get("annotations", {})
        cron = cronjob["spec"]
        assert cron["schedule"] and cron["timeZone"] == "Etc/UTC"
        assert cron["concurrencyPolicy"] == "Forbid"
        assert cron["successfulJobsHistoryLimit"] == 1 and cron["failedJobsHistoryLimit"] == 3
        maintenance_job = cron["jobTemplate"]["spec"]
        assert maintenance_job["activeDeadlineSeconds"] > 0
        maintenance_pod = maintenance_job["template"]["spec"]
        assert maintenance_pod["restartPolicy"] == "Never"
        assert maintenance_pod["automountServiceAccountToken"] is False
        assert maintenance_pod["securityContext"] == migration_pod["securityContext"] == {
            "runAsNonRoot": True, "runAsUser": 65532, "runAsGroup": 65532,
            "seccompProfile": {"type": "RuntimeDefault"},
        }
        maintenance_container, = maintenance_pod["containers"]
        command, months_flag, months = maintenance_container["args"]
        assert command == "ensure-partitions" and months_flag == "--months"
        assert isinstance(months, str) and 1 <= int(months) <= 120
        assert maintenance_container["image"] == migration_container["image"]
        assert maintenance_container["env"] == migration_container["env"]
        maintenance_env, = maintenance_container["env"]
        assert maintenance_env["name"] == "ALLOWOPS_DATABASE_URL"
        secret = maintenance_env["valueFrom"]["secretKeyRef"]
        assert secret["name"] and secret["key"]
        assert maintenance_container["securityContext"] == migration_container["securityContext"] == {
            "allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        }
        if values is not None:
            expected = values.get("imagePullSecrets", [])
            actual = maintenance_pod.get("imagePullSecrets", [])
            assert actual == expected, f"CronJob imagePullSecrets: expected {expected}, actual {actual}"

    for workload in [deployment, *states, job]:
        spec = workload["spec"]["template"]["spec"]
        security = spec["securityContext"]
        assert spec["automountServiceAccountToken"] is False
        assert security["runAsUser"] == security["runAsGroup"] == 65532
        assert security["runAsNonRoot"] is True
        assert security["seccompProfile"] == {"type": "RuntimeDefault"}
        for container in spec["containers"] + spec.get("initContainers", []):
            security = container["securityContext"]
            assert security["allowPrivilegeEscalation"] is False
            assert security["readOnlyRootFilesystem"] is True
            assert security["capabilities"]["drop"] == ["ALL"]
        if values is not None:
            expected = values.get("imagePullSecrets", [])
            actual = spec.get("imagePullSecrets", [])
            assert actual == expected, f'{workload["kind"]} imagePullSecrets: expected {expected}, actual {actual}'

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
        assert environment["AWS_EC2_METADATA_DISABLED"]["value"] == "true"
        assert environment["ALLOWOPS_DATABASE_URL"]["valueFrom"]["secretKeyRef"]["name"]
        assert "WEED_S3_SSE_KEY" not in environment
        volumes = {volume["name"]: volume for volume in spec["volumes"]}
        mounts = {mount["name"]: mount for mount in container["volumeMounts"]}
        assert spec["securityContext"]["fsGroup"] == 65532
        assert mounts["credentials"]["readOnly"] is True
        assert volumes["credentials"]["emptyDir"] == {"medium": "Memory"}
        for name in ("secret", "audit-secret", "output-secret"):
            assert volumes[name]["secret"]["defaultMode"] == 0o440
            assert volumes[name]["secret"]["secretName"]
        assert volumes["audit-secret"]["secret"] == audit_secret
        if values is not None:
            assert container["env"][3:] == values.get("extraEnv", [])
            assert container.get("envFrom", []) == values.get("envFrom", [])
            for volume in values.get("extraVolumes", []):
                assert volumes[volume["name"]] == volume
            for mount in values.get("extraVolumeMounts", []):
                assert mounts[mount["name"]] == mount

    if values is not None:
        expected = values.get("gateway", {})
        for cfg in (gateway, exporter):
            assert cfg["gateway"].get("certificate_ttl") == expected.get("certificateTTL")
            assert cfg["providers"] == expected.get("providers", [])
            if expected.get("jobs"):
                assert cfg["jobs"] == expected["jobs"]
            else:
                assert "jobs" not in cfg
        verify_credentials(pod["initContainers"][0]["args"][0], catalog_keys)


def verify_credentials(script, catalog_keys):
    with TemporaryDirectory() as directory:
        root = Path(directory)
        tls_files = ["ca.crt", "ca.key", "tls.crt", "tls.key"]
        audit_file = "audit-cursor-key"
        output_file = "aws-credentials"
        for mount, names in (
            ("secret", [*tls_files, "unrelated.pub.pem", *catalog_keys]),
            ("audit-secret", [audit_file]),
            ("output-secret", [output_file]),
        ):
            projection = root / mount / "..data"
            projection.mkdir(parents=True)
            for name in names:
                (projection / name).write_text(name)
                (projection / name).chmod(0o440)
                (projection.parent / name).symlink_to(Path("..data") / name)
            script = script.replace(f"/{mount}/", f"{mount}/")
        script = script.replace("/run/allowops", "run")
        subprocess.run(["/bin/sh", "-ec", script], cwd=root, check=True)
        credentials = root / "run/credentials"
        catalog = credentials / "catalog-keys"
        actual_keys = {path.name for path in catalog.iterdir()}
        assert actual_keys == set(catalog_keys), f"Catalog keys: expected {set(catalog_keys)}, actual {actual_keys}"
        for path in (credentials, catalog):
            assert stat.S_IMODE(path.stat().st_mode) == 0o700
        files = [credentials / name for name in [*tls_files, audit_file, output_file]]
        for path in [*files, *catalog.iterdir()]:
            assert path.is_file() and not path.is_symlink() and path.read_text() == path.name
            assert stat.S_IMODE(path.stat().st_mode) == 0o600
        if len(catalog_keys) > 1:
            removed, *remaining = catalog_keys
            (root / "secret" / removed).unlink()
            subprocess.run(["/bin/sh", "-ec", script], cwd=root, check=True)
            actual_keys = {path.name for path in catalog.iterdir()}
            assert actual_keys == set(remaining), f"Retired catalog key {removed} was retained: {actual_keys}"


def verify_chart():
    chart = Path(__file__).resolve().parent / "allowops"
    production = {
        "imagePullSecrets": [{"name": "registry"}],
        "extraEnv": [{"name": "OIDC_CLIENT_SECRET", "valueFrom": {
            "secretKeyRef": {"name": "oidc", "key": "client-secret"},
        }}],
        "envFrom": [{"secretRef": {"name": "ldap"}}],
        "extraVolumes": [{"name": "provider-ca", "secret": {"secretName": "provider-ca"}}],
        "extraVolumeMounts": [{"name": "provider-ca", "mountPath": "/etc/provider-ca", "readOnly": True}],
        "gateway": {
            "certificateTTL": "168h",
            "jobs": {"wait_seconds": 15, "max_wait_seconds": 60, "batch_size": 10, "max_failures": 0},
            "providers": [
                {"id": "oidc", "kind": "oidc", "client_secret_env": "OIDC_CLIENT_SECRET",
                 "ca_file": "/etc/provider-ca/ca.crt"},
                {"id": "ldap", "kind": "ldap", "bind_password_env": "LDAP_BIND_PASSWORD",
                 "ca_file": "/etc/provider-ca/ca.crt"},
            ],
        },
    }
    for name, values, keys, disabled in (
        ("Default", {}, ["catalog.pub.pem"], False),
        ("Production", production, ["catalog.pub.pem", "catalog-next.pub.pem"], False),
        ("PartitionsDisabled", {"partitions": {"enabled": False}}, ["catalog.pub.pem"], True),
    ):
        rendered = subprocess.run(
            ["helm", "template", "allowops", str(chart), "--values", "-"],
            input=yaml.safe_dump(values), stdout=subprocess.PIPE, text=True, check=True,
        ).stdout
        verify(rendered, values, keys, partitions_disabled=disabled)
        print(f"{name} chart verification passed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", nargs="?", type=Path)
    parser.add_argument("--partitions-disabled", action="store_true")
    args = parser.parse_args()
    if args.manifest is not None:
        verify(args.manifest.read_text(), partitions_disabled=args.partitions_disabled)
        print("Rendered chart verification passed.")
    else:
        verify_chart()
