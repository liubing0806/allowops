"""Check that provider secrets reach the gateway pods as Secret references (local tool).

Renders the chart with an LDAP and an OIDC provider whose secrets are read from
the environment, and asserts that both workloads receive secretKeyRef variables
while the ConfigMap carries only the variable names. Needs helm and PyYAML;
CI does not install helm, so this check is not part of `make script-checks`.

Usage: python3 deploy/helm/verify-provider-secrets.py
"""
import json
import subprocess
import tempfile
from pathlib import Path

import yaml

CHART = Path(__file__).resolve().parent / "allowops"
LDAP_SECRET = ("directory-credentials", "bind-password")
OIDC_SECRET = ("idp-credentials", "client-secret")

values = {
    "gateway": {
        "providers": [
            {"id": "directory", "kind": "ldap", "url": "ldaps://directory.example.org:636",
             "bind_dn": "cn=reader,dc=example,dc=org", "bind_password_env": "ALLOWOPS_LDAP_BIND_PASSWORD",
             "user_base_dn": "ou=people,dc=example,dc=org", "user_attribute": "uid"},
            {"id": "identity", "kind": "oidc", "issuer_url": "https://idp.example.org",
             "client_id": "allowops", "client_secret_env": "ALLOWOPS_OIDC_CLIENT_SECRET"},
        ],
        "providerSecretEnv": [
            {"name": "ALLOWOPS_LDAP_BIND_PASSWORD", "secretName": LDAP_SECRET[0], "key": LDAP_SECRET[1]},
            {"name": "ALLOWOPS_OIDC_CLIENT_SECRET", "secretName": OIDC_SECRET[0], "key": OIDC_SECRET[1]},
        ],
    },
}


def render(values_file: Path) -> subprocess.CompletedProcess:
    return subprocess.run(["helm", "template", "allowops", str(CHART), "-f", str(values_file)],
                          capture_output=True, text=True, check=False)


def write_values(directory: str, name: str, data: dict) -> Path:
    path = Path(directory) / name
    path.write_text(json.dumps(data), encoding="utf-8")
    return path


with tempfile.TemporaryDirectory() as directory:
    rendered = render(write_values(directory, "values.json", values))
    assert rendered.returncode == 0, f"helm template failed:\n{rendered.stderr}"
    documents = [item for item in yaml.safe_load_all(rendered.stdout) if item]
    workloads = [item for item in documents if item["kind"] in ("Deployment", "StatefulSet")]
    assert sorted(item["kind"] for item in workloads) == ["Deployment", "StatefulSet"], \
        f"expected a Deployment and an export StatefulSet, got {[item['kind'] for item in workloads]}"
    expected = {
        "ALLOWOPS_LDAP_BIND_PASSWORD": {"secretKeyRef": {"name": LDAP_SECRET[0], "key": LDAP_SECRET[1]}},
        "ALLOWOPS_OIDC_CLIENT_SECRET": {"secretKeyRef": {"name": OIDC_SECRET[0], "key": OIDC_SECRET[1]}},
    }
    for workload in workloads:
        environment = {item["name"]: item for item in workload["spec"]["template"]["spec"]["containers"][0]["env"]}
        for name, source in expected.items():
            actual = environment.get(name, {}).get("valueFrom")
            assert actual == source, f"{workload['kind']} env {name}: expected valueFrom {source!r}, actual {actual!r}"
        assert "ALLOWOPS_DATABASE_URL" in environment and "AWS_SHARED_CREDENTIALS_FILE" in environment

    config = next(item for item in documents if item["kind"] == "ConfigMap")["data"]
    for file, text in config.items():
        for name in expected:
            assert name in text, f"ConfigMap {file} must name {name}"
        for value in (*LDAP_SECRET, *OIDC_SECRET, "secretKeyRef"):
            assert value not in text, f"ConfigMap {file} must not contain {value!r}"
    print("Provider secret variables reach both workloads as Secret references; the ConfigMap holds only names.")

    for label, entry in (("missing key", {"name": "X_SECRET", "secretName": "s"}),
                         ("unknown field", {"name": "X_SECRET", "secretName": "s", "key": "k", "value": "plain"}),
                         ("reserved name", {"name": "ALLOWOPS_DATABASE_URL", "secretName": "s", "key": "k"})):
        bad = render(write_values(directory, "bad.json", {"gateway": {"providerSecretEnv": [entry]}}))
        assert bad.returncode != 0, f"{label}: expected the schema to reject the entry, helm template succeeded"
    print("Schema rejects entries with a missing key, an unknown field or a reserved name.")
