"""Use real login, service-account APIs and P4B CLI. Never write the database."""
import base64
import hashlib
import http.client
import json
import os
import ssl
import subprocess
import sys
import time
from pathlib import Path

local = Path(__file__).resolve().parent / ".local"
gateway = "https://gateway:8443"
ca = local / "secrets/tls-ca.crt"

def hostnames():
    """Demo hosts to register; default keeps the two-host quickstart unchanged."""
    names = [name.strip() for name in os.environ.get("ALLOWOPS_DEMO_HOSTS", "demo-1,demo-2").split(",")]
    names = [name for name in names if name]
    if not names:
        raise SystemExit("ALLOWOPS_DEMO_HOSTS is empty.")
    return names

def cli(*args, extra_env=None, input_text=None):
    env = os.environ.copy()
    env["XDG_CONFIG_HOME"] = str(local / "cli")
    env.update(extra_env or {})
    result = subprocess.run([str(local / "bin/allowops"), *args], input=input_text,
                            env=env, text=True, capture_output=True)
    private = [value for value in (extra_env or {}).values() if value]
    if input_text:
        private.append(input_text.strip())
    if any(value in result.stdout or value in result.stderr for value in private):
        raise SystemExit("Generated credentials appeared in CLI logs.")
    if result.returncode:
        raise SystemExit(result.stderr)
    return result.stdout

def rpc(service, method, payload):
    credentials = json.loads((local / "cli/allowops/credentials").read_text())
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    connection = http.client.HTTPSConnection("gateway", 8443, context=context, timeout=10)
    connection.request("POST", f"/allowops.v1.{service}/{method}", json.dumps(payload),
                       {"Content-Type": "application/json", "Connect-Protocol-Version": "1",
                        "Authorization": "Bearer " + credentials["token"]})
    response = connection.getresponse()
    body = json.loads(response.read(1 << 20))
    connection.close()
    if response.status != 200:
        # Do not print untrusted error messages or credential-bearing response bodies.
        raise SystemExit(f"{service}/{method} failed: HTTP {response.status}, code={body.get('code')}")
    return body

def main():
    os.umask(0o077)
    print(cli("login", "--gateway", gateway, "--ca-file", str(ca), "--provider", "demo",
              "--username", "demo-admin", "--password-stdin",
              input_text=(local / "auth/login-password").read_text()).strip())
    user = rpc("AuthService", "GetCurrentSession", {})["user"]
    assert "admin" in user.get("effectiveRoles", []), "LDAPS administrator role mapping missing"
    account = rpc("ServiceAccountService", "CreateServiceAccount",
                  {"name": "demo-publisher", "owner_user_id": user["userId"], "roles": ["publisher"]})["account"]
    publisher = rpc("ServiceAccountService", "CreateServiceAccountToken",
                    {"account_id": account["accountId"], "valid_days": 1})["secret"]
    published = json.loads(cli("catalog", "publish", "--file", str(local / "catalog.dsse.json"),
                               "--gateway", gateway, "--ca-file", str(ca),
                               "--token-env", "ALLOWOPS_DEMO_PUBLISHER_TOKEN", "--json",
                               extra_env={"ALLOWOPS_DEMO_PUBLISHER_TOKEN": publisher}))
    del publisher
    catalog = published["catalog"]
    print("Published signed catalog:", catalog["catalog"]["catalog_id"],
          catalog["catalog"]["version"], "actions=", catalog["action_count"])
    expected_pin = (local / "ca-pin").read_text().strip()
    names = hostnames()
    for hostname in names:
        token = json.loads(cli("jointoken", "create", "--uses", "1", "--ttl", "24h",
                               "--gateway", gateway, "--ca-file", str(ca), "--json"))
        assert token["ca_pin"] == expected_pin, "G35 returned a different TLS CA pin"
        assert token["upstream"] == "https://gateway:8443", "Join upstream differs from agent config"
        (local / "joins" / (hostname + ".token")).write_text(token["secret"] + "\n")
    if names == ["demo-1", "demo-2"]:
        print("Created two real single-use join tokens; secrets stored in local 0600 files.")
    else:
        print(f"Created {len(names)} real single-use join tokens ({', '.join(names)});"
              " secrets stored in local 0600 files.")

def ensure_mcp():
    """Create the persistent local MCP service account token once (P13).

    Reuses the existing account when present and never rewrites a stored token.
    The secret is written to a local 0600 file and never printed.
    """
    os.umask(0o077)
    token_file = local / "mcp-token"
    if token_file.is_file() and token_file.stat().st_size:
        print("MCP service account token already stored; reusing local 0600 file.")
        return
    print(cli("login", "--gateway", gateway, "--ca-file", str(ca), "--provider", "demo",
              "--username", "demo-admin", "--password-stdin",
              input_text=(local / "auth/login-password").read_text()).strip())
    user = rpc("AuthService", "GetCurrentSession", {})["user"]
    assert "admin" in user.get("effectiveRoles", []), "LDAPS administrator role mapping missing"
    accounts = rpc("ServiceAccountService", "ListServiceAccounts", {}).get("accounts", [])
    account = next((entry for entry in accounts if entry.get("name") == "local-mcp"), None)
    if account is None:
        account = rpc("ServiceAccountService", "CreateServiceAccount",
                      {"name": "local-mcp", "owner_user_id": user["userId"],
                       "description": "Persistent local Compose environment MCP client",
                       "roles": ["admin"]})["account"]
    secret = rpc("ServiceAccountService", "CreateServiceAccountToken",
                 {"account_id": account["accountId"], "description": "local-compose-mcp",
                  "valid_days": 365})["secret"]
    token_file.write_text(secret + "\n")
    token_file.chmod(0o600)
    print("Created MCP service account token (365 days); stored in local 0600 file.")

def verify_job():
    names = hostnames()
    cli("hosts", "label", *names, "--set", "environment=demo", "--json")
    started = json.loads(cli("run", "disk_usage", "--selector", "environment=demo",
                             "--expected-count", str(len(names)), "--reason", "Local Compose read-only verification",
                             "--wait-seconds", "30", "--json"))
    job_id = started["job"]["job_id"]
    deadline = time.monotonic() + 90
    while True:
        result = json.loads(cli("jobs", "get", job_id, "--wait-seconds", "5",
                                "--response-format", "detailed", "--json"))
        if result["job"]["status"] not in ("JOB_STATUS_QUEUED", "JOB_STATUS_RUNNING"):
            break
        if time.monotonic() >= deadline:
            raise SystemExit("Job completion timed out.")
    assert result["job"]["status"] == "JOB_STATUS_SUCCEEDED", result["job"]["status"]
    assert int(result["job"]["total_tasks"]) == len(names)
    groups = result["summary"]["groups"]
    assert sum(int(group["host_count"]) for group in groups) == len(names)
    assert {name for group in groups for name in group["hosts"]} == set(names)
    # Persistence is asynchronous: inspect task metadata before reading complete objects.
    while True:
        tasks = rpc("JobService", "ListTasks", {"job_id": job_id})["tasks"]
        assert len(tasks) == len(names)
        if all(task.get("outputStored", False) for task in tasks):
            break
        if time.monotonic() >= deadline:
            raise SystemExit("Job output persistence timed out (output_stored=false).")
        time.sleep(1)
    collected = {}
    for stream in ("stdout", "stderr"):
        offset = 0
        data = bytearray()
        while True:
            page = json.loads(cli("jobs", "output", job_id, "--host", "demo-1", "--stream", stream,
                                  "--offset", str(offset), "--json"))
            assert page["output_stored"] is True
            assert page["output_trust"] == "OUTPUT_TRUST_UNTRUSTED"
            chunk = base64.b64decode(page.get("data", ""), validate=True)
            next_offset = int(page.get("next_offset", 0))
            assert next_offset == offset + len(chunk)
            data.extend(chunk)
            if page.get("eof", False):
                break
            assert next_offset > offset, "Completed output page did not advance"
            offset = next_offset
        collected[stream] = bytes(data)
    group = next(group for group in groups if "demo-1" in group["hosts"])
    for stream in ("stdout", "stderr"):
        digest = base64.b64decode(group[stream + "_sha256"], validate=True)
        assert hashlib.sha256(collected[stream]).digest() == digest, "Object output digest differs from summary"
    assert b"Filesystem" in collected["stdout"]
    assert not collected["stderr"]
    if names == ["demo-1", "demo-2"]:
        print("PASS: disk_usage job", job_id, "succeeded on two hosts; summary read; output_stored=true for both.")
    else:
        print("PASS: disk_usage job", job_id, f"succeeded on {len(names)} hosts ({', '.join(names)});"
              " summary read; output_stored=true for all.")
    print("PASS: demo-1 complete stdout/stderr read through object storage; SHA-256 matches summary.")
    print(collected["stdout"].decode("utf-8").strip())

if __name__ == "__main__":
    if sys.argv[1:] == ["verify-gateway"]:
        hosts = json.loads(cli("hosts", "list", "--json"))
        catalog = json.loads((local / "catalog.json").read_text())
        distribution = rpc("CatalogService", "GetCatalogDistribution", {"catalog_id": catalog["catalog_id"]})
        print(json.dumps({"hosts": [{"host_id": host["host_id"], "hostname": host["hostname"],
                                      "online": host.get("online", False)} for host in hosts.get("hosts", [])],
                          "distribution": distribution}))
    elif sys.argv[1:] == ["verify-job"]:
        verify_job()
    elif sys.argv[1:] == ["ensure-mcp"]:
        ensure_mcp()
    else:
        main()
