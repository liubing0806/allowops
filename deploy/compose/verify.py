"""Verify real P4B host state and P3 catalog loading on the local demo."""
import json
import os
import subprocess
import time

from pathlib import Path

local = Path(__file__).resolve().parent / ".local"
os.environ.setdefault("ALLOWOPS_DEMO_UID", str(os.getuid()))
os.environ.setdefault("ALLOWOPS_DEMO_GID", str(os.getgid()))

if os.environ.get("COMPOSE_FILE"):
    compose = ["docker", "compose"]
else:
    compose = ["docker", "compose", "-f", "compose.yaml"]
hostnames = tuple(name.strip() for name in
                  os.environ.get("ALLOWOPS_DEMO_HOSTS", "demo-1,demo-2").split(",") if name.strip())
if not hostnames:
    raise SystemExit("ALLOWOPS_DEMO_HOSTS is empty.")
catalog = json.loads((local / "catalog.json").read_text())
for attempt in range(60):
    state = json.loads(subprocess.check_output([*compose, "run", "--rm", "--no-deps", "admin-tool", "verify-gateway"], text=True))
    hosts = state["hosts"]
    statuses = []
    for hostname in hostnames:
        output = subprocess.check_output([*compose, "exec", "-T", "--user", "65532:65532", hostname,
                                          "allowops-agent", "status"], text=True)
        statuses.append(json.loads(output))
    online = len(hosts) == len(hostnames) and all(host["online"] for host in hosts)
    loaded = all(status["running"] and status["connected"] and any(
        ref["catalog_id"] == catalog["catalog_id"] and int(ref["version"]) == int(catalog["version"])
        for ref in status.get("loaded_catalogs", [])) for status in statuses)
    distribution = state["distribution"]
    reported = any(int(version["catalog"]["version"]) == int(catalog["version"])
                   and int(version["hostCount"]) == len(hostnames) for version in distribution.get("versions", []))
    if online and loaded and reported:
        assert len({status["host_id"] for status in statuses}) == len(hostnames)
        if hostnames == ("demo-1", "demo-2"):
            print("PASS: two distinct registered hosts online; signed catalog loaded and reported by both.")
        else:
            print(f"PASS: {len(hostnames)} distinct registered hosts online;"
                  " signed catalog loaded and reported by all.")
        print("Catalog:", catalog["catalog_id"], "version:", catalog["version"], "actions:", len(catalog["actions"]))
        break
    if attempt == 59:
        raise SystemExit(f"Host verification timed out: online={online}, loaded={loaded}, reported={reported}")
    time.sleep(1)
