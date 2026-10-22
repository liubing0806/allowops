"""Validate the persistent local overlay defaults to loopback-only exposure (P13)."""
from pathlib import Path

import yaml

root = Path(__file__).resolve().parent
base = yaml.safe_load((root / "compose.yaml").read_text())
overlay = yaml.safe_load((root / "local.yaml").read_text())

assert base["networks"]["default"]["internal"] is True
assert all(not service.get("ports") for service in base["services"].values())
gateway_ports = overlay["services"]["gateway"]["ports"]
assert gateway_ports, "Overlay must publish the gateway port"
for entry in gateway_ports:
    assert entry.startswith("${ALLOWOPS_LOCAL_BIND:-127.0.0.1}:"), f"Gateway port must default to loopback: {entry!r}"
    assert "0.0.0.0" not in entry, entry
    assert entry.endswith(":8443"), f"Gateway container port must stay 8443: {entry!r}"
others = [name for name, service in overlay["services"].items()
          if service.get("ports") and name != "gateway"]
assert not others, others
demos = {name for name in list(base["services"]) + list(overlay["services"])
         if name.startswith("demo-")}
assert demos == {"demo-1", "demo-2", "demo-3"}, demos
assert overlay["services"]["demo-3"]["environment"]["JOIN_TOKEN_FILE"] == "/joins/demo-3.token"
# The extra bridge lets Docker publish the loopback-only gateway port; the
# default network stays internal and no other service joins the extra bridge.
host_access = overlay.get("networks", {}).get("host-access", {})
assert host_access.get("internal") is not True
attached = {name for name, service in overlay["services"].items()
            if "host-access" in (service.get("networks") or {})}
assert attached == {"gateway"}, attached
print("Local overlay checks passed: single-address gateway port, three demo hosts.")
