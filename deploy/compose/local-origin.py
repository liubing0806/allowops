"""Set the gateway identity origin for host-reachable browser access (P13).

The base preparation writes identity.origin as https://gateway:8443, which only
resolves inside the Compose network. The persistent local environment serves
the console on the host loopback or one LAN address, so the origin must be
https://<host>:<port>; otherwise browsers send a different Origin header and
the gateway rejects console logins and mutations. The container-reachable
management.upstream is left unchanged. Prints "changed" or "unchanged".
"""
import sys
from pathlib import Path

import yaml

host, port = sys.argv[1], sys.argv[2]
local = Path(__file__).resolve().parent / ".local"
path = local / "gateway-auth.yaml"
config = yaml.safe_load(path.read_text())
desired = f"https://{host}:{port}"
if config["identity"]["origin"] != desired:
    config["identity"]["origin"] = desired
    path.write_text(yaml.safe_dump(config, sort_keys=False))
    print("changed")
else:
    print("unchanged")
