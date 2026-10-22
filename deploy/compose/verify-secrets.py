"""Scan local generated secrets against captured logs entirely in memory."""
import json
import subprocess
from pathlib import Path

local = Path(__file__).resolve().parent / ".local"
private = []
for name in ("secrets/postgres-password", "auth/directory-password", "auth/config-password",
             "auth/login-password"):
    private.append((local / name).read_bytes().strip())
s3 = json.loads((local / "secrets/s3.json").read_text())["identities"][0]["credentials"][0]
private.extend(value.encode() for value in s3.values())
private.append((local / "secrets/seaweedfs.env").read_bytes().strip().split(b"=", 1)[1])
private.append((local / "secrets/audit-cursor-key").read_bytes())
private.extend(path.read_bytes().strip() for path in (local / "joins").glob("*.token"))
mcp_token = local / "mcp-token"
if mcp_token.is_file():
    private.append(mcp_token.read_bytes().strip())
private.append(json.loads((local / "cli/allowops/credentials").read_text())["token"].encode())
logs = subprocess.check_output(["docker", "compose", "--profile", "demo", "logs", "--no-color"],
                               stderr=subprocess.STDOUT)
if any(value and value in logs for value in private):
    raise SystemExit("FAIL: generated secret found in Compose logs (value suppressed).")
print("PASS: process-local scan found no generated passwords, tokens, S3 or SSE keys in Compose logs.")
