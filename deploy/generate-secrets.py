#!/usr/bin/env python3
"""Generate local audit/S3/SSE files; never print secret values."""
import json
import os
import secrets
import sys
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit("usage: generate-secrets.py <local-secret-directory>")
os.umask(0o077)
directory = Path(sys.argv[1])
directory.mkdir(mode=0o700, parents=True, exist_ok=True)
credentials = {"accessKey": secrets.token_hex(16), "secretKey": secrets.token_hex(24)}
files = {
    "audit-cursor-key": secrets.token_bytes(32),
    "aws-credentials": ("[default]\naws_access_key_id = " + credentials["accessKey"] +
                        "\naws_secret_access_key = " + credentials["secretKey"] + "\n").encode(),
    "s3.json": (json.dumps({"identities": [{"name": "local-demo", "credentials": [credentials],
                    "actions": ["Admin", "Read", "Write", "List", "Tagging"]}]}) + "\n").encode(),
    "seaweedfs.env": ("WEED_S3_SSE_KEY=" + secrets.token_urlsafe(24) + "\n").encode(),
}
if any((directory / name).exists() for name in files):
    raise SystemExit("Refusing to overwrite existing audit/S3/SSE secrets.")
for name, value in files.items():
    with (directory / name).open("xb") as output:
        output.write(value)
print("Generated local audit cursor key, S3 credentials and SeaweedFS SSE key (0600).")
