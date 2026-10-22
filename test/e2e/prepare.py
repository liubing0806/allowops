"""Copy sources and extend only temporary Compose fixtures for browser testing."""
import base64
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys

import yaml

repo = Path(sys.argv[2]).resolve()
stage = Path(sys.argv[3]).resolve()

if sys.argv[1] == "copy":
    paths = subprocess.check_output(["git", "-C", str(repo), "ls-files", "-z"])
    for relative in paths.decode().split("\0"):
        if not relative:
            continue
        source, target = repo / relative, stage / relative
        if not source.exists():
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    (stage / "web/node_modules").symlink_to(repo / "web/node_modules", target_is_directory=True)
    # prepare.sh needs provenance but the staging directory is not a Git checkout.
    sha = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    script = stage / "deploy/compose/prepare.sh"
    text = script.read_text().replace('commit=$(git -C "$repo" rev-parse HEAD)', f"commit={sha}")
    # Chromium does not negotiate the demo's Ed25519 TLS signature scheme.
    # Change only temporary gateway TLS keys, retaining the host CA and catalog keys.
    text = text.replace('openssl genpkey -algorithm ED25519 -out ".local/secrets/$name.key"', '''if [ "$name" = tls-ca ]; then
        openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out ".local/secrets/$name.key"
    else
        openssl genpkey -algorithm ED25519 -out ".local/secrets/$name.key"
    fi''')
    text = text.replace('openssl genpkey -algorithm ED25519 -out .local/secrets/tls.key',
                        'openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out .local/secrets/tls.key')
    script.write_text(text)
else:
    os.umask(0o077)
    compose = stage / "deploy/compose"
    local = compose / ".local"
    password = secrets.token_hex(24)
    (local / "auth/viewer-password").write_text(password + "\n")
    salt = secrets.token_bytes(16)
    digest = base64.b64encode(hashlib.sha1(password.encode() + salt).digest() + salt).decode()
    with (local / "auth/ldif/50-demo.ldif").open("a") as ldif:
        ldif.write(f"""
dn: uid=demo-viewer,ou=users,dc=demo,dc=invalid
objectClass: inetOrgPerson
uid: demo-viewer
cn: Local Demo Viewer
sn: Demo
userPassword: {{SSHA}}{digest}

dn: cn=demo-viewers,ou=groups,dc=demo,dc=invalid
objectClass: groupOfNames
cn: demo-viewers
member: uid=demo-viewer,ou=users,dc=demo,dc=invalid
""")
    origin = "https://gateway:8443"
    config_path = local / "gateway-auth.yaml"
    config = yaml.safe_load(config_path.read_text())
    config["identity"]["origin"] = origin
    config["identity"]["role_mappings"].append({
        "provider_id": "demo", "group": "demo-viewers", "roles": ["viewer"],
    })
    config_path.write_text(yaml.safe_dump(config, sort_keys=False))
    artifacts = Path(sys.argv[4]).resolve()
    (compose / "e2e.yaml").write_text(yaml.safe_dump({"services": {"browser": {
        "profiles": ["e2e"],
        "image": "mcr.microsoft.com/playwright:v1.62.1-noble@sha256:c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac",
        "platform": "linux/amd64",
        "user": f"{os.getuid()}:{os.getgid()}",
        "working_dir": "/tests",
        "command": ["node", "/tests/node_modules/@playwright/test/cli.js", "test"],
        "environment": {
            "ALLOWOPS_E2E_URL": origin,
            "ALLOWOPS_E2E_AUTH_DIR": "/run/e2e/auth",
            "ALLOWOPS_E2E_ARTIFACTS": "/evidence",
        },
        "volumes": [
            f"{repo}/test/e2e:/tests:ro",
            f"{artifacts}:/evidence",
            f"{local}/auth/login-password:/run/e2e/auth/login-password:ro",
            f"{local}/auth/viewer-password:/run/e2e/auth/viewer-password:ro",
        ],
        "cap_drop": ["ALL"],
        "read_only": True,
        "tmpfs": ["/tmp:mode=1777,size=1g"],
        "security_opt": ["no-new-privileges:true"],
    }}}))
    (local / "browser-url").write_text(origin)
