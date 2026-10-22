"""G47: create a separate local LDAPS demo identity source and gateway config."""
import base64
import hashlib
import os
import secrets
import subprocess
from pathlib import Path

import yaml

os.umask(0o077)
local = Path(__file__).resolve().parent / ".local"
auth = local / "auth"
auth.mkdir()
(auth / "ldif").mkdir()
directory_password = secrets.token_hex(24)
user_password = secrets.token_hex(24)
(auth / "directory-password").write_text(directory_password + "\n")
(auth / "config-password").write_text(secrets.token_hex(24) + "\n")
(auth / "login-password").write_text(user_password + "\n")
(auth / "gateway-ldap.env").write_text("ALLOWOPS_DEMO_LDAP_BIND_PASSWORD=" + directory_password + "\n")
salt = secrets.token_bytes(16)
password_hash = "{SSHA}" + base64.b64encode(hashlib.sha1(user_password.encode() + salt).digest() + salt).decode()
(auth / "ldif" / "50-demo.ldif").write_text(f"""dn: ou=users,dc=demo,dc=invalid
objectClass: organizationalUnit
ou: users

dn: ou=groups,dc=demo,dc=invalid
objectClass: organizationalUnit
ou: groups

dn: uid=demo-admin,ou=users,dc=demo,dc=invalid
objectClass: inetOrgPerson
uid: demo-admin
cn: Local Demo Admin
sn: Demo
userPassword: {password_hash}

dn: cn=demo-admins,ou=groups,dc=demo,dc=invalid
objectClass: groupOfNames
cn: demo-admins
member: uid=demo-admin,ou=users,dc=demo,dc=invalid
""")

def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True)

openssl("genrsa", "-out", auth / "ca.key", "3072")
openssl("req", "-new", "-x509", "-key", auth / "ca.key", "-days", "30",
        "-subj", "/CN=Allowops local LDAPS CA", "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-out", auth / "ca.crt")
openssl("genrsa", "-out", auth / "ldap.key", "2048")
openssl("req", "-new", "-key", auth / "ldap.key", "-subj", "/CN=ldap", "-out", auth / "ldap.csr")
(auth / "ldap.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:ldap,DNS:localhost\n")
openssl("x509", "-req", "-in", auth / "ldap.csr", "-CA", auth / "ca.crt", "-CAkey", auth / "ca.key",
        "-CAcreateserial", "-days", "30", "-extfile", auth / "ldap.ext", "-out", auth / "ldap.crt")
(auth / "ca.crt").chmod(0o644)
config = yaml.safe_load((local / "gateway.yaml").read_text())
config["identity"]["bootstrap_admins"] = ["demo-admin"]
config["identity"]["role_mappings"] = [{"provider_id": "demo", "group": "demo-admins", "roles": ["admin"]}]
config["providers"] = [{"id": "demo", "display_name": "Local LDAPS demo", "kind": "ldap",
                        "url": "ldaps://ldap:636", "ca_file": "/etc/allowops/idp-ca.crt",
                        "user_base_dn": "ou=users,dc=demo,dc=invalid", "group_base_dn": "ou=groups,dc=demo,dc=invalid",
                        "bind_dn": "cn=admin,dc=demo,dc=invalid", "bind_password_env": "ALLOWOPS_DEMO_LDAP_BIND_PASSWORD"}]
(local / "gateway-auth.yaml").write_text(yaml.safe_dump(config, sort_keys=False))
(local / "gateway-auth.yaml").chmod(0o644)
print("Independent local LDAPS credentials, certificates and provider configuration prepared.")
