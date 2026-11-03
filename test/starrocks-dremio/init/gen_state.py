#!/usr/bin/env python3
"""生成本地测试环境的随机凭据：.state/credentials.json 和各 StarRocks 账号的 mysql 选项文件。

目录权限 0700，文件权限 0600。密码只写入这些文件，不打印。
"""
import json
import os
import secrets
import sys

state = sys.argv[1]
os.makedirs(state, mode=0o700, exist_ok=True)
os.chmod(state, 0o700)

accounts = {
    "dremio_admin": "allowops_admin",
    "dremio_user": "allowops_reader",
    "sr_root": "root",
    "sr_query": "allowops_query",
    "sr_diag": "allowops_diag",
    "sr_dremio_ro": "dremio_ro",
    "sr_dremio_rw": "dremio_rw",
}


def write(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


creds = {k: {"userName": v, "password": secrets.token_hex(12)} for k, v in accounts.items()}
write(os.path.join(state, "credentials.json"), json.dumps(creds, indent=2) + "\n")
for key, c in creds.items():
    if not key.startswith("sr_"):
        continue
    name = key[3:]
    write(os.path.join(state, "sr-%s.cnf" % name),
          "[client]\nhost=127.0.0.1\nport=29030\nuser=%s\npassword=%s\nskip-ssl\n" % (c["userName"], c["password"]))
