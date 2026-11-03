#!/usr/bin/env python3
"""Dremio REST 小工具：读取 .state 中的账号，登录后发送请求。

用法：
  dremio.py [--role admin|user] [--noauth] METHOD PATH [--data JSON | --data-file FILE | --data-stdin] [--save FILE] [--raw]
  dremio.py init        # 由 up.sh 调用：首用户引导、非管理员用户、数据源

密码只从 .state/credentials.json 读取，不出现在命令行参数和输出中。
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
STATE = os.path.join(HERE, ".state")
BASE = os.environ.get("DREMIO_URL", "http://127.0.0.1:29047")


def creds(role):
    """role: admin、user（Dremio 账号），或 credentials.json 中的其他键，如 sr_dremio_ro。"""
    key = {"admin": "dremio_admin", "user": "dremio_user"}.get(role, role)
    with open(os.path.join(STATE, "credentials.json")) as f:
        return json.load(f)[key]


def http(method, path, body=None, token=None, timeout=120, raw=False):
    """返回 (status, headers, body_bytes)。HTTP 错误状态不抛异常。"""
    data = None
    headers = {"Content-Type": "application/json"}
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
    if token:
        headers["Authorization"] = "_dremio" + token
    req = urllib.request.Request(BASE + path, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def login(role):
    c = creds(role)
    st, _, b = http("POST", "/apiv2/login", {"userName": c["userName"], "password": c["password"]})
    if st != 200:
        raise RuntimeError("login %s failed: HTTP %d %s" % (role, st, b[:200]))
    return json.loads(b)["token"]


def call(role, method, path, body=None, **kw):
    st, h, b = http(method, path, body, token=login(role), **kw)
    try:
        return st, json.loads(b) if b else None
    except ValueError:
        return st, b.decode(errors="replace")


def wait_ready(timeout=600):
    end = time.time() + timeout
    while time.time() < end:
        try:
            st, _, b = http("GET", "/apiv2/server_status", timeout=5)
            if st == 200 and b"OK" in b:
                return
        except Exception:
            pass
        time.sleep(3)
    raise RuntimeError("dremio not ready")


def job_wait(role, job_id, timeout=300):
    end = time.time() + timeout
    while time.time() < end:
        st, j = call(role, "GET", "/api/v3/job/%s" % job_id)
        if st == 200 and j.get("jobState") in ("COMPLETED", "FAILED", "CANCELED"):
            return j
        time.sleep(0.5)
    raise RuntimeError("job timeout")


def sql(role, text):
    st, j = call(role, "POST", "/api/v3/sql", {"sql": text})
    if st != 200:
        raise RuntimeError("submit failed: HTTP %d %s" % (st, j))
    j = job_wait(role, j["id"])
    if j["jobState"] != "COMPLETED":
        raise RuntimeError("job %s: %s" % (j["jobState"], j.get("errorMessage")))
    return j


def init():
    wait_ready()
    admin = creds("admin")
    # 1. 首用户引导（已存在时 login 成功，跳过）
    st, _, _ = http("POST", "/apiv2/login", {"userName": admin["userName"], "password": admin["password"]})
    if st != 200:
        body = {"userName": admin["userName"], "firstName": "Allowops", "lastName": "Admin",
                "email": "admin@example.invalid", "createdAt": int(time.time() * 1000),
                "password": admin["password"]}
        st, _, b = http("PUT", "/apiv2/bootstrap/firstuser", body)
        if st not in (200, 201):
            raise RuntimeError("bootstrap firstuser failed: HTTP %d %s" % (st, b[:300]))
        print("dremio: admin user created")
    # 2. 非管理员用户
    user = creds("user")
    st, _, _ = http("POST", "/apiv2/login", {"userName": user["userName"], "password": user["password"]})
    if st != 200:
        st, r = call("admin", "POST", "/api/v3/user", {"name": user["userName"], "firstName": "Allowops",
                     "lastName": "Reader", "email": "reader@example.invalid", "password": user["password"]})
        if st not in (200, 201):
            raise RuntimeError("create user failed: HTTP %d %s" % (st, r))
        print("dremio: non-admin user created")
    # 3. 数据源
    _, existing = call("admin", "GET", "/api/v3/catalog")
    names = {d.get("path", [None])[0] for d in (existing or {}).get("data", [])}
    for src in SOURCES:
        if src["name"] in names:
            continue
        pw = creds(src["cred"])["password"]
        body = {"entityType": "source", "name": src["name"], "type": "MYSQL",
                "config": {"hostname": "sr-fe", "port": "9030", "authenticationType": "MASTER",
                           "username": creds(src["cred"])["userName"], "password": pw,
                           "fetchSize": 200, "netWriteTimeout": 60},
                "metadataPolicy": {"authTTLMs": 86400000, "namesRefreshMs": 3600000,
                                   "datasetRefreshAfterMs": 3600000, "datasetExpireAfterMs": 10800000,
                                   "datasetUpdateMode": "PREFETCH_QUERIED", "deleteUnavailableDatasets": True}}
        st, r = call("admin", "POST", "/api/v3/catalog", body)
        if st not in (200, 201):
            raise RuntimeError("create source %s failed: HTTP %d %s" % (src["name"], st, r))
        print("dremio: source %s created" % src["name"])


SOURCES = [
    {"name": "starrocks", "cred": "sr_dremio_ro"},
    {"name": "starrocks-scratch", "cred": "sr_dremio_rw"},
]


def main(argv):
    if argv and argv[0] == "init":
        init()
        return 0
    role, noauth, data, save, raw = "admin", False, None, None, False
    pos = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--role":
            role = argv[i + 1]; i += 2
        elif a == "--noauth":
            noauth = True; i += 1
        elif a == "--data":
            data = argv[i + 1].encode(); i += 2
        elif a == "--data-file":
            data = open(argv[i + 1], "rb").read(); i += 2
        elif a == "--data-stdin":
            data = sys.stdin.buffer.read(); i += 1
        elif a == "--save":
            save = argv[i + 1]; i += 2
        elif a == "--raw":
            raw = True; i += 1
        else:
            pos.append(a); i += 1
    method, path = pos[0], pos[1]
    token = None if noauth else login(role)
    st, h, b = http(method, path, data, token=token)
    print("HTTP %d  content-type=%s" % (st, h.get("Content-Type")), file=sys.stderr)
    if save:
        with open(save, "wb") as f:
            f.write(b)
    if raw:
        sys.stdout.buffer.write(b)
    else:
        try:
            print(json.dumps(json.loads(b), indent=2, ensure_ascii=False))
        except ValueError:
            sys.stdout.write(b.decode(errors="replace"))
    return 0 if st < 400 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
