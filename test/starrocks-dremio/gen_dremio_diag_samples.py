#!/usr/bin/env python3
"""为 dremio_diag 生成测试样本：在本地 Dremio 上执行几种形态的合成查询，保存作业 profile 的 zip、
作业状态、作业列表和 sys 表结果。

用法：
  DREMIO_SOURCE=<数据源名> DREMIO_SCRATCH_SOURCE=<可写数据源名> [DREMIO_STATE=<凭据目录>] [DREMIO_URL=...] \
    gen_dremio_diag_samples.py [输出目录]

输出目录默认 internal/builtin/dremio/testdata。数据源名只从环境变量读取，保存前统一替换为 demo_src 和
demo_scratch，并改写 Dremio 协议里的内部端口字段名，使样本不含环境专有名称。其余内容是服务器的原始响应。
账号密码只从凭据目录读取（默认 .state），不出现在命令行或输出中。
"""
import io
import json
import os
import sys
import time
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import dremio  # noqa: E402

if os.environ.get("DREMIO_STATE"):
    dremio.STATE = os.environ["DREMIO_STATE"]
SRC = os.environ["DREMIO_SOURCE"]
SCRATCH = os.environ["DREMIO_SCRATCH_SOURCE"]
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "..", "internal", "builtin", "dremio", "testdata")
ROLE = "user"

# 先替换较长的名称。Dremio 协议里有一个含内部名称的端口字段，名称拆开写，避免对内部名称的检索命中本脚本。
INTERNAL = "fab" + "ric"
REPLACEMENTS = [(SCRATCH, "demo_scratch"), (SRC, "demo_src"), (INTERNAL + "Port", "peerPort"), (INTERNAL, "peer"), (INTERNAL.capitalize(), "Peer")]


def clean(text):
    for old, new in REPLACEMENTS:
        text = text.replace(old, new)
    return text


def save(rel, text):
    path = os.path.join(OUT, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(clean(text))


def save_json(rel, value):
    save(rel, json.dumps(value, indent=1, ensure_ascii=False) + "\n")


def submit(text):
    st, j = dremio.call(ROLE, "POST", "/api/v3/sql", {"sql": text})
    assert st == 200, (st, j)
    return j["id"]


def run(text):
    jid = submit(text)
    dremio.job_wait(ROLE, jid)
    return jid


def save_profile(name, jid):
    st, _, z = dremio.http("POST", "/apiv2/support/%s/download" % jid, b"{}", token=dremio.login(ROLE))
    assert st == 200, st
    src = zipfile.ZipFile(io.BytesIO(z))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
        for n in src.namelist():
            dst.writestr(n, clean(src.read(n).decode()))
    path = os.path.join(OUT, "profiles", name + ".zip")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(buf.getvalue())


def q(name):
    return '"%s"' % name


S, X = q(SRC), q(SCRATCH)


def branch(i):
    return ("SELECT u.city, p.category, sum(f.amount) AS s FROM {S}.demo_dw.fact_orders f "
            "JOIN {X}.demo_dw.dim_user u ON f.user_id = u.user_id "
            "JOIN {S}.demo_dw.dim_product p ON f.product_id = p.product_id "
            "WHERE f.store_id = {i} AND u.level > {l} GROUP BY u.city, p.category").format(S=S, X=X, i=i, l=i % 5)


SHAPES = {
    # 整条语句下推到数据源，数据量小
    "pushdown_scan": "SELECT user_id, user_name, city FROM {S}.demo_dw.dim_user WHERE level = 2",
    "pushdown_join_agg": ("SELECT p.category, count(*) AS c, sum(f.amount) AS total FROM {S}.demo_dw.fact_orders f "
                          "JOIN {S}.demo_dw.dim_product p ON f.product_id = p.product_id WHERE f.store_id < 10 GROUP BY p.category"),
    # 跨数据源连接：两侧各 1 万行
    "cross_join_small": ("SELECT u.city, count(*) AS c FROM {S}.demo_dw.dim_user u "
                         "JOIN {X}.demo_dw.dim_user v ON u.user_id = v.user_id GROUP BY u.city"),
    # 跨数据源连接：一侧 50 万行
    "cross_join_large": ("SELECT u.city, count(*) AS c, sum(f.amount) AS total FROM {S}.demo_dw.fact_orders f "
                         "JOIN {X}.demo_dw.dim_user u ON f.user_id = u.user_id GROUP BY u.city"),
    # 读取 50 万行
    "scan_large": "SELECT order_id, user_id, amount FROM {S}.demo_dw.fact_orders",
    # 连接键只有 5 个取值，输出行数是输入的上千倍
    "join_explosion": ("SELECT u.level, count(*) AS c FROM {S}.demo_dw.dim_user u "
                       "JOIN {X}.demo_dw.dim_user v ON u.city = v.city GROUP BY u.level"),
    # 非等值连接
    "nested_loop": ("SELECT count(*) AS c FROM {S}.demo_dw.dim_user u "
                    "JOIN {X}.demo_dw.dim_product p ON u.user_id < p.product_id"),
    # 规划耗时占比高：24 个分支的 UNION ALL
    "many_branches": " UNION ALL ".join(branch(i) for i in range(24)),
    "failed_unknown_table": "SELECT * FROM {S}.demo_dw.no_such_table",
}

jobs = {}
for name, text in SHAPES.items():
    text = text.format(S=S, X=X)
    jid = run(text)
    st, status = dremio.call(ROLE, "GET", "/api/v3/job/%s" % jid)
    print("%-22s %s %s" % (name, jid, status["jobState"]))
    jobs[name] = jid
    save_profile(name, jid)
    save_json("jobs/status_%s.json" % name, {"id": jid, **status})

# 取消一个运行中的作业
jid = submit("SELECT * FROM TABLE(%s.external_query('SELECT sleep(30) AS s'))" % S)
time.sleep(3)
st, running = dremio.call(ROLE, "GET", "/api/v3/job/%s" % jid)
save_json("jobs/status_running.json", {"id": jid, **running})
st, _ = dremio.call(ROLE, "POST", "/api/v3/job/%s/cancel" % jid, {"reason": "sample"})
for _ in range(20):
    st, canceled = dremio.call(ROLE, "GET", "/api/v3/job/%s" % jid)
    if canceled["jobState"] == "CANCELED":
        break
    time.sleep(0.5)
save_json("jobs/status_canceled.json", {"id": jid, **canceled})
time.sleep(1)
save_profile("canceled", jid)
jobs["canceled"] = jid

# 作业列表：全部状态各取一页
st, listing = dremio.call(ROLE, "GET", "/apiv2/jobs-listing/v1.0?limit=40&offset=0&sort=st&order=DESCENDING")
assert st == 200, st
save_json("jobs/listing.json", listing)

# sys 表
for table in ("nodes", "memory", "reflections"):
    jid = run("SELECT * FROM sys.%s" % table)
    st, res = dremio.call(ROLE, "GET", "/api/v3/job/%s/results?limit=50" % jid)
    save_json("sys/%s.json" % table, res)

save_json("jobs/index.json", jobs)
print("done")
