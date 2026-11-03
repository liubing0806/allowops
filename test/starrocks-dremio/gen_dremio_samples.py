#!/usr/bin/env python3
"""在本地 Dremio 上执行几种形态的合成查询，保存作业状态、结果、profile 等样本。

输出目录默认本目录下的 samples/（只含合成数据，不入库；登录令牌和构建者邮箱已脱敏）。依赖 up.sh 已启动的环境。
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

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "samples")
os.makedirs(OUT, exist_ok=True)
ROLE = "user"


def save(name, data, raw=False):
    mode = "wb" if raw else "w"
    with open(os.path.join(OUT, name), mode) as f:
        f.write(data if raw else (data if isinstance(data, str) else json.dumps(data, indent=2, ensure_ascii=False) + "\n"))


def submit(text, wait=True):
    st, j = dremio.call(ROLE, "POST", "/api/v3/sql", {"sql": text})
    assert st == 200, (st, j)
    jid = j["id"]
    if wait:
        dremio.job_wait(ROLE, jid)
    return jid


SHAPES = {
    "pushdown_scan": 'SELECT user_id, user_name, city FROM "starrocks".demo_dw.dim_user WHERE level = 2',
    "pushdown_join_agg": 'SELECT p.category, count(*) AS c, sum(f.amount) AS total FROM "starrocks".demo_dw.fact_orders f JOIN "starrocks".demo_dw.dim_product p ON f.product_id = p.product_id WHERE f.store_id < 10 GROUP BY p.category',
    "cross_source_join": 'SELECT u.city, count(*) AS c FROM "starrocks".demo_dw.dim_user u JOIN "starrocks-scratch".demo_dw.dim_user v ON u.user_id = v.user_id GROUP BY u.city',
    "failed_unknown_table": 'SELECT * FROM "starrocks".demo_dw.no_such_table',
}

# 登录响应（令牌脱敏）
c = dremio.creds(ROLE)
st, _, b = dremio.http("POST", "/apiv2/login", {"userName": c["userName"], "password": c["password"]})
login = json.loads(b)
login["token"] = "<masked>"
save("dremio_apiv2_login__response_masked.json", login)

header_saved = False
for shape, text in SHAPES.items():
    jid = submit(text)
    st, status = dremio.call(ROLE, "GET", "/api/v3/job/%s" % jid)
    save("dremio_v3_job_status__%s.json" % shape, {"id": jid, "sql": text, "status": status})
    if status["jobState"] == "COMPLETED":
        st, res = dremio.call(ROLE, "GET", "/api/v3/job/%s/results?offset=0&limit=20" % jid)
        save("dremio_v3_job_results__%s.json" % shape, res)
        st, ex = dremio.call(ROLE, "POST", "/api/v3/sql", {"sql": "EXPLAIN PLAN FOR " + text})
        ejid = ex["id"]
        dremio.job_wait(ROLE, ejid)
        st, er = dremio.call(ROLE, "GET", "/api/v3/job/%s/results" % ejid)
        save("dremio_explain_plan_for__%s.txt" % shape, er["rows"][0]["text"])
    st, h, z = dremio.http("POST", "/apiv2/support/%s/download" % jid, b"{}", token=dremio.login(ROLE))
    zf = zipfile.ZipFile(io.BytesIO(z))
    for n in zf.namelist():
        if n.startswith("profile_attempt_"):
            p = json.loads(zf.read(n))
            save("dremio_support_download__%s__%s" % (shape, n), p)
        elif n == "header.json" and not header_saved:
            save("dremio_support_download__header.json", json.loads(zf.read(n)))
            header_saved = True
    st, h, jp = dremio.http("GET", "/apiv2/queryProfile/%s/JobProfile" % jid, None, token=dremio.login(ROLE))
    if st == 200:
        save("dremio_apiv2_queryProfile_JobProfile__%s.json" % shape, json.loads(jp))
    st, det = dremio.call(ROLE, "GET", "/apiv2/job/%s/details" % jid)
    save("dremio_apiv2_job_details__%s.json" % shape, det)

# 下推到 StarRocks 的 SQL 带作业 ID 注释（取自 FE 审计日志，见 sr_fe_audit_log__pushdown.txt）

# 取消一个运行中的作业
jid = submit("SELECT * FROM TABLE(\"starrocks\".external_query('SELECT sleep(30) AS s'))", wait=False)
time.sleep(3)
st, running = dremio.call(ROLE, "GET", "/api/v3/job/%s" % jid)
save("dremio_v3_job_status__running.json", running)
st, r = dremio.call(ROLE, "POST", "/api/v3/job/%s/cancel" % jid, {"reason": "sample"})
time.sleep(2)
st, canceled = dremio.call(ROLE, "GET", "/api/v3/job/%s" % jid)
save("dremio_v3_job_status__canceled.json", {"cancel_http_status": st if r is None else r, "status": canceled})

# 系统表
def sysq(name, text):
    jid = submit(text)
    st, res = dremio.call(ROLE, "GET", "/api/v3/job/%s/results?limit=50" % jid)
    for row in res.get("rows", []):
        if "build_email" in row:
            row["build_email"] = "<redacted>"
    save(name, res)

sysq("dremio_sys_version.json", "SELECT * FROM sys.version")
sysq("dremio_sys_nodes.json", "SELECT * FROM sys.nodes")
sysq("dremio_sys_memory.json", "SELECT * FROM sys.memory")
sysq("dremio_sys_reflections.json", "SELECT * FROM sys.reflections")
sysq("dremio_sys_jobs__running.json", "SELECT job_id, status, query_type, user_name, submitted_ts, rows_scanned, queue_name, engine, error_msg, query FROM sys.jobs")
sysq("dremio_describe_sys_jobs.json", "DESCRIBE sys.jobs")

st, lst = dremio.call(ROLE, "GET", "/apiv2/jobs-listing/v1.0?limit=5&offset=0&sort=st&order=DESCENDING")
save("dremio_apiv2_jobs-listing__limit5.json", lst)
print("done")
