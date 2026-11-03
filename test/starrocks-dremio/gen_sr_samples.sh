#!/usr/bin/env bash
# 在本地 StarRocks 上执行 5 种形态的合成查询，保存 profile、ANALYZE PROFILE、EXPLAIN COSTS/ANALYZE 等样本。
# 输出目录默认本目录下的 samples/（只含合成数据，不入库）。依赖 up.sh 已启动的环境。
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${1:-$HERE/samples}
mkdir -p "$OUT"
SQLRUN=${SQLRUN:-"go run ./test/starrocks-dremio/tools/sqlrun"}
sq() { (cd "$REPO" && $SQLRUN -state "$HERE/.state" "$@"); }

declare -A Q
Q[scan_agg]='SELECT store_id, sum(amount) AS total FROM demo_dw.fact_orders GROUP BY store_id'
Q[hash_join]='SELECT p.category, u.city, sum(f.amount) AS total FROM demo_dw.fact_orders f JOIN demo_dw.dim_product p ON f.product_id = p.product_id JOIN demo_dw.dim_user u ON f.user_id = u.user_id WHERE f.order_date >= "2026-02-01" GROUP BY p.category, u.city'
Q[window]='SELECT count(*) FROM (SELECT order_id, row_number() OVER (PARTITION BY user_id ORDER BY order_date, order_id) AS rn, sum(amount) OVER (PARTITION BY user_id ORDER BY order_date, order_id) AS running FROM demo_dw.fact_orders) t WHERE rn <= 3'
Q[nestloop_join]='SELECT count(*) FROM demo_dw.fact_orders f JOIN demo_dw.dim_product p ON f.amount > p.price * 20 AND f.product_id < p.product_id WHERE f.order_id <= 20000'
Q[project_json]='SELECT count(*) FROM demo_dw.fact_orders WHERE get_json_string(origin_data, "$.channel") = "app" AND origin_data LIKE "%xxxx%"'

for shape in scan_agg hash_join window nestloop_join project_json; do
  sql=${Q[$shape]}
  # 同一会话：开启 profile，执行查询，取 last_query_id()
  qid=$(sq -as query -rows 1 -- 'SET enable_profile=true' "$sql" 'SELECT last_query_id()' | awk '/^> SELECT last_query_id/{f=1;next} f&&NF&&!/^last_query_id/&&!/^--/{print;exit}')
  echo "$shape query_id=$qid"
  for _ in $(seq 1 30); do   # profile 在查询结束后异步登记
    n=$(sq -as diag -raw -- "SELECT length(get_query_profile('$qid'))")
    [ "${n:-0}" -gt 0 ] && break
    sleep 1
  done
  sq -as diag -raw -- "SELECT get_query_profile('$qid')" > "$OUT/sr_get_query_profile__${shape}.txt"
  sq -as diag -raw -- "ANALYZE PROFILE FROM '$qid'" > "$OUT/sr_analyze_profile__${shape}.txt"
  sq -as query -raw -- "EXPLAIN COSTS $sql" > "$OUT/sr_explain_costs__${shape}.txt"
  sq -as query -raw -- "EXPLAIN $sql" > "$OUT/sr_explain__${shape}.txt"
  sq -as query -raw -- "EXPLAIN VERBOSE $sql" > "$OUT/sr_explain_verbose__${shape}.txt"
  sq -as query -raw -- "EXPLAIN LOGICAL $sql" > "$OUT/sr_explain_logical__${shape}.txt"
  sq -as query -raw -- "EXPLAIN ANALYZE $sql" > "$OUT/sr_explain_analyze__${shape}.txt"
  echo "$sql" > "$OUT/sr_query_sql__${shape}.sql"
done
echo done
