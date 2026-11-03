#!/usr/bin/env bash
# 启动 allowops-srdr 环境（StarRocks FE/BE、Dremio + ZooKeeper）并初始化。
# 幂等：已初始化的环境重复运行只会补齐缺失的部分。从干净状态启动前先运行 down.sh。
# 镜像由 images.env 提供（SR_FE_IMAGE、SR_BE_IMAGE、DREMIO_IMAGE）：默认本目录下的 images.env（不入库），可用 IMAGES_ENV 指定其他文件，格式见 images.env.example。
set -euo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
STATE=$HERE/.state
IMAGES_ENV=${IMAGES_ENV:-$HERE/images.env}
MYSQL=$(command -v mariadb || command -v mysql)

log() { echo "[up] $*"; }
die() { echo "[up] ERROR: $*" >&2; exit 1; }

[ -f "$IMAGES_ENV" ] || die "缺少 $IMAGES_ENV（定义 SR_FE_IMAGE、SR_BE_IMAGE、DREMIO_IMAGE）"
set -a; . "$IMAGES_ENV"; set +a
: "${SR_FE_IMAGE:?}" "${SR_BE_IMAGE:?}" "${DREMIO_IMAGE:?}"
umask 077

# 凭据：卷已存在时复用 .state，否则重新生成（StarRocks root 密码和 Dremio 用户随卷一起重置）。
if docker volume inspect allowops-srdr_sr-fe-meta >/dev/null 2>&1; then
  [ -f "$STATE/credentials.json" ] || die "卷已存在但缺少 $STATE/credentials.json，先运行 down.sh"
else
  log "生成凭据到 $STATE"
  python3 "$HERE/init/gen_state.py" "$STATE"
fi

log "docker compose up"
docker compose -f "$HERE/docker-compose.yml" up -d --wait --wait-timeout 900 >/dev/null

# ---- StarRocks ----
src() { "$MYSQL" --defaults-extra-file="$STATE/sr-$1.cnf" --default-character-set=utf8mb4 -N -B "${@:2}"; }
pw() { python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]]["password"])' "$STATE/credentials.json" "$1"; }

log "等待 FE 查询端口"
for _ in $(seq 1 60); do
  "$MYSQL" --skip-ssl -h127.0.0.1 -P29030 -uroot -e 'select 1' >/dev/null 2>&1 \
    || src root -e 'select 1' >/dev/null 2>&1 && break
  sleep 2
done

if ! src root -e 'select 1' >/dev/null 2>&1; then
  log "设置 StarRocks root 密码"
  "$MYSQL" --skip-ssl -h127.0.0.1 -P29030 -uroot <<SQL
SET PASSWORD = PASSWORD('$(pw sr_root)');
SQL
  src root -e 'select 1' >/dev/null
fi

if [ -z "$(src root -e 'SHOW BACKENDS')" ]; then
  log "注册 BE"
  src root -e 'ALTER SYSTEM ADD BACKEND "sr-be:9050"'
fi
for _ in $(seq 1 90); do
  [ "$(src root -e 'SHOW BACKENDS' | awk -F'\t' '{print $9}')" = "true" ] && break
  sleep 2
done
[ "$(src root -e 'SHOW BACKENDS' | awk -F'\t' '{print $9}')" = "true" ] || die "BE 未存活"

log "创建合成库表"
# BE 变为 Alive 后，磁盘容量上报可能晚于心跳；此前出现过 "available backends: []" 的建表失败。SQL 为 IF NOT EXISTS，可重试。
for i in $(seq 1 30); do
  src root < "$HERE/init/10-starrocks-fixtures.sql" && break
  [ "$i" = 30 ] && die "BE 持续不能建表"
  log "BE 尚不能建表，2 秒后重试（$i/30）"
  sleep 2
done
if [ "$(src root -e 'SELECT count(*) FROM demo_dw.fact_orders')" = "0" ]; then
  log "写入合成数据（50 万行事实表）"
  src root < "$HERE/init/20-starrocks-data.sql"
fi
src root < "$HERE/init/30-starrocks-audit.sql"
if [ "$(src root -e 'SELECT count(*) FROM starrocks_audit_db__.starrocks_audit_tbl__')" = "0" ]; then
  log "写入合成审计行"
  src root < "$HERE/init/31-starrocks-audit-data.sql"
fi

log "创建 StarRocks 账号"
src root <<SQL
CREATE DATABASE IF NOT EXISTS scratch;
CREATE TABLE IF NOT EXISTS scratch.t_write_probe (id INT, note VARCHAR(64))
  DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES ("replication_num" = "1");

-- allowops_query：只有合成库的 SELECT
CREATE USER IF NOT EXISTS 'allowops_query'@'%' IDENTIFIED BY '$(pw sr_query)';
ALTER USER 'allowops_query'@'%' IDENTIFIED BY '$(pw sr_query)';
GRANT SELECT ON ALL TABLES IN DATABASE demo_dw TO USER 'allowops_query'@'%';

-- allowops_diag：SELECT（合成库和审计库）加 SYSTEM 级 OPERATE
CREATE USER IF NOT EXISTS 'allowops_diag'@'%' IDENTIFIED BY '$(pw sr_diag)';
ALTER USER 'allowops_diag'@'%' IDENTIFIED BY '$(pw sr_diag)';
GRANT SELECT ON ALL TABLES IN DATABASE demo_dw TO USER 'allowops_diag'@'%';
GRANT SELECT ON ALL TABLES IN DATABASE starrocks_audit_db__ TO USER 'allowops_diag'@'%';
GRANT OPERATE ON SYSTEM TO USER 'allowops_diag'@'%';

-- dremio_ro：Dremio 数据源 starrocks 使用，只有 SELECT（合成库和审计库）
CREATE USER IF NOT EXISTS 'dremio_ro'@'%' IDENTIFIED BY '$(pw sr_dremio_ro)';
ALTER USER 'dremio_ro'@'%' IDENTIFIED BY '$(pw sr_dremio_ro)';
GRANT SELECT ON ALL TABLES IN DATABASE demo_dw TO USER 'dremio_ro'@'%';
GRANT SELECT ON ALL TABLES IN DATABASE starrocks_audit_db__ TO USER 'dremio_ro'@'%';

-- dremio_rw：Dremio 数据源 starrocks-scratch 使用，只在 scratch 库有写权限（核实 external_query 能否写入）
CREATE USER IF NOT EXISTS 'dremio_rw'@'%' IDENTIFIED BY '$(pw sr_dremio_rw)';
ALTER USER 'dremio_rw'@'%' IDENTIFIED BY '$(pw sr_dremio_rw)';
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN DATABASE scratch TO USER 'dremio_rw'@'%';
GRANT CREATE TABLE, DROP ON DATABASE scratch TO USER 'dremio_rw'@'%';
GRANT SELECT ON ALL TABLES IN DATABASE demo_dw TO USER 'dremio_rw'@'%';
SQL

# ---- Dremio ----
log "初始化 Dremio（首用户、非管理员用户、数据源）"
python3 "$HERE/dremio.py" init

log "完成"
cat <<EOM
  StarRocks FE MySQL  127.0.0.1:29030   （sr.sh <root|query|diag|dremio_ro|dremio_rw>）
  StarRocks FE HTTP   127.0.0.1:28030
  Dremio REST         http://127.0.0.1:29047   （dremio.py）
  凭据与 mysql 选项文件  $STATE
EOM
