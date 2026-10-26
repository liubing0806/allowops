#!/usr/bin/env bash
# 端到端验证：MCP 客户端 -> gateway 二进制 -> 容器内 agent -> sudo -> allowops-exec -> 处理器 -> 本地 StarRocks/Dremio。
# 需要 up.sh 已启动 allowops-srdr 环境；gateway 的 PostgreSQL 和 SeaweedFS 由 test/harness 起临时容器。
# 用法: test/starrocks-dremio/e2e.sh [结果目录]    （默认 /tmp/allowops-srdr-e2e）
# 环境变量: ALLOWOPS_SRDR_CREDENTIALS 指向 credentials.json（默认 test/starrocks-dremio/.state/credentials.json）。
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
export ALLOWOPS_SRDR_CREDENTIALS=${ALLOWOPS_SRDR_CREDENTIALS:-$HERE/.state/credentials.json}
export ALLOWOPS_SRDR_RESULTS=${1:-/tmp/allowops-srdr-e2e}
export ALLOWOPS_REQUIRE_DOCKER=1
[ -r "$ALLOWOPS_SRDR_CREDENTIALS" ] || { echo "缺少 $ALLOWOPS_SRDR_CREDENTIALS，先运行 up.sh" >&2; exit 1; }
cd "$REPO"
make allowops-gateway
go test -tags=srdr ./test/starrocks-dremio/e2e -run '^TestEndToEnd$' -count=1 -v -timeout=20m
echo "结果: $ALLOWOPS_SRDR_RESULTS/results.json、tool-schemas.json"
