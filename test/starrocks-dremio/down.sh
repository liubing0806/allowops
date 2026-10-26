#!/usr/bin/env bash
# 停止并删除 allowops-srdr 项目的容器、卷和网络，并清除 .state 中的凭据。
# 只作用于 compose 项目 allowops-srdr，不触碰其他容器。
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
IMAGES_ENV=${IMAGES_ENV:-$HERE/images.env}
# down 需要变量存在才能解析 compose 文件；缺少 images.env 时用占位值。
if [ -f "$IMAGES_ENV" ]; then set -a; . "$IMAGES_ENV"; set +a; fi
: "${SR_FE_IMAGE:=placeholder}" "${SR_BE_IMAGE:=placeholder}" "${DREMIO_IMAGE:=placeholder}"
export SR_FE_IMAGE SR_BE_IMAGE DREMIO_IMAGE
docker compose -p allowops-srdr -f "$HERE/docker-compose.yml" down -v --remove-orphans
rm -rf "$HERE/.state"
echo "[down] allowops-srdr 已清理"
