#!/usr/bin/env bash
# 用 .state 中的账号连接本地 StarRocks FE。
# 用法：sr.sh <root|query|diag|dremio_ro|dremio_rw> [mysql 参数...]   （SQL 从 -e 或标准输入给出）
# 密码在 .state/<name>.cnf（0600），不出现在命令行参数中。
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
who=${1:?usage: sr.sh <root|query|diag|dremio_ro|dremio_rw> [mysql args]}
shift
MYSQL=$(command -v mariadb || command -v mysql)
exec "$MYSQL" --defaults-extra-file="$HERE/.state/sr-$who.cnf" --default-character-set=utf8mb4 "$@"
