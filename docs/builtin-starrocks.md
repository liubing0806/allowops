# starrocks_query 只读 SQL 执行方案

## 范围与完成条件

`starrocks_query` 通过 MySQL 协议向 StarRocks FE（Frontend，前端节点）发送一条只读 SQL。
实现位于 `internal/builtin/starrocks`，注册在 `internal/catalog` 的 `Builtins`。
`starrocks_diag`（诊断）和 Dremio 处理器不在本文范围内。

完成条件：配置与参数校验、SQL 校验先于凭据读取、凭据文件检查、TSV 与 NULL、截断、超时、错误码、
panic 恢复的单元测试通过；设置 `ALLOWOPS_STARROCKS_ADDR` 后，对本地 StarRocks 3.3 的集成测试通过；
go vet、staticcheck、`make examples-check` 通过。验证记录见交付报告。

## 设计依据

本处理器的会话设置和结果限制按 StarRocks 3.3 的实测行为设计：

| 事实 | 处理方式 |
| --- | --- |
| 不支持 `START TRANSACTION READ ONLY`（1064）；`SET transaction_read_only=1` 不阻止写入 | 不使用只读事务，只读边界由账号权限、sqlguard 和结果限制共同构成 |
| `max_execution_time` 不是变量，生效的是 `query_timeout`，超时错误码 5024 | 会话只设置 `query_timeout` |
| 显式 `LIMIT` 覆盖 `sql_select_limit` | 不设置 `sql_select_limit`，客户端读取 `max_rows + 1` 行后截断 |
| 服务端执行同一次请求中的所有语句 | sqlguard 拒绝 `;` 之后的任何内容；驱动保持多语句关闭 |
| 只有 SELECT 权限的账号可以 `INTO OUTFILE`、`FILES()`、读取其他账号的 profile、`SET PASSWORD` | sqlguard 拒绝对应写法；`SHOW PROFILELIST` 和 `ANALYZE PROFILE` 在本处理器中始终拒绝 |
| `#` 不是注释，其后的语句会被执行 | sqlguard 拒绝引号之外的 `#` |

SQL 校验规则见 [builtin-sqlguard.md](builtin-sqlguard.md)。校验是词法级白名单，不能单独保证只读。

## 安全规则与执行链

1. 校验配置：`Config.Validate` 只检查配置，不打开文件或联网。
2. 校验参数：`database` 为空或匹配 `^[a-zA-Z0-9_]{1,64}$`；`sql` 最长 4000 字符（由 sqlguard 检查）。
3. 运行 sqlguard（StarRocks 方言），再应用 `statement_types`、`show_types`。
   `ANALYZE PROFILE` 和 `SHOW PROFILELIST` 在此拒绝，任何配置都不能开启。
   sqlguard 的 panic 被恢复并转为拒绝错误，错误信息不含 SQL。
4. 以上步骤全部通过后才读取凭据文件、建立连接。被拒绝的语句不会读取凭据，也不会产生连接。
5. 凭据文件检查沿用 mysql_query（`internal/builtin/credfile`）：O_NOFOLLOW 打开，在同一文件描述符上核验普通文件、属主 root、权限精确 0600、大小不超过 16 KiB，严格解码 JSON。
6. 使用 go-sql-driver/mysql 的结构化配置构造连接，不接受地址查询参数或凭据中的连接参数。多语句、LOCAL INFILE、参数插值和 TLS 均保持关闭。
7. 独占一条连接。执行 `SET query_timeout = N`（N 为超时向上取整的秒数，至少 1）；失败时直接返回错误，不再执行查询。
8. context 覆盖连接和查询，截止时间等于配置的超时。
9. 读取最多 `max_rows + 1` 行，返回前 `max_rows` 行；总文本字节超过 `max_bytes` 时丢弃放不下的整行。
   发生截断时取消查询 context，驱动关闭连接，不继续读取剩余结果。

数据库账号权限是读取范围的唯一限制。处理器不提供 `databases`、`catalogs` 配置：词法校验不能区分 `db.table` 与 `alias.column`，
以名称检查表范围会产生误判和绕过。需要限制可读表时，在 StarRocks 中给查询账号授予对应库表的 SELECT。
`database` 参数只是默认库，不是授权边界。

## builtin_config

| 字段 | 合法配置与省略时的行为 |
| --- | --- |
| `credential` | 必填，凭据文件的绝对路径 |
| `address` | 必填，只接受 `tcp://host:port`，不接受用户信息、路径、查询参数和片段 |
| `max_rows` | 0..500 的整数；省略或 0 为 500。只能收紧 |
| `max_bytes` | 0..1 MiB，可写 `64KB` 等 B/KB/MB/GB 形式；省略或 0 为 1 MiB。只能收紧 |
| `timeout` | 1ms..10s；省略为 10s。只能收紧 |
| `statement_types` | SELECT、SHOW、DESCRIBE、EXPLAIN 的非空子集；省略时允许这四类。EXPLAIN 的目标语句也必须满足该列表 |
| `show_types` | sqlguard 的 SHOW 种类（不含 PROFILELIST）的非空子集，名称不区分大小写；省略时不增加限制 |
| `allow_explain_analyze` | 默认 false。为 true 时允许 `EXPLAIN ANALYZE <SELECT 或 WITH 查询>`，该语句会执行查询；INSERT 目标仍拒绝 |

SHOW 种类为：DATABASES、TABLES、TABLE STATUS、COLUMNS、CATALOGS、CREATE TABLE、CREATE VIEW、
CREATE MATERIALIZED VIEW、CREATE DATABASE、PARTITIONS、TABLET、MATERIALIZED VIEWS、FUNCTIONS、VARIABLES、
STATUS、PROCESSLIST、FRONTENDS、BACKENDS、COMPUTE NODES。其中 FRONTENDS、BACKENDS、COMPUTE NODES 需要
SELECT 之外的权限，只有 SELECT 的账号会得到权限错误。`PROCESSLIST` 对只有 SELECT 的账号只返回该账号自己的连接。

显式 `null`、空列表、非字符串成员和未知字段均报错。拒绝信息列出可用成员，不回显 SQL。

目录对外的参数 schema：

| 参数 | 规则 |
| --- | --- |
| `database` | 可选，匹配 `^[a-zA-Z0-9_]{1,64}$` |
| `sql` | 必填，最长 4000 字符；action 可以用 `regex` 和更小的 `max_len` 进一步限制 |

## 默认值与上限

| 项目 | 默认值（同时是硬上限） | 说明 |
| --- | --- | --- |
| 行数 | 500 | 不含表头 |
| 结果字节 | 1 MiB | TSV 文本，含表头；单行放不下时该行不返回 |
| 超时 | 10 s | 客户端截止时间；同时以向上取整的秒数设置 `query_timeout` |
| SQL 长度 | 4000 字符 | sqlguard 检查 |

结果字节上限是新增项，mysql_query 没有对应字段。action 的 `max_output` 仍由执行器另行应用；
示例把 `max_bytes` 与 `max_output` 设为相同值，使截断在处理器内发生并带有 `truncated` 标记。

## 输出与错误

输出是 TSV：首行为列名，NULL 为 `\N`，制表符、换行、回车、反斜线和 NUL 分别转义为 `\t`、`\n`、`\r`、`\\`、`\0`，格式与 mysql_query 相同
（`internal/builtin/tsv`）。列名和每个单元格在编码前经 `RunRedacted` 的脱敏函数处理，然后才计入行数和字节上限。
空结果仍有表头。`Result{Output, Rows, Truncated}` 中 `Rows` 不含表头。

行数或字节超限时 `Truncated` 为 true，目录层映射为资源截断，退出码保持 0。

服务端错误只返回错误码，例如 `starrocks query failed (code 5203)`。服务端消息可能包含 SQL 字面值和账号信息，不回显。
超时分两种：

- 客户端截止时间先到：返回 `context deadline exceeded`。这是 `Run` 的常见情形，因为 context 的截止时间等于配置的超时。
- 服务端 `query_timeout` 先到：返回 `starrocks query failed (code 5024)`。调用方 context 的截止时间长于配置的超时时才会出现。

## 凭据与账号部署

凭据文件为 JSON，属主 root、权限 0600，父目录由 root 管理：

```json
{"username":"allowops_query","password":"replace-on-host"}
```

`username`、`password` 必填，密码可以为空字符串；拒绝未知字段、尾随对象、目录、FIFO 和末级符号链接。
凭据路径写在 `builtin_config.credential`，目录和签名包中不含密码。

查询账号只授予读取权限。示例（账号名、密码、库名为占位值，密码在主机上生成）：

```sql
CREATE USER 'allowops_query'@'%' IDENTIFIED BY '<在主机上生成的密码>';
GRANT SELECT ON ALL TABLES IN DATABASE app TO USER 'allowops_query'@'%';
```

- 不授予 INSERT、UPDATE、DELETE、DDL、`OPERATE`、`ADMIN` 等权限。
- 读取范围由授权决定：需要读取多个库时分别授权，未授权的库返回权限错误。
- 只有 SELECT 的账号仍可以读取 FILES()、写 `INTO OUTFILE`、修改自己的密码。这些写法在 sqlguard 中拒绝，账号权限不能替代这一层，反之亦然。
- 账号写入被服务端拒绝时的错误码为 5203（集成测试验证）。

## 与 mysql_query 的差异

| 项目 | mysql_query | starrocks_query |
| --- | --- | --- |
| 校验 | TiDB parser 的 AST | sqlguard 词法白名单 |
| 地址 | `tcp://` 和 `unix://` | 只接受 `tcp://` |
| 只读事务 | `START TRANSACTION READ ONLY` | 不支持，不使用 |
| 超时变量 | `max_execution_time`（毫秒） | `query_timeout`（秒，向上取整） |
| 库范围 | `databases` 收紧并递归检查 AST 中的库名 | 无；由账号授权决定 |
| 字节上限 | 无 | `max_bytes`，默认和上限 1 MiB |
| EXPLAIN ANALYZE | 始终拒绝 | 默认拒绝，`allow_explain_analyze` 开启后允许 SELECT 和 WITH 目标 |
| profile 语句 | 不适用 | 始终拒绝 |

## 测试与复现

单元测试使用 `database/sql` 的固定驱动，不联网，覆盖：配置校验与收紧、参数和取消、
SQL 拒绝先于凭据读取、被拒绝的 SQL 不产生任何 TCP 连接（本地监听器计数）、凭据文件检查、驱动配置、
TSV 与 NULL、脱敏先于行数和字节限制、读到上限即停止、`query_timeout` 取整和设置失败、
服务端错误只含错误码、context 取消、sqlguard panic 恢复。

集成测试由环境变量 `ALLOWOPS_STARROCKS_ADDR`（如 `127.0.0.1:29030`）启用，未设置时 `t.Skip` 并说明原因。
凭据文件的位置由 `ALLOWOPS_STARROCKS_STATE` 指定，密码只在测试进程内读取，不打印、不写入日志。
覆盖：

- 查询账号的 SELECT、EXPLAIN、DESC、SHOW TABLES，TSV 与 NULL，默认库，三段式表名。
- `SELECT sleep(3)` 在 1 秒超时下返回 5024（用测试专用的绕过 sqlguard 入口，因为 sqlguard 拒绝 `sleep`）。
- 50 万行表的行数截断和字节截断；截断读取耗时约 10 到 20 ms，不读取剩余结果。
- 查询账号的 INSERT、DELETE、TRUNCATE、CREATE、DROP、ALTER、GRANT、INSTALL PLUGIN 被服务端拒绝（5203）。`KILL` 对不存在的线程返回 1094，`SET PASSWORD` 会修改共享环境的账号，两者不在测试中。
- `#` 注入、多语句、`INTO OUTFILE`、`FILES()`、`get_query_profile` 被 sqlguard 拒绝，服务端没有执行：
  用有写权限的对照账号确认测试表行数不变，且对照插入证明该账号可写。
- 公开的 `Run` 入口：测试二进制在 `unshare -Ur`（用户命名空间，当前用户映射为 uid 0）下重新执行，使 root:0600 凭据检查按生产规则通过，不放宽检查。

验收命令：

```sh
gofmt -l internal
go vet ./...
go test -race ./internal/builtin/starrocks ./internal/catalog ./internal/executor ./internal/agent ./internal/gateway/mcp
ALLOWOPS_STARROCKS_ADDR=127.0.0.1:29030 go test -race -count=1 ./internal/builtin/starrocks
make examples-check
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./internal/builtin/... ./internal/catalog/... ./internal/agent/...
```

## 已知限制

- 词法校验不展开视图定义，不识别服务端插件和自定义函数的副作用。
- 没有 `databases` 或 `catalogs` 收紧项，读取范围只由账号授权限制。
- 查询在客户端截断后，服务端可能继续执行到自己的 `query_timeout`；连接关闭后服务端是否立即取消查询未验证。
- 超时错误按 context 是否到期判断，只有调用方 context 长于配置超时时才能观察到服务端的 5024。
- 校验针对 StarRocks 3.3 设计，其他版本未验证。
