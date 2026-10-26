# starrocks_query 只读 SQL 执行方案

## 范围与完成条件

`starrocks_query` 通过 MySQL 协议向 StarRocks FE（Frontend，前端节点）发送一条只读 SQL。
实现位于 `internal/builtin/starrocks`，注册在 `internal/catalog` 的 `Builtins`。
`starrocks_diag`（诊断）见本文末尾的“starrocks_diag”一节，Dremio 处理器不在本文范围内。

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

# starrocks_diag 诊断

## 范围

`starrocks_diag` 通过 MySQL 协议向 StarRocks FE 发送 allowops 生成的固定语句，读取集群状态、运行中查询、审计表中的慢查询和查询 profile。
实现位于 `internal/builtin/starrocksdiag`（处理器）、`internal/builtin/starrocksprofile`（profile 解析、摘要和规则）和 `internal/builtin/srconn`（与 `starrocks_query` 共用的连接和结果读取）。
连接地址、凭据文件检查、TSV 编码和错误处理与 `starrocks_query` 相同。除 `profile_run` 外，调用方不能提供任何 SQL 文本。

## op 与固定语句

| op | 固定语句 | 参数 |
| --- | --- | --- |
| `cluster` | `SHOW FRONTENDS`、`SHOW BACKENDS`、`SHOW COMPUTE NODES` | `component`：all（默认）、frontends、backends、compute_nodes。输出按 `# <component>` 分节，行数与字节上限由各节共用 |
| `running` | `SHOW PROC '/current_queries'` | 无。实测该语句需要 OPERATE 权限 |
| `slow_queries` | 对审计表的一条 SELECT，见下文 | `since_minutes`（1..10080，默认 60）、`min_duration_ms`（0..86400000，默认 0）、`state`（any、EOF、OK、ERR，默认 any）、`limit`（1..`max_rows`，默认 20） |
| `profile_list` | `SHOW PROFILELIST LIMIT n` | `limit`（同上） |
| `profile_analyze` | `ANALYZE PROFILE FROM '<query_id>'` | `query_id`（必填） |
| `profile_summary` | `SELECT get_query_profile('<query_id>')`，主机端解析 | `query_id`（必填）、`top_n`（1..50，默认 10） |
| `profile_run` | 见下文 | `sql`（必填）、`database`、`top_n`；默认关闭 |

规则：

- 参数按 op 在处理器内校验，不使用工具 schema 根部的 `oneOf` 等组合关键字。schema 列出已启用 op 的全部参数，只有 `op` 必填。
  其他 op 的参数被忽略的情形见下一条；`query_id` 用于不接受它的 op、`sql` 和 `database` 用于 `profile_run` 以外的 op 时返回错误。
- 带默认值的参数（`component`、`since_minutes`、`min_duration_ms`、`state`、`limit`、`top_n`）在目录层始终有值，不适用的 op 不使用它们。
- `query_id` 只接受 UUID（`^[0-9a-fA-F]{8}-…-[0-9a-fA-F]{12}$`），拼入 SQL 前按 StarRocks 字面量规则转义（`\`、`'`、NUL、换行）。
- 参数校验和配置校验先于凭据读取。被拒绝的请求不读取凭据，也不连接。
- `profile_analyze` 的输出含终端颜色转义序列（`ESC[…m`），处理器在脱敏前去掉它们。

## slow_queries 与审计表

固定语句的形式：

```sql
SELECT `queryId` AS `query_id`, `timestamp` AS `timestamp`, `user` AS `user`, `db` AS `db`, `state` AS `state`,
       `queryTime` AS `query_time`, `scanBytes` AS `scan_bytes`, `scanRows` AS `scan_rows`, `returnRows` AS `return_rows`,
       `cpuCostNs` AS `cpu_cost_ns`, `memCostBytes` AS `mem_cost_bytes`, LEFT(`stmt`, 1000) AS `stmt`
FROM `starrocks_audit_db__`.`starrocks_audit_tbl__`
WHERE `timestamp` >= DATE_SUB(NOW(), INTERVAL <since_minutes*60> SECOND) AND `queryTime` >= <min_duration_ms>
  [AND `state` = '<state>'] ORDER BY `queryTime` DESC LIMIT <limit>
```

- 默认表名是 AuditLoader 插件的默认表 `starrocks_audit_db__.starrocks_audit_tbl__`。`builtin_config.audit_table` 可以改为 `table` 或 `database.table`。
- 列名默认取 AuditLoader 的列名（上式）。`builtin_config.audit_columns` 按逻辑名（`query_id`、`timestamp`、`user`、`db`、`state`、`query_time`、`scan_bytes`、`scan_rows`、`return_rows`、`cpu_cost_ns`、`mem_cost_bytes`、`stmt`）改名。
- 表名和列名只来自 `builtin_config`，必须匹配 `^[A-Za-z_][A-Za-z0-9_]{0,63}$`；调用方的参数只以整数和固定集合中的 `state` 进入语句。
- `stmt` 截取前 1000 个字符；SQL 文本中的密码、令牌等由 `redact` 处理。
- 未验证：本地环境没有 AuditLoader 插件，集成测试使用按同一结构手工创建的合成审计表，列名取自 AuditLoader 的文档。真实插件的列类型和 `queryTime` 单位（毫秒）未在本地验证。

## profile_summary 与 profile_run

`profile_summary` 读取 `get_query_profile` 的合并文本，在主机端解析，输出一个 JSON 对象：

- `query`：查询状态、总耗时、`QueryPeakMemoryUsagePerNode`、`QuerySpillBytes`、扫描行数和字节等查询级指标。
- `top_operators`：按算子时间（OperatorTotalTime，扫描算子另加 ScanTime）排序的前 `top_n` 个算子：fragment、算子名、plan node id、耗时占比、输入输出行数、峰值内存、spill 字节，以及多实例时的最大值与平均值之比。
- `findings`：规则命中项，含规则编号、算子、证据（指标名、数值、单位）、可能原因和建议。
- `operator_count`、`operators_omitted`（为适应 `max_bytes` 去掉的算子数）。
- `profile_run` 另有 `result_rows`（被丢弃的结果行数）。

摘要不含 SQL 文本，只含指标和算子名；字符串在输出前经脱敏函数处理，JSON 超过 `max_bytes` 时从排序靠后的算子开始删除，规则命中项保留。

约束：

- profile 文本不得超过 `max_profile_bytes`（默认和上限 16 MiB），否则报错，不解析。解析器还限制行数（400000 行）。
- `get_query_profile` 对未知 `query_id` 返回空字符串，返回 `the profile of the query was not found …`。profile 在查询结束后异步登记（实测最长约 8 秒），已结束的查询可以稍后重试。
- 只有 `enable_profile` 开启或超过 `big_query_profile_threshold` 的查询才有 profile，FE 只保留最近的一批。

`profile_run`：默认关闭，`builtin_config.allow_profile_run: true` 才出现在 `op` 枚举和 `sql`、`database` 参数中。

1. 调用方的 SQL 先经 sqlguard（StarRocks 方言）。只接受 SELECT 和 WITH 查询；`EXPLAIN`、`SHOW`、`ANALYZE PROFILE`、`get_query_profile`、多语句等被拒绝。校验先于凭据读取。
2. 同一连接上执行 `SET enable_profile = true`，执行 SQL，读取并丢弃所有结果行，只统计行数。
3. 执行 `SELECT last_query_id()` 得到 query id，以 200 ms 间隔轮询 `get_query_profile`，直到 profile 登记或整个超时（默认 10 s）到期，再生成摘要。
4. 查询由 `query_timeout` 和客户端截止时间限制。SQL 在服务器上真实执行，可能消耗大量资源；这是默认关闭的原因。

## builtin_config

| 字段 | 合法配置与省略时的行为 |
| --- | --- |
| `credential`、`address`、`timeout` | 同 `starrocks_query` |
| `max_rows` | 0..500；省略或 0 为 500。限制 `cluster`、`running`、`slow_queries`、`profile_list`、`profile_analyze` 的行数，也是 `limit` 的上限 |
| `max_bytes` | 0..1 MiB；省略或 0 为 1 MiB。限制 TSV 文本或摘要 JSON 的字节数 |
| `max_profile_bytes` | 0..16 MiB，可写 `8MB` 等形式；省略或 0 为 16 MiB。限制可解析的 profile 文本 |
| `audit_table` | `table` 或 `database.table`，各段为标识符；省略为 AuditLoader 默认表 |
| `audit_columns` | 逻辑名到列名的映射，列名为标识符；未知逻辑名报错 |
| `allow_profile_run` | 默认 false；true 时启用 `profile_run` |

`statement_types`、`show_types`、`allow_explain_analyze` 不适用于 diag，出现即报错（语句固定）。

## 账号

diag 账号与 query 账号分开配置，凭据文件格式相同，示例路径为 `/etc/allowops/credentials/starrocks-diag.json`。授予 SELECT 加 SYSTEM 级 OPERATE：

```sql
CREATE USER 'allowops_diag'@'%' IDENTIFIED BY '<在主机上生成的密码>';
GRANT OPERATE ON SYSTEM TO USER 'allowops_diag'@'%';
GRANT SELECT ON ALL TABLES IN DATABASE starrocks_audit_db__ TO USER 'allowops_diag'@'%';
```

OPERATE 权限同时允许 KILL 和修改配置。本处理器的语句固定，调用方无法使用这部分权限；该账号不得配置给 `starrocks_query`。
`profile_run` 执行调用方的 SELECT，因此启用它的 action 应使用只有 SELECT 的 query 账号，而不是 diag 账号。

## profile 规则与阈值

算子名和指标名取自本地 StarRocks 3.3.22 的真实 profile。
时间占比的分母是所有算子 `effectiveTime` 之和；`effectiveTime` 为 OperatorTotalTime，扫描算子另加 ScanTime（扫描的 IO 时间不计入 OperatorTotalTime）。

| 编号 | 条件（默认阈值） | 阈值说明 |
| --- | --- | --- |
| SR-SCAN-1 | OLAP_SCAN 时间占比 ≥ 30%，且 RawRowsRead ≥ 1 亿或 BytesRead ≥ 10 GiB | 无 |
| SR-PROJ-1 | PROJECT 时间占比 ≥ 30%，且算子时间 ≥ 10 ms | 增加 10 ms 下限，避免毫秒级查询误报 |
| SR-AGG-1 | 聚合算子 spill 字节 > 0，或 HashTableMemoryUsage ≥ 128 MiB 且 ≥ 查询峰值内存的 50% | 真实 profile 的算子级内存指标是 HashTableMemoryUsage；增加 128 MiB 下限 |
| SR-SORT-1 | LOCAL_SORT_SINK、SPILLABLE_LOCAL_SORT_SINK、LOCAL_PARTITION_TOPN_SINK、ANALYTIC_SINK、ANALYTIC_SOURCE 的时间占比之和 ≥ 30% | 真实窗口查询的占比分散在排序与窗口算子，单个均低于 30%，因此合并计算 |
| SR-JOIN-1 | 出现 NESTLOOP_JOIN_PROBE | 无 |
| SR-JOIN-2 | HASH_JOIN_PROBE 的 PullRowNum ≥ PushRowNum × 10 且 PullRowNum ≥ 10 万 | 增加 10 万行下限 |
| SR-XCHG-1 | EXCHANGE_SINK 的 BytesSent ≥ 10 GiB | 无 |
| SR-SKEW-1 | 非扫描算子的 `__MAX_OF_OperatorTotalTime` / 平均 ≥ 3 且最大值 ≥ 10 ms | 排除 `*_SCAN` 算子：扫描各实例的时间由 tablet 大小和 IO 调度决定，在样本中比值经常超过 3 而没有数据倾斜 |
| SR-MEM-1 | QueryPeakMemoryUsagePerNode ≥ `query_mem_limit` 的 90%，或 ErrorMsg 含内存超限信息 | “接近上限”取 90% |

阈值定义在 `starrocksprofile.DefaultThresholds()`，`TestThresholdsAreConfigurable` 覆盖修改。阈值未经生产数据校准；交付后按实际环境调整，改动需同步更新测试表 `TestRulesOnRealProfiles`。

### 测试样本

`internal/builtin/starrocksprofile/testdata/` 有 14 个来自本地 StarRocks 3.3.22 的真实 profile（合成库 `demo_dw.fact_orders`，50 万行）。
`TestRulesOnRealProfiles` 固定每个样本命中的规则；下表列出各规则的命中与未命中样本。

| 规则 | 命中（真实） | 未命中（真实） |
| --- | --- | --- |
| SR-SCAN-1 | 无 | scan_agg、scan_heavy 等全部样本 |
| SR-PROJ-1 | project_expr、mem_limit_ok | project_json、hash_join、window 等 |
| SR-AGG-1（内存） | agg_memory、mem_limit_ok | scan_agg、hash_join 等 |
| SR-AGG-1（spill） | 无 | 全部样本 |
| SR-SORT-1 | window_multi、window_topn | window、scan_agg 等 |
| SR-JOIN-1 | nestloop_join | hash_join、join_expand |
| SR-JOIN-2 | join_expand | hash_join、nestloop_join |
| SR-XCHG-1 | 无 | 全部样本 |
| SR-SKEW-1 | skew_window | window、hash_join 等 |
| SR-MEM-1 | mem_limit_exceeded | mem_limit_ok 等 |

生成样本的查询（`SET enable_profile = true` 后执行，用 `SELECT last_query_id()` 取 id，再 `SELECT get_query_profile(id)`）：

| 样本 | 查询要点 |
| --- | --- |
| join_expand | `SELECT count(*) FROM demo_dw.fact_orders a JOIN demo_dw.fact_orders b ON a.store_id = b.store_id WHERE a.order_id < 2000` |
| project_expr | 对 `origin_data` 做 `regexp_replace`、`get_json_string` 后 `ORDER BY order_id LIMIT 400000`，外层 `WHERE length(x) > 0` |
| skew_window | `row_number() OVER (PARTITION BY k ORDER BY order_id)`，其中 `k = if(order_id % 100 < 97, 1, order_id)` |
| mem_limit_exceeded | `SET query_mem_limit = 50000000` 后对 `order_id, origin_data` 分组聚合 |
| 其他 | 单表聚合、哈希连接、窗口函数、`TopN` 窗口、笛卡尔连接 |

### 未用真实 profile 验证的规则

本地合成数据量小，以下条件无法由真实查询触发，对应测试用改写的样本（在真实 profile 上修改指标值，行数不变）：

- SR-SCAN-1：RawRowsRead 或 BytesRead 达到阈值（`TestScanRuleOnRewrittenProfiles`）。
- SR-AGG-1 spill 分支：本地查询未产生 spill。判断方式是算子的任何名称含 `Spill` 且为字节量的指标之和大于 0，具体指标名**未用真实 profile 验证**（`TestAggregateSpillOnRewrittenProfile`）。
- SR-XCHG-1：BytesSent 达到 10 GiB（`TestExchangeRuleOnRewrittenProfile`）。
- SR-MEM-1 的峰值内存与限制比值分支（`TestMemoryRuleOnRewrittenProfile`）；错误信息分支有真实样本 mem_limit_exceeded。

这些规则只验证了判断逻辑，没有验证真实环境中指标的取值范围，使用时需要结合实际 profile 复核。

## 其他 BE 构建的差异（未验证）

样本全部来自本地 StarRocks 3.3.22 的 AVX2 构建。其他构建（例如 AVX-512 构建）的 profile 指标名和文本结构是否相同未验证。
解析器只读取需要的指标，缺失或格式未知的指标视为未上报，不当作问题证据；算子名和指标名变化时，对应规则不命中。

## 测试

单元测试使用固定驱动，覆盖配置与参数校验、每个 op 的固定语句（驱动记录的 `exec:` 与 `query:`）、`quoteLiteral`、`slowQuerySQL`、参数先于凭据校验、脱敏、截断、ANSI 转义、profile 未登记时的轮询、摘要收缩。
集成测试由 `ALLOWOPS_STARROCKS_ADDR` 和 `ALLOWOPS_STARROCKS_STATE` 启用，使用独立的 diag 账号：

- `cluster`、`running`、`profile_list`、`profile_analyze`、`profile_summary` 对本地 StarRocks 的真实输出。
- `slow_queries` 对合成审计表。
- `profile_run` 的 SELECT 在服务器上执行且结果行不返回。
- 通过 `unshare -Ur` 以 root 属主的凭据文件调用公开入口。

验收命令：

```sh
gofmt -l internal
go vet ./...
go test -race ./internal/builtin/srconn ./internal/builtin/starrocks ./internal/builtin/starrocksprofile ./internal/builtin/starrocksdiag ./internal/catalog ./internal/executor ./internal/agent ./internal/gateway/mcp
ALLOWOPS_STARROCKS_ADDR=127.0.0.1:29030 ALLOWOPS_STARROCKS_STATE=<环境凭据目录> go test -race -count=1 ./internal/builtin/starrocksdiag
make examples-check
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./internal/builtin/... ./internal/catalog/... ./internal/agent/...
```
