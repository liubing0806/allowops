# StarRocks 与 Dremio 示例 action 端到端验证

范围：`examples/catalog/actions/` 中 `starrocks_*`、`dremio_*` 共 11 个示例 action，经 MCP 实际执行。

被验证的代码：`test/starrocks-dremio/e2e` 与 `examples/`，复验结果见第 6 节。

## 1. 调用链

```
MCP 客户端（官方 Go SDK，Streamable HTTP）
  -> allowops-gateway 二进制（本机进程，临时 PostgreSQL 与 SeaweedFS 容器）
  -> allowops-agent（Debian 12 容器，网络模式 host，经 mTLS 连接 gateway）
  -> sudo -n /usr/libexec/allowops/allowops-exec（容器内，sudoers 取自 deploy/packaging）
  -> 内置处理器（starrocks_query、starrocks_diag、dremio_query、dremio_diag）
  -> 本机 compose 项目 allowops-srdr 的 StarRocks FE（127.0.0.1:29030）和 Dremio（http://127.0.0.1:29047）
```

- gateway 加载的是 `examples/catalog` 的临时副本，只把地址 `tcp://127.0.0.1:9030`、`http://127.0.0.1:9047` 改为本机端口 29030、29047；`examples/` 不变。副本经 `catalog.Build` 构建，用临时密钥签名并发布，agent 校验签名后加载。目录共 119 个工具，其中 11 个为本次对象（`tools/list` 分页读取）。
- 凭据文件由测试经 `docker exec` 写入容器内 `/etc/allowops/credentials/`（属主 root、权限 0600），容器删除后随之消失。宿主机的 `/etc` 和 `/tmp` 不放凭据。账号对应关系：`starrocks_query_readonly`、`starrocks_explain` 用 `allowops_query`；`starrocks_cluster_status`、`starrocks_slow_queries`、`starrocks_profile_*` 用 `allowops_diag`；`dremio_*` 用 `allowops_reader`。
- 账号和密码来自 `up.sh` 生成的 `.state/credentials.json`，不进入仓库和本文档。
- 调用身份为测试夹具创建的服务账号（admin 角色），主机授权标签在夹具数据库中设置。未覆盖 LDAP 登录、OPA 策略的细分规则。

## 2. 启动方式

前提：Docker、Go（版本见 `go.mod`）、本机可访问 `deb.debian.org`（镜像构建时安装 `sudo`；`docker build` 使用 `--network host` 并传入 `HTTP_PROXY`/`HTTPS_PROXY`）、`allowops-srdr` 环境已运行。

```bash
# 1. 启动 StarRocks 与 Dremio（幂等；环境已在运行时跳过）
test/starrocks-dremio/up.sh

# 2. 端到端：构建 gateway，起 PostgreSQL/SeaweedFS 临时容器、agent 容器，经 MCP 调用全部用例
ALLOWOPS_SRDR_CREDENTIALS=test/starrocks-dremio/.state/credentials.json \
  test/starrocks-dremio/e2e.sh /tmp/allowops-srdr-e2e
```

`e2e.sh` 等价于 `make allowops-gateway` 加 `go test -tags=srdr ./test/starrocks-dremio/e2e -run '^TestEndToEnd$' -count=1 -v`。耗时约 50 秒。

输出目录含：

- `results.json`：每次调用的请求参数、耗时、状态、完整 stdout/stderr、任务原因码、数据库侧核对结果。
- `tool-schemas.json`：11 个工具的 `inputSchema`。
- `server-statements.json`：StarRocks FE 审计日志（`allowops_*` 账号）和 Dremio 作业列表中的语句。

环境变量：`ALLOWOPS_SRDR_CREDENTIALS`（必填）、`ALLOWOPS_SRDR_RESULTS`（结果目录；`e2e.sh` 用第一个参数设置，默认 `/tmp/allowops-srdr-e2e`）、`ALLOWOPS_SRDR_FE_CONTAINER`（FE 容器名，默认 `allowops-srdr-sr-fe`）。

测试结束后 agent 容器、镜像、PostgreSQL 与 SeaweedFS 容器由 `t.Cleanup` 删除。

### 判定方法

- 成功调用：job 状态为 `succeeded`，stdout 含预期内容；
- 拒绝调用：job 状态不是 `succeeded`，或网关在创建 job 之前返回参数错误；
- 数据库侧核对：成功调用的语句必须出现在 StarRocks FE 审计日志或 Dremio 作业列表中；被处理器拒绝的语句必须不出现。被拒绝的语句使用唯一字面值（`p6_e2e_denied`、`987654321`），避免与其他会话的流量混淆。

## 3. 结果

时间为 MCP `tools/call` 从发出到收到结果的耗时（含网关调度、agent、sudo、处理器和数据库访问，不含之后读取完整输出的 `jobs_get`）。主机名在此处省略为 `<host>`。

"拒绝层"：**网关**表示 MCP 在创建 job 之前按目录 `params` 校验拒绝，返回 `isError`，没有 job；**处理器**表示请求到达 agent 和处理器，job 状态为 `failed`，退出码 1，任务原因码 `EXECUTION_FAILED`，stdout 与 stderr 为空。

### 3.1 汇总

| action | 成功调用 | 拒绝调用 | 结果 |
| --- | --- | --- | --- |
| `starrocks_query_readonly` | 4 次（含行数上限、脱敏） | 2 次（处理器） | 通过 |
| `starrocks_explain` | 1 次 | 2 次（处理器 1、网关 1） | 通过（修复后，见第 5 节问题 1） |
| `starrocks_cluster_status` | 2 次 | 1 次（网关） | 通过 |
| `starrocks_slow_queries` | 1 次 | 1 次（网关） | 通过 |
| `starrocks_profile_list` | 1 次 | 1 次（网关） | 通过 |
| `starrocks_profile_summary` | 1 次 | 2 次（网关） | 通过 |
| `dremio_query_readonly` | 2 次（含脱敏） | 2 次（处理器） | 通过 |
| `dremio_explain` | 1 次 | 2 次（处理器 1、网关 1） | 通过 |
| `dremio_nodes` | 1 次 | 1 次（网关） | 通过 |
| `dremio_jobs_recent` | 1 次 | 1 次（网关） | 通过 |
| `dremio_job_profile` | 1 次 | 1 次（网关） | 通过 |

32 次调用（另有 3 次辅助调用未计入：生成 Dremio 作业的查询、按语句文本查找作业 ID、最后读取作业列表作为数据库侧记录），未出现与预期不符的结果。

### 3.2 成功调用

参数省略了公共字段 `targets`（单台主机）、`reason`、`wait_seconds`。`database` 均为 `demo_dw`。

| action | 参数 | 返回摘要 | 耗时 ms |
| --- | --- | --- | --- |
| `starrocks_query_readonly` | `sql: SELECT count(*) FROM fact_orders` | 1 行：`500000` | 345 |
| `starrocks_query_readonly` | `sql: SHOW TABLES` | 3 个表：`dim_product`、`dim_user`、`fact_orders` | 356 |
| `starrocks_query_readonly` | `sql: SELECT order_id FROM fact_orders ORDER BY order_id LIMIT 1000` | 200 行（`max_rows: 200`）；结果标记 `truncated: true` | 349 |
| `starrocks_query_readonly` | `sql: SELECT 'password=hunter2-p6' AS v` | `[REDACTED:credential]`，原值不出现 | 320 |
| `starrocks_explain` | `sql: EXPLAIN SELECT count(*) FROM fact_orders` | 676 字节计划，含 `OlapScanNode`、`cardinality=500000` | 341 |
| `starrocks_cluster_status` | `op: cluster` | `# frontends`、`# backends`、`# compute_nodes` 分节，1230 字节 | 387 |
| `starrocks_cluster_status` | `op: running` | 仅表头（当前没有运行中的查询），150 字节 | 412 |
| `starrocks_slow_queries` | `op: slow_queries, since_minutes: 10080, limit: 5` | 5 行合成审计记录，1075 字节 | 479 |
| `starrocks_profile_list` | `op: profile_list, limit: 5` | 5 行，含测试生成的 query_id | 913 |
| `starrocks_profile_summary` | `op: profile_summary, query_id: <本次生成>, top_n: 5` | JSON：`query`（13 ms、扫描 500000 行）、5 个 `top_operators`（OLAP_SCAN 占 66.3%）、`findings` | 1121 |
| `dremio_query_readonly` | `sql: SELECT count(*) AS n FROM "starrocks".demo_dw.dim_user` | 1 行：`10000` | 390 |
| `dremio_query_readonly` | `sql: SELECT 'password=hunter2-p6' AS v` | `[REDACTED:credential]`，原值不出现 | 445 |
| `dremio_explain` | `sql: EXPLAIN PLAN FOR SELECT count(*) FROM "starrocks".demo_dw.dim_user` | 2730 字节计划文本 | 381 |
| `dremio_nodes` | `{}` | `# sys.nodes` 1 行、`# sys.memory` 1 行，559 字节 | 491 |
| `dremio_jobs_recent` | `since: 1h, limit: 5` | 5 行作业，列为 `id, state, user, …, query` | 348 |
| `dremio_job_profile` | `job_id: <本次生成>, top_n: 5` | JSON：状态 `COMPLETED`、各阶段耗时、`operators`，1470 字节 | 356 |

`starrocks_profile_summary` 的 query_id 由测试用 `allowops_query` 账号在一条连接上执行 `SET enable_profile = true`、一条聚合查询和 `SELECT last_query_id()` 取得，并轮询 `get_query_profile` 到 profile 登记为止。`dremio_job_profile` 的 job_id 先经 `dremio_query_readonly` 执行一条查询，再由 `dremio_jobs_recent` 的输出按语句文本找到。

### 3.3 拒绝调用

| action | 参数 | 拒绝层 | 结果 | 数据库侧 | 耗时 ms |
| --- | --- | --- | --- | --- | --- |
| `starrocks_query_readonly` | `sql: DROP TABLE p6_e2e_denied` | 处理器 | `failed`，退出码 1 | FE 审计日志没有该语句 | 345 |
| `starrocks_query_readonly` | `sql: INSERT INTO p6_e2e_denied VALUES (987654321)` | 处理器 | 同上 | 没有该语句 | 362 |
| `starrocks_explain` | `sql: EXPLAIN ANALYZE SELECT … WHERE order_id = 987654321` | 处理器 | 同上 | 没有该语句 | 349 |
| `starrocks_explain` | `sql: SELECT 1` | 网关 | `parameter sql allowed: regex ^EXPLAIN [^\r\n]+$` | 无请求 | 80 |
| `starrocks_cluster_status` | `op: cluster, component: "frontends; DROP"` | 网关 | `parameter component: not an enum value` | 无请求 | 66 |
| `starrocks_slow_queries` | `op: slow_queries, state: "OK' OR '1'='1"` | 网关 | `parameter state: not an enum value` | 无请求 | 91 |
| `starrocks_profile_list` | `op: profile_list, limit: 100000` | 网关 | `parameter limit: above max; allowed: integer min=1 max=200` | 无请求 | 110 |
| `starrocks_profile_summary` | `query_id: not-a-query-id` | 网关 | `parameter query_id: does not match regex`（UUID 正则） | 无请求 | 74 |
| `starrocks_profile_summary` | `query_id: <UUID>' OR '1'='1` | 网关 | `parameter query_id: exceeds max_len` | 没有该语句 | 80 |
| `dremio_query_readonly` | `sql: CREATE TABLE "starrocks-scratch".scratch.p6_e2e_denied AS SELECT 1` | 处理器 | `failed`，退出码 1 | 作业列表没有该语句 | 342 |
| `dremio_query_readonly` | `sql: DROP TABLE "starrocks-scratch".scratch.p6_e2e_denied` | 处理器 | 同上 | 没有该语句 | 380 |
| `dremio_explain` | `sql: SELECT 1` | 网关 | `parameter sql allowed: regex ^EXPLAIN PLAN …` | 无请求 | 73 |
| `dremio_explain` | `sql: EXPLAIN PLAN FOR INSERT INTO "starrocks-scratch".scratch.p6_e2e_denied VALUES (987654321)` | 处理器 | `failed`，退出码 1 | 没有该语句 | 346 |
| `dremio_nodes` | `op: jobs` | 网关 | `parameter op: not an enum value; allowed: enum ["nodes"]` | 无请求 | 73 |
| `dremio_jobs_recent` | `user: "x' OR '1'='1"` | 网关 | `parameter user: does not match regex` | 无请求 | 73 |
| `dremio_job_profile` | `job_id: not-a-query-id` | 网关 | `parameter job_id: does not match regex`（UUID 正则） | 无请求 | 68 |

处理器层的拒绝由数据库侧记录证明语句没有到达服务器；处理器的错误原因本身在 MCP 结果中不可见（见问题 2），因此不能仅凭 `failed` 区分"被 sqlguard 拒绝"和"到达服务器后被拒绝"，需要依靠数据库侧核对。

## 4. 另行观察到的行为

- `starrocks_profile_summary`、`dremio_job_profile` 的 job 输出体积分别为 1166、1470 字节，均小于 `max_bytes`，未触发摘要收缩。
- MCP 结果中 stdout 预览每组最多 4 KiB，完整输出通过 `jobs_get`（`host`、`stream`、`offset` 分页）读取，测试用该方式取得全部 stdout 与 stderr。
- `dremio_jobs_recent` 输出的 `query` 列也经过脱敏：含 `password=…` 的语句显示为 `SELECT '[REDACTED:creden…`。
- 每次调用耗时 0.3 至 1.1 秒；网关参数校验拒绝为 66 至 110 毫秒。

## 5. 发现的问题

### 问题 1（已修复）：`starrocks_explain` 示例拒绝所有 EXPLAIN SELECT

现象：`starrocks_explain` 执行 `EXPLAIN SELECT count(*) FROM fact_orders` 返回 `failed`，退出码 1，StarRocks FE 审计日志没有该语句，说明在连接之前被处理器拒绝。

原因：示例配置 `statement_types: [EXPLAIN]`。`starrocks_query` 要求 EXPLAIN 的目标语句也满足 `statement_types`（`internal/builtin/starrocks/starrocks.go` 的 `checkStatement`），目标是 SELECT，所以被拒绝。`dremio_explain` 示例配置为 `[SELECT, EXPLAIN]`，不受影响。单元和集成测试直接构造配置，没有使用示例文件，所以此前没有发现。

处理：

- 失败测试：`internal/catalog/examples_sql_actions_test.go` 加载示例目录，对 5 个 SQL 示例 action 的合法和非法语句断言处理器在读取凭据之前的校验结果。
- 修复：`starrocks_explain.yaml` 改为 `statement_types: [SELECT, EXPLAIN]`。`params.sql` 的正则 `^EXPLAIN …` 仍限制调用方只能提交 EXPLAIN 开头的语句。

### 问题 2（未修复，需要决定）：处理器的错误原因不返回给 MCP 调用方

现象：处理器拒绝或执行失败时，MCP 结果只有 `status: failed`、`exit_code: 1`，stdout 与 stderr 为空；任务结果中的原因码只有 `EXECUTION_FAILED`。AI 客户端无法得知语句被拒绝的原因。

依据：

- `internal/catalog/builtin_adapters.go` 的各处理器适配器在出错时返回 `BuiltinResult{ExitCode: ExitFailure}, err`，不填 `Stderr`；
- `internal/execd/exec.go` 的 `ExecutionReason` 把任意错误归为 `EXECUTION_FAILED`，不传递错误文本。

范围：`log_search`、`redis_command`、`mysql_query` 等已有内置处理器使用同一适配器模式，行为相同；`docs/builtin-starrocks.md`、`docs/builtin-dremio.md` 中描述的错误文本（例如 `starrocks query failed (code 5203)`）在 MCP 结果里不可见，只在处理器的单元测试里可见。

未修复原因：错误文本是否可以返回、返回哪些（处理器错误已按"不含 SQL 和凭据"设计）属于跨处理器的协议决定，不限于本次的四个处理器。

### 问题 3（未修复，需要决定）：`pii` 脱敏误改诊断输出中的数字

现象：

- `starrocks_cluster_status` 的 FE 节点名 `sr-fe_9010_<13 位毫秒时间戳>` 显示为 `sr-fe_9010_[REDACTED:bank_card]`（本环境中每次调用都出现）；
- `dremio_nodes` 的 `load` 列 `0.<16 位小数>` 显示为 `0.[REDACTED:bank_card]`（该列的值随时间变化，是否出现取决于当时的数值是否通过 Luhn 校验）。

原因：`internal/redact/redact.go` 的 `bank_card` 规则匹配连续 13 至 19 位数字并做 Luhn 校验，约 10% 的随机数字串通过校验。11 个示例都配置 `redact.builtin: [secrets, pii]`。

影响：节点名被改写后，后续用节点名过滤其他输出会失败；`load` 等数值列不可读。查询类 action（`*_query_readonly`）输出用户数据，保留 `pii` 有依据；`starrocks_cluster_status`、`dremio_nodes` 的输出不含个人数据。

建议（待决定）：对 `starrocks_cluster_status`、`dremio_nodes` 去掉 `pii`，仅保留 `secrets`；或为 `bank_card` 规则增加数字边界（不匹配小数部分和以字母、下划线相连的数字）。

## 6. 复验与命令

| 项目 | 命令 | 被验证的代码 | 结果 |
| --- | --- | --- | --- |
| 端到端 | `test/starrocks-dremio/e2e.sh` | 问题 1 修复后 | 32 次调用，0 个与预期不符 |
| 失败测试在修复前失败 | `go test ./internal/catalog -run TestSQLExampleActionsAcceptTheirOwnStatements` | 问题 1 修复前 | `starrocks_explain "EXPLAIN SELECT count(*) FROM demo_dw.fact_orders": accepted=false … statement_types allows only: EXPLAIN` |
| 修复后 | 同上，`make examples-check` | 问题 1 修复后 | 通过 |

## 7. 未验证项

- 处理器对诊断参数（`query_id`、`state`、`limit` 越界）的二次校验没有经 MCP 触发：网关先按目录 `params` 拒绝。这部分只由 `internal/builtin/starrocksdiag`、`internal/builtin/dremio`（`diag_test.go`）的单元测试覆盖。
- `starrocks_slow_queries` 读取的是按 AuditLoader 结构手工建立的合成审计表，真实插件未验证。
- 主机环境是 Debian 12 容器，sudoers 取自 `deploy/packaging/allowops.sudoers`；systemd 服务单元、软件包安装脚本和 RPM 系发行版没有参与。
- 输出超过 `max_output`/`max_bytes` 的摘要收缩、处理器超时（`timeout`）、多主机并发、`jobs_cancel` 没有经 MCP 验证。
- 调用身份是夹具服务账号；非 admin 角色、策略拒绝、`view_output` 权限没有覆盖。
- gateway 二进制由本工作树构建（版本 `dev`），不是发布镜像。
