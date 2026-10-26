# dremio_query 只读 SQL 执行

`dremio_query` 是自包含的内置处理器，位于 `internal/builtin/dremio`，只使用标准库 HTTP 客户端，不增加依赖。它先用 `internal/builtin/sqlguard` 的 Dremio 方言校验一条 SQL，再通过 Dremio REST API v3 提交为作业，读取结果的第一页并以 TSV 返回。

词法校验的规则见 [builtin-sqlguard.md](builtin-sqlguard.md)。

## 安全边界

Dremio 24.1 社区版没有可用的权限边界。实测所有登录账号都是管理员，可以创建视图、`TRUNCATE`、`ALTER SYSTEM`、修改数据源配置，并通过 `external_query` 以数据源账号的权限执行任意语句。因此：

1. 词法校验是 Dremio 一侧唯一的写入限制。校验在读取凭据和发送任何请求之前执行，未通过时没有请求到达 Dremio。
2. 数据源一侧的写入限制取决于数据源配置所用的账号。每个数据源必须配置只读账号。词法校验拒绝 `external_query`，但校验器被绕过时，数据源账号的权限是后一道限制。
3. 处理器不限制可读取的对象范围：词法校验不解析对象名，Dremio 没有权限可以限制范围，`builtin_config` 没有 `databases` 之类的字段，参数也没有 `context`。读取范围由各数据源账号决定。
4. 凭据文件中的 Dremio 账号在社区版里是管理员。凭据文件的 root 属主和 0600 权限是防止其他进程使用该账号的唯一限制，该账号不与其他用途共用。

词法校验的已知限制（完整列表见 `builtin-sqlguard.md`“已知限制”）：

- 不识别视图定义。视图内部引用的函数和表不受检查。
- 不识别数据源插件和自定义函数的副作用。
- 不检查语法正确性。语法错误由 Dremio 报告，作业状态为 FAILED。
- 不限制读取范围。名单外的函数和系统表仍可读取。
- 禁用关键字按词法单元匹配，未加引号的同名列名、别名被拒绝，调用方需要加引号。
- 针对 Dremio 24.1 的语法设计，其他版本的行为未验证。

## 配置

`builtin_config` 的字段如下。未知字段、`null`、类型错误一律在目录校验和执行时报错。所有数值上限同时是默认值，配置只能收紧。

| 字段 | 合法值与省略时的行为 |
| --- | --- |
| `credential` | 必填，绝对路径。root 属主、权限精确为 0600 的 JSON 文件，格式见“凭据” |
| `url` | 必填，`http://host:port` 或 `https://host:port`，不含用户信息、路径、查询和片段。HTTPS 只信任系统根证书，没有自定义 CA 和跳过校验的选项 |
| `max_rows` | 0 到 500，省略为 500。Dremio 单次最多返回 500 行，因此 `max_rows` 就是一页 |
| `max_bytes` | 0 到 1 MiB（`1MB`），省略为 1 MiB。TSV 文本的字节上限，表头计入，放不下的行不返回并标记 `truncated` |
| `timeout` | 1ms 到 10s，省略为 10s。覆盖登录、提交、轮询和读取结果 |
| `statement_types` | SELECT、SHOW、DESCRIBE、EXPLAIN 的非空子集，不区分大小写；省略时允许全部。EXPLAIN 的目标语句也必须满足该限制，`EXPLAIN PLAN FOR SELECT ...` 需要同时列出 EXPLAIN 和 SELECT |
| `show_types` | SCHEMAS、TABLES、VIEWS、PARTITIONS、FILES、CREATE TABLE、FUNCTIONS 的非空子集，不区分大小写；省略时允许全部 |

限制只能在词法校验接受的范围内再收紧，不能放宽校验。

动作参数只有 `sql`：必填，最长 4000 字符。没有 context、database 等参数。Dremio 作业没有默认上下文，SQL 中的对象必须写完整路径，例如 `"source".schema.table`。目录中的参数覆盖只能增加 `regex` 或减小 `max_len`。

`Result` 的 JSON 字段是 `output`、`rows`、`truncated`。`rows` 不含表头，空结果仍有表头。

## 执行链

1. 校验配置，用 sqlguard 的 Dremio 方言校验 SQL，再检查 `statement_types` 和 `show_types`。任何一步失败都直接返回，此时不读取凭据，也不发送请求。
2. 读取凭据文件。
3. 在 `timeout` 内依次执行：
   1. `POST /apiv2/login`，请求体 `userName`、`password`，得到会话 token。后续请求带 `Authorization: _dremio<token>`。
   2. `POST /api/v3/sql`，请求体 `{"sql": ...}`，得到作业 id。作业 id 只接受字母、数字、`_`、`-`，最长 128 字符，防止它改变后续请求的路径。
   3. `GET /api/v3/job/{id}` 轮询。间隔从 25ms 起每次加倍，最长 500ms。状态 COMPLETED、FAILED、CANCELED、INVALID_STATE 结束轮询，其他状态继续轮询到超时。
   4. `GET /api/v3/job/{id}/results?offset=0&limit=N`，N 为 `min(max_rows+1, 500)`。
4. 返回时，无论成功、失败、超时还是调用方取消，都在独立的 3 秒期限内执行清理：作业未到终止状态时 `POST /api/v3/job/{id}/cancel`，然后 `DELETE /apiv2/login` 注销会话。Dremio 的会话 token 有效期约 720 小时，不注销会长期保留可用 token。

整个调用的最长耗时是 `timeout` 加 3 秒清理期限。示例 action 的 `timeout: 15s` 大于这个值。

HTTP 客户端不使用代理，不跟随重定向（收到 3xx 按失败处理，凭据和 token 不会发往其他地址），每个请求受 context 约束，每个响应体有字节上限：登录、提交、状态、取消、注销为 256 KiB，结果页为 16 MiB（JSON 行重复列名，远大于 `max_bytes`）。

### 截断判定

`truncated` 在以下情况为 true：结果行数多于 `max_rows`，或 TSV 超过 `max_bytes`。

- `max_rows` 小于 500 时，请求 `max_rows+1` 行，多出的一行说明有更多数据。
- `max_rows` 为 500 时，一页恰好 500 行，再请求 `offset=500&limit=1`，返回一行则标记截断。
- 不使用作业的 `rowCount` 判断：实测 SHOW、DESCRIBE、EXPLAIN 的 `rowCount` 为 0。

## 输出

输出是 TSV，首行为表头，格式与 `mysql_query` 一致：制表符、换行、回车、反斜线和 NUL 转义，NULL 为 `\N`。表头和每个单元格先经调用方给出的脱敏函数处理再编码。

单元格取值：

| Dremio 返回 | TSV 文本 |
| --- | --- |
| `null`（实测顶层 NULL 列为显式 `null`），或该行没有此列 | `\N` |
| 字符串 | 字符串内容 |
| 数字 | Dremio 发送的数字文本，不经过 float64 |
| 布尔 | `true` 或 `false` |
| 对象和数组 | 紧凑 JSON 文本。实测 Dremio 在对象内省略值为 NULL 的字段（`CONVERT_FROM('{"a":1,"c":null}', 'json')` 返回 `{"a":1}`），文本中不出现该字段 |

实测：`BIGINT` 最大值 `9223372036854775807` 和 `DECIMAL(38,9)` 的 `12345678901234567890.123456789` 原样返回，`DECIMAL(10,2)` 的 `1.50` 保留小数位，`DOUBLE` 以 Dremio 的写法返回（如 `1.0E300`）。

## 错误

错误信息只包含阶段、HTTP 状态码或固定类别，不包含 SQL、服务端原始消息、token、密码和传输层错误文本。

| 情况 | 错误信息 |
| --- | --- |
| 登录、提交、状态、结果、取消的请求被拒绝 | `dremio <stage> failed (status N)` |
| 连接失败 | `dremio <stage> request failed` |
| 响应不是预期格式 | `dremio <stage> failed (invalid response)` |
| 响应超过字节上限 | `dremio <stage> response exceeds N bytes` |
| 作业 FAILED | `dremio job FAILED (<category>)` |
| 作业 CANCELED | `dremio job CANCELED` |
| 超时、取消 | `context deadline exceeded`、`context canceled` |
| 表头放不进 `max_bytes` | `dremio result header exceeds max_bytes` |

作业失败的类别由服务端消息中的子串归入五类之一：`syntax or validation error`、`object not found`、`access denied`、`resource limit`、`execution error`，消息本身不返回。分类只是提示，不是契约。

## 凭据

凭据文件与 `mysql_query` 相同：root 属主、权限精确为 0600 的普通文件，末级路径不能是符号链接，最大 16 KiB，内容是一个 JSON 对象，只有 `username`、`password` 两个字段。

```json
{"username":"allowops_ro","password":"replace-on-host"}
```

- 文件所在目录由 root 管理，代码不检查父目录权限。
- `url` 使用 `http://` 时，登录请求以明文发送密码和随后的 token。只在回环地址或受信任的内部网络使用 HTTP，其他场景使用 HTTPS。
- 处理器不缓存 token，每次调用登录一次、注销一次。

## 已知限制与未验证项

- 提交请求在超时或取消时被中断时，处理器不知道作业 id，无法取消可能已创建的作业。该作业由 Dremio 自行执行完毕。
- 超时只覆盖处理器和 Dremio 之间的交互。作业取消后，数据源上已经开始的查询是否立即停止取决于数据源。
- 单页结果最多 500 行，不翻页。需要更多数据时缩小查询范围。
- HTTPS 使用真实证书的场景未验证，测试只覆盖自签名证书被拒绝。
- 长时间运行和高并发场景未验证。每次调用一个登录会话，并发调用同时存在多个会话。
- Dremio 24.1 之外的版本未验证。

## 测试与复现

单元测试用 httptest 模拟 Dremio，覆盖：配置校验和默认值、请求顺序和请求头、登录失败、作业 FAILED 与 CANCELED 及错误类别、轮询超时时验证已发出取消请求、调用方取消、状态请求挂起、截断（含 `max_rows` 为 500 的探测）、NULL、嵌套类型、大数字、`max_bytes`、响应超限、结果格式错误、非法作业 id、重定向不被跟随、自签名证书被拒绝、HTTP 客户端设置、token 和密码不出现在错误中、校验失败时没有任何 HTTP 请求（以请求计数验证）、凭据在 SQL 校验之后读取、守卫 panic 的处理、并行调用。

集成测试需要本地环境 `test/starrocks-dremio`，由环境变量门控，未设置时跳过并给出原因：

| 变量 | 含义 |
| --- | --- |
| `ALLOWOPS_DREMIO_URL` | Dremio REST 地址，例如 `http://127.0.0.1:29047` |
| `ALLOWOPS_DREMIO_STATE` | 账号文件目录，默认 `test/starrocks-dremio/.state` |
| `ALLOWOPS_DREMIO_SOURCE` | 指向演示库（含 `demo_dw` 表）的 Dremio 数据源名称 |
| `ALLOWOPS_DREMIO_SCRATCH_SOURCE` | 指向可写 scratch 库的 Dremio 数据源名称 |
| `ALLOWOPS_STARROCKS_ADDR` | 数据源背后的 StarRocks FE 地址，例如 `127.0.0.1:29030` |

集成测试读取 MySQL 协议数据源中的表，执行 `EXPLAIN PLAN FOR`、`SHOW`、`DESCRIBE`，验证截断、超时和调用方取消后 Dremio 一侧的作业为 CANCELED、注销后 token 失效，并验证被拒绝的语句没有执行：`external_query`（包括 EXPLAIN 中的）、`CREATE VIEW`、`TRUNCATE`、`ALTER SYSTEM`、多语句。每个“未执行”的检查都有对照：同一语句绕过守卫执行时数据确实被改变，说明检查能发现变化。

测试进程不是 root，无法读取 root 属主的凭据文件。集成测试把 `readCredential` 替换为读取账号文件，其余流程不变。属主和权限检查由 `internal/builtin/credfile` 的测试覆盖。

```sh
go vet ./internal/builtin/dremio/...
go test -race ./internal/builtin/dremio/...
ALLOWOPS_DREMIO_URL=http://127.0.0.1:29047 ALLOWOPS_DREMIO_SOURCE=<数据源> ALLOWOPS_DREMIO_SCRATCH_SOURCE=<scratch 数据源> ALLOWOPS_STARROCKS_ADDR=127.0.0.1:29030 go test -race -run TestIntegration ./internal/builtin/dremio
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./internal/builtin/dremio/...
```

# dremio_diag 诊断

`dremio_diag` 是第二个内置处理器，位于同一个包 `internal/builtin/dremio`，复用 `dremio_query` 的 HTTP 客户端、凭据读取和登录注销流程（客户端代码未修改）。它只发送固定的请求：调用方选择 `op` 和参数，请求的路径、SQL 和过滤表达式由处理器生成，调用方的值只在通过固定格式或范围校验后才进入请求。它不执行调用方的 SQL，不经过 sqlguard。

## op 与参数

`op` 必填，取值如下。参数按 op 在处理器内校验，不在工具 schema 的根上声明依赖关系；某个 op 不接受的参数出现时报错 `op <op> does not take parameter <name>`。所有参数都在读取凭据和发送请求之前校验。

| op | 数据来源 | 接受的参数 | 返回 |
| --- | --- | --- | --- |
| `nodes` | `SELECT * FROM sys.nodes`、`SELECT * FROM sys.memory` | 无 | 两个 TSV 表，各有一行标题 `# sys.nodes`、`# sys.memory` |
| `jobs` | `GET /apiv2/jobs-listing/v1.0` | `since`、`min_duration`、`state`、`user`、`limit` | TSV，列为 `id, state, user, query_type, queue, start_time, duration_ms, rows_scanned, output_records, accelerated, spilled, query` |
| `job` | `GET /api/v3/job/{id}` | `job_id` | 一行 JSON：`job_id, state, query_type, queue, started_at, ended_at, row_count`，有时还有 `duration_ms, error, error_category, cancellation_reason` |
| `job_profile` | `POST /apiv2/support/{id}/download` | `job_id`、`top_n` | 一行 JSON 摘要，字段见“job_profile 摘要” |
| `reflections` | `SELECT * FROM sys.reflections` | 无 | TSV |

Dremio 24.1 没有 `sys.jobs_recent`，`sys.jobs` 只含运行中的作业，因此 `jobs` 使用作业列表接口。

| 参数 | 类型与范围 | 说明 |
| --- | --- | --- |
| `op` | 枚举 | 见上表，必填 |
| `job_id` | 字符串 | `job`、`job_profile` 必填。格式 8-4-4-4-12 位十六进制，校验通过后才写入请求路径 |
| `since` | 时长，大于 0，最长 168h | 只列出开始时间晚于“当前时间减 since”的作业，省略为 1h |
| `min_duration` | 时长，0 到 168h | 只列出耗时不小于该值的作业。大于 0 时按耗时降序，否则按开始时间降序 |
| `state` | 枚举 `RUNNING`、`COMPLETED`、`FAILED`、`CANCELED`，不区分大小写 | 作业状态 |
| `user` | 字符串，字母、数字和 `. _ @ -`，不以 `-` 开头，最长 128 字符 | 提交作业的用户 |
| `limit` | 整数，1 到 `max_rows` | 作业条数，省略为 20 |
| `top_n` | 整数，1 到 50 | 摘要中的算子数，省略为 10 |

作业列表的过滤键只使用本地实测接受的 `st`（开始时间）、`jst`（状态）、`usr`（用户）、`dur`（耗时，毫秒）。过滤表达式形如 `(st=ge=<毫秒>;jst=="FAILED";usr=="name";dur=ge=<毫秒>)`，值只来自上述校验后的参数。其他过滤键（`qt` 之外的集合、`contains`）未验证，处理器不使用。`jobs` 多请求一条以判断是否还有更多结果，有则 `truncated` 为 true。作业的 SQL 文本折叠为单行并截断为 200 字符。

## 配置

`builtin_config` 的字段与 `dremio_query` 的 `credential`、`url`、`max_rows`、`max_bytes`、`timeout` 相同（含取值范围和默认值），另有：

| 字段 | 合法值与省略时的行为 |
| --- | --- |
| `max_profile_bytes` | 0 到 32 MiB（`32MB`），省略为 32 MiB。解压后的 profile JSON 字节上限，也限制已解压数据占用的内存 |
| `ops` | `op` 取值的非空子集；省略时允许全部。只有一个值时，`op` 参数省略即取该值 |

`dremio_diag` 没有 `statement_types`、`show_types`。目录中的参数覆盖只能增加 `regex` 或减小 `max_len`，不能限制枚举的取值，因此固定 op 使用 `ops`：配置 `ops: [nodes]` 的 action 不能执行其他 op，列表外的 op 在读取凭据和发送请求之前被拒绝。示例中的三个 action 各固定一个 op。

返回值与 `dremio_query` 相同：`output`、`rows`、`truncated`。`job` 和 `job_profile` 返回一行 JSON，`rows` 为 1。

## job_profile 摘要

`POST /apiv2/support/{id}/download` 返回 zip（含 `header.json` 和 `profile_attempt_N.json`），profile 约 100 KB 到数 MB。处理器在内存中解压，取编号最大的 attempt，只解析下表字段，其余内容（`jsonPlan`、`relInfoMap`、各数据集的 Base64 `batchSchema` 等）由解码器跳过。摘要不含用户提交的原始 SQL。

| 字段 | 含义 | profile 来源 |
| --- | --- | --- |
| `job_id`、`state`、`user`、`queue` | 作业标识与状态 | `state`、`user`、`resourceSchedulingProfile.queueName` |
| `total_ms` | 总耗时 | `end - start` |
| `planning_ms` | 规划耗时 | `planningEnd - planningStart` |
| `phases` | 各状态的耗时（PLANNING、QUEUED、RUNNING 等，不含终止状态） | `stateList` 相邻状态的时间差 |
| `planning_top` | 耗时最长的规划阶段 | `planPhases` |
| `peak_memory_bytes`、`direct_memory_bytes` | 单个节点的内存峰值与该节点的直接内存上限 | `nodeProfile[].maxMemoryUsed`、`foreman.maxDirectMemory` |
| `scan_records` | 所有扫描算子的输出行数之和 | 算子 `outputRecords` |
| `operators` | 按处理时间加等待时间降序的前 N 个算子，字段 `fragment, id, type, instances, process_ms, wait_ms, records_in, records_out, peak_memory_bytes, skew_ratio` | `fragmentProfile[].minorFragmentProfile[].operatorProfile[]` |
| `operators_omitted` | 未列出的算子数 | |
| `pushdown_sql` | 计划中交给 JDBC 数据源的 SQL，最多 10 条，每条最长 2000 字符 | `plan` 中的 `Jdbc(sql=[...]) : rowType` |
| `acceleration` | `accelerated, substitutions, considered, reflections`：是否使用反射、替换次数、规划器考虑的反射数、使用过的反射名 | `accelerationProfile` |
| `error` | 失败作业错误信息的第一行，最长 300 字符 | `error` |
| `hits` | 命中的规则，见下节 | |

算子类型名来自 `UserBitShared.CoreOperatorType`（dremio-protocol 24.1.0，68 个取值）。未知编号显示为 `OPERATOR_<n>`。同一算子在多个实例（minor fragment）上的数据先相加；`skew_ratio` 是实例间最大处理时间除以平均处理时间，只在实例数大于 1 时给出。

所有来自服务器的字符串（用户、队列、错误、下推 SQL、反射名）先经调用方的脱敏函数处理再编码。摘要超过 `max_bytes` 时依次丢弃：`planning_top`、`pushdown_sql`（从末尾）、`operators`（从末尾，`operators_omitted` 相应增加），`hits` 保留，`truncated` 为 true。`hits` 放不下时返回 `{"error":"summary exceeds max_bytes"}`。

### zip 与 profile 的限制

zip 来自网络，按不可信数据处理：

- 压缩后的下载上限为 `min(16 MiB, max_profile_bytes)`，超出时按响应超限报错。
- 目录项最多 64 个，超过则拒绝，此时没有解压任何内容。
- 只接受名称匹配 `profile_attempt_<数字>.json` 的项，名称不用作路径。
- 目录中声明的解压后大小超过 `max_profile_bytes` 时拒绝，不解压。声明值小于实际大小时，读取以 `max_profile_bytes+1` 字节为上限，超出则拒绝。测试用 64 MiB 的零字节压成的 zip（压缩后小于 1 MiB）验证上述两种情况，以及恰好等于上限时接受、多一字节时拒绝。
- profile 不是合法 JSON、没有 profile 项、不是 zip 时返回 `dremio profile is not valid`，不包含响应内容。

## 规则

规则对摘要求值，命中时在 `hits` 中给出 `rule`、`evidence`（实测值与阈值）、`cause`、`advice`。阈值由本地 Dremio 24.1 上生成的 profile 设定，是初始值，未用生产数据校准。规则不改变作业，只给出排查方向；`cause` 是常见原因，不是对该作业的确诊。

| 编号 | 触发条件 | 可能原因 | 建议 |
| --- | --- | --- | --- |
| DR-FAIL-1 | 作业状态为 FAILED 或 CANCELED | 对象不存在、无权限、资源超限、语法或校验错误、执行错误；或被取消。`evidence.category` 使用与 `dremio_query` 相同的五类 | 读取 `error`；对象不存在时检查路径和数据源；资源超限见 DR-MEM-1；被取消时用 `job` 查取消原因 |
| DR-PLAN-1 | 规划耗时 ≥ 250 ms 且 ≥ 总耗时的 25% | 读取或刷新数据集元数据；语句含很多表、视图或 UNION 分支；规划方案多 | 查看 `planning_top`；元数据阶段在查询前刷新数据集元数据；语句过长时拆分或减少引用的视图 |
| DR-SCAN-1 | 所有扫描算子输出行数之和 ≥ 100000 | 没有数据源可执行的过滤条件；过滤、聚合或 limit 没有下推 | 对照 `pushdown_sql` 与原语句；在分区列或键列上加过滤；少选列；使用数据源支持的表达式以便下推 |
| DR-JOIN-1 | 某个 HASH_JOIN 或 MERGE_JOIN 的输入行数 ≥ 100000（`evidence.operators` 列出全部满足的算子） | 连接在 Dremio 内执行：两侧来自不同数据源，或连接条件无法下推 | 检查两侧的数据源；同一数据源的表在数据源内连接；连接前用过滤或聚合缩小一侧；小表放入反射 |
| DR-JOIN-2 | NESTED_LOOP_JOIN 的输入行数 ≥ 1000 | 连接没有等值条件，只有范围或 OR 条件；Dremio 逐对比较 | 增加键上的等值条件，或改写范围条件（如分桶列）；连接前缩小两侧 |
| DR-JOIN-3 | HASH_JOIN 或 MERGE_JOIN 的输出行数 ≥ 100000 且 ≥ 输入行数的 10 倍 | 连接键在两侧都不唯一，每行匹配多行 | 检查连接键在两侧的唯一性；连接前对一侧按键聚合或去重 |
| DR-MEM-1 | 峰值内存 ≥ 直接内存上限的 20% | 连接、聚合或排序处理的行多或行宽；分支多且同时运行 | 在 `operators` 中找 `peak_memory_bytes` 最高的算子，在它之前减少行和列，或拆分语句；之后再考虑增大执行节点的直接内存 |

表中“输入行数”是算子各输入的行数之和；“峰值内存”是各节点 `maxMemoryUsed` 的最大值。

### 样本

样本由 `test/starrocks-dremio/gen_dremio_diag_samples.py` 在本地 Dremio 24.1.0 上执行合成查询生成，存放在 `internal/builtin/dremio/testdata`，说明见该目录的 README.md。每条规则至少有一个命中样本和一个未命中样本，由 `TestRulesOnSamples` 和 `TestEveryRuleHasHitAndMissSample` 检查。下表是各样本的实测值：

| 样本 | 总耗时 ms | 规划 ms（占比） | 扫描行数 | 连接输入 / 输出行数 | 峰值内存 | 命中 |
| --- | --- | --- | --- | --- | --- | --- |
| `pushdown_scan` | 20 | 6（30%） | 2500 | 无 | 8.3 MiB | 无 |
| `pushdown_join_agg` | 30 | 7（23%） | 8 | 无 | 8.3 MiB | 无 |
| `cross_join_small` | 28 | 5（17%） | 20000 | 20000 / 10000 | 17.7 MiB | 无 |
| `cross_join_large` | 116 | 7（6%） | 510000 | 510000 / 500000 | 18.5 MiB | DR-SCAN-1、DR-JOIN-1 |
| `scan_large` | 92 | 5（5%） | 500000 | 无 | 8.3 MiB | DR-SCAN-1 |
| `join_explosion` | 466 | 5（1%） | 20000 | 20000 / 20000000 | 16.4 MiB | DR-JOIN-3 |
| `nested_loop` | 99 | 6（6%） | 11000 | 嵌套循环输入 11000 | 18.2 MiB | DR-JOIN-2 |
| `many_branches` | 1093 | 291（26%） | 339000 | 各连接之和 459000 / 240000 | 481.9 MiB | DR-PLAN-1、DR-SCAN-1、DR-MEM-1 |
| `failed_unknown_table` | 8 | 0 | 0 | 无 | 0 | DR-FAIL-1 |
| `canceled` | 4020 | 11（0%） | 0 | 无 | 7.2 MiB | DR-FAIL-1 |

`pushdown_scan` 的规划占比为 30%，但规划耗时 6 ms 低于 250 ms 的下限，不命中 DR-PLAN-1。`many_branches`（24 个分支的 UNION ALL）的规划占比在本地多次生成时为 25% 至 33%，该样本的 26% 接近阈值；占比随元数据缓存状态变化。DR-MEM-1 的 20% 与 DR-PLAN-1 的 25% 只在这一个样本上命中，阈值只能证明在本地环境能区分这些样本，不能证明在生产数据上合适。

### 未验证项

- **实例间倾斜（SKEW）**：本地 JDBC 数据源的扫描宽度为 1，连接和聚合与扫描在同一个片段内，没有任何算子有多个实例，因此没有倾斜规则（不设 DR-SKEW-1）。`skew_ratio` 的计算只由手写的 profile 单元测试验证算术（`TestSkewAndReflectionFieldsFromWrittenProfile`），没有真实样本。
- **反射命中**：本地环境不能创建反射（刷新作业报 `NodeStripper` 类加载失败），`acceleration` 对 `accelerationProfile` 的解析按 profile 的 protobuf 定义编写，只由手写 profile 测试，没有真实命中反射的样本。`reflections` op 在样本环境中返回 0 行，只有列定义。
- 阈值（DR-PLAN-1 的 250 ms 和 25%，DR-MEM-1 的 20%，行数阈值）只来自本地合成数据。
- 作业列表接口的过滤键只验证了 `st`、`jst`、`usr`、`dur`；`jobs` 在作业数很多时只取排序后的前 `limit` 条。
- 其他 Dremio 版本、多节点集群、`profile_attempt` 多于一个（作业重试）的 profile 未验证；多 attempt 时处理器读取编号最大者，该行为只由合成 zip 测试。

## 安全边界

- 凭据与 `dremio_query` 相同，只从凭据文件读取，不在参数、日志和错误中出现。Dremio 24.1 没有权限边界，该账号是管理员，见上文“安全边界”第 4 条。
- 固定请求只有读取：`sys` 表的 `SELECT`、作业列表、作业状态、profile 下载（`POST`，请求体为空对象，不修改作业）。
- 调用方的值进入请求前的校验：`job_id` 为 UUID 格式，`user` 为受限字符集（不含引号、括号、分号和比较符，因此不能改变过滤表达式），时长和数值有上限，`state` 为枚举。校验失败时没有请求到达 Dremio（测试以请求计数验证）。
- `job_profile` 摘要中的错误信息、SQL、用户名、队列和反射名来自 Dremio，会包含库表名和用户名。输出经过脱敏函数；示例 action 配置 `redact.builtin: [secrets, pii]`。
- 错误信息的规则与 `dremio_query` 相同：只含阶段、状态码或固定类别，不含服务端消息、token 和密码。

## 示例 action

`examples/catalog/actions/` 中的 `dremio_nodes`、`dremio_jobs_recent`、`dremio_job_profile` 各固定一个 `op`（`ops: [nodes]` 等），`risk: read`、`run_as: root`，`params: {}`（参数由处理器提供，见“op 与参数”）。`test/examples/check_examples.py` 校验示例目录的动作数为 95。

## 测试与复现

单元测试用 httptest 模拟 Dremio（`diag_test.go`）：配置与 `ops` 校验、各 op 的参数校验和他 op 参数被拒绝、过滤表达式、作业列表的截断与排序、`job` 的字段、profile 下载与摘要、zip 炸弹、响应超限、脱敏、超时、校验失败时无请求。`diag_profile_test.go` 在样本上检查算子名、规则命中矩阵、摘要字段、`fitSummary` 的丢弃顺序和 `extractProfile`。

集成测试（`diag_integration_test.go`）使用与 `dremio_query` 相同的环境变量：`ALLOWOPS_DREMIO_URL`、`ALLOWOPS_DREMIO_SOURCE`、`ALLOWOPS_DREMIO_SCRATCH_SOURCE` 必需，未设置时跳过；`ALLOWOPS_DREMIO_STATE` 指定账号文件目录。测试在 Dremio 上执行带标记注释的查询，再用 `jobs` 找到该作业，并对它执行 `job` 和 `job_profile`，核对状态、下推 SQL 和命中的规则。同一 Dremio 被其他会话共用时，测试只按自己的标记查找作业。

```sh
go vet ./internal/builtin/dremio/... ./internal/catalog/...
go test -race ./internal/builtin/dremio/... ./internal/catalog/...
ALLOWOPS_DREMIO_URL=http://127.0.0.1:29047 ALLOWOPS_DREMIO_STATE=<账号文件目录> ALLOWOPS_DREMIO_SOURCE=<数据源> ALLOWOPS_DREMIO_SCRATCH_SOURCE=<scratch 数据源> go test -race -run 'TestIntegrationDiag' ./internal/builtin/dremio
make examples-check
```

重新生成样本：

```sh
DREMIO_SOURCE=<数据源> DREMIO_SCRATCH_SOURCE=<scratch 数据源> DREMIO_STATE=<账号文件目录> python3 test/starrocks-dremio/gen_dremio_diag_samples.py
```

重新生成会改变作业 ID、耗时和内存，需要同时核对 `sampleRules` 与上表。
