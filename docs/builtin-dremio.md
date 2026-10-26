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
