# mysql_query 只读 SQL 校验与执行方案

## 范围与完成条件

基线：`ae79ac769288f17f95ff8acd8b3db11a177fb7e2`。仅新增
`internal/builtin/mysql`，维护本文和 Go 依赖。处理器自包含，不注册公共 builtin。
完成条件：攻击语料、模糊测试、Go race/vet/staticcheck 通过；本机 Docker 可用时，
testcontainers MySQL 验证只读事务、超时和截断。Docker 不可用时明确跳过，不连接外部数据库。

## 歧义与候选方案

| 问题 | 候选方案 | 推荐及依据 |
| --- | --- | --- |
| SELECT 的范围 | 仅简单 SELECT / 包含 CTE、UNION、子查询 | 包含后者，递归检查整个抽象语法树（AST） |
| EXPLAIN | 允许任意目标 / 仅只读目标 | 仅只读目标；拒绝 ANALYZE，避免执行型解释扩大范围 |
| 函数 | 危险函数黑名单 / 明确安全函数白名单 | 白名单；黑名单无法识别自定义函数和存储函数的副作用 |
| 默认和上限 | 任意配置 / 按设计示例限制 | 默认 500 行、10 秒，配置只能收紧 |
| 凭据格式 | MySQL cnf / JSON | JSON 的 username、password 两个必填字段，避免 cnf 额外配置注入 |
| 输出 | 引号转义 TSV / 反斜线转义 TSV | 反斜线转义制表符、换行、回车、反斜线；NULL 为 `\N`，首行为表头 |
| SQL mode | 跟随服务器 / 固定会话 mode | 解析器与会话都固定为 `IGNORE_SPACE`，统一引号、反斜线和内置函数名称解析；字符集固定为 utf8mb4 |
| 注释 | 全部拒绝 / 普通注释允许 | 允许普通注释；拒绝版本注释、MariaDB 执行注释和优化器提示 |

## SQL 解析器比较与选择

比较依据为上游源码和模块声明，不把整个模块依赖数量等同于实际编译产物体积。

| 解析器 | 许可 | 依赖体积 | MySQL 方言覆盖 | 维护状态 |
| --- | --- | --- | --- | --- |
| `github.com/pingcap/tidb/pkg/parser` | Apache-2.0 | 独立子模块；日志、错误、字符集和解析器工具依赖，规模较小 | MySQL 风格 AST，支持 CTE、集合查询、SHOW、锁、SELECT INTO；也包含 TiDB 扩展，必须限制语句与节点 | 位于 TiDB 主仓库；旧 `pingcap/parser` 仓库已迁移 |
| `vitess.io/vitess/go/vt/sqlparser` | Apache-2.0 | 位于 Vitess 主模块，模块声明包含云 SDK、gRPC 等大量依赖；实际 sqlparser 编译依赖小于整个模块 | MySQL/Vitess 方言，支持 SELECT、SHOW 和 EXPLAIN；仍需限制 Vitess 扩展和执行型语句 | 主仓库维护并持续发布版本 |

选择 TiDB parser：独立模块边界更小，AST 可直接检查 SELECT INTO、锁、变量赋值和函数调用。
解析成功不等于安全；只允许明确审核的语句和函数。解析错误、警告、未知语句类型均拒绝。
固定依赖版本写入 go.mod/go.sum；不使用旧的独立 pingcap/parser 仓库。

固定版本：TiDB parser `v0.0.0-20261013111941-9abd970a126e`；
go-sql-driver/mysql `v1.10.1`；testcontainers-go `v0.44.0`（MIT，仅测试）。
本机 parser 模块压缩包 993158 字节，解压目录约 12 MiB。
`go list -deps` 显示生产包涉及 12 个外部模块；包含容器测试后为 56 个。
这些数值不代表链接后二进制大小；未测量 Vitess 的编译产物。
已检查这些 Linux 编译依赖的顶层许可证，均在允许类别内；发布物的完整许可证清单由公共构建流程生成。

参考：[TiDB parser README](https://github.com/pingcap/tidb/blob/master/pkg/parser/README.md)、
[TiDB parser go.mod](https://github.com/pingcap/tidb/blob/master/pkg/parser/go.mod)、
[旧仓库迁移说明](https://github.com/pingcap/parser)、
[Vitess go.mod](https://github.com/vitessio/vitess/blob/main/go.mod)、
[Vitess LICENSE](https://github.com/vitessio/vitess/blob/main/LICENSE)、
[Vitess releases](https://github.com/vitessio/vitess/releases)。

## 安全规则与执行链

1. 校验配置；database 必须匹配 `^[a-zA-Z0-9_]{1,64}$`，SQL 最长 4000 字符。
2. 在解析前识别执行注释和提示；解析后要求恰好一条允许语句，递归检查子查询、CTE 和 EXPLAIN 目标。
3. 拒绝 INTO（包含 OUTFILE、DUMPFILE 和变量目标）、锁定读取、用户变量赋值、危险或未知函数、限定 schema 或反引号包裹名称的函数。函数白名单见 `internal/builtin/mysql/validate.go` 的 `safeFunction`。
4. SET、CALL、HANDLER、LOCK TABLES 和其他写语句不属于允许语句。
5. 打开凭据后在同一文件描述符上核验普通文件、root 属主和精确 0600；拒绝符号链接，严格解码 JSON。
6. 使用 go-sql-driver/mysql 的结构化配置构造连接，禁用多语句、LOCAL INFILE 任意文件读取。不接受地址查询参数或凭据中的连接参数。
7. 独占连接，固定会话 SQL mode，设置 max_execution_time，执行 START TRANSACTION READ ONLY；结束时回滚并关闭连接。
8. 使用 context 覆盖连接和查询超时；遍历最多 max_rows + 1 行判断是否截断，只返回前 max_rows 行 TSV。驱动关闭结果集时可能继续排空数据，仍受超时限制。

只读事务不能替代数据库权限。部署时必须使用只读账号，不授予 FILE、EXECUTE 或管理权限。
调用方负责脱敏和输出字节限制；本包返回 TSV、实际返回行数和 truncated。database 为默认库，
不是库访问授权边界，跨库权限由数据库账号控制。本任务不引入 TLS 配置接口。
SQL 文本检查不会展开数据库中的视图定义；视图中的函数和数据库插件仍由数据库权限及运维配置约束。
只限制行数，不限制单个字段或整个结果的字节数，不能把 max_rows 当作内存上限。
支持目标是 MySQL 8；MariaDB/TiDB 的执行兼容性未验证。

## 接口与使用

`Config` 字段：`Credential`、`Address`、`MaxRows`、`Timeout`，YAML 标签分别为
`credential`、`address`、`max_rows`、`timeout`。零行数/超时表示默认值；负数和超过默认上限报错。
非零超时最小 1ms，写入 max_execution_time 时向上取整为毫秒。
`Validate()` 只检查配置，不打开文件或联网；`Run` 在数据库名和 SQL 校验后读取凭据。
`Params{Database, SQL}` 与 JSON Schema 2020-12 对应；额外参数由调用方按 schema 拒绝。
`Result{Output, Rows, Truncated}` 的 JSON 字段是 `output`、`rows`、`truncated`。
`Rows` 不含表头。空结果仍有表头。输出转义还包含 NUL → `\0`。

凭据示例（主机端 root 属主、0600；应位于 root 管理的父目录）：

```json
{"username":"readonly_user","password":"replace-on-host"}
```

密码字段必须存在，可以为空字符串。凭据最大 16 KiB；拒绝未知 JSON 字段、尾随对象、
目录、FIFO、末级符号链接。服务器错误只返回错误码，不回显 SQL 和服务器原始消息。

## 待负责人确认（答复记录）

- 已确认：500 行和 10 秒作为默认值与可收紧的硬上限。
- 已确认：SELECT 包含 CTE/UNION；EXPLAIN 仅可包装只读语句，拒绝 EXPLAIN ANALYZE。
- 已确认：安全函数白名单，拒绝存储函数、未知函数和优化器提示。
- 已确认：JSON 凭据，root 属主与 0600。

本次实现没有待确认的阻塞项。交由负责人评审上述 TSV 表示、函数白名单和 SQL mode 的兼容性。

## 测试与复现

测试包括攻击语料表（各类至少两条）、合法 SELECT/CTE/UNION/SHOW/DESC/EXPLAIN、
数据库名和配置边界、凭据缺失/属主/权限/格式/链接/FIFO、TSV 与 NULL、空结果/恰好上限/超限、
会话初始化顺序和错误停止、取消与解析器模糊测试。

容器测试固定 `mysql:8.4.6`，只使用本机 `/var/run/docker.sock`，端口只绑定 127.0.0.1。
容器不可用会跳过并打印原因；创建或测试失败不会转为跳过。验证写入被只读事务拒绝（1792）、
max_execution_time、行数上限、TSV、SQL mode、查询失败、超时、MySQL 日志中的 ROLLBACK。
测试二进制复制到测试容器，由容器内 root 进程验证公开 `Run` 接口和 root:0600 凭据，
不改变宿主机权限。凭据密码仅在本机测试进程内生成、传入测试容器环境，不放在命令参数中。

开发中保留的失败证据：

- 实现前：`undefined: validateSQL`，退出码 1；方案与失败测试提交 `1f782fe`。
- 初始 fuzz 断言对 `SELECT A#` 误报 `accepted appended write`，退出码 1。
  追加内容属于行注释；断言改为先换行再追加写语句，保留 `testdata/fuzz/FuzzValidateSQL/c8a85700e6959448`。
- 容器首次初始化报 `[mysql] ... unexpected EOF` 和 `mysql seed fixture failed`，退出码 1。
  复现日志同时出现 `X Plugin ready for connections` 与临时 mysqld 的 `port: 0`；
  就绪检查改为等待第二次 `mysqld: ready for connections.`，排除 X Plugin 文本。
- 初始 staticcheck 报 `WithAPIVersionNegotiation is deprecated (SA1019)`，退出码 1；
  删除无效选项，保留当前客户端默认版本协商。

验收命令（依赖缓存可设置到可写目录；模糊测试用 `GOMAXPROCS=2` 控制并发）：

```sh
go vet ./internal/builtin/mysql/...
go test -race ./internal/builtin/mysql/...
go test -run='^$' -fuzz=FuzzValidateSQL -fuzztime=30s ./internal/builtin/mysql
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./internal/builtin/mysql/...
```

验收 commit、各命令实际输出和退出码随交付报告提供。

## 只读账号部署

凭据来源为每台主机部署的只读账号凭据文件，沿用上文的 JSON 格式。内置处理器不从应用配置文件读取凭据。

### 最小 GRANT

以下语句在目标 MySQL 上创建账号。账号名、密码和库名为占位值，密码在主机上生成，不写入目录或文档。`app` 是 catalog 中 `databases` 与 `database` 参数固定的库名，按每台主机替换。

```sql
CREATE USER 'allowops_ro'@'localhost' IDENTIFIED BY '<在主机上生成的密码>';
GRANT SELECT ON app.* TO 'allowops_ro'@'localhost';
-- 仅在需要查看所有会话时增加：
GRANT PROCESS ON *.* TO 'allowops_ro'@'localhost';
```

各项权限的实测结果（MySQL 8.4.6，本机容器，账号经 `tcp://` 连接）：

| 用途 | 需要的权限 | 实测现象 |
| --- | --- | --- |
| 连接并使用默认库 `app` | 对 `app` 库至少有一项权限（如 `SELECT` 或 `SHOW VIEW`） | 账号只有 `USAGE` 时连接失败，错误码 1044 |
| `SHOW VARIABLES` | 无需额外权限 | 只有 `SHOW VIEW ON app.*` 的账号可以读取 |
| `SHOW PROCESSLIST` | 无 `PROCESS` 时只返回本账号自己的会话；有 `PROCESS` 时返回所有会话 | 无 `PROCESS` 的账号只看到自己的一行，不报错 |
| `SELECT` 类 action | 对相应库表的 `SELECT` | 未在本节验证 |

`PROCESS` 是全局权限（`ON *.*`）。授予后，`SHOW PROCESSLIST` 的 `Info` 列会返回其他账号正在执行的 SQL 文本，其中可能含密码、令牌和手机号字面值。`mysql_processlist` 对输出启用 secrets 和 pii 脱敏，但脱敏规则不能识别所有敏感内容。不需要查看其他会话的主机不要授予 `PROCESS`。不授予 `FILE`、`EXECUTE`、`SUPER`、`ALL PRIVILEGES` 或任何写权限。

### 凭据文件

格式见上文：

```json
{"username":"allowops_ro","password":"replace-on-host"}
```

- `username`、`password` 两个字段必填，密码可以是空字符串，不接受其他字段。
- 属主 root，权限精确为 0600，必须是普通文件，末级路径不能是符号链接。处理器打开文件后在同一文件描述符上核验，不满足时拒绝连接。
- 文件所在的父目录由 root 管理（属主 root，其他账号无写权限）。代码不检查父目录权限，该要求由部署步骤保证，否则非 root 账号可以替换文件。
- 凭据文件路径写在 catalog 的 `builtin_config.credential`，示例为 `/etc/allowops/credentials/mysql-main.json`；目录和签名包中不包含密码。

### 地址选择

`builtin_config.address` 只接受 `tcp://host:port` 和 `unix:///绝对路径`，不接受用户信息和查询参数。

| 场景 | 地址 | 账号的主机部分 |
| --- | --- | --- |
| MySQL 与 allowops 在同一台主机，且使用本机 socket | `unix:///var/run/mysqld/mysqld.sock`（实际路径以 `SHOW VARIABLES LIKE 'socket'` 为准） | `localhost` |
| MySQL 在容器内、已发布端口，或在远程主机 | `tcp://127.0.0.1:3306` 或 `tcp://<主机>:<端口>` | 服务端看到的客户端地址。经 Docker 发布端口连接时，服务端看到的是 Docker 网桥地址，账号主机部分需要匹配该地址（本机实测使用 `'%'`） |

本机实测仅覆盖 `tcp://` 地址。`unix://` 地址未在本机验证，原因是测试容器未挂载 socket 目录。

### 每台主机的 databases 配置

每台主机的数据库名和地址不同，在该主机对应的私有 catalog 中分别配置：

- `builtin_config.databases`：该主机允许访问的库名列表，`database` 参数的正则也固定为其中之一。
- `builtin_config.address` 和 `builtin_config.credential`：该主机的地址和凭据文件路径。
- `show_types`：配置 `databases` 后，服务器级的 `SHOW PROCESSLIST`、`SHOW VARIABLES`、`SHOW STATUS`、`SHOW DATABASES` 必须在 `show_types` 中显式列出才允许（G34）。`mysql_processlist` 列出 `PROCESSLIST`，`mysql_variables` 列出 `VARIABLES`。
- 服务器级 SHOW 的输出不按 `databases` 过滤，库范围之外的会话和变量也会返回，只读账号的权限是唯一的数据范围限制。

公开示例 catalog 中的 `app`、凭据路径和 socket 路径是占位值，部署时在私有 catalog 中替换。
