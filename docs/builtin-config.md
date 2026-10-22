# Redis 与 MySQL 的 builtin_config 收紧项

目录校验和执行均验证以下字段。执行时在读取凭据和建立连接前拒绝越界参数。
所有字段省略时保留处理器默认行为。显式 `null`、空列表、非字符串列表和非法成员均报错。
重复成员不扩大范围。命令名、分区名、语句类型和 SHOW 种类不区分大小写；
键前缀与数据库名按大小写敏感的字节比较。拒绝信息列出可用成员或格式规则。

## redis_command

| 字段 | 合法配置与省略时的行为 |
| --- | --- |
| `commands` | GET、MGET、HGET、HLEN、TTL、TYPE、EXISTS、STRLEN、LLEN、SCARD、ZCARD、SCAN、INFO、CONFIG、SLOWLOG 的非空子集；省略时允许前 13 个命令，不包含 CONFIG 和 SLOWLOG（二者必须显式列出） |
| `key_prefixes` | 非空字面前缀列表，每项 1..4096 字节，不含 NUL、CR、LF；省略时不增加键范围限制 |
| `info_sections` | server、clients、memory、persistence、stats、replication、cpu、commandstats、errorstats、latencystats、cluster、keyspace、modules、sentinel 的非空子集；省略时保留原生 INFO 分区选择行为 |
| `config_params` | CONFIG GET 允许读取的参数名列表。非空，每项为 1..64 字节的字母、数字和 `-`，不含通配符，不属于敏感参数；省略时 CONFIG GET 一律拒绝 |

`commands` 同时收紧目录对外参数 schema 中的 command 枚举，枚举值统一为大写。
省略 `commands` 时枚举保持原有 13 个值，不含 CONFIG 和 SLOWLOG。
处理器直接调用仍接受大小写不同的命令名。内部为响应大小检查而使用的 STRLEN、HSTRLEN、
EXISTS、GETRANGE 不属于调用方命令子集；这些读操作只使用已经通过前缀校验的键。

GET、MGET、HGET、HLEN、TTL、TYPE、EXISTS、STRLEN、LLEN、SCARD、ZCARD 的每个键，
必须以至少一个配置前缀开头。MGET 和 EXISTS 的全部键都检查。HGET 的 field 不作为键检查。
前缀是字面值，包含 `*` 等字符时也不解释为通配符。

配置 `key_prefixes` 后，SCAN 必须显式提供 MATCH。解析 MATCH 模式的开头固定字符串：
未转义的 `*`、`?`、`[` 结束固定字符串；反斜线转义下一个字节；末尾单独的反斜线按字面值处理。
解码后的固定字符串必须以至少一个配置前缀开头。
因此，通配符可以出现在整个允许前缀之后，不能在允许前缀之前或内部改变前缀。
对 `tenant:`，`tenant:*`、`tenant:?[ab]*`、`tenant\:*` 允许；
`*tenant:*`、`[t]enant:*`、`ten*ant:*`、`Tenant:*` 拒绝。
前缀 `literal[*?:` 可用 `literal\[\*\?:*` 匹配。
COUNT 上限和游标校验沿用原有规则。

CONFIG 只支持 `CONFIG GET <参数名>...`，一次最多 16 个参数名。SET、RESETSTAT、REWRITE、HELP 等子命令拒绝。
参数名必须是字面名称：含 `*`、`?`、`[` 等字符的名称拒绝，因此无法用通配符枚举全部配置。
每个参数名必须出现在 `config_params` 中（不区分大小写），未配置 `config_params` 时 CONFIG GET 拒绝。
敏感参数不能出现在 `config_params` 中，也不能被请求，即使目录配置了也拒绝（校验和执行都检查）。
判定规则：名称（不区分大小写）以 `acl` 开头，或包含 `pass`、`auth`、`user`。
该规则覆盖 requirepass、masterauth、masteruser、primaryauth、primaryuser、aclfile、tls-key-file-pass 等。
规则偏宽，被误判的普通参数改用 INFO 读取。输出内容不按参数名二次过滤，
能否读取某个值只由 `config_params` 和上述规则决定；action 仍应保留 `redact.builtin: [secrets]`。
结果是 JSON 字符串数组，按服务端返回的顺序交替排列参数名和值。

SLOWLOG 只支持 `SLOWLOG GET [count]` 和 `SLOWLOG LEN`。count 为 1..128 的整数，省略时使用服务端默认条数。
RESET、HELP 和其他子命令拒绝，因此不会清空慢日志。
SLOWLOG GET 返回的命令参数、客户端地址可能含业务数据和其他键，不受 `key_prefixes` 约束；
因此配置 `key_prefixes` 后 SLOWLOG GET 拒绝，仅 SLOWLOG LEN 可用。使用 SLOWLOG GET 的 action 应启用 `redact.builtin: [secrets, pii]`。
builtin 的 secrets 规则只识别 `password=`、`secret=`、`token=` 形式和常见令牌格式，
慢日志中 `secret: value` 形式的值不会被脱敏。
结果是 JSON 嵌套数组（条目编号、时间戳、耗时微秒、命令参数数组、客户端地址、客户端名称）。

CONFIG GET 和 SLOWLOG 的响应沿用 `max_response_bytes` 限制：返回文本超限时退出码 0、标记 `truncated`、不输出内容。
慢日志条目由服务端限制参数数量和单个参数长度，SLOWLOG GET 最多 128 条。

配置 `info_sections` 后，INFO 显式指定分区时只返回该允许分区。
未传分区时，按配置顺序逐个执行 INFO 分区请求，并将原始文本拼接为一个 JSON 字符串结果。
例如 `[memory, server]` 返回 Memory 和 Server 分区，顺序与配置一致。
返回文本仍受 `max_response_bytes` 限制，资源截断返回退出码 0 并标记 `truncated`。
聚合选择器 `all`、`default`、`everything` 不能出现在收紧列表中，也不能绕过执行时的分区校验。
分区能否提供内容取决于 Redis/Valkey 的版本和运行模式，处理器不会替换成其他分区。

省略 `info_sections` 且 INFO 未传分区时，发送原生无参数 INFO，返回该服务器的默认分区集合，
与本次改动前一致。具体集合由服务器版本和运行模式决定，allowops 不规定固定集合。
省略 `info_sections` 且显式传分区时，保留原有服务器分区选择，包括聚合选择器。

## mysql_query

| 字段 | 合法配置与省略时的行为 |
| --- | --- |
| `databases` | 非空数据库名列表，每项匹配 `^[a-zA-Z0-9_]{1,64}$`；参数 database 和 SQL AST 中所有显式库名均须在列表内；省略时仅检查原有数据库名格式 |
| `statement_types` | SELECT、SHOW、DESCRIBE、EXPLAIN 的非空子集；省略时允许原有全部只读语句类型 |
| `show_types` | TABLES、DATABASES、PROCESSLIST、VARIABLES、STATUS、CREATE TABLE、COLUMNS 的非空子集；省略时不增加种类限制，但配置 databases 后仍受 G34 的库范围和服务器级 SHOW 规则约束 |

G34：配置 `databases` 后，递归检查所有显式库名，包括表引用、列引用、通配字段、
子查询、CTE、JOIN、集合查询、EXPLAIN 目标和 DESCRIBE 表名。
SHOW 的 FROM/IN 库名和 SHOW CREATE TABLE 等限定表名也检查。
库名使用 AST 中的原始大小写；反引号不绕过检查。
未限定库名的表和有默认库的 SHOW 使用已校验的 database 参数。
information_schema、mysql、performance_schema、sys 与其他库相同，必须显式列出才允许引用。
USE 继续按原有只读语句白名单拒绝，即使目标库在列表内也不能执行。
无法判定目标库的 SHOW（例如 ENGINES、WARNINGS）拒绝；省略 `databases` 时保留原有行为。

G34 补充：配置 `databases` 时，服务器级 SHOW DATABASES、PROCESSLIST、VARIABLES、STATUS
只有在 `show_types` 中显式列出对应种类才允许，包括 FULL、GLOBAL、SESSION 变体。
省略 `show_types` 时拒绝这些服务器级 SHOW；LIKE/WHERE 条件不能替代显式授权。
显式授权允许返回服务器级信息，包含其他库的库名、SQL 文本或运行状态；不会按 databases 过滤输出。
数据库账号的只读权限仍是必要限制。AST 检查不展开视图定义，不检查服务器级 SHOW 返回的内容。

语句类型按 TiDB parser 的抽象语法树（AST）判定。SelectStmt 和 SetOprStmt 归 SELECT，
因此 CTE、UNION 和其他原来允许的集合查询仍可使用。ShowStmt 归 SHOW。
DESC、DESCRIBE、EXPLAIN 表名解析为包装 ShowColumns 的 ExplainStmt，统一归 DESCRIBE。
DESC SELECT 与 DESCRIBE SELECT 按 AST 归 EXPLAIN。
G31：EXPLAIN 的目标也必须满足 `statement_types`，EXPLAIN SELECT 必须同时配置 EXPLAIN 与 SELECT。
仅配置 EXPLAIN 不能执行 EXPLAIN SELECT。原有递归只读检查继续拒绝写语句、危险表达式、
EXPLAIN ANALYZE 等，任何收紧项都不能放宽这些检查。

SHOW 种类直接映射 AST 的 Tp：ShowTables、ShowDatabases、ShowProcessList、ShowVariables、
ShowStatus、ShowCreateTable、ShowColumns 分别映射到上述 7 个合法值。
FULL、GLOBAL、SESSION、LIKE、WHERE 等修饰不改变种类。SCHEMAS 归 DATABASES；FIELDS 归 COLUMNS。
TABLE STATUS、CREATE VIEW、CREATE DATABASE、INDEX 等不属于配置后的合法种类。
DESCRIBE 内部的 ShowColumns 不受 `show_types` 限制，DESCRIBE 有独立语句类型限制。
配置 `show_types` 不会自动允许 SHOW；它与 `statement_types` 取交集。

## 本地目录校验配置

以下 builtin_config 可用于两个独立 action。配置不包含凭据内容；目录校验不读取凭据或连接服务。

```yaml
# builtin: redis_command
builtin_config:
  address: 127.0.0.1:6379
  credential: /etc/allowops/credentials/redis.json
  commands: [GET, MGET, HGET, HLEN, TTL, TYPE, EXISTS, STRLEN, LLEN, SCARD, ZCARD, SCAN, INFO]
  key_prefixes: ['tenant:']
  info_sections: [memory, server]
```

```yaml
# builtin: redis_command（CONFIG GET 和 SLOWLOG 需要显式启用）
builtin_config:
  address: 127.0.0.1:6379
  credential: /etc/allowops/credentials/redis.json
  commands: [CONFIG, SLOWLOG]
  config_params: [maxmemory, maxmemory-policy, slowlog-max-len]
```

```yaml
# builtin: mysql_query
builtin_config:
  address: tcp://127.0.0.1:3306
  credential: /etc/allowops/credentials/mysql.json
  databases: [fixture]
  statement_types: [SELECT, SHOW, DESCRIBE, EXPLAIN]
  show_types: [TABLES, DATABASES, PROCESSLIST, VARIABLES, STATUS, CREATE TABLE, COLUMNS]
```
