# sqlguard：StarRocks 与 Dremio 的只读 SQL 词法校验

## 范围

`internal/builtin/sqlguard` 校验调用方提供的 SQL，供 StarRocks 和 Dremio 的只读处理器使用。包只做词法级白名单：切分词法单元，接受以白名单关键字开头的一条语句，拒绝禁用关键字、函数、Hint 和可执行注释。包不解析语法，不连接数据库，不依赖外部库。

校验器不单独保证只读。只读边界由三层共同构成：数据库账号只授予读取权限、本包的词法校验、处理器设置的会话超时和结果上限。

Dremio 一侧没有权限边界：实测 Dremio 24.1 的所有账号都是管理员，可以创建视图、`TRUNCATE`、`ALTER SYSTEM`、修改数据源配置，并通过 `external_query` 以数据源账号的权限执行任意语句。在 Dremio 一侧，本包是唯一的写入边界，数据源账号应只授予读取权限。

校验器和服务端必须对字符串、标识符和注释的边界得出相同的理解。凡是两者可能理解不同的写法一律拒绝，见“拒绝的写法”。

## 接口

```go
func Validate(d Dialect, sql string, opts Options) (Statement, error)
```

| 名称 | 说明 |
| --- | --- |
| `Dialect` | `StarRocks`、`Dremio`。未知值返回拒绝错误 |
| `Options.AllowExplainAnalyze` | 默认 `false`。为 `true` 时放行 StarRocks 的 `EXPLAIN ANALYZE`，目标只能是 SELECT 或 WITH |
| `Statement.Kind` | `KindSelect`（SELECT、WITH、集合查询，Dremio 含 VALUES）、`KindShow`、`KindDescribe`、`KindExplain`、`KindAnalyzeProfile`（`"ANALYZE PROFILE"`，仅 StarRocks） |
| `Statement.ShowType` | `Kind` 为 SHOW 时的规范化种类名，如 `TABLES`、`CREATE TABLE`。别名归一：StarRocks 的 `SCHEMAS` 为 `DATABASES`，`FIELDS` 为 `COLUMNS`；Dremio 的 `DATABASES` 为 `SCHEMAS` |
| `Statement.Variant` | `Kind` 为 EXPLAIN 时的变体：StarRocks 为 `""`（无修饰词）、`LOGICAL`、`VERBOSE`、`COSTS`、`ANALYZE`；Dremio 为 `PLAN FOR`、`PLAN WITH IMPLEMENTATION FOR` |
| `Statement.Target` | EXPLAIN 的目标语句，已通过同样的校验，`Kind` 只会是 `KindSelect` |
| `ShowTypes(d)` | 方言允许的 SHOW 种类名列表（副本）。处理器可用它校验 `show_types` 配置 |
| `MaxLength` | 4000 字符 |
| `ErrRejected`、`*RejectError` | 所有拒绝错误都满足 `errors.Is(err, ErrRejected)`。`RejectError.Reason` 是固定文本，不包含 SQL 内容 |

拒绝时返回零值 `Statement`。

处理器按 `Statement` 收紧 `statement_types` 和 `show_types`：先用 `Kind` 比较 `statement_types`；`Kind` 为 EXPLAIN 时对 `Target` 再比较一次，与 mysql 处理器对 EXPLAIN 目标的做法一致；`Kind` 为 SHOW 时用 `ShowType` 比较 `show_types`。库和 catalog 的范围收紧不在本包内，包不提取表名。

```go
st, err := sqlguard.Validate(sqlguard.StarRocks, "EXPLAIN VERBOSE SELECT * FROM catalog.db.t", sqlguard.Options{})
// st.Kind == KindExplain, st.Variant == "VERBOSE", st.Target.Kind == KindSelect
```

## 校验步骤

1. 预检查：有效 UTF-8；不超过 4000 字符（按字符计，不按字节）；不含 NUL 和其他控制字符（制表、换行、回车除外）；不含 U+2028、U+2029。控制字符包括 C0、DEL 和 C1（含 U+0085）。该检查覆盖字符串和注释内部。
2. 词法切分：单引号字符串、双引号、StarRocks 反引号标识符、`--` 和 `/* */` 注释。空白和注释不产生词法单元。引号和注释之外的 `#`、`//` 直接拒绝，不作为注释处理。
3. 只允许一条语句，末尾分号可选。空语句拒绝。
4. 首关键字白名单：SELECT、WITH、SHOW、DESC、DESCRIBE、EXPLAIN；Dremio 增加 VALUES；StarRocks 增加 ANALYZE。语句可以以 `(` 开头，但括号后必须是查询。首关键字后必须还有内容。
5. SHOW、EXPLAIN、ANALYZE 检查后续关键字：
   - SHOW 先跳过 `FULL`、`GLOBAL`、`SESSION`、`BUILTIN`，再匹配允许的种类。
   - StarRocks 的 EXPLAIN 后可跟 `LOGICAL`、`VERBOSE`、`COSTS`，或在 `AllowExplainAnalyze` 为 `true` 时跟 `ANALYZE`。目标必须是查询。
   - Dremio 的 EXPLAIN 必须是 `PLAN FOR` 或 `PLAN WITH IMPLEMENTATION FOR`，目标必须是查询。
   - StarRocks 的 ANALYZE 只允许 `ANALYZE PROFILE FROM '<字符串>'`，后面可以跟 `, <整数>` 重复若干次。`ANALYZE TABLE` 拒绝。Dremio 不允许 ANALYZE。
   - DESC、DESCRIBE 后必须是表名，不能是 SELECT、WITH、VALUES。
6. 禁用关键字：除 SHOW 种类名本身的关键字外，语句中任何未加引号的词法单元出现在名单内即拒绝。
7. 禁用函数：未加引号或带引号的名称后面（跳过空白和注释）紧跟 `(` 时，按名称拒绝，包括 EXPLAIN 目标和子查询中的调用。
8. Dremio 的 `TABLE(` 后必须是不带限定名的白名单表函数加 `(`。
9. 拒绝 Hint、可执行注释、含 `set_var` 的注释、`:=`、`?`、`#`、`//`。Dremio 方言还拒绝字符串和带引号标识符中的 `/*`，当它之后的语句文本含 `set_var` 时。

## 名单

名单是包内变量，在 `rules.go`：

| 变量 | 内容 |
| --- | --- |
| `deniedKeywords` | INSERT、UPDATE、DELETE、MERGE、CREATE、DROP、ALTER、TRUNCATE、GRANT、REVOKE、SET、RESET、KILL、ADMIN、INSTALL、UNINSTALL、LOAD、EXPORT、SUBMIT、CANCEL、REFRESH、OPTIMIZE、VACUUM、ROLLBACK、COMMIT、USE、CALL、INTO |
| `starrocksDeniedFunctions` | `files`、`sleep`、`get_query_profile` |
| `dremioDeniedFunctions` | `external_query` |
| `dremioTableFunctions` | `table_history`、`table_snapshot`、`table_manifests`、`table_files` |
| `starrocksShowTypes` | DATABASES、TABLES、TABLE STATUS、COLUMNS、CATALOGS、CREATE TABLE、CREATE VIEW、CREATE MATERIALIZED VIEW、CREATE DATABASE、PARTITIONS、TABLET、MATERIALIZED VIEWS、FUNCTIONS、VARIABLES、STATUS、PROCESSLIST、PROFILELIST、FRONTENDS、BACKENDS、COMPUTE NODES |
| `dremioShowTypes` | SCHEMAS、TABLES、VIEWS、PARTITIONS、FILES、CREATE TABLE、FUNCTIONS |

说明：

- 关键字按词法单元匹配，不按子串。`updated_at`、`settings`、`deleted` 不受影响。带引号的 `` `delete` ``、`"delete"` 和字符串 `'delete'` 不算关键字。
- `INTO` 整体拒绝，覆盖 `INTO OUTFILE`、`INTO DUMPFILE` 和 `SELECT ... INTO`。
- `SHOW CREATE TABLE` 中的 `CREATE` 属于种类名，不按禁用关键字处理。种类名之后再出现 `CREATE` 仍拒绝。
- `TRUNCATE` 后紧跟 `(` 时是数值函数 `TRUNCATE(x, n)`，放行。作为语句首词的 `TRUNCATE` 被首关键字白名单拒绝，其他位置的 `TRUNCATE` 被禁用关键字规则拒绝。
- 不做函数白名单。名单外的函数由数据库账号权限约束。
- 不列入 `SHOW PROC`。
- Dremio 24.1 实测 `SHOW CREATE VIEW` 是语法错误，因此 Dremio 不列入 CREATE VIEW。

## profile 与其他账号的查询

实测 StarRocks 3.3 中只有 SELECT 权限的账号可以读取其他账号的查询文本和 profile，途径有三个：

| 途径 | 校验器的处理 |
| --- | --- |
| `get_query_profile(...)` 函数 | 在 `starrocksDeniedFunctions` 中，任何位置的调用都拒绝 |
| `SHOW PROFILELIST` | 仍识别，返回 `Kind` 为 `KindShow`、`ShowType` 为 `PROFILELIST` |
| `ANALYZE PROFILE FROM '<id>'` | 仍识别，返回 `Kind` 为 `KindAnalyzeProfile` |

`SHOW PROFILELIST` 和 `ANALYZE PROFILE` 的识别保留，供处理器按种类分流。`starrocks_query` 处理器在校验后无条件拒绝这两种语句，任何 `statement_types`、`show_types` 配置都不能开启（`PROFILELIST` 也不是合法的 `show_types` 成员），它们归入使用固定语句的 diag 类处理器。仅靠词法校验无法阻止读取其他账号的 profile，查询类账号仍然需要按权限边界配置。

## 方言差异

| 项目 | StarRocks | Dremio |
| --- | --- | --- |
| 单引号字符串 | 反斜线转义（`\'`、`\\`），`''` 转义 | 只有 `''` 转义，反斜线是普通字符 |
| 双引号 | 字符串，规则同单引号 | 标识符，只有 `""` 转义 |
| 反引号 | 标识符，只有 ` `` ` 转义，无反斜线转义 | 拒绝 |
| `#` | 拒绝（服务端丢弃 `#`，其后内容照常解析） | 拒绝 |
| `@`、`{`、`}` | 允许（`@@version`、`MAP{...}`） | 拒绝 |
| 禁用函数 | `files`、`sleep`、`get_query_profile` | `external_query`；`TABLE(...)` 只放行四个表函数 |
| 首关键字 | 无 VALUES，含 ANALYZE PROFILE | 含 VALUES，无 ANALYZE |
| EXPLAIN | `[LOGICAL｜VERBOSE｜COSTS｜ANALYZE]` | `PLAN [WITH IMPLEMENTATION] FOR` |

同一条 SQL 在两种方言下的词法结果可以不同。例如 ``SELECT 'a\'; DROP TABLE t; --'`` 在 StarRocks 是一个字符串，被接受；在 Dremio 里字符串在 `\` 后的引号处结束，之后出现第二条语句，被拒绝。调用方必须传入与目标服务一致的方言。

## 拒绝的写法

下列写法在服务端可能被不同地理解，校验器一律拒绝。

| 写法 | 拒绝理由 |
| --- | --- |
| `--` 后不是空白字符，包括 `--` 位于输入末尾 | 各词法器对 `--` 后是否需要空白的处理不同：MySQL 要求空白，StarRocks 3.3 实测不要求（`SELECT 1--1` 返回 1）。只接受后跟空白的 `--`，因为只有这种写法在各词法器中都是注释 |
| `#` 在引号和注释之外 | StarRocks 3.3 实测 `#` 不是注释，服务端丢弃该字符并继续解析（`SELECT 1 # + 1` 返回 2，`#` 之后的 INSERT 会被执行）。其他词法器把它当作行注释或非法字符。两种方言都拒绝 |
| `//` 在引号和注释之外 | Calcite 类词法器把 `//` 当作行注释（未实测）。`//` 之后的引号对服务端不可见，对校验器会打开字符串，字符串之后的内容就会被误判 |
| 嵌套的 `/*`，包括 `/*/` 形式 | 部分词法器支持嵌套注释，部分不支持 |
| `/*+ ... */` Hint | 可修改并行度和内存上限 |
| `/*!`、`/*M!` 可执行注释 | 注释内容会被服务端执行 |
| 任何注释中出现 `set_var`（不区分大小写） | 部分服务端把它当作会话参数设置 |
| Dremio：字符串或带引号标识符中的 `/*`，且其后的语句文本（到输入末尾）含 `set_var`（不区分大小写） | Dremio 24.1 用正则从原始 SQL 文本提取 `/* */` 注释，不区分引号。注释可以跨多个字符串，例如 `'/*'` 与 `' set_var.x=1 */'`，其中的 `set_var.x=v` 被改写为 SET_VAR Hint。引号内的 `/*` 而其后没有 `set_var` 时允许 |
| 未闭合的字符串、标识符或注释 | 服务端按各自规则报错或延伸到输入末尾，边界无法一致 |
| Dremio 中的反引号、`@`、`{`、`}` | Dremio 对这些字符的处理未实测 |
| 引号和标识符之外的非 ASCII 字符，包括 U+00A0、U+2003、U+3000、U+200B、全角字符、BOM | 服务端可能把它们当作空白、标识符字符或分隔符 |
| U+0085、U+2028、U+2029 以及 C0、C1 控制字符、DEL、NUL，出现在任何位置 | 部分词法器把它们当作行结束符，行注释的终点因此不同 |
| `$` 在引号之外 | MySQL 和 Calcite 对 `$` 是否属于标识符字符的处理不同 |
| `\` 在引号之外 | MySQL 有 `\N` 等转义，其他词法器没有 |
| `:=` | 变量赋值 |
| `?` | 参数占位符 |
| 多个语句或空语句，包括 `;;` | 只允许一条语句 |
| 带引号的函数名含非 ASCII 字符 | 服务端的 Unicode 大小写折叠规则不同，无法可靠比较名称 |

处理方式说明：

- `--` 行注释在 LF 或 CR 处结束。只在 LF 结束的服务端看到的内容是校验器所见内容的子集，不会漏检。
- 数字后紧跟字母时拆成两个词法单元（`1DELETE` 拆成 `1` 和 `DELETE`），使校验器暴露的关键字多于服务端。
- 带引号的函数名按解码后的名称比较：折叠重复的引号，去除首尾空白，转小写。
- 中文放在字符串或带引号的标识符中仍然允许，放在注释中也允许。

## 已知限制

- 词法校验不识别视图的定义。视图内部引用的函数和表不受检查。
- 不识别服务端插件和自定义函数的副作用。
- 只读边界依赖数据库账号权限。账号不得有写入、DDL、文件读写和管理权限。
- 不检查语法正确性和括号配对。语法错误由服务端报告。
- 不提取表名和库名。库、catalog 范围需要由账号权限或处理器的其他配置限制。
- 禁用关键字按词法单元匹配，未加引号的同名列名、别名也被拒绝，例如 `SELECT admin FROM t`、`SELECT load FROM t`。调用方需要加引号。
- `$` 出现在未加引号的标识符中被拒绝。
- 词法校验不限制读取范围：名单外的函数和系统表仍可读取，账号权限需要按“只读”配置。
- 实测 StarRocks 3.3 中 SELECT-only 账号可以执行 `SET PASSWORD` 修改自己的密码。`SET` 被校验器拒绝，但其他途径修改密码需要在运维上限制。
- 校验针对 StarRocks 3.3 和 Dremio 24.1 的语法设计。其他版本的行为未验证。

## 服务端行为实测结果

下表是在本地 StarRocks 3.3 和 Dremio 24.1 上实测的结果，以及校验器对应的处理。

| 项目 | 实测 | 校验器处理 |
| --- | --- | --- |
| StarRocks `#` | 不是注释。服务端丢弃 `#`，其后内容照常解析；`#` 之后的 INSERT 被执行 | 两种方言都拒绝引号之外的 `#`。字符串、反引号标识符、块注释和 `--` 注释中的 `#` 不受影响 |
| StarRocks `--` | 后无空白仍是注释，`SELECT 1--1`、`SELECT 1 --` 都返回 1；`--` 之后的 INSERT 不执行 | 只接受后跟空白的 `--`，其余拒绝（比服务端严格） |
| StarRocks 字符串 | 单引号、双引号都是字符串字面量，`''` 和 `\` 都是转义；`SET sql_mode='NO_BACKSLASH_ESCAPES'` 被接受但反斜线仍是转义；双引号不是列引用 | 与实现一致：两种引号都按字符串切分，同时处理两种转义 |
| StarRocks 块注释 | 不嵌套，在第一个 `*/` 结束；`/*+ x */` 是普通注释；`/*! ... */` 被当作普通注释，内容不执行 | 嵌套、`/*+`、`/*!` 一律拒绝（比服务端严格） |
| StarRocks 多语句 | 请求中的所有语句都会执行，只返回第一条语句的结果，与驱动是否启用多语句无关 | 拒绝 `;` 之后的任何内容，包括 `;;` |
| StarRocks 未闭合结构 | 服务端报语法错误 | 拒绝 |
| StarRocks 读写路径 | SELECT-only 账号可以：`INTO OUTFILE` 在后端节点写文件，`FILES('path'='file:///...')` 读后端节点文件，`CREATE TEMPORARY TABLE`，`SET PASSWORD`，`sleep()` | `INTO`、`CREATE`、`SET` 在禁用关键字中；`files`、`sleep` 在禁用函数中 |
| StarRocks profile 读取 | SELECT-only 账号可以用 `get_query_profile`、`SHOW PROFILELIST`、`ANALYZE PROFILE` 读取其他账号的查询文本 | 见“profile 与其他账号的查询” |
| StarRocks EXPLAIN | `EXPLAIN [LOGICAL｜VERBOSE｜COSTS]` 可用；`EXPLAIN SCHEMA` 是语法错误；`EXPLAIN ANALYZE SELECT` 会执行查询；`EXPLAIN ANALYZE INSERT` 中止事务且不写入；`EXPLAIN ANALYZE DELETE` 是语法错误 | 与实现一致；`EXPLAIN ANALYZE` 默认拒绝 |
| StarRocks SHOW 权限 | `SHOW FRONTENDS`、`SHOW BACKENDS`、`SHOW COMPUTE NODES` 对只有 SELECT 的账号报权限错误；`SHOW PROCESSLIST` 只返回本账号的连接 | 仍识别这些种类，是否放行由处理器决定 |
| Dremio 语句数 | 多条语句报错（只支持单条语句）；末尾分号可用 | 与实现一致 |
| Dremio 权限 | 所有账号都是管理员，可以创建视图、`TRUNCATE`、`ALTER SYSTEM`、`ALTER SESSION`、`ALTER PDS ... REFRESH METADATA`、修改数据源配置 | 校验器是唯一写入边界：`CREATE`、`DROP`、`ALTER`、`TRUNCATE`、`INSERT`、`DELETE`、`UPDATE`、`GRANT`、`REFRESH` 等都在拒绝范围内 |
| Dremio `external_query` | 以数据源账号的权限执行任意语句；`EXPLAIN PLAN FOR` 中的 `external_query` 在规划时就执行，作业状态是失败，数据已写入 | 任何位置的 `external_query(` 都拒绝，包括 EXPLAIN 目标 |
| Dremio `set_var` 注释 | `/* set_var.x='v' */` 被改写为 StarRocks 的 SET_VAR Hint 并生效，位置可在语句开头或 SELECT 之后；直接写 `SET_VAR` Hint 是语法错误 | 任何注释中出现 `set_var` 都拒绝。服务端从原始文本提取注释，不区分字符串和带引号标识符：`WHERE 'x' <> '/* set_var.pipeline_dop=2 */'` 和 `AS "/* set_var.pipeline_dop=3 */"` 都会生成 Hint（`EXPLAIN PLAN FOR` 的计划文本已确认；字符串版本的 SELECT 执行后，StarRocks 审计日志中也带有 Hint），`'/*' ... ' set_var.x=2 */'` 跨两个字符串也生成 Hint；`-- /*` 加字符串中的 `*/` 未生成 Hint。因此引号内的 `/*` 之后的语句文本含 `set_var` 时拒绝 |
| Dremio 字符串 | 单引号字符串只有 `''` 转义，反斜线是普通字符（`SELECT 'a\' AS x` 返回 `a\`） | 与实现一致 |
| Dremio 带引号标识符 | 双引号是标识符，只有 `""` 转义；反引号只在系统属性 `dremio.legacy.backticks_for_identifiers=true` 时是引号 | 与实现一致；反引号一律拒绝（比服务端严格） |
| Dremio `--` | 后无空白也是注释（`SELECT 1 AS x--c\n, 2 AS y` 返回两列）；CR 结束行注释 | 只接受后跟空白的 `--`（比服务端严格）；CR、LF 都结束行注释 |
| Dremio `//` | 是行注释 | 拒绝 |
| Dremio 块注释 | 不嵌套（第二个 `*/` 处报语法错误）；`/**/` 正常跳过 | 嵌套、`/*+`、`/*!` 一律拒绝（比服务端严格） |
| Dremio `#`、`[` | `#` 报词法错误；`[x]` 报语法错误，`[` 不是方括号标识符 | `#` 拒绝；`[` 作为标点 |
| Dremio EXPLAIN | `PLAN FOR`、`PLAN WITH IMPLEMENTATION FOR`、`PLAN INCLUDING ALL ATTRIBUTES FOR`、`PLAN WITHOUT IMPLEMENTATION FOR` 可用；`EXPLAIN JSON FOR` 失败；`EXPLAIN PLAN FOR INSERT` 只规划 | 只放行前两种变体，其余拒绝 |
| Dremio SHOW 与 DESCRIBE | `SHOW SCHEMAS`、`SHOW TABLES IN`、`SHOW PARTITIONS`、`SHOW CREATE TABLE`、`DESCRIBE`、`DESC`、`VALUES` 可用；`SHOW TABLES`、`SHOW VIEWS` 没有上下文时报错；`SHOW FILES` 只支持文件系统数据源；`SHOW CREATE VIEW`、`SHOW TBLPROPERTIES` 是语法错误 | 白名单不含 CREATE VIEW |
| Dremio 表函数 | `table_history`、`table_snapshot`、`table_files` 存在，对 Iceberg 表的行为未验证 | `TABLE(...)` 只放行四个白名单表函数 |

## 待确认的规则

下列规则依赖服务端行为，尚未实测，当前采用保守实现：

| 规则 | 当前行为 | 需要实测的内容 |
| --- | --- | --- |
| Dremio 词法 | 拒绝反引号、`@`、`{`、`}`；`--` 需后跟空白 | `{fn ...}` 转义；这些字符的实际处理 |
| 行注释终点 | LF 或 CR | U+0085、U+2028 是否结束行注释（两种服务端；Dremio 的 CR 已实测） |
| StarRocks `//` | 拒绝 | 是否为注释（预期不是） |
| StarRocks 未知字符 | 拒绝未列入的 ASCII 字符 | `#` 被丢弃说明词法器可能丢弃未识别的字符，其他字符是否同样被丢弃 |
| 禁用函数 | StarRocks：`files`、`sleep`、`get_query_profile`；Dremio：`external_query` | 是否还有读取外部数据、阻塞或写入的函数和表函数 |
| Dremio `TABLE(...)` 白名单 | 四个 Iceberg 元数据函数，不带限定名 | 对 Iceberg 表的名称和调用形式 |
| SHOW 白名单 | 见“名单” | StarRocks 的 `TABLET`、`TABLE STATUS`、`CREATE MATERIALIZED VIEW` 等种类的真实语法；`SHOW FUNCTIONS` 在 Dremio 实测返回 0 行，原因未查明 |
| StarRocks EXPLAIN 变体 | `LOGICAL`、`VERBOSE`、`COSTS`、`ANALYZE` | 3.3 是否还有其他变体，如 `SCHEDULER` |
| `ANALYZE PROFILE FROM` | 字符串加可选整数列表（`, 0` 实测可用） | query id 的格式；整数列表的含义 |
| `DESC` 后的形式 | 表名（词或带引号标识符） | 是否有其他合法形式；`DESC <查询>` 是否等同 EXPLAIN |
| 未加引号标识符 | ASCII 字母、数字、下划线，`$` 拒绝 | 两种服务端接受的标识符字符 |
| `TRUNCATE(` 例外 | 后紧跟 `(` 时放行 | 两种服务端都有 `TRUNCATE` 数值函数，且不存在以 `TRUNCATE (` 开头的写语句 |

## 测试

测试文件：

- `corpus_test.go`：攻击语料，按类别分组，每类至少两条；分为两种方言共用和各方言独有。类别包括写语句、DDL、管理语句、多语句、注释隐藏语句、未闭合结构、Hint 与参数注释、嵌套注释、`--` 变体、危险函数、`INTO OUTFILE`、`ANALYZE TABLE` 与 `ANALYZE PROFILE` 变体、EXPLAIN 变体与目标、SHOW 与 DESC 变体、Unicode 空白、非 ASCII 字符、控制字符、非法 UTF-8、超长输入。
- `corpus_measured_test.go`：按实测结果整理的语料，包括 StarRocks 的字符串转义、注释、多语句、写入路径、`FILES()`、`get_query_profile`，Dremio 的写入语句、`external_query`（含 `EXPLAIN PLAN FOR` 内）、`set_var.` 注释、其他表函数，以及两种方言的 `//`、`#`。每条被接受的语句与服务端的读法一致，每条被拒绝的语句在服务端会被执行或会对校验器隐藏内容。
- `validate_test.go`：合法语料及其期望的 `Statement`；`EXPLAIN ANALYZE` 默认关闭、开启后目标为 SELECT、WITH 与 INSERT 等目标的矩阵；两种方言的转义差异；每个禁用关键字的位置、大小写、注释分隔、带引号和子串用例；禁用函数和 `TABLE(...)` 白名单；4000 字符边界（ASCII、中文、4 字节字符）；错误不回显输入；`FuzzValidate`。

`FuzzValidate` 对两种方言和两组 `Options` 检查：

- 不 panic，结果可重复，拒绝错误满足 `ErrRejected`。
- 被接受的输入追加 `; DROP TABLE t` 后必须拒绝。输入以行注释结尾时，追加内容在注释内，此时要求词法单元序列与原输入相同，即追加内容完全被注释吸收。
- 被接受的输入在末尾追加换行或回车加写语句后必须拒绝。
- 默认选项下不得接受 `EXPLAIN ANALYZE`；开启 `AllowExplainAnalyze` 只能多接受含 `EXPLAIN ANALYZE` 的语句，不改变其他结果。

验收命令：

```sh
gofmt -l internal/builtin/sqlguard
go vet ./internal/builtin/sqlguard/...
go test -race ./internal/builtin/sqlguard/...
GOMAXPROCS=2 go test -run='^$' -fuzz=FuzzValidate -fuzztime=60s ./internal/builtin/sqlguard
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./internal/builtin/sqlguard/...
```

测试只在本地运行，不连接数据库或外部服务。
