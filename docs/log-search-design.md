# 日志检索设计

本文是设计。状态：第一阶段已实现（见 6.11），第二、三阶段未实现。

## 1. 背景

### 1.1 使用频率

AI agent 通过 SSH 执行的远程命令中，日志相关的命令最多：grep、awk、zgrep 过滤日志，`tail -n` 查看日志末尾，`docker exec` 进容器查看文件，`docker logs` 和 `kubectl logs` 读取容器日志。

### 1.2 一次失败的检索

2026-10-23，一个 AI agent（Codex）通过 allowops 检查一台测试主机上某个 Web 应用容器的业务日志，没有得出结论。按原因分为以下几项。

1. **参数结构不可见**：Codex 看到的工具声明是 `args: unknown & unknown & unknown & unknown`，只能靠错误信息试出参数名（`hosts`、`help`、`path` 均被拒绝）。根因是参数结构顶层有组合规则，已修复（"keep cross-field rules out of the tool schema root"）。当时使用的试用网关构建于修复之前。
2. **失败原因丢失**：5 次 `log_search` 都返回 `exit_code=1`，stdout 和 stderr 为空。原因有两处：
   - `internal/execd/exec.go` 的 `ExecutionReason` 和 `internal/agent/task.go` 的 `taskStatus` 把所有错误合并成 `EXECUTION_FAILED`。
   - MCP 结果的 `OutputGroup` 只有 exit_code、stdout 和 stderr，没有原因字段。
3. **一个目录导致整次失败**：`path_glob=/var/log/*` 匹配到 `anaconda`、`audit` 等子目录时，`logsearch.files()` 返回 `matched path must be a regular file`，整次检索失败。
4. **日志不在允许的根目录内**：`log_search` 的 `allowed_roots` 只有 `/var/log` 和 `/data/logs`。Codex 检索的 `/opt/app/*/logs/*` 返回 `path_glob is outside allowed_roots`。该应用的业务日志实际在哪里，原因未查明。
5. **`docker_logs` 读不到较早的日志**：`lines` 最大 500，Docker 先按 `--tail` 截取最后 N 行，再按 `--since`/`--until` 过滤（见 1.3）。Codex 查 6h 到 4h 前的时间段，结果为空。
6. **无法区分“没有命中”和“失败”**：现在没有命中时退出码为 0、输出为空；第 2 项的失败退出码为 1、输出也为空。调用方看到的结果只差一个退出码。

第 3、4、6 项已用临时测试复现（测试未提交）：

| path_glob | 退出码 | 错误 |
|---|---|---|
| `<root>/*`，含一个子目录 | 1 | `matched path must be a regular file` |
| `/opt/app/*/logs/*` | 1 | `path_glob is outside allowed_roots` |
| `<root>/*.log`，没有命中 | 0 | 无 |

### 1.3 Docker 的 tail 与时间过滤顺序

验证环境：Docker 29.8.2，json-file 日志驱动。测试容器先输出 A1 到 A1000，暂停 4 秒后输出 B1 到 B1000。`mid2` 取 A1000 之后 2 秒的时间点。

| 参数 | 行数 | 第一行 | 最后一行 |
|---|---|---|---|
| 无 | 2000 | A1 | B1000 |
| `--tail 500` | 500 | B501 | B1000 |
| `--until mid2` | 1000 | A1 | A1000 |
| `--until mid2 --tail 500` | 0 | | |
| `--until mid2 --tail 1500` | 500 | A501 | A1000 |
| `--since mid2` | 1000 | B1 | B1000 |

结论：在该版本和驱动下，`--tail` 先作用于整个日志，`--since`/`--until` 再过滤截取结果。`--tail` 不能和 `--until` 组合起来读取较早的日志。其他日志驱动（local、journald）和其他 Docker 版本未验证。

## 2. 目标与非目标

目标：

1. 调用方按日志源名称和时间范围检索，不需要知道主机上的路径。
2. 先返回统计，再分页返回日志行；每页有上限，可以用游标继续读取。
3. 每种失败都返回固定的原因代码和改写提示。没有命中时成功返回，匹配数为 0。
4. 覆盖宿主机日志文件、容器标准输出、容器内日志文件和 Kubernetes Pod 日志。

非目标：

1. 不建立中心日志存储或索引。检索在各主机的 agent 上实时扫描，扫描量和时间都有上限。
2. 不替代 Loki、Elasticsearch 等日志平台。已经接入日志平台的应用，可以另外提供对应平台的查询 action。

## 3. 约束

1. **先匹配后脱敏**：按模式检索在原文上匹配，之后才脱敏。调用方可以通过命中与否推断被脱敏的内容（`docs/action-catalog-requirements.md` 第 4 节第 11 项）。所以日志源只能指向日志，不能指向配置文件；统计和模式聚类同样受这个限制。
2. **签名 catalog**：日志源、根目录和上限都写在签名的 catalog 里，调用方只能在其中选择，不能扩大范围。
3. **主机端能力协商**：新的 builtin 需要写入 `AgentHello.Capabilities.Builtins`。不支持的主机把对应 action 标记为 `unsupported`（`docs/design.md` 第 122、180 行）。
4. **输出预算**：MCP 摘要每组预览 4KB（`internal/gateway/mcp/output.go` 的 `groupByteLimit`），完整输出用 `jobs_get` 分页读取，内容是 base64 编码。`max_output` 默认 64KB。
5. **主机系统**：主机端支持 CentOS 7，只支持 amd64。builtin 用 Go 实现，不依赖主机上的 grep 版本。

## 4. 借鉴的工具

| 工具 | 做法 | 本设计采用的点 |
|---|---|---|
| Grafana MCP（Loki） | 提供 `list_loki_label_names`（列标签）、`query_loki_stats`（统计）、`query_loki_patterns`（日志模式）、`query_loki_logs`（取日志）；默认每次最多 100 行，内部多取 1 行判断后面是否还有；可以在查询前估算扫描量，超限时拒绝并返回改写提示 | 发现、统计、取数三类工具；多取 1 行判断是否还有更多；拒绝时附带改写提示 |
| Datadog MCP | `search_datadog_logs` 返回单条日志，`analyze_datadog_logs` 做计数和聚合；建议始终带时间范围 | 检索和统计分成两个工具 |
| lnav（终端日志查看器） | 识别时间戳和日志级别；多个文件按时间合并；自动读取 .gz；按时间显示直方图 | 解析时间戳；轮转文件合并成一条时间线；按时间分桶计数 |

来源：

- <https://github.com/grafana/mcp-grafana>
- <https://docs.datadoghq.com/mcp_server/tools/>
- <https://github.com/tstack/lnav/blob/master/NEWS.md>

## 5. 总体结构

新增 builtin `log_query`，提供 `sources`、`search`、`stats`、`patterns` 四种模式。每种模式由一个 catalog action 使用，每个 action 只能使用一种模式。

| action | 模式 | 阶段 |
|---|---|---|
| `log_sources` | sources | 第一阶段 |
| `log_search` | search | 第一阶段（替换现有 `log_search`，见 6.8） |
| `log_stats` | stats | 第二阶段 |
| `log_patterns` | patterns | 第二阶段 |

调用方的推荐顺序（写入工具描述）：

1. `log_sources`：查看主机上有哪些日志源，以及每个源覆盖的时间范围。
2. `log_stats`：按关键词统计命中数和时间分布，确定时间范围。
3. `log_search`：在确定的时间范围内分页读取日志行。
4. 不确定关键词时，先用 `log_patterns` 查看日志中出现过哪些模板。

## 6. 第一阶段：日志源、时间范围、多行、分页、错误原因

### 6.1 日志源

在 action 的 `builtin_config.sources` 中声明。调用方的 `source` 参数是这里的名称组成的枚举。

```yaml
name: log_search
builtin: log_query
builtin_config:
  mode: search
  sources:
    web-app:
      type: file
      paths: [/data/logs/web-app/*.log, /data/logs/web-app/*.log.*.gz]
      timestamp:
        layouts: ['2006-01-02 15:04:05.000']
        timezone: Asia/Shanghai
      multiline: timestamp_start
    nginx-access:
      type: file
      paths: [/var/log/nginx/access.log*]
      timestamp:
        layouts: ['02/Jan/2006:15:04:05 -0700']
        bracketed: true
      multiline: none
  allowed_roots: [/var/log, /data/logs]
  max_files: 50
  max_scan: 256MB
  max_window: 24h
  max_page_records: 200
  max_record_bytes: 64KB
```

规则：

1. `paths` 是 glob，必须在 `allowed_roots` 内。签名校验时检查文字前缀，执行时再检查解析符号链接后的路径，规则和现在的 `logsearch.files()` 相同。
2. glob 匹配到的非普通文件（目录、FIFO、设备）跳过，计入结果的 `skipped`，不再让整次检索失败（对应 1.2 第 3 项）。
3. 同一个源的文件按时间组成一条时间线，排序依据见 6.2。
4. `timestamp.layouts` 使用 Go 时间格式，可以写多个，按顺序尝试。没有时区的格式按 `timezone` 解释；省略 `timezone` 时使用主机本地时区。
5. 第三阶段增加 `container_stdout`、`container_file`、`k8s_pod` 三种类型，见第 8 节。

### 6.2 时间范围

参数：

| 参数 | 类型 | 说明 |
|---|---|---|
| `since` | 字符串 | RFC 3339 绝对时间，或 `30m`、`2h` 这样的相对时长（相对执行时刻）。省略时等于 `until - 1h` |
| `until` | 字符串 | 同上。省略时为执行时刻 |

`until - since` 不能超过 `max_window`。省略时间范围时只检索最近 1 小时，响应里写明实际使用的范围。

选择文件：

1. 文件的结束时间取修改时间，开始时间取第一条可解析的时间戳（.gz 文件需要解压开头部分）。
2. 时间范围和 `[开始, 结束]` 不重叠的文件跳过，不计入扫描量。
3. 剩下的文件按开始时间排序。开始时间相同时按文件名排序。

定位起点：

1. 对未压缩文件，用二分查找定位到 `since` 附近：在偏移处向后找到下一行行首，解析时间戳；连续 64 行解析不出时间戳时，停止二分，从文件开头扫描。
2. .gz 文件只能从头顺序解压，解压的字节数计入 `max_scan`。
3. 读到时间戳大于 `until` 的记录后停止读取该文件。

没有时间戳的行归入上一条记录（见 6.3），不单独参与时间判断。

### 6.3 多行记录

`multiline` 取值：

| 值 | 规则 |
|---|---|
| `timestamp_start` | 能解析出时间戳的行开始一条新记录，其他行接到上一条记录后面。Java 异常堆栈作为一条记录 |
| `none` | 每行一条记录 |

单条记录超过 `max_record_bytes` 时截断，并标记 `record_truncated`。匹配作用于整条记录，所以关键词出现在堆栈里的任意一行都能命中整条记录。

### 6.4 匹配参数

| 参数 | 说明 |
|---|---|
| `pattern` | RE2 正则，可选。省略时返回时间范围内的全部记录 |
| `fixed` | 布尔值。为 true 时 `pattern` 和 `exclude` 按字面文本匹配 |
| `exclude` | 排除模式 |
| `ignore_case` | 布尔值 |
| `level` | 可选，`ERROR`、`WARN`、`INFO`、`DEBUG` 中的一个或多个。只在源声明了 `level` 提取规则时可用 |

`pattern` 和 `exclude` 的长度上限与现有 `log_search` 相同（200）。它们在 builtin 内部、脱敏之前匹配，限制见第 3 节第 1 项。

### 6.5 分页与顺序

参数：

| 参数 | 说明 |
|---|---|
| `limit` | 本页最多返回的记录数，1 到 `max_page_records`，默认 50 |
| `order` | `desc`（默认，新的在前）或 `asc` |
| `cursor` | 上一页返回的 `next_cursor`。传入后，其他参数必须与上一页相同 |

实现：

1. 内部读取 `limit + 1` 条，用来判断后面是否还有记录，`has_more` 由此得出。
2. `desc` 用环形缓冲保留时间范围内最后 `limit + 1` 条命中。扫描量受 `max_scan` 限制。超限时返回已扫描部分的结果，同时标记 `scan_limit_reached`，并返回实际扫描到的时间范围 `scanned_since`。
3. 游标内容是 base64 编码的 JSON：源名称、文件的设备号和 inode、字节偏移、记录时间戳、请求参数的哈希值。
4. 游标不签名。调用方修改游标后，最多只能读取同一源内的其他位置，这些位置本来就允许读取。agent 检查：游标里的文件属于该源、偏移不超过文件大小、参数哈希与本次请求一致。检查失败返回 `CURSOR_INVALID`。
5. 日志轮转后，按 inode 找到原文件的新文件名；找不到时返回 `CURSOR_EXPIRED`，并提示用游标中的时间戳作为新的 `until` 或 `since` 重新查询。

### 6.6 输出格式

builtin 实现 `RedactingBuiltinHandler`，在编码前对每条记录的文本脱敏，做法与 redis builtin 相同。输出是一个 JSON 对象，不再使用 `文件名:行号:内容` 的文本格式。

```json
{
  "source": "web-app",
  "since": "2026-10-23T14:45:00+08:00",
  "until": "2026-10-23T16:45:00+08:00",
  "order": "desc",
  "records": [
    {"time": "2026-10-23T16:44:58.120+08:00", "file": "/data/logs/web-app/app.log", "line": 18233, "text": "...", "record_truncated": false}
  ],
  "matched": 37,
  "has_more": true,
  "next_cursor": "eyJ...",
  "files": {"searched": 3, "skipped_out_of_range": 5, "skipped_not_regular": 2},
  "scanned_bytes": 48211002,
  "scan_limit_reached": false,
  "scanned_since": "2026-10-23T14:45:00+08:00"
}
```

1. `matched` 是已扫描范围内的命中总数，不是本页的条数。
2. 输出是 JSON，`match`、`exclude` 等输出过滤对它没有意义。新 action 的 `filters` 设为 `[]`。
3. JSON 编码后的输出受 `max_output` 限制。builtin 按 `max_output` 预留空间，先减少本页记录数，不截断 JSON。

### 6.7 错误原因

builtin 的错误使用固定的代码。代码写入 `ExecutionResult.reason`，MCP 结果的每个分组增加 `reason` 和 `hint` 两个字段。

| 代码 | 场景 | 提示 |
|---|---|---|
| `SOURCE_UNKNOWN` | 源名称不在 catalog 中 | 列出可用源名称 |
| `SOURCE_NO_FILES` | 源的 glob 没有匹配到文件 | 列出源的 glob；建议先调用 `log_sources` |
| `PATH_OUTSIDE_ROOTS` | 解析符号链接后不在允许的根目录内 | 无 |
| `WINDOW_TOO_LARGE` | 时间范围超过 `max_window` | 给出允许的最大范围 |
| `TIME_INVALID` | `since`/`until` 格式错误，或 since 不早于 until | 给出接受的格式示例 |
| `TIMESTAMP_UNPARSED` | 时间范围内的文件都解析不出时间戳 | 建议去掉时间范围，或检查源的 `timestamp.layouts` |
| `PATTERN_INVALID` | 正则编译失败 | 返回 RE2 的错误位置 |
| `CURSOR_INVALID`、`CURSOR_EXPIRED` | 见 6.5 | 见 6.5 |

改动点：

1. `internal/execd/exec.go` 的 `ExecutionReason` 和 `internal/agent/task.go` 的 `taskStatus`：上表中的代码原样传递，其他错误仍然合并成 `EXECUTION_FAILED`。
2. `internal/agent/runner.go` 的 `helperReason` 同样原样传递上表中的代码。
3. `OutputGroup` 增加 `reason` 字段，分组键加入 reason。MCP 摘要输出 `reason`，`hint` 由网关按代码查表生成，不从主机端传递原文。
4. 这一项也适用于现有的其他 builtin。现在 `http_get`、`redis_command`、`mysql_query` 的错误原因同样会丢失。

没有命中时成功返回，`matched=0`，退出码 0（对应 1.2 第 6 项）。

### 6.8 现有 action 的处理

1. 新的 `log_search` action 使用 `log_query` builtin。旧的 `log_search` builtin 保留一个版本，示例 catalog 中改名为 `log_grep`，`allowed_roots` 和参数不变。
2. `log_search` builtin 中目录导致整次失败的问题（1.2 第 3 项）在保留期内单独修复：跳过非普通文件。
3. `mysql_error_log` 继续使用旧的 `log_search` builtin，不在本设计范围内。

### 6.9 `log_sources`

不接受参数（除 targets 等公共参数）。对每个源返回：

```json
{"sources": [
  {"name": "web-app", "type": "file", "files": 8, "bytes": 1203400211,
   "earliest": "2026-10-16T00:00:01+08:00", "latest": "2026-10-23T16:50:12+08:00",
   "timestamp_parsed": true, "status": "ok"}
]}
```

`status` 取 `ok`、`no_files`、`timestamp_unparsed` 之一。只读取每个文件的开头和元数据，不扫描全文。

### 6.10 完成条件

1. 单元测试覆盖：时间格式解析；二分定位（含解析失败退回顺序扫描）；多行合并；`asc` 和 `desc` 分页；游标的校验、轮转和过期；每个错误代码；跳过非普通文件。
2. 在 compose 演示主机上用轮转的 Logback 格式日志（含 .gz 和异常堆栈）执行 `log_sources` 和 `log_search`，结果与 `zcat | grep` 在同一时间范围内的结果一致。
3. MCP 调用失败时，结果中带 `reason` 和 `hint`。
4. 用当前 main 重建本地试用网关后，Codex 能看到参数结构（对应 1.2 第 1 项，不属于本设计的代码改动）。

### 6.11 第一阶段实现记录

第一阶段已在 `internal/builtin/logquery` 实现（2026-10-23）。示例 catalog 增加 `log_sources`，`log_search` 改用 `log_query`，原定义改名 `log_grep`。6.7 的改动点 1 到 4（reason 传递、`OutputGroup.reason`、`hint`）由另一项工作完成，不在本包内；本包的错误类型实现 `Reason() string`，返回上表中的代码。

与上文设计不一致之处：

1. `level`（6.4）未实现，`log_search` 不提供该参数。它依赖 7.3 的级别提取规则，与第二阶段一起实现。
2. 记录增加 `offset`（字节偏移，.gz 为解压后的偏移）。从二分定位的偏移开始读取时行号未知，`line` 省略。
3. `asc` 输出 `scanned_until`，`desc` 输出 `scanned_since`。`asc` 从早到晚扫描，扫描量超限时已扫描部分是时间范围的开头一段。
4. `files` 增加 `skipped_unparsed`：开头 64 行没有可解析时间戳的文件不参与检索。时间范围内所有文件都是这种情况时返回 `TIMESTAMP_UNPARSED`。
5. 两种顺序都扫描整个时间范围（受 `max_scan` 和 `max_files` 限制），`matched` 是已扫描范围内的命中总数。每一页都从游标位置扫描到范围的另一端。
6. 游标另外保存解析后的 `since`、`until`，相对时长的范围在翻页时不随执行时刻移动。游标偏移处不在行首，或该处记录的时间戳与游标不同，返回 `CURSOR_EXPIRED`，对应 copytruncate 等文件内容改变的情况。偏移超出文件大小仍返回 `CURSOR_INVALID`。inode 被重用且内容相同的文件会通过校验。
7. `desc` 的扫描量限制：从最新的文件开始扫描。未压缩文件剩余预算不足时，从 `until` 位置向前预算长度处开始读；.gz 文件用 gzip 尾部的 ISIZE 预先判断。扫描到文件中途超限时丢弃该文件的命中，使结果始终是时间范围的结尾一段。
8. 匹配作用于截断到 `max_record_bytes` 之后的记录文本，超出部分的关键词不会命中。
9. `max_output`：catalog 增加 `BudgetedBuiltinHandler` 接口，执行器把 action 的 `max_output` 和按 stdout 同样规则逐行脱敏的函数传给 builtin（同一条记录内保持 PEM 状态）。`RunRedacted` 同样实现，但不知道 `max_output`。
10. 错误信息（`Error()`）包含具体细节，例如可用源名称、RE2 错误、游标时间戳；6.7 的 `hint` 文本由网关生成。
11. 同一源的文件按首个时间戳排序后依次读取，不对时间重叠的文件做逐条合并。
12. 相对时长只接受 Go 时长格式（`30m`、`2h`），不接受 `1d`。

留给第二、三阶段的扩展点：

- 模式：`ModeSources`、`ModeSearch` 常量，`Config.Validate`、`Run`、`Parameters` 中按 `Mode` 的分支。`stats`、`patterns` 可复用 `searcher.scanFile` 的逐条回调和 `compilePatterns`。
- 源类型：`TypeFile` 常量，`Source.validate` 和 `buildTimeline`（经 `resolveFiles`）中按 `Type` 的分支。`searcher.ascending`、`descending` 目前直接读取 `logFile`；容器标准输出和 Pod 日志需要把这一层换成按类型提供记录流的接口，`recordReader`、`ring`、`encodeSearch` 和游标编码可以复用。

第 6.10 第 2 项的对照在本机用 `allowops catalog try` 执行（未使用 compose 演示主机）。三个文件为 2026-10-23 00:00 到 06:00 的 Logback 日志：`app.log.2026-10-23.0.gz`、`app.log.2026-10-23.1.gz`、`app.log`，共 107942 行，含 Java 异常堆栈。时间范围 01:30 到 04:30 跨三个文件，与 `zcat -f … | awk 按时间过滤并记录所属记录的首行 | grep` 的结果比较：

| pattern | zcat\|grep 记录数 | asc 记录数（页数） | desc 记录数（页数） | 记录首行序列一致 |
|---|---|---|---|---|
| `ERROR` | 514 | 514（5） | 514（5） | 是 |
| `SocketTimeoutException`（只出现在堆栈续行） | 167 | 167（2） | 167（2） | 是 |
| `listAll` | 2092 | 2092（11） | 2092（11） | 是 |

`password=` 所在记录的输出为 `[REDACTED:credential]`。范围 05:00 到 05:10 只在 `app.log`（3.5MB）中，二分定位后扫描 347953 字节，命中 32 条，与 `grep -c` 一致。

## 7. 第二阶段：统计与模式聚类

### 7.1 `log_stats`

参数：`source`、`since`、`until`、`pattern`、`fixed`、`exclude`、`ignore_case`、`level`，含义与 `log_search` 相同；另有 `bucket`。

`bucket` 是时间分桶的宽度，例如 `1m`、`5m`、`1h`。省略时自动选择，使桶数不超过 60。

输出：

```json
{
  "source": "web-app",
  "since": "...", "until": "...", "bucket": "5m",
  "matched": 412,
  "first_match": "...", "last_match": "...",
  "histogram": [{"start": "2026-10-23T14:45:00+08:00", "count": 12}],
  "by_level": {"ERROR": 3, "WARN": 40, "INFO": 369},
  "by_file": [{"file": "/data/logs/web-app/app.log", "count": 400}],
  "scanned_bytes": 48211002, "scan_limit_reached": false
}
```

1. 输出只有数字、时间和文件名，不含日志内容。
2. 统计仍在原文上匹配，限制同第 3 节第 1 项。
3. `by_level` 只在源声明了 `level` 提取规则时输出。

### 7.2 `log_patterns`

用 Drain 算法把记录聚类成模板。Loki 的 pattern 功能使用的也是 Drain 的变体。

1. 聚类前替换变量：数字、十六进制串、UUID、IP 地址、时间戳替换为 `<_>`。
2. 只用每条记录的第一行聚类，避免堆栈的不同改变模板。
3. 输出按条数排序的前 `top`（默认 20，最大 100）个模板。每个模板包含条数、首次和最后出现时间、一条样例。
4. 模板和样例都经过脱敏。
5. 参数：`source`、`since`、`until`、`level`、`exclude`、`top`。不接受 `pattern`，因为它的用途是没有关键词时发现异常。

```json
{"patterns": [
  {"template": "OwnerService.listAll parse failed: <_>", "count": 120,
   "first": "...", "last": "...", "sample": "..."}
], "records": 18233, "scanned_bytes": 48211002, "scan_limit_reached": false}
```

### 7.3 日志级别提取

源配置增加可选的 `level`：

```yaml
level:
  regex: '^\S+ \S+ \[[^\]]*\] (?P<level>ERROR|WARN|INFO|DEBUG)'
```

正则必须有名为 `level` 的捕获组，只作用于记录的第一行。

### 7.4 完成条件

1. `log_stats` 的直方图总数等于同一参数下 `log_search` 的 `matched`。
2. `log_patterns` 对固定样例日志的输出稳定：同一输入多次执行，结果相同。
3. 两个 action 在 compose 演示主机上执行成功；扫描量超限时标记 `scan_limit_reached`。

## 8. 第三阶段：容器、Kubernetes 和导出

### 8.1 容器标准输出

源类型 `container_stdout`：

```yaml
sources:
  web-app-stdout:
    type: container_stdout
    container: web-app
    multiline: timestamp_start
```

1. builtin 通过 `/var/run/docker.sock` 调用 Docker Engine API 的 `GET /containers/{name}/logs?stdout=1&stderr=1&timestamps=1&since=…&until=…`，不传 `tail`。
2. 由 builtin 读取流、做匹配并保留最后 `limit + 1` 条，读取的字节数计入 `max_scan`。这样不受 1.3 中 `--tail` 先生效的影响。
3. 时间戳使用 Docker 记录的时间，不解析日志正文的时间戳。
4. `container` 在 catalog 中写死，调用方只选择源名称。
5. 游标保存最后一条记录的 Docker 时间戳，下一页用它作为新的 `until`（desc）或 `since`（asc）。同一纳秒有多条记录时，游标同时记录已返回的条数。
6. 与日志驱动无关：json-file 以外的 local、journald 驱动也通过同一个 API 读取。local 和 journald 驱动的行为未验证。

### 8.2 容器内日志文件

源类型 `container_file`：

```yaml
sources:
  web-app-files:
    type: container_file
    container: web-app
    paths: [/opt/app/logs/*.log*]
    allowed_roots: [/opt/app/logs]
```

1. 执行时调用 `GET /containers/{name}/json` 获取挂载和存储信息。
2. 容器内路径位于某个 bind mount 或卷之内时，换算成宿主机上的路径。
3. 不在挂载内时，使用 overlay2 的 `GraphDriver.Data.MergedDir` 拼出宿主机路径。其他存储驱动返回 `SOURCE_UNSUPPORTED`。
4. 换算后的目录作为 `os.Root` 打开，容器内的符号链接不能跳出该目录。这比现在 `docker_file_*` 的处理更严格：它们的路径正则只能排除 `..` 段，容器内指向其他位置的符号链接会被跟随。
5. 其余规则同 `file` 类型的源。

### 8.3 Kubernetes Pod 日志

源类型 `k8s_pod`，读取节点上 `/var/log/pods/<namespace>_<pod>_<uid>/<container>/*.log`。

1. catalog 写死 namespace 和容器名，Pod 名称用前缀或标签匹配。
2. 解析 CRI 日志格式：`<RFC3339Nano 时间> <stdout|stderr> <P|F> <内容>`。`P` 表示一行被拆分的片段，与后续片段拼成一行。
3. 不调用 kubectl，不需要 pods/exec 权限。
4. 只能读取 agent 所在节点上的 Pod。跨节点检索需要以多台主机为目标执行。

### 8.4 导出

1. `jobs_get` 增加 `encoding=text`：输出是合法 UTF-8 时直接返回文本，否则返回 `ENCODING_NOT_TEXT`。现在只返回 `data_base64`，AI 调用方需要自己解码。
2. 新增 action `log_export`：参数与 `log_search` 相同，`order` 固定为 `asc`，`max_output` 可配置到 8MB，输出为每行一条记录的文本。调用方用 `jobs_get` 分页读取，或用 CLI `allowops jobs output <job-id>` 保存到本地文件。
3. 导出内容同样经过脱敏，并计入审计。

### 8.5 完成条件

1. `container_stdout` 在本地 Docker 上复现 1.3 的场景：`until=mid2`、`limit=500` 返回 A501 到 A1000，不再为空。
2. `container_file` 覆盖 bind mount 和 overlay2 两种情况，并验证容器内指向 `/etc/passwd` 的符号链接被拒绝。
3. `k8s_pod` 在本地 k3s 集群上读取一个 Pod 的日志，结果与 `kubectl logs --since-time` 一致。
4. `jobs_get encoding=text` 和 `log_export` 在 compose 演示主机上执行成功。

## 9. 待定问题

1. 实际部署中应用日志的位置各不相同：可能在容器内、宿主机的 bind mount 或只在标准输出。私有 catalog 需要按实际位置选择源类型。
2. 默认时间范围取 1 小时还是 24 小时，结论待定。
3. `max_scan` 默认 256MB 对 `desc` 是否足够，需要用实际主机的日志量测量。
4. `OutputGroup` 增加 `reason` 是协议改动，网关和 agent 的版本兼容方式需要另行确定。
5. 旧 `log_search` builtin 的保留期限待定。
