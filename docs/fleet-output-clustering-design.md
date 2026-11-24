# 机群输出去噪归一化聚类、异常优先排序与跨 Job 基线对比设计

状态：已吸收独立复审意见（2026-11-24，复审记录见第 11 节）。本文档以当前仓库 `HEAD`（`9640cd8`）为基线。

## 1. 背景与现状痛点

当前 `allowops` 的 job 汇总链路如下：

1. **主机侧执行与预览落库**：`allowops-agent` / `allowops-exec` 在主机端完成「脱敏 → 过滤 → 截断」，将已脱敏输出流式传回网关。任务完成时，[`internal/gateway/job/events.go`](../internal/gateway/job/events.go) 计算完整 `stdout`/`stderr` 的 SHA-256，并将每个流的前 4 KiB（`GroupBytes = 4096`）作为 `stdout_preview`/`stderr_preview` 写入 PostgreSQL `tasks` 表（`CHECK (octet_length <= 4096)`，见设计 A23），完整输出异步写入 S3 兼容存储。
2. **网关汇总分组**：[`internal/gateway/job/summary.go`](../internal/gateway/job/summary.go) 的 `groupPreviews` 从 PostgreSQL 读取有界预览，按 `exit_code + reason + stdout_sha256 + stderr_sha256` 精确分组；分组顺序为任务位置首次出现顺序；无输出哈希的终态任务（如 `SKIPPED/MAX_FAILURES`、`FAILED/DISPATCH_CAPACITY`、`GATEWAY_INSTANCE_LOST`、`CANCELLED`）直接被跳过；随后以反复对整个响应调用 `protojson.Marshal` 的二次方循环缩减到 32 KiB（实测 1000 组耗时 10.85s）。
3. **MCP 映射与分页**：[`internal/gateway/mcp/summary.go`](../internal/gateway/mcp/summary.go) 的 `nativeSummaryResult` 严格遵守 G57/P6 原则——只映射和分页后端已授权的 `JobSummary`，不重读 task、不重建分组，同时将完整 MCP 响应（含 `structuredContent`、JSON 文本副本及 `_meta`）控制在 32 KiB 内。

在实际大规模排障中，这套机制暴露出四个核心痛点：

1. **高噪输出导致分组爆炸**：只要输出包含时间戳、PID、内存/CPU/磁盘数值、容器运行时间、请求 ID 或主机自身 `hostname`（如 `uptime`、`free -m`、`df -h`、`docker ps --format '{{json .}}'`、`systemctl status`、`jvm_perfdata`、`log_query`），50 台健康主机就会产生 50 个不同 SHA-256 的分组，迅速打满 32 KiB 预算，排在后面的真正故障节点被截断丢失。
2. **排序缺乏排障优先级且无输出终态任务不可见**：分组按任务位置顺序返回；同时网关直接写入终态且无输出哈希的 `SKIPPED`/`CANCELLED`/`DISPATCH_CAPACITY`/`GATEWAY_INSTANCE_LOST` 任务完全不出现在 `groups` 中。
3. **大规模汇总预算收敛呈二次方复杂度**：现有 32 KiB 裁剪循环在 1000 组时执行近 2000 次全量 `protojson.Marshal`，耗时超 10 秒。
4. **跨时间点基线对比缺失**：排障常需对比「当前 vs 15 分钟前 / 发版前」两次同 action job，目前 AI 只能手工拉取两份输出自行 diff，极耗 token 且容易漏掉关键退化。

## 2. 目标、非目标与红线

### 2.1 目标

1. **去噪归一化聚类（Normalized Clustering）**：保留 `exact` 精确哈希分组作为基础事实；新增 `normalized` 归一化聚类模式，将仅在易变噪声上存在差异的输出聚入同一模板聚类，同时保留版本号与语义状态码，并提取有限浮点数值分布（min/p50/max/p95 及离群主机提示）。
2. **异常优先排序（Anomaly-First Ranking）与线性预算裁剪**：
   - 将无输出哈希的终态任务纳入 Tier 0 分组，并将未完成任务计入 `unfinished_hosts_count`，严格满足主机守恒等式；
   - 在 32 KiB 预算裁剪与分页之前，按确定性三层优先级（`failure` → `anomaly` → `normal`）对分组排序；
   - 用单遍前缀和线性估算替换现有二次方 `protojson.Marshal` 裁剪循环，将 1000 组裁剪降至毫秒级。
3. **跨 Job 基线对比（`jobs_diff`）**：提供只读固定 MCP 工具 `jobs_diff`、对应 `JobService.DiffJobs` RPC 以及 `allowops jobs diff` CLI，按不可变 `host_id` 对齐对比同一 action 的两次已结束非拒绝 job，输出主机集合变化、状态跃迁（退化优先）、模式聚类跃迁（同类变化自动聚合）以及结构化数值漂移，严格受 32 KiB 预算与逐主机权限控制。

### 2.2 非目标（本阶段不做）

- **不修改原始证据与 S3 存储格式**：不改变 `tasks.stdout_sha256`、`tasks.stderr_sha256`、S3 对象内容或审计哈希链。
- **不引入 PostgreSQL Schema 迁移**：完全复用现有 `jobs` 和 `tasks` 表（仅在 `ListJobTaskPreviews` 的 sqlc 查询中补选已有列 `host_id`）。
- **不修改签名目录格式（`catalog.Action`）**：见第 3.2 节说明，避免旧版主机端因严格 JSON 解析拒绝目录包。
- **不在网关拉取完整 S3 对象做全量聚类或全量 diff**：仅消费 PostgreSQL 中每流 ≤ 4 KiB 的已脱敏预览；超出部分通过 `truncated` / `preview_truncated` 显式告知调用方，由其按需使用 `jobs_get(job_id, host)` 分页读取单机完整输出。
- **不改动 Web 控制台页面**：仅重新生成 `gen/` 与 `web/src/gen/` 并保持 `wire.check.ts` 与前端检查通过。

### 2.3 安全与工程红线

| 红线 | 强制保障 |
|---|---|
| 原始证据零污染 | 聚类与 diff 为纯只读视图层，不修改 S3 对象、原始 SHA-256 和审计字段。`normalized` 分组留空 `stdout_sha256`/`stderr_sha256`，仅填充 `template_sha256`，避免与原始证据哈希混淆。 |
| 仅处理已脱敏输出 | 输入仅来自 `tasks.stdout_preview` / `tasks.stderr_preview`（A23 保证离开主机前已完成脱敏）；词法扫描器第一优先级原样保留 `[REDACTED:...]` 标记。 |
| 不可信数据隔离 | 所有汇总与 diff 响应强制携带 `output_trust: "untrusted"`；由输出派生的 `variances[].label`/`unit`、`metric_drifts[].label`/`unit` 均做控制字符清理与 64 字节上限截断，并在工具描述中明确声明同样为不可信输出。 |
| 多租户与逐主机权限 | `DiffJobs` 直接复用 `s.authorize` 对两个 job 分别执行 `view_jobs` 和 `view_output` 逐主机 ABAC 判定（服务账号严格校验 `subject_id == actor`），与 `GetJob` 存在性语义一致；先鉴权 `view_jobs` 再校验同 action；审计同时记录目标 `job_id` 与 `resource="job:<base_job_id>"` 及合并的命中规则。 |
| 防 DoS 与确定性线性复杂度 | 聚类与 diff 引擎零 `regexp` 依赖，纯单遍 `O(N)` 词法扫描器；不使用依赖 CPU 负载的墙钟超时，全部采用**确定性字节/行数/任务数/聚类数硬上限**，保证同输入输出字节级一致且 `summaryCursor` 稳定；32 KiB 预算采用 `O(G)` 线性前缀和；并发分析受信号量（默认 8）限流。 |
| 有限浮点数不变式 | 丢弃一切 `NaN`/`±Inf` 数值；`MetricDrift.max_delta_pct` 在 `base == 0` 时不计算（proto optional 留空），防止 `encoding/json` 编码失败导致工具不可用。 |
| 向后兼容 | `grouping` 在 `RunJob`/`GetJob`/MCP `jobs_get` 默认为 `exact`；`jobs_diff` 默认为 `normalized`；proto 变更全部 additive；`native_summary_golden.json` 零破坏。 |

## 3. 架构抉择

### 3.1 归一化放在网关，而非主机端

| 维度 | 网关侧只读视图层（**采用**） | 主机端预计算（否决） |
|---|---|---|
| 旧版 Agent 兼容 | 100% 兼容 v0.1/v0.2 主机端，无需全网升级 agent | 需升级全部主机端与 gRPC 协议 |
| 历史 Job 兼容 | 支持对已完成的任意历史 job 切换 `exact`/`normalized` 或执行 `jobs_diff` | 仅对升级后新 job 生效 |
| 内存与 I/O 边界 | 复用 PostgreSQL 已有 ≤ 4 KiB 脱敏预览，零 S3 读取 | 需额外传输特征字段 |
| 跨主机视角 | 网关掌握全部主机的 `hostname`、`host_id` 与跨主机分布（p50/p95/离群主机） | 单机无法计算集群分布与少数派 |
| 主机侧攻击面 | 不在被管主机/root 侧引入额外解析逻辑 | 增加主机侧复杂度 |

### 3.2 `grouping` 放在请求参数，本期不改 `catalog.Action`

[`internal/catalog/dsse.go`](../internal/catalog/dsse.go) 使用 `decoder.DisallowUnknownFields()` 严格解码签名目录。若在 `catalog.Action` 增加字段，旧版主机端会以 `CATALOG_REJECTED` 拒收整个目录包。因此本期采用请求参数 `grouping: exact | normalized`；MCP 工具描述显式指导 AI 对高噪多主机命令使用 `grouping="normalized"`。

### 3.3 `jobs_diff` 采用独立固定 MCP 工具，且不分页（仅高价值截断）

- `jobs_get` 已有 9 个参数（新增 `grouping` 后为 10 个），承担汇总与单机输出两种职责；新增固定工具 **`jobs_diff`** 符合单一职责原则，并将 `jobs_diff` 加入 `catalog.validateIdentity` 保留名（升级说明明确提示私有目录不得包含同名 action）。
- **DiffJobs 不提供 `next_cursor` 分页**：Connect 层（`WithSendMaxBytes(32 KiB)`）与 `job.Service` 本身就按 32 KiB 预算裁剪响应；若仅在 MCP 层叠加 `next_cursor` 会产生“游标无法找回后端已丢弃条目”的语义矛盾。因此 `DiffJobs` 在 Connect、CLI、MCP 三端保持一致语义：按异常优先保留最高价值的变更项至 32 KiB，保留精确计数（`added_hosts_count`、`removed_hosts_count`、`unchanged_hosts_count`、`total_pattern_changes`、`omitted_pattern_changes`）并置 `truncated: true`。

### 3.4 独立纯逻辑包 `internal/gateway/cluster`

将词法归一化、两遍确定性聚类、数值分布统计、Anomaly-First 排序与有界 Diff 引擎封装为独立的零外部依赖包 `internal/gateway/cluster`（无数据库、无网络、无 `regexp`），由 `internal/gateway/job` 调用。

## 4. 去噪归一化与两遍聚类引擎（`internal/gateway/cluster`）

### 4.1 确定性硬上限（无墙钟非确定性）

```go
const (
    MaxPreviewBytesPerStream = 4096 // 与 job.GroupBytes 及 DB CHECK 一致
    MaxLinesPerPreview       = 128  // 每流最多扫描行数
    MaxLineBytes             = 1024 // 单行最大扫描字节
    MaxTasks                 = 5000 // normalized 模式最大任务数；超过时确定性回退 exact
    MaxClusters              = 256  // 成功任务最大归一化聚类数
    MaxSlotsPerTask          = 64   // 单任务最多提取数值槽位数
    MaxSlotsPerCluster       = 64   // 单聚类最多跟踪数值槽位数
    MaxSamplesPerSlot        = 5000 // 与 MaxTasks 对齐，确保 5000 机规模下尾段离群主机不被漏掉
    MaxReportedVariances     = 5    // 每聚类最多输出的数值分布条目
    MaxLabelBytes            = 64   // 输出派生 label / unit 最大长度（防注入与膨胀）
    MaxJSONDepth             = 8    // JSON 递归归一化最大深度
    MaxJSONKeys              = 128  // 单个 JSON 对象最大键数
    MaxJSONArrayItems        = 64   // JSON 数组最大扫描元素数
    MaxDetailedPatternDiffs  = 32   // DiffJobs 仅对排名前 K 的模式跃迁执行有界行级 Diff
    MaxDiffLinesPerEntry     = 6    // 每条模式跃迁最多输出的增/删代表行
    MaxDiffLineBytes         = 256  // 单条 Diff 代表行最大字节
)
```

- **绝对确定性**：不引入墙钟时间预算。所有上界均为与输入强绑定的整数常数，确保对同一已完成 job 任意次调用产出字节级一致的分组、排序与 `summaryCursor` 快照哈希。
- **超大规模回退**：当 `len(items) > MaxTasks`（5000）时，`normalized` 模式确定性回退为 `exact` 分组（仍执行 Anomaly-First 排序），并设置 `grouping: "exact"`、`truncated: true`。
- **并发限流**：`job.Service` 内置容量为 8 的分析并发信号量（`analysisSem chan struct{}`），保护 normalized 汇总与 `DiffJobs` 在高并发下不耗尽网关内存，等待时响应 `ctx.Done()`。
- **性能目标**：1000 台主机 × 4 KiB 典型运维输出，归一化 + 聚类 + Anomaly-First 排序总耗时 **< 50 ms**、总堆分配 **< 16 MiB**；1000 组 32 KiB 预算裁剪 **< 5 ms**。

### 4.2 预览截断边界处理与双模态一致归一化

针对 4 KiB 字节截断导致的同类主机分裂问题：

1. **截断尾行丢弃**：当某任务的 `stdout_size > uint64(len(stdout_preview))`（或 stderr 同理）且预览中包含至少一个 `\n` 时，在归一化前丢弃最后一个 `\n` 之后的不完整尾行（文本与 NDJSON 均适用），避免每台主机因最后一行截断字节偏移不同而裂变成不同模板。
2. **Job 级统一 JSON 判定（防 JSON/文本混流分裂）**：
   - 在 Pass 2 对成功任务归一化之前，先用 `O(N)` 轻检查所有非空成功任务的预览：
     - **完整 JSON 对象模式**：仅当**所有**非空成功任务预览均未在 JSON 内部被截断、去空白后以 `{` 开头且可通过有界 JSON 深度/键数校验解析为单个 JSON 对象（如 `jvm_perfdata`、`log_query`）时，全部成功任务统一走结构化 JSON 归一化；
     - **NDJSON 模式**：否则若预览按行切分（丢弃截断尾行后）所有非空行均为合法 JSON 对象（如 `docker ps --format '{{json .}}'`），逐行执行 JSON 归一化，并对归一化后的行模板按字典序排序并折叠重复计数（例如相同容器运行在不同启动顺序下归为同一聚类）；
     - **文本 / 表格 / KV 模式**：其余情况（包括部分主机 JSON 超 4 KiB 被截断的场景）所有任务统一走文本词法归一化，彻底杜绝 3.9 KiB 走 JSON、4.1 KiB 走文本导致的误报 `minority_cluster`。

3. **结构化 JSON 归一化规则**：
   - 键按字典序稳定排序递归输出，保留键名；
   - 字符串值若为短低熵状态词（如 `running`、`active`、`healthy`、`INFO`、`ERROR`）原样保留，否则走文本词法归一化；
   - **语义状态/退出码字段保护**：若键名（小写）属于 `exit_code`、`exitcode`、`status_code`、`http_status`、`code`、`errno`、`signal`，其整数值原样保留为字面量（不替换为 `<NUM>`），避免 `"exit_code": 1` 与 `"exit_code": 0` 被合并；
   - 其余有限数值替换为 `<NUM>`，并以清理后的 JSON Path（≤ 64 字节）记录数值样本；
   - 数组最多扫描 `MaxJSONArrayItems` 个元素；若全部元素归一化后模板一致（如 `log_query` 的 `records`），折叠为 `[<ELEM_TEMPLATE>, ...]` 并记录 `path.$len` 数值槽位。

4. **单遍 `O(N)` 文本词法扫描规则（零 `regexp`，仅在 token 边界生效）**：

| 优先级 | 识别模式 | 替换结果 | 数值提取与保护规则 |
|---|---|---|---|
| 1 | `[REDACTED:...]` | 原样保留 | 保护主机端脱敏标记不被拆分或改写 |
| 2 | 主机自身 `hostname` 及合法短名 | `<HOST>` | 非字母数字边界匹配；短名（首个 `.` 前）仅在长度 ≥ 3 且含数字或 `-` 时启用 |
| 3 | ISO8601/RFC3339、斜杠日期、CLF 日期、Syslog/systemd 日期时间 | `<TS>` | 覆盖常见日志与 `systemctl` 时间戳 |
| 4 | 纯时钟 `HH:MM:SS(.fff)` | `<TIME>` | 覆盖 `uptime` 与日志时间 |
| 5 | UUID (`8-4-4-4-12` hex) | `<UUID>` | 大小写不敏感 |
| 6 | IPv4 / IPv6（含可选 `:port` / `/cidr`） | `<IP>` / `<IP_PORT>` | 受 `NormalizeOptions.MaskIPs`（默认 `true`）控制 |
| 7 | `0x[0-9a-fA-F]+` 及长度 ≥ 8 且含至少一个数字的纯 Hex 串 | `<HEX>` | 覆盖 Docker 12 位容器 ID、Trace ID、Git SHA |
| 8 | 版本号形态（`[vV]?\d+\.\d+\.\d+(?:[-+][A-Za-z0-9._-]+)?` 或 `name/\d+\.\d+(?:\.\d+)?`） | **原样保留** | 保护 `nginx/1.24.0` vs `nginx/1.25.3`、`v1.27.3` 等版本差异不被抹平 |
| 9 | 语义状态/退出码语境（`HTTP/1.x 500`、`HTTP 200`、`status=503`、`status: 500`、`exit_code=1`、`exit code 137`、`Exited (137)`、`signal 9`） | **数字原样保留** | 防止成功码与错误码被归一化合并 |
| 10 | 显式 PID 语境（`pid=123`、`PID: 123`、`Main PID: 123`、`[123]:`） | `<PID>` | 保留标签前缀提升可读性 |
| 11 | 时长表达（`123ms`、`4.5s`、`12m34s`、`3h20m`、`42 days`、`5 hours`、`3 min`） | `<DUR>` | 提取有限毫秒值（单位 `ms`） |
| 12 | 百分比（`42%`、`99.2%`） | `<PCT>` | 提取有限浮点值（单位 `%`） |
| 13 | 字节/容量单位（`128K`、`4.2G`、`512MiB`、`1024KB`、`2.5T`、`4096B`） | `<SIZE>` | 换算 1024 进制有限字节数（单位 `bytes`） |
| 14 | 独立整数 / 浮点数（两侧非标识符字母，且 `math.IsInf`/`IsNaN` 均被过滤） | `<NUM>` | 提取有限浮点值；不破坏 `/dev/sda1`、`nvme0n1p1`、`eth0`、`utf8` |

- **空白规范化**：行内连续空格/Tab 折叠为单个空格并去行尾空白，消除表格列宽偏移。
- **Label / Unit 清洗（防输出注入网关元数据）**：所有槽位 `label` 和 `unit` 剥离控制字符（`< 0x20`、`0x7f`），折叠空白，截断至合法 UTF-8 且 `<= MaxLabelBytes`（64 字节）。

### 4.3 两遍聚类与数值离群判定

#### 两遍处理（解决 B1、B2）

- **Pass 1（`O(N)` 分类与 Tier 0 零丢失保障）**：
  1. 扫描全部任务，按状态分类：
     - `TASK_STATUS_OFFLINE`：加入 `result.OfflineHosts`（保持原有离线列表语义）；
     - 未完成状态（`PENDING`、`RUNNING`、`UNSPECIFIED`）：累加 `result.UnfinishedHostsCount`；
     - **故障/非成功终态任务**（`FAILED`、`TIMEOUT`、`UNSUPPORTED`、`CANCELLED`、`SKIPPED`，或 `exit_code != 0`，或 `exit_code == nil`，或 `reason != ""`）：**无条件进入 Tier 0 故障分组**，不受 `MaxClusters` 成功聚类配额影响！
       - 若存在 32 字节输出哈希：`exact` 模式按 `(status_rank_class, exit_code, reason, stdout_hash, stderr_hash)` 分组；`normalized` 模式在 Tier 0 独立配额（`MaxFailureClusters = 128`）内按归一化模板分组，超配额时按精确哈希或 `(status, exit_code, reason)` 聚合，绝不丢弃任何故障主机；
       - 若无输出哈希（如网关直接写入的 `SKIPPED/MAX_FAILURES`、`FAILED/DISPATCH_CAPACITY`、`FAILED/GATEWAY_INSTANCE_LOST`、`CANCELLED`）：按 `(status, exit_code, reason)` 建立无输出 Tier 0 分组（`stdout=""`, `stderr=""`）。
  2. 剩余全部为已成功完成（`TASK_STATUS_SUCCEEDED`、`exit_code == 0`、`reason == ""`）且有输出哈希的任务，进入 Pass 2。

- **Pass 2（成功任务聚类）**：
  - `exact` 模式：按 `(stdout_hash, stderr_hash)` 精确分组，保留原始 `stdout_sha256`、`stderr_sha256`；
  - `normalized` 模式：执行第 4.2 节归一化，按 `(sha256(norm_stdout), sha256(norm_stderr))` 聚类（上限 `MaxClusters = 256`）。若超过 `MaxClusters`，后续无法归入已有聚类的成功任务统一归入一个显式的溢出分组（`severity: NORMAL`、`anomaly_reason: "cluster_limit_overflow"`、`truncated: true`、保留 2 台样本主机与准确 `host_count`），严格保持主机总数守恒且内存 `O(MaxClusters)`。
  - **低基数结构整数拆分**：在 `normalized` 模式下，对主机数 ≥ 10 的成功聚类，若某个无单位纯整数槽位（非 `<PCT>`/`<SIZE>`/`<DUR>`/`<PID>`）在全聚类内仅出现 2 个不同小整数值（范围 `[0, 999]`），且其中一个值占比 ≤ 20%（如 98 台为 `0`、2 台为 `1`），不拆分也可以通过 MAD==0 离群检测直接提升为 Tier 1 `metric_outlier` 并将这 2 台主机精准列入 `outlier_hosts` 和 `sample_hosts`！这种方式比强行二次分裂更稳定且保证结果中直接展示 `min=0, p50=0, max=1, outlier_hosts=[host-a, host-b]`。

#### 数值分布与离群主机判定（修复 H3、H5）

对聚类内样本数 `n >= 2` 且 `min != max` 的有限浮点数值槽位计算：
- `min`（`min_host`）、`p50`（中位数）、`p95`、`max`（`max_host`）；
- 安全相对偏离：`relDiff(x, med) = math.Abs(x - med) / math.Max(math.Abs(med), 1.0)`（永不除以 0）；
- **离群主机判定（`n >= 5`）**：
  - 计算 `MAD = median(|x_i - p50|)`；
  - 当 `MAD == 0`：任何 `x != p50` 的主机均视为离群（解决 99 台为 0、1 台为 1 漏检问题），按 `|x - p50|` 降序、主机名字典序取最多 3 台作为 `outlier_hosts`；
  - 当 `MAD > 0`：满足 `|x - p50| > 4.5 * MAD && relDiff(x, p50) >= 0.25` 的主机视为离群，按偏离降序取最多 3 台作为 `outlier_hosts`。
- 每个聚类按「存在离群主机优先 → 相对跨度 `(max - min) / max(|p50|, 1)` 降序 → 标签字典序」保留最多 `MaxReportedVariances = 5` 个槽位。
- `concise` 样本主机选择：若聚类检出离群主机，优先保留「1 台最接近 `p50` 的典型主机 + 1 台最极端离群主机」。

## 5. 异常优先排序、主机守恒与线性 32 KiB 预算裁剪

### 5.1 统一三层排序与严重子级表（修复 L2、L3）

`exact` 与 `normalized` 两种模式均执行同一确定性三层排序；若 `exact` 组内包含多个不同状态（例如无输出的 `FAILED` 与 `UNSUPPORTED`），取组内最严重状态决定 `severity` 与 `anomaly_reason`：

| 层级（`GroupSeverity`） | 触发条件 | 组内严重子级（升序优先） | `anomaly_reason` | 组内次级排序 |
|---|---|---|---|---|
| Tier 0: `FAILURE` | 任务状态为 `TIMEOUT` | 0 | `timeout` | `host_count DESC`, `reason ASC`, `exit_code ASC`, 首主机名 `ASC` |
| Tier 0: `FAILURE` | 任务状态为 `FAILED` 或 `exit_code != 0` 或 `exit_code == nil` | 1 | `nonzero_exit`（若 exit≠0）否则 `task_failed` | 同上 |
| Tier 0: `FAILURE` | 任务状态为 `UNSUPPORTED` | 2 | `task_unsupported` | 同上 |
| Tier 0: `FAILURE` | 任务状态为 `CANCELLED` | 3 | `task_cancelled` | 同上 |
| Tier 0: `FAILURE` | 任务状态为 `SKIPPED` | 4 | `task_skipped` | 同上 |
| Tier 0: `FAILURE` | 其余携带非空 `reason` 的终态 | 5 | `error_reason` | 同上 |
| Tier 1: `ANOMALY` | 成功（`exit_code == 0`, `reason == ""`）且非空 `stderr` | 0 | `stderr_present` | `host_count ASC`, 首主机名 `ASC` |
| Tier 1: `ANOMALY` | 成功且存在 ≥ 2 个成功组，且 `host_count < max_succeeded_hosts` | 1 | `minority_cluster` | `host_count ASC`, 首主机名 `ASC` |
| Tier 1: `ANOMALY` | 成功且 `normalized` 检出数值离群主机 | 2 | `metric_outlier` | `host_count ASC`, 首主机名 `ASC` |
| Tier 2: `NORMAL` | 其余成功多数派聚类（或唯一成功聚类） | 0 | `majority_normal` | `host_count DESC`, 首主机名 `ASC` |
| Tier 2: `NORMAL` | 超出 `MaxClusters` 的成功溢出桶 | 1 | `cluster_limit_overflow` | — |

### 5.2 主机守恒不变式（修复 B1）

`JobSummary` 暴露以下精确计数：
- `total_groups`：排序后、32 KiB 预算裁剪前的总分组数；
- `omitted_groups`：因 32 KiB 预算被整组省略的分组数；
- `omitted_hosts`：因 32 KiB 预算被整组省略的所有分组的主机数之和 + 被裁剪掉的 `offline_hosts` 数量；
- `unfinished_hosts_count`：仍处于 `pending`/`running` 状态的未完成任务数；
- `folded_normal_hosts`：所有 `NORMAL` 组中未被逐台列出的正常主机数（保留 `NORMAL` 组的 `host_count - len(hosts)` 之和 + 被省略 `NORMAL` 组的 `host_count` 之和）。

**严格守恒等式（测试强制断言）**：
$$\sum_{g \in \text{Groups}} g.\text{host\_count} + \text{len}(\text{offline\_hosts}) + \text{unfinished\_hosts\_count} + \text{omitted\_hosts} = \text{job.total\_tasks}$$

### 5.3 线性 `O(G)` 32 KiB 预算裁剪与模板长度约束（修复 H1、M1）

1. **单组预览硬上限**：在构造每个 `OutputGroup` 时，`len(stdout) + len(stderr) + len(template_stdout) + len(template_stderr) <= GroupBytes`（4 KiB）。优先给 `stdout`/`stderr` 留足空间，余量给 `template_stdout`/`template_stderr`（若 `template_stdout == stdout` 则省略 `template_stdout` 以省字节，仅在模板与样本不同时填充！）。
2. **线性前缀和裁剪（替代原 `O(G^2)` 循环）**：
   - 先测量空摘要基线响应 `baseSize = max(len(protojson(base)), proto.Size(base))`；
   - 按 Anomaly-First 顺序逐组序列化一次 `OutputGroup`，估算增量字节 `groupSize = max(len(protojson(g)), proto.Size(g)) + 2`；
   - 累计总字节不超过 `ResponseBytes`（32 KiB）则保留整组；遇到首个超出预算的边界组 `k`，先尝试依次缩减该边界组（`hosts` 缩至 2 → 清空 `variances` → 清空 `template_*` → 清空 `stderr` → 清空 `stdout`），能容纳则保留，否则在 `k` 处直接截断，后续所有尾部组一次性切掉并直接累加其 `HostCount` 到 `OmittedGroups`/`OmittedHosts`/`FoldedNormalHosts`；
   - 同理线性估算 `OfflineHosts` 切片，将截掉的离线主机数计入 `OmittedHosts`；
   - 最后对完整 `GetJobResponse` 做一次精确 `protojson.Marshal` + `proto.Size` 终检（若因 JSON 字段开销差几字节超限，仅需对末尾 1~2 项微调，总计 `O(G)`）。
3. **MCP 层模板缩减（修复 M1）**：`internal/gateway/mcp/summary.go` 的 `groupPreview(source, previewLimit)` 同步按 `previewLimit` 共享上限切分 `stdout`、`stderr`、`template_stdout`、`template_stderr`，确保单组在 `fit()` 的折半循环中绝不会因模板膨胀超出 32 KiB。

## 6. 跨 Job 基线对比（`jobs_diff` / `DiffJobs`）

### 6.1 权限、前置条件与审计（修复 H4、M2、M4、L1）

`JobService.DiffJobs(ctx, req)` 严格按以下流程执行：

1. **参数校验**：校验 `base_job_id`、`target_job_id` 非空，校验 `grouping` 为 `""` / `"normalized"` / `"exact"`（`""` 默认 `"normalized"`）。
2. **读取两个 Job 元数据**：若任一不存在，返回 `CodeNotFound` (`JOB_UNKNOWN`，与 `GetJob` 一致)。
3. **双 Job `view_jobs` 鉴权（复用 `s.authorize`）**：
   - 分别调用 `s.authorize(ctx, baseJob, authz.ViewJobs, false, "")` 与 `s.authorize(ctx, targetJob, authz.ViewJobs, false, "")`；
   - 服务账号自动强制 `baseJob.SubjectId == actor && targetJob.SubjectId == actor`；
   - 控制台/CLI 用户对两个 job 涉及的全部主机（含 tombstone 软删除主机的历史 `authorization_labels`，与 A21 一致）执行 `RequireBatch(ViewJobs)`。
4. **同 Action 与终态前置校验**：
   - `baseJob.Action != targetJob.Action` → `CodeInvalidArgument` (`DIFF_ACTION_MISMATCH`)；
   - 任一 job 为 `QUEUED` 或 `RUNNING` → `CodeFailedPrecondition` (`DIFF_JOB_NOT_FINISHED`)；
   - 任一 job 为 `DENIED` → `CodeFailedPrecondition` (`DIFF_JOB_DENIED`)。
5. **双 Job `view_output` 鉴权（复用 `s.authorize`）**：
   - 分别调用 `s.authorize(ctx, baseJob, authz.ViewOutput, false, "")` 与 `s.authorize(ctx, targetJob, authz.ViewOutput, false, "")`（注意 `access.go:28` 不会对服务账号短路 `ViewOutput`，同样完整走 `RequireBatch`！）。
6. **审计归属（修复 M2）**：
   - `operationState` 新增 `Resource string` 字段，在 `DiffJobs` 中显式设置 `state.JobID = targetJob.JobId`、`state.Resource = "job:" + baseJob.JobId`，累积两个 job 鉴权的全部去重 `MatchedRules`，并取最新 `PolicyVersion`，不改变 `audit.Payload` v1 契约与哈希链。
   - MCP 层 `callState.jobID = targetJobID`，记录 `mcp/jobs_diff` 结果审计。

### 6.2 有界 Diff 计算模型（修复 H4、H5、M6、L6）

1. **按 `host_id` 对齐（修复 H4）**：
   - `ListJobTaskPreviews` SQL 查询补充返回 `host_id`（`tasks.host_id` 已有列，零 schema 迁移）；
   - `DiffJobs` 按不可变 `host_id` 对齐 `base` 与 `target` 的任务：
     - 仅在 `target` 出现的 `host_id` → `added_hosts`（记录其 `hostname`）；
     - 仅在 `base` 出现的 `host_id` → `removed_hosts`（记录其 `hostname`）；
     - 若某 `hostname` 同时出现在 `removed_hosts` 与 `added_hosts`（即主机曾被删除并重新注册得到新 `host_id`），在 `replaced_hosts` 中显式列出该主机名，绝不将两台不同机器误当作同一台主机对比！
2. **特殊边界语义（修复 L6）**：
   - `base_job_id == target_job_id`：合法幂等操作，返回零变化 diff（`unchanged_hosts_count == total_tasks`）；
   - `!bytes.Equal(baseJob.ActionSha256, targetJob.ActionSha256)`：设置 `action_definition_changed: true`，提示调用方两次执行间签名目录中的 action 定义已发生变化；
   - `only_changed == false`：在 `pattern_changes` 尾部附加未发生变化的模式聚类（标记 `unchanged: true`），仍严格服从 32 KiB 预算。
3. **四类有界变化计算（受并发信号量保护）**：
   - **目标主机集合变化**：`added_hosts` / `removed_hosts` / `replaced_hosts` 及精确计数；
   - **状态跃迁（`status_transitions`）**：按 `(from_status, to_status, from_exit, to_exit, reason)` 聚合，**退化优先**（`succeeded → timeout/failed/offline` → 异常间互转 → `failed/offline → succeeded` 恢复）；
   - **输出模式跃迁（`pattern_changes`）**：按 `(base_sig, target_sig, target_severity)` 聚合同类主机变化；先按 Anomaly-First 排序（目标态为故障最前 → 少数派跃迁 `host_count ASC` → 多数派同步跃迁），**仅对排名前 `MaxDetailedPatternDiffs = 32` 条跃迁**执行有界行级 Diff（丢弃截断尾行、最多 128 行、首尾公共前后缀裁剪 + 有界 LCS，最多输出 6 条 `removed_lines` 与 6 条 `added_lines`，单行 ≤ 256 字节）；
   - **数值漂移（`metric_drifts`，仅 `normalized` 模式）**：按 `host_id` + 清洗后的槽位 `label` 对齐计算 `delta = target - base`；全部数值满足有限浮点不变式；筛选显著漂移（百分比 `|delta| >= 10` 或一般数值 `base != 0 && |delta/base| >= 0.20 && |delta| >= 1` 或 `base == 0 && |target| >= 1`）；`max_delta_pct` 为 `optional double`，当 `max_delta_base == 0` 时留空不输出；按显著性降序最多保留 10 条。
4. **线性 32 KiB 预算裁剪**：同第 5.3 节前缀和策略，确保 `DiffJobsResponse` 与 MCP `jobs_diff` 响应均严格 ≤ 32 KiB，保留精确总数并置 `truncated: true`。

## 7. Protobuf、接口、MCP 与 CLI 契约

### 7.1 Protobuf 增量扩展（`api/proto/allowops/v1/job.proto`）

- `RunJobRequest`：新增 `string grouping = 11;`
- `GetJobRequest`：新增 `string grouping = 4;`
- `OutputGroup`：新增 `GroupSeverity severity = 10;`、`string anomaly_reason = 11;`、`bytes template_sha256 = 12;`、`string template_stdout = 13;`、`string template_stderr = 14;`、`repeated MetricVariance variances = 15;`
- `MetricVariance`：`label = 1`、`unit = 2`、`min = 3`、`max = 4`、`p95 = 5`、`min_host = 6`、`max_host = 7`、`repeated string outlier_hosts = 8`、`double p50 = 9;`
- `JobSummary`：新增 `string grouping = 5;`、`string ranking = 6;`、`uint64 total_groups = 7;`、`uint64 omitted_groups = 8;`、`uint64 folded_normal_hosts = 9;`、`uint64 omitted_hosts = 10;`、`uint64 unfinished_hosts_count = 11;`
- `JobService`：新增 `rpc DiffJobs(DiffJobsRequest) returns (DiffJobsResponse);` 及 `DiffJobsRequest`、`DiffJobsResponse`、`JobDiff`、`StatusTransition`、`PatternChange`、`MetricDrift`（其中 `max_delta_pct` 为 `optional double`）。
- 修改 proto 后执行 `make generate` 同步生成 `gen/` 与 `web/src/gen/` 并验证 `web` TypeScript 检查（`wire.check.ts`）。

### 7.2 需同步更新的 Go 接口与调用点（L4）

- `internal/gateway/job/client.go`：`job.Client` 增加 `DiffJobs`；
- `internal/gateway/job/connect.go`：`ConnectService` 增加 `DiffJobs`；
- `internal/gateway/mcp/job.go`：`mcp.JobService` 增加 `DiffJobs`；
- `internal/gateway/mcp/fixed.go`、`call.go`、`arguments.go`、`schema.go`、`summary.go`：新增 `jobs_diff` 工具定义、路由与参数校验；为 `jobs_get` 与 action 工具增加可选 `grouping`；
- `internal/catalog/catalog.go`：`validateIdentity` 保留名列表新增 `"jobs_diff"`；
- 测试 fake 同步补齐：`internal/gateway/mcp/transport_test.go`、`step_test.go`、`output_text_test.go`。

### 7.3 MCP 与 Golden 演进说明

- `jobs_get` / action 工具默认 `grouping: "exact"`（向后兼容）；`jobs_diff` 默认 `grouping: "normalized"`（面向时间点对比）；两者默认值差异在工具描述中明确说明。
- `jobs_get` 同时传 `host` 和 `grouping` 返回 `INVALID_ARGUMENT`。
- `native_summary_golden.json`：**零变动**（新字段为零值时不在 JSON 序列化与游标哈希中出现）。
- `server_tools_golden.json`、`action_request_golden.json`：**预期演进**（反映新增 `jobs_diff` 与可选 `grouping` 参数）。
- `CHANGELOG.md` 升级说明明确列出两项行为变化：
  1. `exact` 模式默认启用 Anomaly-First 排序并将无输出终态任务纳入分组；
  2. `jobs_diff` 成为保留工具名，升级前需确认私有目录中无同名 action。

### 7.4 CLI 扩展（`internal/cli/jobs.go`）

- `allowops run <action>` 新增 `--grouping exact|normalized`（默认 `exact`）；
- `allowops jobs get <job-id>` 新增 `--grouping exact|normalized`（默认 `exact`）；
- 新增 `allowops jobs diff <base-job-id> <target-job-id> [--grouping normalized|exact] [--only-changed=true] [--json]`。

## 8. 威胁分析与防护矩阵

| 威胁场景 | 风险 | 防护措施 |
|---|---|---|
| 恶意输出触发正则回溯（ReDoS） | 网关 CPU 打满 | 零 `regexp` 依赖，单遍 `O(N)` 状态机 + 确定性字节/行数上限 |
| 1000+ 不同输出导致 32 KiB 预算裁剪二次方耗时 | 网关请求阻塞 >10s | 线性 `O(G)` 前缀和估算替代反复全量 `protojson.Marshal` |
| 高并发分析 / 恶意高熵输出导致内存暴涨 | 网关 OOM | `MaxClusters=256`、`MaxTasks=5000`、`analysisSem=8` 并发信号量、仅对前 32 条跃迁做行级 Diff |
| 恶意主机输出 `1e999` 或基线为 0 触发 `NaN`/`Inf` | MCP JSON 编码报错致工具不可用 | 提取与输出全链路过滤非有限浮点，`max_delta_pct` 在 base=0 时置 nil |
| 输出注入伪造 `label`/`unit` 或 Prompt Injection | 误导 AI 执行危险操作 | `label`/`unit` 清理控制字符且 ≤ 64 字节，强制 `output_trust: "untrusted"` |
| `[REDACTED:...]` 被归一化拆分破坏 | 脱敏边界退化 | 扫描器优先级 1 原样保留 `[REDACTED:...]` |
| 跨租户调用 `jobs_diff` 探测或读取他人输出 | 权限越界 | 复用 `s.authorize` 对双 job 逐主机核验 `view_jobs` + `view_output`，服务账号限本人 job，双 job 审计 |
| 同名重注册主机被误对齐 | 错误的变更归因 | 按不可变 `host_id` 对齐并标记 `replaced_hosts` |
| 旧版主机端加载目录失败 | 生产批量 `unsupported` | 不修改 `catalog.Action` schema |

## 9. 验证与基准测试矩阵

1. **真实运维命令样本集**（`internal/gateway/cluster` 单元测试）：`df -h`、`free -m`、`uptime`、`docker ps --format '{{json .}}'`（含 4 KiB 截断）、`systemctl status`、`jvm_perfdata` JSON（含 4 KiB 边界）、`log_query` JSON、版本升级（`nginx/1.24.0` → `1.25.3`）与 HTTP/退出码差异（`200` vs `500`、`Exited (0)` vs `Exited (137)`）。
2. **对抗与不变式测试**：非法 UTF-8、NUL、4 KiB 单行无换行、深度 50 嵌套 JSON、`1e999`/`NaN` 有限浮点不变式、`[REDACTED:secrets]` 保护、1000 高熵主机溢出且位置 999 的超时任务仍排第 1、主机守恒等式断言、确定性重复调用一致、Go Fuzz 测试。
3. **规模与性能基准**：120 主机 32 KiB 预算测试；`BenchmarkNormalizePreview`、`BenchmarkCluster1000Hosts`（< 50ms）、`BenchmarkTrimSummary1000Groups`（< 5ms）、`BenchmarkDiff1000Hosts`。
4. **安全与端到端测试**：`DiffJobs` 跨服务账号拒绝、无 `view_output` 拒绝、未完成/已拒绝 job 返回 `FailedPrecondition`、跨 action 返回 `InvalidArgument`、同名换 `host_id` 报 `replaced_hosts`、审计含双 job 标识且不含输出正文；MCP 与 CLI 端到端测试。

## 10. 独立复审意见及处理记录（2026-11-24）

独立复审（Claude Opus 5.5）共提出 2 条 Blocker、5 条 High、8 条 Medium、6 条 Low，全部吸收并修订至本设计文档：

| 编号 | 级别 | 核心问题 | 处理结果 |
|---|---|---|---|
| B1 | Blocker | 无输出哈希终态任务被跳过，`folded_normal_hosts` 无法证明无主机丢失 | 第 4.3、5.2 节：无哈希终态任务按 `(status,exit,reason)` 建 Tier 0 组；新增 `unfinished_hosts_count` 与 `omitted_hosts`，建立严格主机守恒等式 |
| B2 | Blocker | `MaxClusters`/250ms 墙钟预算导致尾段故障任务丢失及游标快照漂移 | 第 4.1、4.3 节：移除墙钟超时改用确定性上限；改为两遍处理，Pass 1 无条件先收录全部 Tier 0 故障，Pass 2 溢出归入显式溢出桶 |
| H1 | High | 32 KiB 预算裁剪循环为 `O(G^2)`（实测 1000 组耗时 10.85s） | 第 5.3 节：改为 `O(G)` 单遍前缀和估算 + 边界组裁剪 + 一次终检，`DiffJobs` 同步采用 |
| H2 | High | 4 KiB 字节截断导致 NDJSON/JSON 同类主机分裂并误报 `minority_cluster` | 第 4.2 节：截断预览丢弃不完整尾行；采用 job 级统一 JSON/文本模式判定 |
| H3 | High | 全量替换 `<NUM>` 抹平版本号与状态码；MAD==0 漏检 0→1 且 med=0 除零 | 第 4.2、4.3 节：词法层保留版本号与语义状态/退出码；安全 `relDiff`；MAD==0 时 `x != p50` 即离群 |
| H4 | High | 主机为软删除 tombstone，fail-closed 假设不成立；按 `hostname` 对齐误合换机节点 | 第 6.1、6.2 节：复用 `s.authorize` 保持与 A21 一致；`ListJobTaskPreviews` 补选 `host_id`，按 `host_id` 对齐并报告 `replaced_hosts` |
| H5 | High | `NaN`/`±Inf` 导致 MCP `encoding/json` 编码失败 | 第 2.3、4.2、6.2 节：全链路过滤非有限浮点；`max_delta_pct` 改为 `optional double`，base=0 时不输出 |
| M1 | Medium | 模板膨胀无上限且 MCP 未缩减模板 | 第 5.3 节：`stdout+stderr+template_*` 共享 `GroupBytes` 并在 MCP 折半循环同步缩减 |
| M2 | Medium | 审计单 `JobID` 无法同时记录双 job | 第 6.1 节：`JobID=target`、`Resource="job:<base>"` 并合并两轮鉴权命中规则 |
| M3 | Medium | `DiffJobs` 后端截断与 MCP `next_cursor` 分页矛盾 | 第 3.3 节：`DiffJobs` 不分页，三端统一为异常优先截断 + 精确计数 |
| M4 | Medium | 未完成或 `DENIED` job 做 diff 行为未定义 | 第 6.1 节：明确返回 `FailedPrecondition` (`DIFF_JOB_NOT_FINISHED` / `DIFF_JOB_DENIED`) |
| M5 | Medium | `MaxSamplesPerSlot=2000 < MaxTasks=5000` 及超 5000 行为未定义 | 第 4.1 节：`MaxSamplesPerSlot=5000`；超 `MaxTasks` 确定性回退 `exact` |
| M6 | Medium | `DiffJobs` 并发内存与 5000 条 LCS 风险 | 第 4.1、6.2 节：并发信号量（8）+ 仅对排名前 32 条跃迁计算行级 Diff |
| M7 | Medium | `jobs_diff` 保留名对存量私有目录的升级影响 | 第 3.3、7.3 节：明确写入 `CHANGELOG.md` 升级说明与文档 |
| M8 | Medium | 派生 `label`/`unit` 无长度字符限制；`MetricVariance` 缺 `p50` | 第 4.2、7.1 节：剥离控制字符并限 64 字节；`MetricVariance` 补齐 `double p50 = 9` |
| L1–L6 | Low | 存在性表述、Tier 0 冲突、exact 状态取最严重、接口列表、`wire.check.ts`/`make generate`、边界语义 | 全部在对应章节统一定义并纳入实施计划 |
