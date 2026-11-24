# 组合动作步骤的受控数据传递与条件分支设计

状态：已通过独立安全复审并修订（Rev 2）
适用范围：`allowops` 目录格式（`schema_version: 1`）、`internal/catalog`、`internal/params`、`internal/redact`、`internal/executor`、`internal/execd`、`internal/agent`、`internal/gateway/job`
底线原则：`No shell. Only actions you defined.`

---

## 1. 背景、痛点与设计边界

### 1.1 现状与痛点

当前 `allowops` 的组合动作（`steps`）仅支持顺序执行一组固定 `exec` 数组（配合 `on_error: continue | stop`），步骤间完全隔离：

1. **无法传递前置探测结果**：Step 1 查出的目标进程 PID、容器 ID 或日志路径无法以受控方式传给 Step 2，AI Agent 必须通过多轮 MCP 往返手动拼接调用。
2. **无法按条件按需深挖**：Step 1 探测服务状态或资源指标后，即使一切正常，Step 2 也会无条件抓取大量日志或快照；或者被迫拆成两次调用，错过瞬态故障现场并消耗上下文预算。

### 1.2 核心目标

在死守零信任与无 Shell 边界的前提下，为 `steps` 引入**声明式、静态可审计、强类型校验**的受控编排能力：

1. **受控输出提取（`steps[].extract`）**：使用静态声明的确定性提取器（Go RE2 单捕获组正则、受限 JSON 字段路径、TSV/空白分隔列提取）从前置步骤**脱敏后的 stdout**（带字节扫描上限与脱敏污染检测）中提取结果，并立即通过复用 `internal/params` 的强类型定义校验。
2. **受控变量引用（`{steps.<step_name>.<var>}`）**：后续步骤的 `exec` 沿用**整元素占位符**与**可选组**规则，仅允许引用更早步骤已声明的提取变量；**仅允许出现在最终命令的普通参数位置**，绝不允许进入 `exec[0]`、任何包装命令选项/操作数、`docker`/`kubectl` 全局选项或 `exec` 目标、以及 `allow_interpreter: true` 动作。
3. **受控条件分支（`steps[].when`）**：使用零第三方依赖的结构化 YAML AST 与 **Kleene 三值逻辑（true / false / unknown）**，基于更早步骤的确定性事实决定是否执行本步骤；不满足时标记 `skipped` 并附带显式原因码 `CONDITION_FALSE`（区别于 `STOPPED`），在结果与 `jobs_get` 中清晰可见。
4. **安全与协议闭环**：完整覆盖 `allowops catalog validate` 静态审计、`allowops-exec` 特权边界、旧版 `allowops-agent`/`allowops-exec` 严格拒收、以及网关 `StepCompleted`/`TaskCompleted` 校验。

### 1.3 明确非目标（拒绝图灵完备）

以下能力被**永久排除**：

- **禁止循环与重试**：无 `for` / `while` / `retry` / 反向跳转；步骤永远严格按声明顺序 `0 .. N-1` 线性前进（天然 DAG）。
- **禁止表达式引擎与动态脚本**：不引入 CEL、JavaScript、expr、Go `text/template` 或字符串内插（`"prefix-{steps.a.x}"` 永远按字面值处理）。
- **禁止自由文本透传**：提取值不可直接作为无约束原始 stdout 注入下游；`string` 类型强制要求 `regex`（强行整串锚定）与 `max_len`，`int` 强制要求 `min`/`max`（用于 `exec` 时 `min >= 0`）。
- **禁止改变主机端构建限制**：保持零新增第三方依赖、`CGO_ENABLED=0` 与 CentOS 7（glibc 2.17）兼容。

---

## 2. 关键范围与兼容性决策

### 2.1 决策 1：保持 `schema_version: 1` + 严格 JSON 拒收 + `features` 能力上报

| 选项 | 方案 | 优缺点评估 |
|---|---|---|
| **方案 A（采用）** | 保持 `schema_version: 1`；在 `Step` 新增 `when`/`extract`（`omitempty`）；新版 agent 在 `AgentHello.Capabilities.Features` 中上报 `step_extract`、`step_when`。 | 与既有 `max_targets` 完全一致（见 [website/publishing.md](../website/publishing.md)）。未使用新字段的旧目录包 `CanonicalJSON` 与摘要逐字节不变；任何包含 `when` 或 `extract` 的目录包会被旧版 agent 的 `strictJSON`（`DisallowUnknownFields`）整包拒绝（`CATALOG_REJECTED`），绝不会静默忽略条件或提取逻辑。 |
| 方案 B（不采用） | 升级 `schema_version: 2`。 | 会迫使未用新特性的所有动作同步切换 schema 版本，与 `allowops` 通过 `strictJSON` + `features` 渐进演进的既有机制（`allow_interpreter`、`exec_fallbacks`、`max_targets`）不一致。 |

**旧版主机与混合版本升级边界**：
1. **旧版 `allowops-agent`**：`Step` 结构不含 `when`/`extract`，`ParsePackage -> strictJSON -> DisallowUnknownFields` 立刻整包拒绝（`CATALOG_REJECTED`）。因为 `{steps.<name>.<var>}` 在新版校验中强制依赖更早步骤上的 `extract`，所以任何含 `{steps.*}` 的合法目录包必含 `extract`，旧版 agent 绝无静默误执行的可能。
2. **混合版本（新 `allowops-agent` + 旧 `allowops-exec`）**：若主机只升级了 `allowops-agent` 而未同步升级 `allowops-exec`，旧版 `allowops-exec` 在 `Prepare -> cache.Load` 阶段同样会因未知字段拒绝加载目录包，导致所有 `run_as` 动作返回 `REQUEST_REJECTED`。因此发布文档明确要求**同步升级同一主机上的 `allowops-agent` 与 `allowops-exec`**（标准 RPM/DEB 发行包已将两者打包同步升级）。

### 2.2 决策 2：第一期 `steps` 保持仅支持 `exec`（不混用 `builtin`）

| 选项 | 方案 | 优缺点评估 |
|---|---|---|
| **方案 A（采用）** | Phase 1 `steps` 保持仅支持固定 `exec` 数组（新增 `when`、`extract`）。 | 1. **特权边界清晰（T6/T7）**：`allowops-exec` 在进程启动后执行一次不可逆的 `dropIdentity(run_as)`。许多内置处理器要求以 `root` 读取 0600 凭据或进入命名空间，而普通 `exec` 步骤可能使用低权限用户；混用会破坏单次降权与单 helper 进程模型。<br>2. **Schema 边界清晰**：内置处理器的 `ParameterDefinitions`、`ValidateActionFields`（如 `jvm_arthas` L2 强制 `risk: write`、`max_targets: 1`、`redact: [secrets, pii]`）均为动作级约束。<br>3. **覆盖核心场景**：Linux/容器/K8s/systemd 排障均通过 `exec` 完成。 |
| 方案 B（后续评估） | 在 `steps[]` 中同时支持 `builtin`、`builtin_config` 与参数映射。 | 需要重新设计步骤级参数绑定、动作级特权提升与 `ValidateActionFields` 组合语义，留待后续独立评审。 |

### 2.3 决策 3：`when` 不是授权或安全边界

`when` 的判断依据来自主机输出，可能被本机低权限进程影响。因此：
- **`when` 仅是排障流程优化（按需采集），绝非授权或安全控制边界**。目录评审时必须确保动作中的**每一个步骤即使在无条件执行时也是安全的**。
- 当非 `read` 风险动作（`risk: write` 或 `dangerous`）使用 `extract` 或 `when` 时，`allowops catalog validate` 与主机加载必须发出显式评审警告（与 `script`、`allow_interpreter` 警告机制一致）。

---

## 3. YAML 与签名 JSON Schema 设计

### 3.1 `Step` 结构扩展

```go
type Step struct {
    Name    string                   `json:"name" yaml:"name"`
    Exec    []any                    `json:"exec" yaml:"exec"`
    When    *StepCondition           `json:"when,omitempty" yaml:"when,omitempty"`
    Extract map[string]StepExtractor `json:"extract,omitempty" yaml:"extract,omitempty"`
}
```

- 当 `When == nil` 且 `len(Extract) == 0` 时，序列化出的 `CanonicalJSON` 与既有格式逐字节一致。
- `When` 与 `Extract` 均计入 `ActionDigest` 并受 Ed25519 DSSE 签名保护。

### 3.2 受控提取器（`extract`）

`extract` 是变量名到 `StepExtractor` 的映射。变量名必须匹配 `^[a-z][a-z0-9_]{0,63}$`，且**禁止使用保留名 `exit_code` 和 `skipped`**。

将**提取规则**与**类型校验闸门（`as`）**显式分离，彻底消除提取正则 `regex` 与字符串类型校验 `as.regex` 的字段冲突：

```yaml
steps:
  - name: find_top_process
    exec: [/usr/bin/ps, -eo, 'pid,comm,rss', --no-headers, --sort=-rss]
    extract:
      pid:
        tsv:
          line: 1
          column: 1
          delimiter: whitespace
        as:
          type: int
          min: 1
          max: 4194304
      comm:
        tsv:
          line: 1
          column: 2
          delimiter: whitespace
        as:
          type: string
          regex: '[A-Za-z0-9_][A-Za-z0-9_.:/@-]{0,63}'
          max_len: 64
      rss_kb:
        tsv:
          line: 1
          column: 3
          delimiter: whitespace
        as:
          type: int
          min: 0
          max: 1073741824
```

Go 类型定义：

```go
type TSVExtractor struct {
    Line      *int   `json:"line,omitempty" yaml:"line,omitempty"`           // 1-based，省略默认 1；显式指定时必须 ∈ [1, 10000]（拒绝 0）
    Column    int    `json:"column" yaml:"column"`                           // 1-based，必填，∈ [1, 64]
    Delimiter string `json:"delimiter,omitempty" yaml:"delimiter,omitempty"` // "tab"（默认）| "whitespace"
}

type ExtractType struct {
    Type         params.Type `json:"type" yaml:"type"`
    Values       []string    `json:"values,omitempty" yaml:"values,omitempty"`
    Min          *int64      `json:"min,omitempty" yaml:"min,omitempty"`
    Max          *int64      `json:"max,omitempty" yaml:"max,omitempty"`
    Regex        string      `json:"regex,omitempty" yaml:"regex,omitempty"`
    MaxLen       int         `json:"max_len,omitempty" yaml:"max_len,omitempty"`
    AllowedRoots []string    `json:"allowed_roots,omitempty" yaml:"allowed_roots,omitempty"`
}

type StepExtractor struct {
    Regex    string        `json:"regex,omitempty" yaml:"regex,omitempty"`
    Match    string        `json:"match,omitempty" yaml:"match,omitempty"`         // 仅 regex 允许："first"（默认）| "exactly_one"
    JSONPath string        `json:"json_path,omitempty" yaml:"json_path,omitempty"`
    TSV      *TSVExtractor `json:"tsv,omitempty" yaml:"tsv,omitempty"`
    MaxBytes Size          `json:"max_bytes,omitempty" yaml:"max_bytes,omitempty"` // 默认 64KB，上限 1MB
    Optional bool          `json:"optional,omitempty" yaml:"optional,omitempty"`
    As       ExtractType   `json:"as" yaml:"as"`
}
```

#### 三种提取器语义与上限

每个 `StepExtractor` **必须且只能**指定 `regex`、`json_path`、`tsv` 之一：

1. **`regex`**（Go RE2 单捕获组正则）：
   - 长度上限：256 字符，禁止 `\x00`、`\r`、`\n`。
   - 必须通过 `regexp.Compile` 且 `re.NumSubexp() == 1`（允许非捕获组 `(?:...)`）。
   - `match`（可选，仅 `regex` 允许）：
     - `"first"`（默认）：逐行流式扫描脱敏 stdout（去除行尾 `\n`，不超过 `max_bytes` 字节），取首个匹配的捕获组 1。
     - `"exactly_one"`：扫描完整 stdout（至多 `max_bytes`）；若匹配行数 `> 1`，或 stdout 超过 `max_bytes`（无法证明后续无第二条匹配），直接判 `EXTRACT_FAILED`。防御攻击者在受控标签/注解中伪造多行记录。
   - **流式执行**：`regex` 在 `Redactor.Stream` 回调中逐行增量匹配，受 `ctx` 取消实时约束，内存复杂度 O(1)。
2. **`json_path`**（确定性字段路径，零第三方依赖）：
   - 语法严格限定为 `$` 开头，后接 1..16 个段（点号键名、下标索引或双引号/单引号键名以支持含 `.`/`/` 的 Kubernetes 标签如 `$.metadata.labels["app.kubernetes.io/name"]`）：
     - 点号键名：`.[A-Za-z0-9_-]{1,64}`
     - 数组下标：`[(?:0|[1-9][0-9]{0,3})]`（0..9999）
     - 引号键名：`["[A-Za-z0-9_./:-]{1,128}"]` 或 `['[A-Za-z0-9_./:-]{1,128}']`
   - **同步骤共享缓冲**：同一步骤的所有 `json_path` 提取器共享**同一个**脱敏 stdout 缓冲区，上限取该步骤各 `json_path` 提取器 `max_bytes` 的最大值（最高 `1MB`，绝不出现 `16 × 1MB`）。
   - **严格单值 JSON 解码**：复用类似 `execd.checkValue` 的校验逻辑对首个 JSON 值执行：最大嵌套深度 ≤ 32、**拒绝重复对象键**、`UseNumber()` 保真（兼容单 JSON 文档如 `docker inspect` 与 NDJSON 首行如 `docker ps --format '{{json .}}'`）。若 stdout 超过该提取器的 `max_bytes` 且首个 JSON 值未能完整解码，直接判 `EXTRACT_FAILED`。
   - **目标值类型**：若路径/下标不存在或目标值为 `null`，视为未命中（`optional: true` 留空，否则 `EXTRACT_FAILED`）；若为 object 或 array，直接判 `EXTRACT_TYPE_INVALID`。
3. **`tsv`**（同记录列位置提取）：
   - `line`：1-based 行号（`*int`），省略默认 `1`，显式提供时必须 ∈ `[1, 10000]`（显式 `line: 0` 被拒绝）。同一步骤内多个 `tsv` 提取器指定相同 `line` 天然保证所有字段来自同一条记录，消除跨行错配。
   - `column`：1-based 列号，必填，∈ `[1, 64]`。
   - `delimiter`：`"tab"`（默认，按 `'\t'` 切分，不折叠连续制表符）或 `"whitespace"`（按 `strings.Fields` 切分）。
   - 逐行流式计数，到达目标行即提取目标列并停止，内存复杂度 O(1)。

#### 扫描与数量上限（防御 T12）

| 限制项 | 值 |
|---|---|
| 单提取器默认 `max_bytes` | `64KB`（65536 字节） |
| 单提取器最大 `max_bytes` | `1MB`（1048576 字节） |
| 单步骤 `json_path` 共享缓冲最大字节 | `1MB`（1048576 字节） |
| 单步骤最多提取变量数 | `16` |
| 单动作最多提取变量总数 | `64` |
| `json_path` 最大 JSON 嵌套深度 | `32`（且拒绝重复键） |
| `string` 类型 `as.max_len` 范围 | `[1, 1024]`（必填） |

#### `ExtractType` 强类型校验规则（复用 `internal/params`）

支持的 `as.type`：`int`、`enum`、`string`、`path`、`bool`（拒绝 `string_array`、`url`、`duration` 及未知类型）。

| `as.type` | 允许的约束字段 | 静态与运行时安全规则 |
|---|---|---|
| `int` | `min`（**必填**）、`max`（**必填**） | 静态校验 `min <= max` 且拒绝 YAML/JSON 浮点截断。**凡在任何步骤 `exec` 中被引用的 `int` 变量，静态强制 `min >= 0`**（彻底杜绝负数 `-1` 进入 `kill`、`head`、`docker logs` 等命令改变语义）。运行时仅接受严格十进制整数（`^-?[0-9]+$` 或无小数 `json.Number`），拒绝浮点/空白/溢出，并检查 `[min, max]`。 |
| `enum` | `values`（必填，非空无重复） | **静态拒绝以 `-` 开头的枚举值**，拒绝 CR/LF/NUL 与非法 UTF-8。运行时必须精确命中 `values`。 |
| `string` | `regex`（**必填**）、`max_len`（**必填**，`1..1024`） | **强制整串锚定匹配**：静态与运行时均按 `^(?:` + `regex` + `)$` 编译匹配，防止作者漏写 `^`/`$` 导致子串匹配放行脏数据。运行时复用 `params` 校验：拒绝以 `-` 开头、拒绝 CR/LF/NUL、校验 rune 长度 `<= max_len`。 |
| `path` | `allowed_roots`（必填，绝对路径列表） | 运行时拒绝以 `-` 开头、拒绝 CR/LF/NUL、调用 `params.ResolvePath`（解析软链接并验证落在 `allowed_roots` 内；失败时**不包装 `*os.PathError`**，绝不回显原始路径）；在引用该变量的步骤真正 `exec` 之前立即调用 `params.CheckPathTrusted(resolved, os.Geteuid())`，防止 TOCTOU。 |
| `bool` | 无 | 运行时仅接受精确 `"true"` / `"false"`（或 JSON `bool`）。 |

**严格标量解码（防 `yaml.v3` 静默截断）**：
`TSVExtractor`（`line`/`column`）、`ExtractType`（`min`/`max`/`max_len`）、`StepCondition`（`gt`/`gte`/`lt`/`lte`）与 `ConditionValue` 均实现自定义 `UnmarshalYAML(*yaml.Node)` 与 `UnmarshalJSON`，检查 YAML tag（仅允许 `!!int` / `!!str` / `!!bool`）与 JSON 精确整数，拒绝 `1.5`、`"2"`、`true`、`null` 静默转换。

**`optional: true` 严守 Fail-Closed**：
- `optional: true` **仅容忍完整输出上的干净未命中**（无正则匹配、JSON 路径不存在或为 `null`、TSV 行/列不存在）。
- 以下情况即使 `optional: true` 也**必须 fail-closed 报错**（`EXTRACT_TYPE_INVALID` / `EXTRACT_FAILED`）：
  1. 提取器命中了候选值，但未通过脱敏污染检查或 `as` 强类型校验；
  2. 步骤输出触发了 `ScanLimitReached`、`exec.ErrWaitDelay` 或超出了 `max_bytes`（无法证明未命中不是由截断导致）。

### 3.3 受控变量引用（`{steps.<step_name>.<var>}`）与安全放置边界

- 占位符正则：
  - 动作参数占位符：`^\{([a-z][a-z0-9_]{0,63})\}$`
  - 步骤变量占位符：`^\{steps\.([a-z][a-z0-9_]{0,63})\.([a-z][a-z0-9_]{0,63})\}$`
- **整元素规则不变**：仅完整等于 `{steps.<step_name>.<var>}` 的 argv 元素会被替换。
- **Phase 1 严禁 `{steps.*}` 出现在以下高危位置**（针对 C1、H1、H3）：
  1. **禁止与 `allow_interpreter: true` 混用**：凡 `allow_interpreter: true` 的动作，静态禁止任何步骤在 `exec` 中引用 `{steps.*}`（避免 `tar`/`perl`/`awk`/`sed`/`sh`/`python` 绕过渲染后 `runsCommands` 检查）。
  2. **禁止进入任何执行环境/包装命令位置**（静态 `checkStepPlaceholders` 检查）：
     - 禁止作为 `exec[0]` 或任何嵌套命令的可执行文件；
     - 禁止作为包装命令（`env`、`timeout`、`nice`、`ionice`、`stdbuf`、`xargs`、`nsenter`、`chroot`）的任何选项、选项值或操作数（例如彻底封堵 `nsenter -t {steps.top.pid} -m ...` 本地提权攻击）；
     - 禁止作为 `docker`、`kubectl` 的全局选项值、子命令、`docker exec` / `kubectl exec` 的选项值或执行目标（容器名/Pod 名/`-n`/`-c`）；同时禁止 `kubectl`/`docker` 子命令后紧跟凭据/端点类全局选项（`--server`/`-s`/`--kubeconfig`/`--token`/`--certificate-authority`/`--context`/`--cluster`/`--user`/`--host`/`-H`/`--config`）的值为 `{steps.*}`；
     - `{steps.*}` **仅允许出现在最终命令（经包装命令解包后）的普通参数位置**（如 `/usr/bin/ps -p {steps.a.pid}`、`/usr/bin/docker inspect {steps.a.container_id}`、`/usr/bin/docker logs --tail 100 {steps.a.container_id}`）。
  3. **运行时统一拒绝前导 `-`**：渲染后的任意 `{steps.*}` 替换结果若以 `-` 开头，一律在启动进程前拒绝（`EXTRACT_TYPE_INVALID`），不区分是否为解释器。
  4. **可选组（`["--flag", "{steps.j.v}"]`）的严格省略条件**（针对 H2）：
     - **仅当**产生步 `j` 正常成功执行（`err == nil && exit_code == 0` 且无输出不完整）、且 `a.Steps[j].Extract[v].Optional == true` 干净未命中时，才省略整个可选组。
     - 若产生步 `j` 执行失败、被跳过或该变量非 `optional`，引用 `{steps.j.v}`（无论是否在可选组内）一律使当前步骤以 `EXTRACT_MISSING` 失败，绝不静默丢掉过滤器参数（如丢掉 `journalctl -u` 导致拉取全部服务日志）。

### 3.4 受控条件分支（`when`）与 Kleene 三值逻辑

`when` 是一个有界、强类型的声明式 YAML AST，无任何表达式求值器。

#### 节点结构

每个 `StepCondition` 节点必须且只能属于以下两种形态之一：

1. **布尔组合节点**（三选一，不可与叶子字段混用）：
   - `all: [StepCondition, ...]`（1..16 个子条件）
   - `any: [StepCondition, ...]`（1..16 个子条件）
   - `not: StepCondition`
2. **叶子谓词节点**（必须包含 `ref` + **恰好一个**运算符）：
   - `ref` 允许的精确格式：
     - `prev.exit_code`（紧邻前一步退出码，类型 `int`）
     - `prev.skipped`（紧邻前一步是否跳过，类型 `bool`）
     - `steps.<step_name>.exit_code`（更早步骤 `<step_name>` 退出码，类型 `int`）
     - `steps.<step_name>.skipped`（更早步骤 `<step_name>` 是否跳过，类型 `bool`）
     - `steps.<step_name>.<var_name>`（更早步骤 `<step_name>` 的提取变量，类型为 `as.type`）
   - 运算符与类型矩阵：

| `ref` 静态类型 | `exists` | `eq` / `ne` | `gt` / `gte` / `lt` / `lte` | `in`（1..32 项） |
|---|---|---|---|---|
| `int`（含 `*.exit_code`） | `bool` | 精确 `int64` | 精确 `int64` | `[]int64` |
| `string` | `bool` | `string`（允许 `""`，即 `ne: ""` 表示存在且非空） | 禁止 | `[]string` |
| `enum` | `bool` | `string`（静态检查必须在 `as.values` 中） | 禁止 | `[]string`（每项必须在 `as.values` 中） |
| `path` | `bool` | **禁止**（软链接解析会使字面路径比较产生误判） | 禁止 | **禁止** |
| `bool`（含 `*.skipped`） | `bool` | `bool` | 禁止 | 禁止 |

#### AST 上限与序列化安全

- **Step 0 禁止声明 `when`**：Step 0 没有前置步骤，因此正常流程下总先执行 Step 0 并产生 `TaskStarted`。（注：若 Step 0 自身在进程启动前失败且 `on_error: continue`，沿用既有组合步骤行为，不在本特性中改变启动回调语义。）
- **最大嵌套深度**：`4`（根节点深度 1）；**单步骤最大条件节点数**：`32`。
- **`omitempty` 零值安全**：`Eq`/`Ne` 使用指针 `*ConditionValue`，`Exists` 使用 `*bool`，`Gt`/`Gte`/`Lt`/`Lte` 使用 `*int64`，`In` 使用 `[]ConditionValue`，确保 `0`、`false`、`""` 永不被 Go `encoding/json` 的 `omitempty` 丢弃。

#### 运行时求值语义：Kleene 强三值逻辑（真正 Fail-Closed）

求值结果属于三值域 `{triFalse, triTrue, triUnknown}`，**仅当根节点求值结果为 `triTrue` 时才执行该步骤**（`triFalse` 与 `triUnknown` 均导致步骤以 `CONDITION_FALSE` 跳过）：

- **存在性判断（永不返回 `triUnknown`）**：
  - `exists: true` → 存在返回 `triTrue`，缺失返回 `triFalse`。
  - `exists: false` → 缺失返回 `triTrue`，存在返回 `triFalse`。
- **值比较（`eq`/`ne`/`gt`/`gte`/`lt`/`lte`/`in`）**：
  - 当 `ref` 缺失（如前序步骤跳过、失败或 `optional` 未命中）→ 返回 **`triUnknown`**。
  - 当 `ref` 存在 → 按比较结果返回 `triTrue` 或 `triFalse`。
- **布尔组合真值表**：
  - `not(triTrue) = triFalse`，`not(triFalse) = triTrue`，**`not(triUnknown) = triUnknown`**（彻底修复 `not: {ref: ..., eq: active}` 在提取缺失时 fail-open 的问题）。
  - `all(xs)`：任一为 `triFalse` → `triFalse`；否则任一为 `triUnknown` → `triUnknown`；全为 `triTrue` → `triTrue`。
  - `any(xs)`：任一为 `triTrue` → `triTrue`；否则任一为 `triUnknown` → `triUnknown`；全为 `triFalse` → `triFalse`。
- `*.skipped` 永远存在（`true` 或 `false`）；`*.exit_code` 在步骤正常退出时存在，跳过或无退出码（`ExitCode == nil`）时缺失；`steps.<name>.<var>` 仅在产生步成功退出且提取成功时存在。

---

## 4. 脱敏与提取的执行先后顺序论证（核心安全设计）

### 4.1 结论

**提取必须发生在脱敏（`Redactor.Stream`）之后，用户输出过滤（`filterWriter`）与共享预算截断（`limitedOutput`）之前，并携带“行级脱敏污染标记”与“JSON 解码后二次脱敏复检”。**

完整单步 stdout 数据流管道如下：

```text
child stdout
  │
  ▼
scanReader (max_scan, 默认 256MB，统计原始字节)
  │
  ▼
Redactor.StreamTracked (逐行脱敏 secrets/pii/custom，单行超 1MiB fail-closed)
  │  输出：(redactedLine string, modified bool) — 原始未脱敏行绝不下传
  ├─────────────────────────────────────────┐
  ▼                                         ▼
extractSink (仅当步骤声明 extract)             filterWriter (调用方 match/exclude/head/tail/count)
  • 仅见脱敏后文本 + modified 污染标记          │
  • regex/tsv 逐行流式匹配 (O(1) 内存)         ▼
  • json_path 共享单缓冲 (≤ 1MB)             limitedOutput (共享 max_output 预算)
  • 拒绝被脱敏修改过的来源行/JSON 文档
  • JSON 解码后对值及 key=value 再过一次 Redactor.Line
  • 拒绝含 "[REDACTED:" 的提取值
  • 过 params 强类型校验（string 整串锚定）
  • 绝不持久化、不进事件流/错误文本
```

### 4.2 为什么绝不能在脱敏之前提取？

1. **防止凭据进入下游命令行（`/proc/<pid>/cmdline`、auditd execve）与二次输出**：原始 stdout 中的凭据一旦被捕获并传入 Step 2 argv，会直接暴露给同主机低权限用户（未挂载 `hidepid=2` 时）及审计日志，且可能以无键名格式出现在 Step 2 输出中绕过脱敏。
2. **杜绝脱敏侧信道预言机（Redaction Oracle）**：遵循 D1 与 `TestExampleRemovedConfigGrepActions`，脱敏必须在任何匹配/分支判定之前，防止攻击者通过 Step 2 是否执行来探测被脱敏的原始敏感值。

### 4.3 为什么必须在用户过滤（`filters`）与共享截断（`max_output`）之前提取？

1. **防止调用方操纵内部数据流**：`match`/`exclude`/`head`/`tail`/`count` 由调用方（AI Agent）在运行时指定；提取在其之前分流，调用方传 `count: true` 不会破坏提取，也无法通过 `exclude` 过滤掉首行以操控提取目标。
2. **独立内存边界**：共享 `max_output` 预算可能截断返回给调用方的文本，但 `extractSink` 使用独立的 `max_bytes`（默认 64KB，最大 1MB），既不受返回预算干扰，又严格防 OOM（T12）。

### 4.4 防御部分脱敏篡改与 JSON 转义绕过（M2 防护）

仅“先脱敏再提取 + 检查 `[REDACTED:`”不足以防御两类高级绕过：
1. **部分脱敏导致合法错位值**：若脱敏规则将 `app-secret-abc1` 改写为 `app-[REDACTED:x]`，正则 `^([a-z-]+)` 会匹配出不含 `[REDACTED:` 的合法前缀 `app-`，从而把 Step 2 指向错误对象。
   - **防护**：`Redactor.StreamTracked` 在不暴露原文的前提下，对每一行报告 `modified bool`（含 PEM 私钥块吞行期间的所有行均标 `modified = true`）。
     - 对 `regex` / `tsv`：若命中的行（或目标 `line`）满足 `modified == true`，立即判 `EXTRACT_FAILED`。
     - 对 `json_path`：若缓冲的 JSON 文档中任意行 `modified == true`，立即判 `EXTRACT_FAILED`。
2. **JSON Unicode 转义绕过**：原始文本 `{"\u0070assword": "hunter2"}` 在行级脱敏时不命中 `password` 规则，但 `json.Decoder` 解码后键名还原为 `password`、值为 `hunter2`。
   - **防护**：`json_path` 解码得到目标标量后，对 `valueStr` 以及 `lastKey + "=" + valueStr` 再执行一次 `Redactor.LineTracked`；任一结果被修改即判 `EXTRACT_FAILED`。

### 4.5 值隔离（Value-Free Diagnostics）与残余风险

- 提取变量**仅存在于单次 `runSteps` 内存中**，从不写入 `StepResult`、事件流、对象存储或审计日志。
- 协议 `reason` 仅传固定大写码：`EXTRACT_FAILED`、`EXTRACT_TYPE_INVALID`、`EXTRACT_MISSING`、`PATH_NOT_TRUSTED`；本地错误仅含步骤名、变量名和类别（例如不透传 `ResolvePath` 中的 `*os.PathError` 路径文本）。
- **残余风险（记入 `SECURITY.md`）**：不命中任何脱敏规则的裸凭据若被提取器匹配并满足 `as` 类型，仍会进入 Step 2 的 argv 并出现在 `/proc/<pid>/cmdline` 与 auditd execve 日志中。目录作者只能提取窄范围运维标识符（PID、容器 ID、挂载点、状态枚举、数值指标），绝不可针对凭据字段定义提取器。

---

## 5. 安全校验、特权边界与组件契约

### 5.1 静态安全校验（`internal/params` & `internal/catalog`）

1. **`params.Placeholder(s)` 与 `params.StepPlaceholder(s)`**：
   - `Placeholder(s)` 统一识别 `{param}` 与 `{steps.<step>.<var>}`，自动接入 `CheckCommand`、`containerCommand`、`xargsReplacement`、`checkProgramText` 与 `host.go`。
2. **`checkStepPlaceholders(argv)`（C1 核心防护）**：
   - 遍历 `commandVariants(step.Exec)` 的每个展开变体：
     - 拒绝 `argv[0]` 为 `{steps.*}`。
     - 对包装命令（`env`/`timeout`/`nice`/`ionice`/`stdbuf`/`xargs`/`nsenter`/`chroot`）：解包得到 `nested`，检查 `argv[:len(argv)-len(nested)]` 中绝不含 `{steps.*}`，再递归检查 `nested`。
     - 对 `docker` / `kubectl`：检查全局选项与子命令绝不含 `{steps.*}`；若子命令为 `exec`，检查直到内层命令（不含内层命令的参数）为止的全部元素（含容器/Pod 目标、`-n`、`-c` 等）绝不含 `{steps.*}`，再递归检查内层命令；对非 `exec` 子命令（如 `docker inspect`/`logs`、`kubectl logs`/`describe`），额外拒绝子命令之后紧跟凭据/端点选项（`--server`/`-s`/`--kubeconfig`/`--token`/`--certificate-authority`/`--context`/`--cluster`/`--user`/`--host`/`-H`/`--config`）的值为 `{steps.*}`。
3. **软链接解析后的真实定义复核**：
   - `ResolveExecutable` 内部通过 `resolveExecutableWithDefs(template, fallbacks, allow, defs)` 传入真实参数与提取类型定义。
4. **`validateSteps` 静态检查**：
   - 步骤名唯一合法；Step 0 禁止 `when`；`allow_interpreter: true` 禁止在 `exec` 中引用 `{steps.*}`；
   - 有序遍历步骤，构建 `priorSteps` 与 `stepDefs`（天然阻断前向引用与自引用）；
   - 校验 `when` AST（深度 ≤ 4、节点 ≤ 32、无混用、引用存在、类型与运算符匹配、`enum` 字面量合法、`path` 禁止值比较）；
   - 校验 `exec`（`validateExec` + `checkStepPlaceholders` + 检查被引用的 `int` 提取变量满足 `min >= 0`）；
   - 校验 `extract`（变量名合法且非 `exit_code`/`skipped`、单步 ≤ 16、全局 ≤ 64、三选一、`regex` 单捕获组 + `match` ∈ `{first, exactly_one}`、`json_path` 语法、`tsv` 范围、`max_bytes ≤ 1MB`、`as` 强类型规则）；
   - 非 `read` 动作使用 `extract`/`when` 时产出评审警告。

### 5.2 运行时执行语义（`internal/executor`）

1. **`StepResult` 扩展**：新增 `SkipReason string`（`json:"skip_reason,omitempty"`），取值为 `""`、`"CONDITION_FALSE"` 或 `"STOPPED"`。
2. **步骤主循环**：
   - `stopped == true` → 记录 `StepResult{Skipped: true, SkipReason: "STOPPED"}`，不求值 `when`。
   - `step.When != nil` 且 `evalCondition(step.When) != triTrue` → 记录 `StepResult{Skipped: true, SkipReason: "CONDITION_FALSE"}`，`stopped` 保持 `false`。
   - 检查本步 `exec` 中的 `{steps.j.v}`：
     - 任一非可选引用缺失 → `ErrExtractMissing`（`ExitCode = -1`）。
     - 任一可选组引用缺失，但产生步 `j` 非干净成功或该提取器 `optional == false` → `ErrExtractMissing`（`ExitCode = -1`）。
     - 任一待渲染步骤变量值以 `-` 开头 → `ErrExtractTypeInvalid`（`ExitCode = -1`）。
   - 渲染 `argv` 并执行 `catalog.CheckCommand(argv, a.AllowInterpreter)`；检查动作级 `plan.trustPaths()` 与本步引用的所有已提取 `path` 变量的 `params.CheckPathTrusted(path, os.Geteuid())`。
   - 执行命令（挂接 `extractSink`）：
     - 若 `err == nil && r.ExitCode == 0` 且 `len(step.Extract) > 0`：
       - 若输出不完整（`r.ScanLimitReached` 或 `ErrWaitDelay`）→ `ErrExtractFailed`（`r.ExitCode = -1`）。
       - 否则执行 `extractSink.Finalize(...)` 完成校验并写入本步提取值表；失败则置 `r.ExitCode = -1` 并返回 `EXTRACT_FAILED` / `EXTRACT_TYPE_INVALID`。
     - 若 `err != nil || r.ExitCode != 0`：不执行提取，保留原始退出码与错误。
   - 更新 `stopped = ctx.Err() != nil || (a.OnError == "stop" && (err != nil || r.ExitCode != 0))`。

### 5.3 `allowops-exec`、`allowops-agent` 与 `gateway/job` 契约

- **`internal/execd`**：
  - `wireStep` 增加 `SkipReason string`（`json:"skip_reason,omitempty"`）。
  - `ExecutionReason` 增加 `executor.ReasonOf(err)`，转发 `EXTRACT_FAILED`、`EXTRACT_TYPE_INVALID`、`EXTRACT_MISSING`。
  - 带 `run_as` 的组合动作全程在 `allowops-exec` 降权后单进程内执行，中间变量不回传 `allowops-agent`（守住 T6/T7）。
- **`internal/agent`**：
  - `AgentHello.Capabilities.Features` 增加 `"step_extract"`、`"step_when"`。
  - `task.go`：跳过步骤将 `step.SkipReason` 写入 `stepResult.Reason`；`taskStatus` 与 `helperReason` 透传 `EXTRACT_FAILED`、`EXTRACT_TYPE_INVALID`、`EXTRACT_MISSING`、`PATH_NOT_TRUSTED`。
- **`internal/gateway/job/events.go`**：
  - `validateStepCompleted`：
    - `Reason == "CONDITION_FALSE"` 仅允许在 `a.Steps[step.StepIndex].When != nil` 时出现；
    - `Reason == "STOPPED"` 或 `""`（兼容旧版 agent）仅允许在先前存在非 `SUCCEEDED` 且非 `SKIPPED` 的失败（在 `a.OnError != "continue"` 时）或存在 `CANCELLED`/`TIMEOUT` 时出现；
    - 其余 reason 一律返回 `INVALID_SKIPPED_STEP`。
  - `validateStepsAggregate`：
    - 当全部步骤状态均属于 `{TASK_STATUS_SUCCEEDED, TASK_STATUS_SKIPPED}` 时，聚合状态为 `TASK_STATUS_SUCCEEDED`、聚合退出码为 `0`。

---

## 6. 安全复审问题闭环追踪

独立安全复审（Rev 1 → Rev 2）共识别 1 Critical / 3 High / 7 Medium / 8 Low + 4 处示例缺陷，全部闭环处理：

| 编号 | 问题摘要 | 本版设计闭环措施 |
|---|---|---|
| C1 | `{steps.*}` 进入 `nsenter -t` / 包装命令 / `docker`/`kubectl` 端点与 `exec` 目标导致本地提权 | 第 3.3、5.1 节：`checkStepPlaceholders` 静态禁止 `{steps.*}` 出现在所有包装命令、`docker`/`kubectl` 全局与 `exec` 目标位置，仅允许最终命令普通参数 |
| H1 | 提取 `int` 无下界，负数 `-1` 进入非解释器命令 | 第 3.2、3.3 节：`as.type: int` 强制 `min`/`max`，用于 `exec` 时强制 `min >= 0`；运行时统一拒绝 `-` 开头替换值 |
| H2 | `not` 遇缺失值 fail-open；失败步骤导致可选组静默省略 | 第 3.3、3.4 节：`when` 采用 Kleene 三值逻辑（`not unknown = unknown`）；可选组仅在产生步成功且 `optional: true` 干净未命中时省略 |
| H3 | `allow_interpreter: true` 下渲染后复检不检查 `runsCommands` | 第 3.3、5.1 节：Phase 1 静态禁止 `allow_interpreter: true` 动作在 `exec` 中使用 `{steps.*}` |
| M1 | 多提取器跨行错配与伪造行抢占首匹配 | 第 3.2 节：同表多字段使用同 `line` 的 `tsv` 或同对象 `json_path`；`regex` 新增 `match: exactly_one` |
| M2 | 部分脱敏产生错位合法值；JSON `\u0070assword` 绕过行级脱敏 | 第 4.4 节：`Redactor.StreamTracked` 传递行级脱敏污染标记（被改行/文档直接拒提）；JSON 解码后对值及 `key=value` 二次 `Redactor.LineTracked` |
| M3 | `as.regex` 未锚定导致子串匹配放行 | 第 3.2 节：提取 `string` 的 `as.regex` 强制按 `^(?:...)$` 整串编译匹配 |
| M4 | `max_scan`/`ErrWaitDelay` 截断后退出码为 0 仍在部分输出上提取 | 第 3.2、5.2 节：`ScanLimitReached`/`ErrWaitDelay`/`max_bytes` 溢出时拒绝提取（含 `optional: true`） |
| M5 | 跳过原因不可区分、网关放宽可能被滥用 | 第 5.2、5.3 节：引入 `SkipReason`（`CONDITION_FALSE` / `STOPPED`），网关按 reason 分别严格校验 |
| M6 | `when` 非授权边界，易被低权限进程诱导触发写操作 | 第 2.3、5.1 节：文档明确非授权边界，非 `read` 动作使用 `extract`/`when` 时 `catalog validate` 发出评审警告 |
| M7 | Step 0 启动前失败时 `TaskStarted` 边界 | 第 3.4 节：如实注明为既有行为，不虚称覆盖启动前失败 |
| L1–L8 | 路径错误泄露、JSONPath 正则笔误与点/斜杠键名、嵌套严格整数、JSON 重复键与共享缓冲流式化、`path` 比较、混合升级、`/proc/cmdline` 残余风险 | 分别在第 2.1、3.2、3.4、4.4、4.5 节全部落实 |

---

## 7. 对抗测试矩阵（`test/attack/step_dataflow_test.go`）

1. **C1 执行环境/包装命令注入**：`nsenter -t {steps.a.pid} -m ...`、`docker -H {steps.a.h}`、`kubectl --server {steps.a.s}`、`kubectl logs pod --kubeconfig {steps.a.k}`、`docker exec {steps.a.c} ps`、`kubectl exec {steps.a.p} -- ps`、`env {steps.a.v} /usr/bin/id`、`timeout {steps.a.t} /usr/bin/id`、`xargs -I {steps.a.r}` — 静态校验与运行全部拒绝。
2. **H1 负数与前导 `-` 注入**：`int` 缺 `min`/`max` 或 `min < 0` 用于 `exec` 被拒；Step 1 输出 `--output=/etc/passwd` / `-rf` / `-1` 触发 `EXTRACT_TYPE_INVALID` 且 Step 2 绝不执行。
3. **H2 Kleene 3VL 与失败步可选组**：Step 1 输出含 `-----BEGIN PRIVATE KEY-----` 吞掉后续行 → `not: {ref: ..., eq: active}` 求值为 `unknown` 不执行 Step 2；Step 1 失败时下游可选组 `[-u, "{steps.s1.unit}"]` 不省略，报 `EXTRACT_MISSING`。
4. **H3 `allow_interpreter` 组合**：`allow_interpreter: true` 动作含 `{steps.*}` 被静态拒绝；`allow_interpreter: false` 下 `tar {steps.a.mode}` 输出 `xIf`、`ip {steps.a.sub}` 输出 `exec` 在渲染后 `CheckCommand` 阶段被拦截。
5. **M1 `match: exactly_one`**：Step 1 输出 2 行匹配记录（模拟注入伪造行）触发 `EXTRACT_FAILED`。
6. **M2 部分脱敏污染与 JSON Unicode 转义**：Step 1 输出 `app-password=secret`（行被脱敏改写）→ 正则匹配前缀 `app-` 仍被行污染标记拦截 `EXTRACT_FAILED`；Step 1 输出 `{"\u0070assword":"hunter2"}` → `json_path: $.password` 被解码后二次脱敏拦截 `EXTRACT_FAILED`。
7. **M3 未锚定正则**：`as.regex: '[a-z0-9]+'` 遇到 `ok;rm -rf /` 因强制整串锚定 `^(?:...)$` 被拒绝。
8. **M4 截断输出不提取**：`max_scan` 触发后 Step 1 虽退出码 0，但提取失败报 `EXTRACT_FAILED`（含 `optional: true`）。
9. **T10 路径逃逸与 TOCTOU**：Step 1 输出 `../../etc/shadow`、软链接逃逸路径、组可写目录路径 → 分别被 `EXTRACT_TYPE_INVALID`（错误不含路径）和 `PATH_NOT_TRUSTED`（错误不含路径）拦截。
10. **T10 调用方过滤器隔离**：带 `count=true` 或 `exclude` 调用时提取仍基于过滤前的脱敏流准确完成。
11. **T12 洪水与深层 JSON / 重复键**：10MB stdout、100 层嵌套 JSON、重复键 JSON `{"k":"a","k":"b"}` 均有界失败 `EXTRACT_FAILED` 且无 OOM。
12. **旧版 agent 严格拒收**：将含 `extract`/`when` 的签名目录 JSON 用不含该字段的旧版 `Step` 结构严格反序列化，验证必定报错（`CATALOG_REJECTED`）。

---

## 8. 示例组合动作设计（覆盖全部 3 种提取器）

在 `examples/catalog/actions/` 新增 3 个真实高价值只读组合动作（全部通过 `allowops catalog validate` 与 `make examples-check`）：

1. **`disk_pressure_diagnose.yaml`**（`regex` + `match: exactly_one` + `int` + `when gte`）：
   - `params`: `mount_path`（`path`, `allowed_roots: [/, /var, /data]`? 注意：为兼容测试与安全，用 `enum` 或 `path`；在只读诊断中 `path` 配合 `allowed_roots: [/var/log, /data, /tmp]` 或根目录 `/` 需注意 `PATH_NOT_TRUSTED`，根目录 `/` 属主 root 且 0755 是可信的！`allowed_roots: [/, /var, /data]` 对 `/var`、`/data` 均要求 root 属主且无组/其他写权限，最安全且可在 `check_examples.py` 用 `/` 或临时目录实测！）。
   - Step 1 (`check_usage`): `[/usr/bin/df, -P, "{mount_path}"]`，用 `regex: '^\S+\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+([0-9]{1,3})%\s+'`、`match: exactly_one` 提取 `use_pct`（`int`, `min: 0`, `max: 100`）。
   - Step 2 (`top_dirs`): `when: { ref: steps.check_usage.use_pct, gte: 80 }` → `[/usr/bin/du, -x, -h, --max-depth=1, --, "{mount_path}"]`。
2. **`top_process_diagnose.yaml`**（同 `line: 1` 多列 `tsv` + `{steps.*}` 数据传递 + `when gte`）：
   - Step 1 (`find_top_process`): `[/usr/bin/ps, -eo, 'pid,comm,rss', --no-headers, --sort=-rss]`，提取 `pid`（`tsv line:1 col:1`, `int 1..4194304`）、`comm`（`tsv line:1 col:2`, `string`）、`rss_kb`（`tsv line:1 col:3`, `int 0..1073741824`）。
   - Step 2 (`process_detail`): `when: { ref: steps.find_top_process.rss_kb, gte: 524288 }` → `[/usr/bin/ps, -ww, -o, 'pid,ppid,user,stat,rss,vsz,etime,comm', -p, "{steps.find_top_process.pid}"]`。
   - Step 3 (`process_threads`): 同条件 → `[/usr/bin/ps, -L, -o, 'pid,tid,pcpu,stat,comm', -p, "{steps.find_top_process.pid}"]`。
3. **`docker_container_diagnose.yaml`**（`json_path` 多字段同对象提取 + `when any` + `{steps.*}` 数据传递）：
   - `run_as: root`，`redact: { builtin: [secrets, pii] }`（因为采集容器日志）。
   - `params`: `container`（`string`, `regex: '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$'`, `max_len: 64`）。
   - Step 1 (`inspect`): `[/usr/bin/docker, inspect, --type, container, "{container}"]`，用 `json_path` 提取 `status`（`$[0].State.Status`, `enum: [created, running, paused, restarting, removing, exited, dead]`）、`oom_killed`（`$[0].State.OOMKilled`, `bool`）、`restart_count`（`$[0].RestartCount`, `int 0..1000000`）、`container_id`（`$[0].Id`, `string`, `regex: '[0-9a-f]{12,64}'`, `max_len: 64`）。
   - Step 2 (`recent_logs`): `when: { any: [{ref: steps.inspect.status, ne: running}, {ref: steps.inspect.oom_killed, eq: true}, {ref: steps.inspect.restart_count, gt: 0}] }` → `[/usr/bin/docker, logs, --tail, '100', --timestamps, "{steps.inspect.container_id}"]`。
