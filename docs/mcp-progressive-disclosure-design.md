# MCP 工具分层与按需发现（Progressive Disclosure）设计文档

状态：评审通过并定稿（2026-11-24，已消化独立架构与安全复审全部 Blocking/Major/Minor 意见）  
基线：`feat/mcp-progressive-disclosure`（commit `9640cd8`）

## 1. 背景与实测基线

当前 `allowops-gateway` 的 MCP 服务（[internal/gateway/mcp/](../internal/gateway/mcp/)）采用官方 `github.com/modelcontextprotocol/go-sdk` 的 **Stateless Streamable HTTP** 模式，在 `tools/list` 中将当前身份经策略预检可见的**每一个**签名 action 平铺注册为一个独立 MCP 工具。

基于仓库公开示例目录 [examples/catalog/actions/](../examples/catalog/actions/)（**133 个 action**）的实际测量结果：

| 指标 | 实测值（紧凑 JSON） | 说明 |
|---|---|---|
| 当前平铺模式（4 个固定工具 + 133 个 action） | **137 个工具 / 484,542 字节（~473 KiB）** | 仅 `tools/list` 工具定义就消耗约 10 万+ tokens |
| 仅 4 个固定工具 | **4 个工具 / 5,637 字节（~5.5 KiB）** | `hosts_search`、`jobs_get`、`jobs_list`、`jobs_cancel` |
| 按需发现模式（固定工具 + 元工具） | **5~9 个工具 / ~12~16 KiB** | 工具列表体积减少约 **97%** |

由此暴露出三个生产痛点：
1. **Context Window 极度膨胀**：133 个 action 仅工具定义就占用 473 KiB，生产环境 200~300+ action 甚至接近或超过部分模型的上下文预算。
2. **工具选择准确率下降**：模型面对上百个命名相近、参数各异的平铺工具（17 个 `jvm_arthas_*`、19 个 `k8s_*`、14 个 `docker_*`、13 个 `log_*`/`journal_*`）容易误选工具或填错参数。
3. **实体与动作之间缺少桥接**：阶段 1 已落地 `entities_search`（[internal/gateway/mcp/inventory.go](../internal/gateway/mcp/inventory.go)），Agent 查到实体（如 `kind: "database"`、`kind: "cache"`、`kind: "service"`）后无法直接获知针对该类实体且当前身份有权限执行的推荐动作。

## 2. 设计目标与红线

### 2.1 目标

1. **目录分类元数据**：为签名目录 action 增加可选的 `toolset`、`tags`、`entity_kinds` 字段，纳入签名保护，完全向后兼容未填写这些字段的旧目录。
2. **MCP 分层按需发现（Progressive Disclosure）**：支持网关级 `mcp.mode`（`flat` / `progressive` / `auto`）与客户端请求头 `X-Allowops-Toolsets` / `X-Allowops-MCP-Mode` 作用域裁剪；在 `progressive` 模式下，以 **`actions_search`** + **按风险分层的调用元工具**（`actions_invoke_read`、`actions_invoke_write`、`actions_invoke_dangerous`）替代全量平铺，既节省 ~97% token，又完整保留客户端按风险等级的人工审批边界。
3. **实体 → 关联动作推荐**：`entities_search` 返回按 `kind` 去重、经策略预检过滤的 `recommended_actions`（独立截断标记 `recommended_actions_truncated`），与 `actions_search(entity_kind=...)` 协同。
4. **示例目录、控制台与文档同步**：补齐 `examples/catalog/actions/` 全量 133 个 action 的元数据标注与校验脚本，控制台 Catalog 详情侧栏展示元数据，同步更新中英文文档、架构决策与升级说明。

### 2.2 不可突破的安全与工程红线

- **No shell & 零信任边界**：任何发现或调用元工具绝不绕过签名目录验签、参数强类型校验、`expected_count`、`max_targets`、OPA ABAC 逐主机判定、主机端二次验签与脱敏、以及结果审计。
- **按风险隔离客户端审批面（防 T1 审批合并与注解过期）**：调用元工具严格按风险等级拆分（`actions_invoke_read` / `actions_invoke_write` / `actions_invoke_dangerous`），服务端每次调用经 `currentAction` 验签后强制核对 `action.Risk` 与工具等级一致，绝不出现“放行只读工具同时放行危险操作”或“目录升风险后沿用旧只读注解”的漏洞。
- **不越权、不枚举泄漏**：`actions_search` 与 `entities_search` 推荐仅基于当前身份可见动作与主机；对不可见或不存在的动作、主机、toolset 返回完全不可区分的响应，无缓存时序侧信道。
- **32 KiB 预算与不可信数据标记**：所有新增工具与增强响应严格遵守 `resultByteLimit = 32 KiB`（含 `structuredContent`、文本副本与 SDK `_meta`）以及 `"output_trust": "untrusted"`。
- **严格解码**：YAML/JSON 配置与工具输入坚持 `KnownFields(true)` / `DisallowUnknownFields()` / `additionalProperties: false`，拒绝未知字段、重复 JSON 键与类型隐式转换。
- **无状态与防 DoS**：保持 `StreamableHTTPOptions.Stateless = true`；客户端过滤后的 `*sdk.Server` 不进入 LRU 缓存，消除组合键缓存抖动 DoS 与全局锁串行阻塞。
- **主机兼容与平滑升级**：保持 `CGO_ENABLED=0` 与 CentOS 7（glibc 2.17）兼容；新保留名仅在编写与发布路径拦截，绝不破坏历史已发布目录的读取。

### 2.3 本期非目标（Non-Goals）

- **不修改 OPA ABAC 策略结构**：`authz.Action` 保持 `{Name, Risk}`，现有策略与 `make opa-test` 零变更；客户端 `X-Allowops-Toolsets` 仅为上下文裁剪提示，不是授权边界（授权仍完全由 OPA 策略决定）。
- **不引入有状态 MCP 会话或 `tools/list_changed`**：见第 4 节。
- **不修改 PostgreSQL schema，不做 protobuf 破坏性变更**。

---

## 3. 目录元数据扩展

### 3.1 字段定义与校验规则

在 `catalog.Action`（[internal/catalog/catalog.go](../internal/catalog/catalog.go)）中新增三个**可选**字段：

```go
type Action struct {
    // ... existing fields ...
    Toolset     string   `json:"toolset,omitempty" yaml:"toolset,omitempty"`
    Tags        []string `json:"tags,omitempty" yaml:"tags,omitempty"`
    EntityKinds []string `json:"entity_kinds,omitempty" yaml:"entity_kinds,omitempty"`
}
```

YAML 示例：

```yaml
name: jvm_perfdata
description: Read JVM heap, GC, class and thread counters from hsperfdata without attaching.
risk: read
toolset: jvm
tags: [gc, heap, threads]
entity_kinds: [jvm]
```

**编写路径校验规则**（`ParseAction`、`Load`、`Build`、`ValidateAction`、`allowops catalog validate` 严格执行）：

| 字段 | 类型 | 编写路径约束 | 省略语义 |
|---|---|---|---|
| `toolset` | `string` | YAML 节点须为 `ScalarNode` 且 `Tag == "!!str"` 且非空；匹配 `^[a-z][a-z0-9_]{0,31}$`（与 `pluginhost.kindPattern` 一致） | 未归类；不匹配 `X-Allowops-Toolsets` 过滤条件，未过滤时在 `actions_search` 中正常返回（`toolset` 省略） |
| `tags` | `[]string` | YAML 节点须为非空 `SequenceNode`，**每一项**须为 `ScalarNode` 且 `Tag == "!!str"`（防止 `yaml.v3` 把 `true`/`123` 隐式转字符串）；1~16 项；每项匹配 `^[a-z][a-z0-9_]{0,31}$`；禁止重复 | 无标签 |
| `entity_kinds` | `[]string` | YAML 节点须为非空 `SequenceNode`，**每一项**须为 `ScalarNode` 且 `Tag == "!!str"`；1~16 项；每项匹配 `^[a-z][a-z0-9_]{0,31}$`（对齐 `plugin/inventory.Entity.Kind`）；禁止重复 | 不关联特定实体类型 |

**读取路径校验规则**（`ParsePackage` / `validateAction(a, true)` / `Verify`）：
- **宽松保留未来扩展性**：不在读取路径执行 `tags`/`entity_kinds` 数量上限与正则拦截（避免未来放宽上限如 16 → 32 时导致旧网关验签整包失败返回 503）。
- **JSON `null` / 空数组 / 空串防护**：`Verify`（[internal/catalog/dsse.go](../internal/catalog/dsse.go) 第 239-245 行）已校验 `bytes.Equal(payload, CanonicalJSON(p))`。因三个字段均带 `omitempty`，签名 payload 中若含 `"toolset":""`、`"tags":null`、`"tags":[]`、`"entity_kinds":null`、`"entity_kinds":[]`，均会因非规范 JSON 被 `Verify` 拒绝。
- 不在 `catalog.yaml` 的 `defaults` 中提供默认 `toolset`，避免单目录跨多领域动作被误标注。

### 3.2 签名摘要、主机特性与升级顺序

1. **纳入签名与 action 摘要**：三个字段在 `catalog.Action` 内，自动计入 `CanonicalJSON(a)` → `ActionDigest(a)` 和 DSSE 签名，防止未签名元数据被篡改诱导 LLM 误选动作（T1/T3）。
2. **旧目录零变更**：均带 `omitempty`，未填写这些字段的旧目录其 `CanonicalJSON` 与 `ActionDigest` 逐字节不变。
3. **旧版组件兼容性与统一 Feature 标识**：
   - `allowops-agent` 与 `allowops-exec` 通过 `strictJSON`（`DisallowUnknownFields()`）解析目录包；旧版 CLI 用 `KnownFields(true)` 解析 YAML。任何未升级的主机收到含新字段的目录包时会整包拒绝并上报 `CATALOG_REJECTED`，保持已加载旧版本不变、保持在线、新版本动作在该主机标记为 `unsupported`（与 `website/publishing.md#fields-that-hosts-must-understand` 中 `max_targets` 完全一致）。
   - 三字段作为一个整体能力发布，在 [internal/agent/agent.go](../internal/agent/agent.go) 的 `hello()` 中统一新增单一 feature 标识 **`"action_metadata"`**：
     `Features: []string{"allow_interpreter", "exec_fallbacks", "max_targets", "action_metadata"}`
   - 同步更新 [api/proto/allowops/v1/agent.proto](../api/proto/allowops/v1/agent.proto) 注释。
   - **升级顺序**：
     1. 升级 `allowops-gateway`（默认 `mcp.mode: flat`，存量行为不变）；
     2. 升级目标主机上的 `allowops-agent` 与 `allowops-exec`，确认控制台主机 `features` 均包含 `action_metadata`；
     3. 升级 CI/本地 `allowops` CLI；
     4. 发布带有 `toolset`、`tags`、`entity_kinds` 的目录包。
   - **否决“网关下发时剥离元数据”**：DSSE 签名覆盖整包字节流，网关无私钥且不可修改已签名字节流。

### 3.3 新增保留动作名（仅编写与发布路径拦截）

- **原有 5 个保留名**（读写路径均保留不变）：`hosts_search`、`jobs_get`、`jobs_list`、`jobs_cancel`、`entities_search`。
- **新增 4 个保留名**（对应渐进式发现元工具）：`actions_search`、`actions_invoke_read`、`actions_invoke_write`、`actions_invoke_dangerous`。
- **防历史目录炸毁机制**：
  - 仅在**编写路径**（`validateAction(a, false)`：`Load`、`Build`、`ValidateAction`、`allowops catalog validate`）和**发布入口**（`catalogsvc.Service.Publish` 及 `api/catalogs.go` `PublishCatalog` 验签之后调用 `catalog.ValidateForPublish(p)`）拒绝新增 4 个保留名。
  - **读取路径**（`ParsePackage` / `catalogsvc.Verify` / `api/catalogs.go` 历史查询 / `job/validation.go`）不拒绝新增 4 个保留名，确保若私有仓库历史版本或升级前当前版本曾存在同名动作，升级网关后不会引发 MCP 全局 503、job 全部不可用或控制台目录历史接口报错。
  - 在 `flat` 模式下元工具不注册，无工具名冲突；在 `progressive` 模式下不注册平铺动作工具，元工具独立生效，也无工具名冲突。
  - `CHANGELOG.md` 升级说明提供升级前检查命令（检查当前发布目录的动作名列表）。

---

## 4. MCP 调用路径选型：按风险分层的 `actions_invoke_<risk>` vs 单一 `actions_invoke` vs `tools/list_changed`

| 方案 | 无状态水平扩展 | 客户端兼容性 | 客户端按风险审批隔离（T1） | 防注解过期低报风险 | Token 节省 |
|---|---|---|---|---|---|
| **按风险分层的元工具**（`actions_search` + `actions_invoke_read` / `actions_invoke_write` / `actions_invoke_dangerous`）（**采纳**） | 完全无状态（`Stateless: true`） | 100% 标准 MCP 客户端 | **保留完整风险分层**：用户可对 `actions_invoke_read` 设“始终允许”，同时对 `write`/`dangerous` 保持逐次人工确认 | **完全免疫**：调用时经 `currentAction` 强校验 `action.Risk == 工具风险等级`，不匹配即拒 | **~97%**（恒定 5~9 个工具） |
| 单一 `actions_invoke`（否决） | 无状态 | 100% | **破坏审批隔离**：具备混合权限的操作员若对 `actions_invoke` 点“始终允许”，提示注入可直接触发 `dangerous` 动作 | **存在窗口**：只读缓存注解在动作升风险后失效 | ~97% |
| `tools/list_changed` 动态装载（否决） | **破坏无状态**：需会话状态或粘滞路由 | 碎片化（许多客户端不支持或关闭独立 SSE） | 保留 | 依赖客户端及时重拉 | 中等（已装载工具持续累积） |

**结论**：采纳 **`actions_search` + 按风险分层的 `actions_invoke_read` / `actions_invoke_write` / `actions_invoke_dangerous`**，保留 `Stateless: true`，不启用 `tools/list_changed`。  
配合 `X-Allowops-Toolsets` 作用域过滤，专项 Agent（如只操作 `mysql` 或 `jvm`）可选择性保持 `flat` 模式获得原生逐动作工具名，大目录通用 Agent 则使用 `progressive` 或 `auto` 模式获得 97% 上下文压缩与完整风险审批边界。

---

## 5. 暴露模式、配置、请求头与两层无抖动缓存

### 5.1 网关配置（`gateway.yaml`）

在 [cmd/allowops-gateway/main.go](../cmd/allowops-gateway/main.go) 的 `configuration` 中新增可选 `mcp` 节（`KnownFields(true)` 严格解码）：

```yaml
mcp:
  mode: flat             # flat（默认）| progressive | auto
  auto_threshold: 40     # 可选（*int）；省略时默认 40；显式指定须在 [1, 1000] 内，显式写 0 拒绝
```

配置校验规则：
- `mode` 省略默认 `"flat"`；仅允许 `"flat"`、`"progressive"`、`"auto"`。
- `auto_threshold` 为 `*int`：省略（`nil`）默认 `40`；若非 `nil` 则无论 `mode` 为何值均须满足 `1 <= *auto_threshold <= 1000`，显式写 `0` 或负数或 `>1000` 启动拒绝。
- **默认 `mode: flat` 的依据**：Claude Code 等客户端的权限白名单按工具名（`mcp__allowops__<action>`）配置；保持默认 `flat` 确保存量部署零破坏升级，管理员按需显式启用 `auto` 或 `progressive`。

### 5.2 客户端请求头（保留零 URL Query 安全不变量）

- **仅支持 HTTP Request Headers，不放宽 `/mcp` 拒绝 URL Query 参数的规则**（[internal/gateway/mcp/service.go](../internal/gateway/mcp/service.go) 保持 `if r.URL.RawQuery != ""` → HTTP 400）。理由：`allowops` MCP 已强制使用 `Authorization: Bearer` 头，支持配置自定义请求头的客户端覆盖全部主流 MCP 客户端；保留零 Query 参数规则可根绝凭证或配置泄漏进 URL 与代理日志。
- 支持两个可选自定义请求头（均在认证与 `Origin` 检查**之后**解析；**非授权边界**，仅用于上下文视图裁剪）：
  1. `X-Allowops-Toolsets`：
     - 超过 1 个同名头直接返回 HTTP 400（与 `Authorization` 同原则，防止代理多行头合并歧义）。
     - 头存在但去空白后为空返回 HTTP 400。
     - 按逗号 `,` 拆分，逐项 `strings.TrimSpace`；空项、超过 **16** 项、或任一项不匹配 `^[a-z][a-z0-9_]{0,31}$` 均返回 HTTP 400。
     - 去重并按字典序排序得到 `requestedToolsets`。
     - **不校验 toolset 是否存在于全局目录**：避免向低权限用户泄漏未授权领域的 toolset 名称。
  2. `X-Allowops-MCP-Mode`：
     - 超过 1 个同名头直接返回 HTTP 400。
     - 去首尾空白（`strings.TrimSpace`）后精确小写匹配 `"flat"` 或 `"progressive"`（不接受 `"auto"`、空串或其他大小写），非法值返回 HTTP 400。
     - **无条件允许客户端覆盖网关 `mcp.mode`**：展示模式不改变任何权限边界，且 `tools/list` 本身已有 `PageSize` 分页保护；选择 `flat` 带来的客户端上下文成本由调用方自担。
- Header 校验失败写入独立操作名审计 `event.Operation = "mcp/request"`、`Phase = "result"`、`Outcome = "deny"`（不复用 `mcp/authenticate`）。

### 5.3 模式判定与工具矩阵

设身份投影可见动作集（含支持与不支持 schema）为 $A$，其中 schema 受支持的可执行子集为 $V \subseteq A$：
- 若请求带 `X-Allowops-Toolsets`：
  - $A_s = \{ a \in A \mid a.\text{Toolset} \in \text{requestedToolsets} \}$（未标注 `toolset` 的动作不在 $A_s$ 中）；
  - $V_s = \{ a \in V \mid a.\text{Toolset} \in \text{requestedToolsets} \}$。
- 若请求未带 `X-Allowops-Toolsets`：$A_s = A$，$V_s = V$。
- 有效模式：
  - 若请求带 `X-Allowops-MCP-Mode`：`effectiveMode = headerMode`
  - 否则若 `cfg.Mode == "auto"`：`effectiveMode = "progressive"` 当且仅当 $|V_s| > \text{cfg.AutoThreshold}$，否则 `"flat"`
  - 否则：`effectiveMode = cfg.Mode`

注册到 `*sdk.Server` 的工具列表：

| 条件 | 固定工具 | 动作工具 / 元工具 |
|---|---|---|
| 任意模式，$|V_s| = 0$（例如 `viewer`，或过滤后无受支持可见动作） | `hosts_search`、`jobs_get`、`jobs_list`、`jobs_cancel` +（若有可用 Inventory）`entities_search` | **无**（保持 `viewer` 为 4 或 5 个工具） |
| `effectiveMode == "flat"`，$|V_s| \ge 1$ | 同上 | $V_s$ 中每个动作注册为独立 `<action>` 工具（与现有行为完全一致） |
| `effectiveMode == "progressive"`，$|V_s| \ge 1$ | 同上 | 注册 `actions_search`，并按 $V_s$ 中实际存在的风险等级注册对应调用工具：<br>- 含 `read` → `actions_invoke_read`（`readOnlyHint: true`）<br>- 含 `write` → `actions_invoke_write`（`readOnlyHint: false, destructiveHint: false`）<br>- 含 `dangerous` → `actions_invoke_dangerous`（`readOnlyHint: false, destructiveHint: true`） |

### 5.4 两层缓存与防缓存抖动 DoS 架构

为彻底解决“已知 toolset 组合（$2^{16}-1$）驱逐 LRU 缓存 + 持有全局锁执行 DB/Ed25519/OPA + 全局 `knownToolsets` 时序探测”问题，采用两层缓存与锁外构建设计：

1. **Tier 1（目录快照缓存，按 `versions` 键控，singleflight 防惊群）**：
   - 缓存当前 `versions` 对应的已验签合并 `actions map[string]catalog.Action` 以及编译好的投影 OPA 引擎 `projectedEngine *authz.Engine`。
   - DB 查询、Ed25519 验签与 Rego 编译**全部在锁外通过 per-key singleflight 执行**，不再阻塞全局互斥锁 `s.mu`。
2. **Tier 2（身份视图 LRU 缓存，键仅为 `sha256(Actor, Subject, Versions)`，每身份恒占 1 槽）**：
   - 缓存该身份的**未过滤**视图 `identityView`：
     - `allAvailable map[string]catalog.Action`（投影允许的全部动作，含 unsupported）
     - `visible map[string]catalog.Action`（投影允许且 schema 受支持的动作）
     - `unsupported map[string]bool`
     - `flatDefs map[string]ToolDefinition`（每个受支持可见动作预构建好的 `ToolDefinition`）
     - `defaultMode string`（无请求头时的 `effectiveMode`）
     - `defaultServer *sdk.Server`（无请求头时的默认 `*sdk.Server`，缓存命中零分配，保持现有 `TestSDKToolFilteringCacheInvalidationAndRevocation` 契约）
3. **带 Header 请求的现场组装（不进 LRU 缓存）**：
   - 当请求未携带 `X-Allowops-Toolsets` 且（未携带 `X-Allowops-MCP-Mode` 或其值等于 `view.defaultMode`）时，直接复用 `view.defaultServer`（零额外构建）。
   - 当请求携带 `X-Allowops-Toolsets` 或改变了 `effectiveMode` 时：
     - **仅**在 `view.visible` / `view.allAvailable`（该身份自身可见集合）上做纯内存过滤，求交集完全不接触全局目录或其他身份的 toolset，**彻底消除存在性时序侧信道**；
     - 用预构建好的 `view.flatDefs` 或固定元工具定义现场构造轻量 `*sdk.Server`（仅若干次内存 map 拷贝与 `AddTool`，微秒级，**不写入 LRU 缓存**，绝不驱逐任何其他身份的缓存槽）。

---

## 6. 元工具详细契约

### 6.1 `actions_search`

**工具注解**：`ReadOnlyHint: true`。

**Input Schema**（`additionalProperties: false`，所有字段均可选）：

| 字段 | 类型 | 约束与说明 |
|---|---|---|
| `query` | `string` | 可选，非空且最长 200 字符；按空白分词，所有词大小写不敏感匹配 `name`、`description`、`toolset`、`tags`、`entity_kinds` 拼接文本（AND 语义）。 |
| `names` | `array<string>` | 可选，1~20 项，每项匹配 `^[a-z][a-z0-9_]{0,63}$`；精确动作名批量筛选（适合 L2 精准拉取 1~3 个动作的 `include_schema: true`）。 |
| `toolset` | `string` | 可选，匹配 `^[a-z][a-z0-9_]{0,31}$`；精确匹配 `action.toolset`。 |
| `tag` | `string` | 可选，匹配 `^[a-z][a-z0-9_]{0,31}$`；要求 `action.tags` 包含该值。 |
| `risk` | `string` | 可选，枚举 `["read", "write", "dangerous"]`。 |
| `entity_kind` | `string` | 可选，匹配 `^[a-z][a-z0-9_]{0,31}$`；要求 `action.entity_kinds` 包含该值。 |
| `hostname` | `string` | 可选，非空且不含 `\x00\r\n`；按目标主机做可见性与实时 ABAC 预检过滤（见 6.1.1）。 |
| `include_schema` | `boolean` | 可选，默认 `false`。为 `true` 时每条结果附带 `input_schema`。 |
| `limit` | `integer` | 可选，范围 `[1, 50]`，默认 `20`。 |
| `next_cursor` | `string` | 可选，非空不透明分页游标。 |

显式传入 `null`、空字符串（如 `{"query": ""}`）、空数组（`{"names": []}`）、未知字段或重复 JSON 键一律返回 `CodeInvalidArgument`。

#### 6.1.1 `hostname` 过滤实现（复用 `api` 单主机预检）

在 `internal/gateway/api` 新增方法并暴露于 `mcp.Identity` 接口：

```go
AllowedActionsOnHost(ctx context.Context, hostname string, actions []authz.Action) (map[string]bool, error)
```

执行逻辑（单主机查询 + 复用 `api.evaluate`，零重复规则逻辑、不破坏审计 `matchedRules`）：
1. 通过 `s.hostsWhere(ctx, s.Store.Pool, " AND h.hostname = $2", false, hostname)` 仅查询该单台活动主机（避免 `ListHosts` 扫描全表主机）。
2. 调用一次 `s.pinPolicy(ctx)` 固定当前策略快照（不重复查库）。
3. 若主机不存在，或 `s.can(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(h))` 返回 `false`：直接返回空 map `map[string]bool{}, nil`（不区分主机不存在、无权查看或无标签，彻底防止主机存在性枚举）。
4. 对每个候选 `authz.Action`，使用当前固定策略引擎调用 `evaluate(ctx, engine, authz.Input{Subject, Operation: authz.ExecuteAction, Action, Host: hostAttributes(h), Env: {TimeNS, SourceIP}})`：
   - 自动复用 [internal/gateway/api/service.go](../internal/gateway/api/service.go) 的 `HOST_UNLABELED` 不变量（无授权标签的主机对含 admin 在内的所有身份均返回空集合）；
   - 仅累加匹配的规则 ID（同 `s.can` 方式，不覆盖 `transport.matchedRules`），并记录 `policyVersion`；
   - 仅将 `Decision == "allow"` 的动作写入返回 map。

#### 6.1.2 排序、响应结构、游标与 32 KiB 预算

- **固定排序规则**：按风险等级升序 `read` (0) < `write` (1) < `dangerous` (2)，同风险按 `name` 字典序升序（优先呈现只读诊断动作，行为完全确定以便黄金测试固定）。
- **响应结构**：

```json
{
  "actions": [
    {
      "name": "jvm_perfdata",
      "description": "Read JVM heap, GC, class and thread counters from hsperfdata without attaching.",
      "risk": "read",
      "idempotent": true,
      "toolset": "jvm",
      "tags": ["gc", "heap", "threads"],
      "entity_kinds": ["jvm"],
      "max_targets": 1,
      "filters": ["match", "exclude"],
      "required_params": ["target"],
      "optional_params": [],
      "invoke_tool": "actions_invoke_read",
      "input_schema": {
        "params": { "...": "signed params JSON Schema" },
        "effective_batch_size": 20,
        "effective_max_failures": 5,
        "max_targets": 1,
        "allowed_filters": ["match", "exclude"]
      }
    }
  ],
  "toolsets": [
    { "name": "docker", "count": 14 },
    { "name": "jvm", "count": 4 }
  ],
  "total": 133,
  "truncated": false,
  "next_cursor": "...",
  "output_trust": "untrusted"
}
```

- `invoke_tool`：直接标明该动作应使用的调用工具名（`actions_invoke_read` / `actions_invoke_write` / `actions_invoke_dangerous`），消除 LLM 猜测。
- `toolsets`：仅在第一页（`next_cursor == ""`）返回当前结果集（经过所有筛选条件后的可见匹配集合）中**已标注 `toolset`** 的动作按 `toolset` 聚合计数（按名称升序；**未标注 `toolset` 的动作省略，不生成伪 `"unassigned"` 项**）。
- **分页游标绑定**：`base64.RawURLEncoding` 编码 `{"snapshot": "<hex>", "offset": <int>}`，长度上限 256 字节；其中：
  `snapshot = sha256(actor, subject, versions, effectiveMode, effectiveToolsets, canonicalQueryParamsIncludingHostname)`。
  任意维度变化（包括角色变更但策略版本未变）或游标篡改均返回 `CodeInvalidArgument`（`"invalid actions_search cursor; restart without next_cursor"`）。
- **32 KiB 预算与单条超限降级**（同时覆盖 `include_schema: true` 和 `false`，防超大 `description` 突破预算）：
  1. 逐条装入 `actions[start:end]`（最多 `limit` 条），每次经 `toolResult(out)` 测量完整 MCP 响应字节数（含 `structuredContent`、文本副本与 `_meta`），超出 `resultByteLimit`（32 KiB）则停在上一条并附带 `next_cursor` 无损分页。
  2. 若 `start` 处仅 1 条（无论是否带 `include_schema`）就超过 32 KiB：先尝试省略 `toolsets` 汇总重试；若单条仍超过 32 KiB，返回 `CodeResourceExhausted`（`"action entry exceeds 32KB result limit"`），绝不突破 32 KiB 上限。
- **审计**：结果审计记录 `event.Operation = "mcp/actions_search"`、`Phase = "result"`、`Outcome = "allow" | "deny"`。

---

### 6.2 按风险分层的调用元工具：`actions_invoke_read` / `actions_invoke_write` / `actions_invoke_dangerous`

三个工具共享相同的输入结构，区别在于固定注解、描述文案与服务端强制校验的目标动作 `Risk`：

| 工具名 | MCP 注解 | 允许执行的 `action.Risk` |
|---|---|---|
| `actions_invoke_read` | `ReadOnlyHint: true`, `IdempotentHint: false` | 仅 `"read"` |
| `actions_invoke_write` | `ReadOnlyHint: false`, `DestructiveHint: &false`, `IdempotentHint: false` | 仅 `"write"` |
| `actions_invoke_dangerous` | `ReadOnlyHint: false`, `DestructiveHint: &true`, `IdempotentHint: false` | 仅 `"dangerous"` |

**Input Schema**（`additionalProperties: false`）：
- `action`（必填，`string`，匹配 `^[a-z][a-z0-9_]{0,63}$`）
- `targets`（必填，同 `actionTool`）
- `reason`（必填，同 `actionTool`）
- `expected_count`、`params`、`wait_seconds`、`batch_size`（上限为网关 `cfg.Jobs.BatchSize`，具体动作更低上限由 `actionRequest` 强制执行）、`max_failures`（上限为网关 `cfg.Jobs.MaxFailures`，具体动作更低上限由 `actionRequest` 强制执行）、`response_format`
- 可选输出过滤器：`match`、`exclude`、`head`、`tail`、`count`（由 `actionRequest` 按目标动作实际声明的 `a.Filters` 严格放行或拒绝）

**调用路径重构（对应 M3）与安全执行步骤**：
将 [internal/gateway/mcp/call.go](../internal/gateway/mcp/call.go) 中 `execute` 的 `default` 分支抽离为共享方法 `runAction(ctx, r, actionName, rawArgs, extraAllowedNames, state)`，并在 `callState` 中新增 `operation string` 和 `mutating bool` 字段：

1. `argumentObject(r.Params.Arguments)` 严格解码顶层 JSON 对象（保留数字精度、拒绝重复键、拒绝尾随数据）。
2. 提取并校验必填字符串 `action`（匹配 `^[a-z][a-z0-9_]{0,63}$` 且非固定工具名），否则返回 `CodeInvalidArgument`（审计 `mcp/actions_invoke_<risk>` + `deny`）。
3. 核查 `scopedAvailable[actionName]`（当前身份投影可见且符合 `X-Allowops-Toolsets`）：
   - 不可见：返回 `CodeNotFound`（`"tool removed or unavailable for this identity; call actions_search to refresh"`），审计 `mcp/actions_invoke_<risk>` + `deny`（不将未知客户端名称写入审计，遵守 G49）。
4. 核查 `scopedUnsupported[actionName]`：
   - 不受支持：返回 `CodeFailedPrecondition`（`errUnsupportedActionSchema.Error()`），审计 `mcp/<actionName>` + `deny`。
5. 标记 `state.operation = "mcp/" + actionName`、`state.mutating = true`（确保若后续结果审计失败且 `state.jobID != ""`，正确追加 `"; operation may have committed"`）。
6. 通过 `s.currentAction(ctx, actionName)` 读取最新验签目录中的动作定义，并**强制校验 `action.Risk == expectedRisk`**（与所调用工具 `actions_invoke_<risk>` 一致）：
   - 不一致：返回 `CodeFailedPrecondition`（`"action risk does not match invocation tool; call the matching actions_invoke_<risk> tool"`），不创建 job，不调用 `RunJob`！
7. 删除顶层 map 中的 `"action"` 键，将剩余字段重新编码后传入 `s.runAction(ctx, r, actionName, remainingRaw, []string{"action"}, state)`：
   - `actionRequest` 校验失败时，未知参数错误提示自动包含 `"action"` 以及该动作允许的公共参数和过滤器名称；
   - 完整复用 `actionRequest` → `s.withProgress` → `s.jobs.RunJob` → `nativeSummaryResult` 全链路。

### 6.3 `progressive` 模式下直接调用 `<action>` 的行为

在 `progressive` 模式下客户端直接发送 `tools/call {name: "<action>"}`：
- 若 `<action>` 不在 `scopedAvailable`：返回 `CodeNotFound`（`"tool removed or unavailable for this identity; call tools/list to refresh"`），审计 `mcp/unknown_tool` + `deny`。
- 若 `<action>` 在 `scopedAvailable` 且属于 `scopedUnsupported`：返回 `CodeFailedPrecondition`（`errUnsupportedActionSchema.Error()`），审计 `mcp/<action>` + `deny`。
- 若 `<action>` 在 `scopedAvailable` 且受支持：返回 `CodeFailedPrecondition`（`"action is not directly exposed in progressive mode; call the matching actions_invoke_<risk> tool"`），审计 `mcp/<action>` + `deny`（静态文案，不回显用户输入）。

---

## 7. 实体 → 关联动作推荐（`entities_search` 协同）

在 [internal/gateway/mcp/inventory.go](../internal/gateway/mcp/inventory.go) 中增强 `entities_search`：

```go
type recommendedAction struct {
    Name        string `json:"name"`
    Description string `json:"description"`
    Risk        string `json:"risk"`
    Toolset     string `json:"toolset,omitempty"`
}

type inventoryResult struct {
    Entities                    []inventoryEntity              `json:"entities"`
    RecommendedActions          map[string][]recommendedAction `json:"recommended_actions,omitempty"`
    RecommendedActionsTruncated bool                           `json:"recommended_actions_truncated,omitempty"`
    Truncated                   bool                           `json:"truncated"`
    SourceErrors                []pluginhost.SourceError       `json:"source_errors"`
    OutputTrust                 string                         `json:"output_trust"`
}
```

实现与预算规则（严格按 M1 意见设计）：
1. **先完成实体过滤与 32 KiB 截断**：完全保持现有 `VisibleHostnames` → `limit` → 32 KiB 二分截断逻辑不变，确保 `truncated` 的含义始终且唯一表示“实体被截断”，不破坏现有行为。
2. **仅基于最终保留实体的 `kind` 生成推荐**：收集最终保留的 `out.Entities` 中出现的去重 `kind` 并按字典序排序（绝不泄漏被隐藏或截断实体的 `kind`）。
3. **仅从当前请求作用域的可见动作 $V_s$ 匹配**：对每个 `kind`，筛选 `slices.Contains(a.EntityKinds, kind)` 的动作，按风险升序（`read` < `write` < `dangerous`）再按 `name` 升序排列，每个 `kind` 最多取前 **10** 条；若某 `kind` 匹配超过 10 条则标记 `RecommendedActionsTruncated = true`。
4. **确定性顺序装入剩余 32 KiB 预算**：按 `kind` 字典序逐组尝试加入 `out.RecommendedActions` 并用 `toolResult(out)` 校验 `<= resultByteLimit`；放不下的整组省略，置 `RecommendedActionsTruncated = true`，并继续保持 `out.Truncated` 不受影响。
5. **无匹配向后兼容**：当无任何匹配动作时（如旧目录无 `entity_kinds`、或 `viewer` 无可执行动作、`catalogs == nil` 的单测夹具），`RecommendedActions` 为 `nil`、`RecommendedActionsTruncated` 为 `false`，因 `omitempty` 均不出现在 JSON 输出中，现有 `inventory_test.go` 全部保持零变更通过。

---

## 8. 示例目录标注体系与控制台适配

### 8.1 约定 Entity Kinds 与示例目录 133 个动作映射

严格对齐仓库现有 [examples/topology.yaml](../examples/topology.yaml)（`service`、`database`、`cache`）与 [plugins/inventory/hostlabels/hostlabels.go](../plugins/inventory/hostlabels/hostlabels.go)（默认 `service`，可配置任意合法 `kind`），避免把泛化 kind 贴满几十个动作导致推荐噪音：

- **通用高信号 Kind**（与 `examples/topology.yaml` 开箱即用）：
  - `service`：精选 **8 个**核心通用服务排障入口（`systemd_service_status`、`log_sources`、`log_search`、`log_stats`、`log_patterns`、`journal_view_log`、`http_get_local`、`app_config_view`），确保 `entities_search(kind="service")` 推荐结果全部在 10 条上限内、零噪音、高信号！
  - `database`：核心只读数据库排障动作（`mysql_processlist`、`mysql_slow_log`、`mysql_error_log`、`mysql_query_readonly`、`starrocks_cluster_status`、`starrocks_slow_queries`、`starrocks_query_readonly`、`dremio_nodes`、`dremio_jobs_recent`、`dremio_query_readonly`，共 10 个）。
  - `cache`：全部 6 个 `redis_*` 动作。
- **细粒度技术栈 Kind**（面向配置了细分 kind 的静态拓扑或自定义 Inventory 插件）：
  - `host`：`system`（13）、`network`（5）、`files`（5）、`logs`（除 `log_search_containers` 外 12 个）、`agent`（1）
  - `docker_container`：`docker`（14）+ `log_search_containers`
  - `k8s_pod` / `k8s_cluster`：`k8s`（19，其中节点/事件类标 `k8s_cluster`，Pod 类标 `k8s_pod`）
  - `jvm`：`jvm`（4）+ `jvm_arthas`（17）+ 容器/Pod 内 JAR/Java 类检查（6）
  - `dubbo`：`dubbo`（9，同时标 `jvm` 便于 JVM 排查关联）
  - `mysql`：`mysql`（7）
  - `redis`：`redis`（6）
  - `nginx`：`nginx`（2）
  - `prometheus` / `alertmanager`：`prometheus`（6 标 `prometheus`；`alertmanager_alerts` 标 `alertmanager`, `prometheus`）
  - `starrocks`：`starrocks`（6）
  - `dremio`：`dremio`（5）

全量 133 个动作分属 **16 个高内聚 Toolset**（`system`, `network`, `files`, `logs`, `docker`, `k8s`, `jvm`, `jvm_arthas`, `dubbo`, `mysql`, `redis`, `nginx`, `prometheus`, `starrocks`, `dremio`, `agent`），所有动作均补齐非空 `toolset`、`tags`、`entity_kinds`。  
同步更新 [test/examples/check_examples.py](../test/examples/check_examples.py)，检查全部 133 个示例动作均具备非空 `toolset`、`tags`、`entity_kinds` 且 `toolset` 落于上述 16 个规范值集合中。

### 8.2 控制台 Catalog 侧栏展示

- `GetAction` 返回的 `definition_json` 直接由 `catalog.CanonicalJSON(a)` 生成，自动携带 `toolset`、`tags`、`entity_kinds`。
- 在 [web/src/api/types.ts](../web/src/api/types.ts) 的 `ActionDefinition` 中增加可选字段 `toolset?: string`、`tags?: string[]`、`entity_kinds?: string[]`，在 [web/src/pages/Catalog.tsx](../web/src/pages/Catalog.tsx) 的 `ActionPanel` 中展示这三个元数据字段并补齐中英文 i18n 文案。

---

## 9. 威胁模型与安全验证矩阵

| 威胁 | 防护机制 | 必备测试 |
|---|---|---|
| **T1 提示注入与审批绕过** | 风险分层元工具 `actions_invoke_read/write/dangerous` + 运行时强校验 `action.Risk`；`output_trust: "untrusted"`；完整复用 `actionRequest`、`expected_count`、`max_targets`、OPA ABAC | 尝试用 `actions_invoke_read` 调用 `write`/`dangerous` 动作被拒；目录动作升风险后旧工具调用被拒；`expected_count` / `max_targets` / 参数注入全部被拒 |
| **越权与存在性枚举** | 不可见动作在 `actions_search` 静默隐藏、在 `actions_invoke_*` 与不存在动作返回相同 `CodeNotFound`；不可见/不存在/无标签主机在 `actions_search(hostname)` 返回相同空集；`X-Allowops-Toolsets` 仅与当前身份可见集求交 | viewer 与受限角色探测隐藏动作、隐藏主机、无标签主机、不存在主机与 toolset |
| **审计完整性（G49）** | 仅可见合法动作名写入 `mcp/<action>`，未知/不可见名称固定记 `mcp/actions_invoke_<risk>` 或 `mcp/unknown_tool`；Header 畸形记 `mcp/request`；`state.mutating` 保证审计失败提示 `operation may have committed` | 审计链测试覆盖 `actions_search`、`actions_invoke_*`（成功/参数错/风险不匹配/被拒/未知）、畸形 Header |
| **T12 缓存抖动 DoS** | Tier 1 锁外 singleflight 缓存目录；Tier 2 LRU 仅按身份+版本建键（每身份 1 槽）；Header 过滤后的 `*sdk.Server` 现场组装不进 LRU | 高频发送不同合法/非法 toolset 组合不增加 LRU 长度、不触发重复验签 |
| **历史目录兼容与安全发布** | 新保留名仅在编写与发布入口拒绝；读取路径宽松不炸毁历史目录与存量网关 | 发布含新保留名目录被拒；读取预存含同名动作的历史包不报错 |
| **32 KiB 预算边界** | `actions_search` 与 `entities_search` 严格通过 `toolResult` 测量总字节数；`actions_search` 支持单条超限降级与拒绝；`entities_search` 独立 `recommended_actions_truncated` | 超长 description、引号转义膨胀、大 schema、多实体多推荐边界测试 |
