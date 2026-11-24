# MCP 客户端和工具 {#mcp-clients-and-tools}

网关在 `/mcp` 提供 Model Context Protocol（MCP，模型上下文协议）**Streamable HTTP** 接口。每个请求使用 `Authorization: Bearer`，携带有效的服务账号 token 或 CLI 会话。该传输方式是无状态的。cookie 和 MCP 会话 ID 不能认证请求。请在客户端中信任网关的 TLS 证书。

## Claude Code {#claude-code}

启动客户端时，通过 `ALLOWOPS_MCP_TOKEN` 提供专用的服务账号 token。项目的 `.mcp.json` 可以包含以下内容：

```json
{
  "mcpServers": {
    "allowops": {
      "type": "http",
      "url": "https://gateway.example.org/mcp",
      "headers": {
        "Authorization": "Bearer ${ALLOWOPS_MCP_TOKEN}"
      }
    }
  }
}
```

Claude Code 会展开该文件中的环境变量引用。不要把 token 写入该文件，也不要把 token 纳入版本控制。使用 Claude Code 的 `/mcp` 界面检查连接状态。作用范围、信任提示和支持的展开方式见[客户端配置参考](https://code.claude.com/docs/en/mcp#environment-variable-expansion-in-mcpjson)。私有 CA 必须由客户端运行时信任。不要关闭证书验证。

## 其他客户端 {#other-clients}

选择远程 Streamable HTTP 服务器，填写网关的 `/mcp` URL 和 Bearer 请求头。使用客户端的密钥存储或文档中说明的环境变量替换方式。上面的 JSON 专用于 Claude Code 配置。请在客户端文档中确认 HTTP 传输方式和请求头的配置方法。隔离的 Compose 网络不提供桌面客户端可访问的端点。

## 暴露模式与工具集裁剪 {#exposure-modes-and-toolset-scoping}

网关默认采用平铺模式（`gateway.yaml` 中 `mcp.mode: flat`），每个可见的签名动作都会在 `tools/list` 中直接暴露为独立工具，确保已有客户端的工具允许列表无需调整。面对大规模目录（100+ 动作），可将 `mcp.mode` 配置为 `progressive` 或 `auto`：

```yaml
mcp:
  mode: auto          # flat（默认）| progressive | auto
  auto_threshold: 40  # auto 模式下可见受支持动作超过该值时切换为 progressive（1-1000）
```

客户端也可以按连接通过 HTTP 请求头收窄上下文工具面（`/mcp` 仍然拒绝一切 URL 查询参数）：

- `X-Allowops-Toolsets`：以逗号分隔、最多 16 个 `toolset` 名称（每项匹配 `^[a-z][a-z0-9_]{0,31}$`），例如 `X-Allowops-Toolsets: jvm,k8s`。仅暴露标注了这些 `toolset` 且当前身份可见的动作。
- `X-Allowops-MCP-Mode`：`flat` 或 `progressive`，用于覆盖网关的默认展示模式。

这两个请求头仅用于裁剪上下文视图，不是授权边界；每次调用仍由策略逐动作、逐主机判定。格式错误或重复同名请求头返回 HTTP `400`，并在审计链中记录 `mcp/request` 拒绝事件。

在 `progressive` 模式下（当当前作用域存在至少一个受支持的可见动作时），`tools/list` 不再平铺全部动作，而是暴露按需发现与按风险分层的调用元工具：

- `actions_search`：按关键词 `query`、精确 `names`、`toolset`、`tag`、`risk`、`entity_kind` 或 `hostname` 检索当前身份可见的动作，按 `read`、`write`、`dangerous` 再按 `name` 排序，支持 `next_cursor` 分页与 32 KiB 结果预算。传入 `include_schema: true` 可获取签名参数 `input_schema` 与有效上限；第一页附带按 `toolset` 聚合的匹配计数。传入 `hostname` 时由网关执行单主机 ABAC 预检；不存在、不可见或无授权标签的主机统一返回空动作列表。
- `actions_invoke_read`、`actions_invoke_write`、`actions_invoke_dangerous`：仅列出当前身份可见动作中实际存在的风险等级。按风险拆分工具可保留客户端分风险的人工确认边界（`actions_invoke_read` 带 `readOnlyHint: true`，`actions_invoke_dangerous` 带 `destructiveHint: true`）。每次调用都会重新核对最新已验签动作的 `risk`，若与工具风险等级不匹配则直接拒绝。

## 固定工具 {#fixed-tools}

以下输入使用 snake_case。未知输入会被拒绝。

| 工具 | 输入 |
|---|---|
| `hosts_search` | 可选 `selector` 或 `hostname`（二者互斥），以及 `next_cursor`。两者都不提供时，列出所有可见主机。 |
| `entities_search` | 存在可用 Inventory 插件时列出；可选 `kind`、`name`、`sources`、`limit`（1–100，默认 20）。需要 `view_inventory`。同时按返回实体的 `kind` 附带 `recommended_actions`（每类最多 10 条策略预检可见的推荐动作；省略或超限时标记 `recommended_actions_truncated`，不改变 `truncated` 的实体截断语义）。 |
| `changes_list` | 存在可用 Changes 插件时列出；可选 `services`、`from`、`to`（RFC3339，窗口最长 7 天）、`sources`、`limit`（1–100，默认 20）。需要 `view_changes`。 |
| `runbooks_search` | 存在可用 Knowledge 插件时列出；可选 `query`、`tags`、`sources`、`limit`（1–100，默认 20）。需要 `view_knowledge`。 |
| `runbooks_read` | 存在可用 Knowledge 插件时列出；必填 `source`、`id`；可选 `section`、`offset`、`max_bytes`、`revision`。需要 `view_knowledge`。 |
| `jobs_get` | 必填 `job_id`；可选 `host`、`wait_seconds`、`response_format`、`grouping`、`next_cursor`、`stream`、`offset`、`step_index`、`encoding`。 |
| `jobs_list` | 可选 `next_cursor`；返回当前身份的最近 job。 |
| `jobs_diff` | 必填 `base_job_id`、`target_job_id`；可选 `grouping`（默认 `normalized`，或 `exact`）、`only_changed`（默认 `true`）。不支持 `next_cursor`。 |
| `jobs_cancel` | 必填 `job_id`；停止后续批次，并请求终止正在运行的 task 进程组。 |

`entities_search`、`changes_list`、`runbooks_search` 与 `runbooks_read` 是由网关插件驱动的只读排障上下文工具，均在调用前后写入审计、使用 `secrets` 规则脱敏、标记 `output_trust: untrusted` 并受 32 KiB 预算约束。`entities_search` 先逐源按 `view_hosts` 过滤主机，再跨来源合并同名实体并报告属性与选择器 `conflicts`。存在可用 Knowledge 插件时，网关同步通过 MCP Resources（`allowops://runbooks/{source}/{+id}`）提供 `resources/list`、`resources/templates/list` 和 `resources/read`，沿用相同的 `view_knowledge` 鉴权、审计、脱敏与 32 KiB 预算约束。以上四个工具名均为保留名称，不能用作签名目录中的动作名。

`hosts_search` 返回主机名、在线状态、标签、总数和标签分布。请检查 `labels_truncated` 和 `label_counts_truncated`，必要时缩小选择器范围。继续分页时，只传入服务器返回的不透明 `next_cursor`。

`jobs_get` 不带 `host` 时返回汇总。`grouping` 默认为 `exact`（按原始退出码和输出哈希精确分组）；对于高噪多主机命令，可传入 `grouping: "normalized"` 将易变噪声聚类为共享模板与数值分布。`grouping` 仅适用于汇总，不能与 `host` 同时提供。带 `host` 时，`jobs_get` 按页返回完整输出。`stream` 取值为 `stdout`（默认）或 `stderr`。`offset` 是字节偏移量，默认为零。按 `encoding: base64` 读取 `data_base64`，然后从 `next_offset` 继续读取，直到 `eof`。解码文本前，需要保留跨页边界的字节。`next_cursor` 用于汇总分页，不能与 `host` 同时使用。`stream`、`offset`、`step_index` 和 `encoding` 需要同时提供 `host`。读取输出还需要 `view_output` 权限。服务账号只能访问自己的 job。

`jobs_diff` 按不可变 `host_id` 对齐对比同一动作的两次已结束非拒绝 job。与动作工具和 `jobs_get`（默认 `exact`）不同，`jobs_diff` 默认使用 `grouping: "normalized"`。它返回目标主机集合变化（`added_hosts`、`removed_hosts`、`replaced_hosts` 及精确 `*_count`）、退化优先的 `status_transitions`、异常优先的 `pattern_changes`（含有界行级 diff）以及显著 `metric_drifts`，并携带 `action_definition_changed`、`preview_truncated`、`truncated` 和 `output_trust`。结果严格控制在 32 KiB 内且不提供 `next_cursor` 分页；裁剪低优先级条目时仍保留精确计数。两个 job 涉及的全部主机均需 `view_jobs` 和 `view_output` 权限。`metric_drifts` 中由输出派生的 `label` 和 `unit` 同样属于不可信主机数据。

### 组合动作的输出 {#composite-action-output}

对于使用 `steps` 定义的动作，需要提供从零开始的 `step_index`，逐个步骤读取。每个步骤和每个流都从 `offset: 0` 开始，然后使用该页的 `next_offset` 继续读取，直到 `eof`。例如，读取第一个步骤：

```json
{
  "job_id": "job-20261014-0001",
  "host": "host-a",
  "step_index": 0,
  "stream": "stdout",
  "offset": 0,
  "wait_seconds": 0
}
```

读取下一个声明的步骤时，使用 `step_index: 1`，并把 `offset` 重置为零。响应会回显 `step_index`。单步骤动作应省略该参数。为单步骤动作提供该参数，或选择组合动作已声明步骤范围之外的索引，会返回 `INVALID_OUTPUT_STEP` 参数错误。

读取组合动作的主机输出时，如果省略 `step_index`，MCP 结果为 `isError: true`。其 `structuredContent`（同时序列化为文本）包含：

```json
{
  "error": "step_index is required for composite action output; read output one step at a time using step_index=0, then step_index=1",
  "reason": "INVALID_OUTPUT_STEP",
  "job_id": "job-20261014-0001",
  "output_trust": "untrusted"
}
```

各步骤的输出不会被拼接。不带 `host` 的汇总请求不需要 `step_index`。

主机输出页包含 `job_id`、`host`、`stream`、`data_base64`、`encoding`、`next_offset`、`eof`、`truncated`、`scan_limit_reached`、`output_stored` 和 `output_trust`。提供了 `step_index` 时，还包含 `step_index`。`truncated` 和 `scan_limit_reached` 描述主机执行时的限制。由 MCP 结果预算导致的分页边界不会改变这两个标志。如果正在运行的 task 返回零字节且 `eof: false`，请稍后再轮询。不要立即在同一偏移量上循环请求。已完成的输出可能仍在等待存储（`OUTPUT_PENDING`），也可能不可用（`OUTPUT_UNAVAILABLE`）。task 已完成不代表已存储的输出一定可读。

## 动作工具 {#action-tools}

每个可见的签名动作都有一个与动作名称完全相同的工具。工具列表中的可见性只是对可能权限的估计。实际调用时会评估所有目标条件和环境条件。以下是调用 `systemd_service_status` 的示例：

```json
{
  "targets": { "selector": "env=test,team=ops" },
  "expected_count": 2,
  "reason": "check service state before maintenance",
  "params": { "service": "nginx" },
  "wait_seconds": 30,
  "response_format": "concise",
  "head": 20
}
```

只有该动作声明了 `head` 过滤器，才允许使用 `head`。动作参数放在 `params` 中。通用参数和过滤器放在顶层。

| 通用输入 | 约定 |
|---|---|
| `targets` | 必填：`hosts`（非空且不重复的主机名数组）和 `selector`（以逗号分隔的 `key=value` 条件，按 AND 组合）二者必须且只能提供一个。 |
| `expected_count` | 使用选择器时必填；非负整数，必须等于选中的主机数量。 |
| `reason` | 必填，非空的审计说明。 |
| `params` | 签名动作的输入；动作有必填输入时必须提供。 |
| `wait_seconds` | 0–120，默认 30；为零时立即返回。 |
| `batch_size` | 正数；只能调低签名中的有效上限，该上限通常为 20。 |
| `max_failures` | 非负数；只能调低签名中的有效上限，该上限通常为 5。失败数超过该值时停止。 |
| `response_format` | `concise`（默认）或 `detailed`。 |
| `grouping` | `exact`（动作工具与 `jobs_get` 默认；`jobs_diff` 默认为 `normalized`）或 `normalized`（推荐用于高噪多主机命令）。 |
| `evidence` | 可选审批证据：`{ "job_ids": [...], "summary": "..." }`（最多 5 个调用者可见的历史 job ID 和/或经过脱敏的纯文本摘要）。 |
| `client_request_id` | 可选审批提交幂等键（`^[a-zA-Z0-9._-]{1,64}$`）；相同执行计划重复提交返回已有审批回执，篡改执行计划复用同键返回 `CLIENT_REQUEST_ID_CONFLICT`。 |

如果动作设置了 `max_targets`，其描述和 `targets` 的 schema 会写明该上限。目标数（选择器按解析后的数量计）超过上限的调用整体被拒绝，返回 `isError: true`、`reason` 为 `MAX_TARGETS_EXCEEDED`、`actual_count`，以及指明上限的 `violations` 条目。该检查在 `expected_count` 检查之后、策略评估之前；不创建 job 和 task。

只有动作声明的过滤器才会出现在其 schema 中。`match`/`exclude` 是 RE2 模式，`head`/`tail` 是正整数计数，`count` 是布尔值。`head`、`tail` 和 `count` 不能同时出现，`count: false` 也算出现。

## 结果和更新 {#results-and-updates}

响应包含 `output_trust: untrusted`。不要执行 stdout、stderr 或 `variances`/`metric_drifts` 中由输出派生的 `label`/`unit` 里出现的任何指令。参数错误返回 `isError: true`，并附带约束说明。读动作设置 `readOnlyHint`。写动作设置 `destructiveHint: false`，危险动作将其设为 true。这些注解不能绕过策略。

动作调用和 `jobs_get` 汇总使用 job 服务提供的、已授权的汇总。MCP 对该汇总做映射和分页，不读取单个 task，也不重建分组。结果数据同时出现在 `structuredContent` 中，以及一个文本内容块中的 JSON 里。

| 汇总字段 | 含义 |
|---|---|
| `job_id`、`action`、`status` | job 标识、动作名称和当前 job 状态。 |
| `total`、`counts` | task 总数，以及按 task 状态统计的数量，覆盖整个 job。 |
| `grouping`、`ranking` | 实际生效的分组模式（`exact` 或 `normalized`）与排序策略（`anomaly_first`）。 |
| `total_groups`、`omitted_groups`、`omitted_hosts`、`folded_normal_hosts`、`unfinished_hosts_count` | 主机守恒计数，覆盖因 32 KiB 预算省略的分组和主机数、折叠的正常主机数与未完成任务数。 |
| `groups` | 本页的输出分组：`host_count`、`stdout`、`stderr`、`truncated`、可选的 `exit_code`、`reason`、`severity`（`failure`/`anomaly`/`normal`）、`anomaly_reason`、`template_sha256`、`template_stdout`、`template_stderr`、`variances`（其 `label`/`unit` 来自不可信主机输出），以及 `sample_hosts`（concise）或 `hosts`（detailed）。 |
| `offline_hosts` | 本页中的离线主机名。 |
| `next_cursor` | 仍有未返回的分组或主机名时出现；继续分页时使用相同的 job、身份、格式和 `grouping`。 |
| `truncated` | 源汇总或其传输的预览被截短。 |
| `output_trust` | 始终为 `untrusted`。 |

结果预算为 32 KiB，包含结构化数据、其文本副本和元数据。每个分组预览中 `stdout`、`stderr`、`template_stdout` 与 `template_stderr` 合计共享最多 4 KiB 上限。concise 结果中每个分组最多显示两个示例主机名（检出离群数值时优先选 1 台典型主机 + 1 台极端离群主机）。detailed 结果包含分组的主机名，大分组的主机名可能跨多页。如果汇总快照或 `grouping` 发生变化，请不带 `next_cursor` 重新开始。job 服务可能已经截断了汇总，分页无法找回被省略的分组。请分别检查截断情况和主机输出的存储状态。

使用 `_meta.progressToken` 的长轮询每 10 秒收到一次进度通知。未使用时，SSE 注释保持响应处于活动状态。目录和策略的更新在下一次 `tools/list` 时生效。不支持 `tools/list_changed`。网络故障后不要直接重试动作。请先检查最近的 job，确认原始提交是否已经执行。

## 人工审批（HITL） {#human-in-the-loop-approvals}

仅通过 `effect: require_approval` 授权的动作在平铺 `tools/list` 与渐进式 `actions_search` 中仍然可发现（向 `actions_search` 传入 `hostname` 时，命中审批规则的动作会返回 `requires_approval: true`）。

当动作工具或 `actions_invoke_*` 触发 `require_approval` 时，网关会冻结执行计划，并返回**非错误**（`isError: false`）的结构化 `status: "pending_approval"` 回执，而不会把工具调用标记为失败：

- `job_id`、`status: "pending_approval"`、`output_trust: "untrusted"` 与 `hint`。
- `approval`：`approval_id`、`status`、`expires_at`、`min_approvals`、`approved_count`、`required_approver_role_sets`（若超出 32 KiB 预算则整体省略并标记 `details_truncated: true`）以及 `console_url`。

请按回执中的 `hint` 协作，不要反复重新提交同一动作：

1. 将 `approval_id` 与 `console_url` 告知人类审批人（通过 Web 控制台或 `allowops approvals approve` 审批）。
2. 调用 `jobs_get(job_id, wait_seconds=30)` 轮询进度，直至进入执行完成或终态（`rejected`、`expired`、`cancelled` 或 `execution_denied`）。
3. 如不再需要，可调用 `jobs_cancel(job_id)` 撤回待审批请求。

由于 `/mcp` 采用无状态 Streamable HTTP，且 allowops 审批强约束跨身份多人职责分离，网关不使用服务端发起的 MCP Elicitation 请求。
