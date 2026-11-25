# 人工审批流与 JIT 单次临时提权（HITL Approval / `require_approval`）设计文档

状态：评审通过并定稿（2026-11-24，已消化独立安全与状态机复审全部 7 项 Blocking / 6 项 Major / 2 项 Minor 意见）  
基线：`feat/hitl-approval-jit`（基于 `origin/main` commit `62e4fda`）

---

## 1. 背景与目标

### 1.1 现状痛点

当前 `allowops` 的 OPA ABAC 策略（[internal/gateway/authz/policy.rego](../internal/gateway/authz/policy.rego)）仅支持二元决策：`allow` / `deny`。这在生产环境引入了三类瓶颈：

1. **缺乏受控提权中间态**：对于 `risk: write` / `dangerous` 动作，以及带生产抖动风险的深度诊断（如 `jvm_arthas` L2 的 `watch`/`trace`/`stack`/`monitor`/`jad`），团队只能在“彻底禁止”与“直接裸放给 AI Agent”之间二选一。
2. **缺乏不可篡改的请求绑定与人工审批上下文**：没有标准化的审批对象承载精确解析后的目标主机清单、规范化参数、动作签名摘要以及 AI 提供的排查理由与前序证据，审批人无法安全、快速地评估变更影响。
3. **缺乏异步通知与审批操作入口**：尚未提供 `plugin/notifier` 扩展点，也缺少面向审批员的 Web 控制台审批队列和 `allowops approvals` CLI 工具链。

### 1.2 核心设计目标

1. **OPA 策略扩展（`require_approval`）**：在固定 Rego 策略程序中新增 `effect: require_approval`，严格遵守 **`deny` > `require_approval` > `allow` > 默认 `deny`** 优先级，支持规则级审批约束（`approver_roles`、`min_approvals`、`ttl_seconds`、`allow_owner_approve`），策略模拟（`TestPolicy` / `allowops policy test` / 控制台模拟页）完整呈现变更前后决策与审批约束差异。
2. **精确参数与主机绑定（防 TOCTOU）+ 单次原子消费**：命中 `require_approval` 时，创建 `JOB_STATUS_PENDING_APPROVAL` 作业与 1:1 绑定的 `approval_requests` 记录，锁定不可变 `request_digest`（基于经严格解码与类型校验后的统一执行载荷：动作名、风险、目录版本、动作 SHA-256、规范化参数、过滤器、**已解析的有序 `host_id` 列表**、批大小与失败上限）。禁止审批时修改任何执行参数。
3. **人员级职责分离（SoD）与事务内零连接泄漏二次复核**：仅人类身份（OIDC/LDAP）可审批；通过 `user_id` + 规范化已验证 `email` + 令牌签发者（`created_by_user_id`）实施防自审批与防共谋校验；终审事务内使用单连接事务查询、共享策略/目录锁与主机 `FOR SHARE` 锁，以实际墙钟（`clock_timestamp()` / `time.Now()`）检过期，核验提交用凭据（`token_id` / `session_id`）仍有效、逐票重验全部历史赞成票、叠加冻结约束与当前更严格策略约束、核验当前活跃目录 `action_sha256` 一致与主机授权标签完整；消费与调度登记受 `submitMu`（`sync.RWMutex`）保护，消除 `Drain` 窗口与孤儿 `QUEUED` 作业。
4. **一致的 AI Agent / MCP 体验**：平铺动作工具与渐进式元工具（`actions_invoke_read/write/dangerous`）统一通过共享响应构造器返回非错误（`isError: false`）的结构化 `pending_approval` 收据（含 32 KiB 预算裁剪与 `client_request_id` 幂等键），支持可选 `evidence` 与显式 `wait_seconds` / `jobs_get` 长轮询。
5. **`plugin/notifier` 扩展点与 `notifier.webhook`**：复用 `plugin.Host` 的出站白名单与凭据文件底座；对 `notifier` 强制 `https://`、允许 `POST`、**禁止一切重定向**（含 301/302/303 降级为 `GET`）、私网字面 IP 也须显式 `allow_private_egress: true`，插件边界严格映射固定错误类别，杜绝查询凭据/响应正文进入日志。
6. **全链路不可篡改审计与 UI/CLI 闭环**：审批请求、逐人表决、二次复核（提交前落盘）、批准、拒绝、撤回、过期全部写入 PostgreSQL v1 审计哈希链；补齐 `allowops approvals` CLI 与深色 redesign 风格控制台审批队列/详情页。

### 1.3 关键产品语义决策

| 决策项 | 定稿方案 | 理由 |
|---|---|---|
| **H1：数据模型** | **Job 新增 `JOB_STATUS_PENDING_APPROVAL = 8` + 独立 1:1 `approval_requests` 与 `approval_decisions` 表** | 保持 `job_id` 在提交即生成，复用 `jobs_get` / `jobs_cancel` / `ListTasks` 统一轮询与撤回链路，零新增 MCP 保留工具名；同时以独立表承载冻结载荷、多签投票与审批状态机。 |
| **H2：审批时修改参数** | **严格禁止修改**，且 `ApproveRequest` 强制携带 `expected_request_digest` | 保障“所见即所签”的密码学绑定；如需修改参数或目标，应拒绝并由发起人重新提交。 |
| **H3：默认/最大过期时间** | 网关默认 **`default_ttl: 30m`**、上限 **`max_ttl: 24h`**（可通过 `gateway.yaml` 配置 `1m..168h`）；规则级 `ttl_seconds` 须在 `[60, max_ttl]` 内 | 控制 JIT 窗口，避免陈旧审批在生产状态漂移后放行。 |
| **H4：服务账号 owner 自审批与令牌签发者 SoD** | **默认禁止 owner 自审批（`allow_owner_approve: false`）**；仅当全部命中规则显式设置 `allow_owner_approve: true` 时豁免服务账号 owner（且若令牌由第三方管理员签发，仍禁止该签发者审批）；人类发起的请求永远禁止本人审批 | 兼顾严格默认职责分离与小团队显式 opt-in 落地。 |
| **H5：默认角色最小权限** | 首次初始化 `DefaultRules()` 仅向 **`admin`** 授予 `view_approvals` 与 `approve_jobs`；不自动向 `operator`/`auditor`/`viewer` 开放原始参数与证据读取；升级绝不静默修改既有数据库策略 | 审批详情包含 `params_json`、`filters_json` 与 `evidence`，遵守最小暴露原则（Major #4）。 |

---

## 2. 不可突破的安全与工程红线

1. **No Shell & 签名目录不变量不变**：审批只控制网关是否允许进入调度队列，绝不绕过签名目录验签、参数强类型校验、`expected_count`、`max_targets`、主机端二次验签与输出脱敏。
2. **严格防 TOCTOU**：
   - `selector` 仅在提交时解析为有序、不可变的 `target_host_ids`；批准与二次复核时**绝不**重新按 selector 解析主机。
   - 参数、过滤器先经严格解码与 `params.ParseGateway` / `executor.ParseFilters` 规范化，同一冻结对象写入 `params_json` / `filters_json`、`request_digest`、`tasks` 并直接用于最终派发 `TaskAssignment`。
   - 终审事务通过共享策略锁（`418005`）、共享目录发布锁（`418001`）与主机行级 `FOR SHARE` 锁，与并发策略保存/回滚、目录发布、主机删改严格串行化；必须同时核验原签名目录 `(catalog_id, catalog_version)` 仍未过期且当前活跃目录仍包含相同 `action_sha256` 的动作。
3. **零连接池死锁与全局无环锁序**：事务内一切数据库查询（策略、目录、用户/服务账号/凭据、主机、任务）均复用当前 `pgx.Tx`，绝不向业务连接池索取第二条连接；全路径遵守统一锁序。
4. **防竞态重放与孤儿作业**：行级 `FOR UPDATE` + 条件更新（`status = 1 AND consumed_at IS NULL`、`jobs.status = 8`）+ `consume_nonce` 提交确认 + `submitMu` (`sync.RWMutex`) 排空屏障，确保单次审批严格至多执行一次且不遗留无人调度的 `QUEUED` 作业。
5. **防 UI 注入 / XSS / 终端转义注入**：控制台在 `UntrustedBanner` 下以纯文本渲染 `reason`、`evidence.summary`、`decision_reason`（禁止 `dangerouslySetInnerHTML`、Markdown 解析与 `i18next` `t()`）；CLI 对所有外部文本字段转义控制字符与 ANSI 转义序列。
6. **Webhook 出站零泄漏**：`notifier` 命名空间强制 `https://`、禁止一切 HTTP 重定向、私网/回环字面 IP 也须显式 `allow_private_egress: true`，插件边界屏蔽 `*url.Error`、查询凭据与上游响应正文。

---

## 3. OPA 策略模型扩展（`require_approval`）

### 3.1 新增授权操作（`authz.Operation`）

在 [internal/gateway/authz/types.go](../internal/gateway/authz/types.go) 新增两项操作并加入 `policy.rego` 的 `action_filtered_operations`：

| 操作名 | 语义 | 作用域 | `DefaultRules()`（仅首次初始化） |
|---|---|---|---|
| `view_approvals` | 查看他人的审批请求队列与详情（含参数、过滤器与证据；发起人始终可查看自己的审批） | 支持按 `actions`/`risks`/`host_labels` 过滤；列表授权逐项、逐目标主机执行 | 仅 `admin` |
| `approve_jobs` | 批准或拒绝他人的审批请求 | 必须提供具体 `action` 与审批单的**每一台冻结目标主机**并全部评估为 `allow` | 仅 `admin` |

> `bootstrap_admins` 仍仅作用于 `modify_policy`，绝不授予 `execute_action`、`view_approvals` 或 `approve_jobs`。

### 3.2 规则结构与校验约束

- `authz.Rule.Effect` 允许 `"allow"` | `"deny"` | `"require_approval"`（proto `PolicyEffect_POLICY_EFFECT_REQUIRE_APPROVAL = 3`）。
- `authz.Rule.Approval *ApprovalConfig`（仅 `effect == "require_approval"` 时允许）：

```go
type ApprovalConfig struct {
	ApproverRoles     []string `json:"approver_roles,omitempty"`
	MinApprovals      int      `json:"min_approvals,omitempty"`
	TTLSeconds        int      `json:"ttl_seconds,omitempty"`
	AllowOwnerApprove bool     `json:"allow_owner_approve,omitempty"`
}

type EffectiveApproval struct {
	RequiredApproverRoleSets [][]string `json:"required_approver_role_sets,omitempty"`
	MinApprovals             int        `json:"min_approvals"`
	TTLSeconds               int        `json:"ttl_seconds,omitempty"`
	AllowOwnerApprove        bool       `json:"allow_owner_approve,omitempty"`
}
```

**校验约束**（`authz.newEngine`、`api.rulesFromProto`、`allowops policy` 共同强制）：
1. `effect == "require_approval"` 时，`operations` **必须**恰好为 `["execute_action"]`；否则拒绝。
2. `effect != "require_approval"` 时，设置 `approval != nil` 一律拒绝。
3. `approval.min_approvals`：省略视为 `1`；显式指定须在 `[1, 5]`。
4. `approval.ttl_seconds`：省略为 `0`（运行时取网关 `approvals.default_ttl`）；显式指定须在 `[60, 604800]`（在 `api` 保存策略时再校验不超过当前网关 `approvals.max_ttl`，防止误配超过上限的规则）。
5. `approval.approver_roles`：最多 16 项，每项匹配 `^[a-zA-Z0-9._-]{1,64}$`，禁止 `"*"`，禁止重复；入引擎时排序去重以保证确定性。

### 3.3 固定 Rego 优先级、结果聚合与深拷贝

[internal/gateway/authz/policy.rego](../internal/gateway/authz/policy.rego)：

```rego
action_filtered_operations := {"execute_action", "view_catalog", "view_jobs", "view_output", "view_approvals", "approve_jobs"}

effects := {rule.effect | some rule in matched}

decision := "deny" if {
	"deny" in effects
} else := "require_approval" if {
	"require_approval" in effects
} else := "allow" if {
	"allow" in effects
} else := "deny"
```

- **保留 `policy.rego` 返回结构** `{"decision": decision, "rules": sort(rule_ids)}`，不破坏既有 `policy_test.rego`。
- `Engine` 在编译时保留 `approvalByRule map[string]ApprovalConfig`；当 `Evaluate` 返回 `"require_approval"` 时，按命中的所有 `require_approval` 规则 ID 计算 `Result.Approval`（`EffectiveApproval`）：
  - `RequiredApproverRoleSets`：每条含非空 `ApproverRoles` 的命中规则贡献一个已排序去重的角色集（整组去重排序）；审批人须**同时满足每一个角色集**（组间 AND、组内 OR）。
  - `MinApprovals`：所有命中 `require_approval` 规则的**最大值**（默认 1）。
  - `TTLSeconds`：所有显式设置了 `TTLSeconds > 0` 的命中规则的**最小值**（若均未设置则为 0，由网关应用 `default_ttl`）。
  - `AllowOwnerApprove`：所有命中 `require_approval` 规则的**逻辑 AND**。
- `EvaluateBatch`（[internal/gateway/authz/batch.go](../internal/gateway/authz/batch.go)）必须**深拷贝** `Result.Approval`（含嵌套 `[][]string`），防止调用方修改缓存。
- `TestPolicy` / `Simulate` / `verifyEnvironment`：
  - 更新 `decision()` 映射 `require_approval` 与 `PolicyApprovalRequirement`。
  - `consoleOperations` 与 `actionViewOperations` 纳入 `ViewApprovals` 与 `ApproveJobs`；显式 `PolicyTestCase` 使用 `approve_jobs` 时强制要求提供 `action` 与 `targets`（同 `execute_action`）。
  - 仅修改 `approval` 配置（如 `min_approvals` 1→2 或变更 `approver_roles`）也会触发 `before != after` 并呈现在变更列表中。
- **MCP 发现投影**：
  - `projectRules`（`cache.go`）保留 `require_approval` 规则（同样剥离 `host_labels`/`hours`/`source_cidrs`）。
  - `buildView` 将 `allow` 与 `require_approval` 动作均视为对当前身份可见可执行。
  - `AllowedActionsOnHost` 保持 `ViewHosts` 与 `HOST_UNLABELED` 拒绝不变量，返回 `map[string]string`（动作名 → `"allow"` 或 `"require_approval"`）；`actions_search(hostname=...)` 在单条结果中对 `"require_approval"` 动作输出 `requires_approval: true`，并将每个匹配动作的 `requires_approval` 状态纳入 `actionsSnapshot` 哈希，保证策略切换时分页游标自动失效。

---

## 4. 数据库 Schema 与迁移（`00010_approvals.sql`）

> 若并行分支先占用 `00010`，合入前顺延为 `00011` 并同步 `store.SchemaVersion`。

```sql
-- +goose Up
ALTER TABLE jobs DROP CONSTRAINT jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check CHECK (status BETWEEN 1 AND 8);
CREATE INDEX jobs_pending_approval ON jobs(created_at DESC, job_id) WHERE status = 8;

ALTER TABLE service_account_tokens
    ADD COLUMN created_by_user_id text NOT NULL DEFAULT '';

CREATE TABLE approval_sequences (
    day date PRIMARY KEY,
    value bigint NOT NULL CHECK (value > 0)
);

CREATE TABLE approval_requests (
    approval_id text PRIMARY KEY,
    job_id text NOT NULL UNIQUE REFERENCES jobs(job_id),
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    status smallint NOT NULL CHECK (status BETWEEN 1 AND 6),
    action text NOT NULL,
    action_risk text NOT NULL CHECK (action_risk IN ('read', 'write', 'dangerous')),
    catalog_id text NOT NULL,
    catalog_version bigint NOT NULL,
    action_sha256 bytea NOT NULL CHECK (octet_length(action_sha256) = 32),
    params_json bytea NOT NULL,
    filters_json bytea NOT NULL,
    target_selector text NOT NULL DEFAULT '',
    target_hosts jsonb NOT NULL,
    batch_size integer NOT NULL CHECK (batch_size > 0),
    max_failures integer NOT NULL CHECK (max_failures >= 0),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    requester_subject_id text NOT NULL,
    requester_kind text NOT NULL CHECK (requester_kind IN ('service_account', 'ldap', 'oidc')),
    requester_email text NOT NULL DEFAULT '',
    requester_owner_id text NOT NULL DEFAULT '',
    requester_credential_id text NOT NULL DEFAULT '',
    requester_token_issuer_id text NOT NULL DEFAULT '',
    requester_source_ip text NOT NULL DEFAULT '',
    client_request_id text NOT NULL DEFAULT '',
    reason text NOT NULL,
    evidence_job_ids text[] NOT NULL DEFAULT '{}',
    evidence_summary text NOT NULL DEFAULT '',
    policy_version bigint NOT NULL,
    matched_rules text[] NOT NULL DEFAULT '{}',
    required_approver_roles jsonb NOT NULL DEFAULT '[]'::jsonb,
    min_approvals integer NOT NULL CHECK (min_approvals BETWEEN 1 AND 5),
    allow_owner_approve boolean NOT NULL DEFAULT false,
    approved_count integer NOT NULL DEFAULT 0 CHECK (approved_count >= 0),
    decided_at timestamptz,
    decided_by text NOT NULL DEFAULT '',
    decision_reason text NOT NULL DEFAULT '',
    consumed_at timestamptz,
    consumed_by_instance text NOT NULL DEFAULT '',
    consume_nonce text NOT NULL DEFAULT '',
    recheck_policy_version bigint,
    recheck_error text NOT NULL DEFAULT '',
    notify_seq bigint NOT NULL DEFAULT 0,
    notify_status text NOT NULL DEFAULT 'skipped' CHECK (notify_status IN ('skipped', 'sent', 'partial_failed', 'failed')),
    notify_error text NOT NULL DEFAULT '',
    CHECK (expires_at > created_at),
    CHECK (approved_count <= min_approvals)
);
CREATE INDEX approval_requests_pending_expires ON approval_requests(expires_at) WHERE status = 1;
CREATE INDEX approval_requests_requester_created ON approval_requests(requester_subject_id, created_at DESC, approval_id);
CREATE INDEX approval_requests_created ON approval_requests(created_at DESC, approval_id);
CREATE UNIQUE INDEX approval_requests_client_request ON approval_requests(requester_subject_id, client_request_id) WHERE client_request_id <> '';

CREATE TABLE approval_decisions (
    approval_id text NOT NULL REFERENCES approval_requests(approval_id),
    actor_id text NOT NULL,
    actor_email text NOT NULL DEFAULT '',
    decision smallint NOT NULL CHECK (decision IN (1, 2)),
    reason text NOT NULL DEFAULT '',
    decided_at timestamptz NOT NULL,
    policy_version bigint NOT NULL,
    matched_rules text[] NOT NULL DEFAULT '{}',
    PRIMARY KEY (approval_id, actor_id)
);
```

**运行时数据库最小权限**（维护角色执行迁移后由 DBA 授予）：
- `approval_sequences`：`SELECT, INSERT, UPDATE`
- `approval_requests`：`SELECT, INSERT, UPDATE`（无 `DELETE`）
- `approval_decisions`：`SELECT, INSERT`（只追加，无 `UPDATE` / `DELETE`）
- `service_account_tokens`：既有 `SELECT, INSERT, UPDATE` 不变。

---

## 5. 状态机、精确绑定、无环锁序与二次复核

### 5.1 统一规范化冻结载荷与 `request_digest`

在 `RunJob` 入口，先通过 `params.ParseGateway` 与 `executor.ParseFilters` 严格解码与校验，并序列化为统一的规范化结构体（保留可选过滤字段存在性，由同一冻结对象同时生成摘要、写库与最终构造 `TaskAssignment`）：

```go
type frozenFilters struct {
	Match   *string `json:"match,omitempty"`
	Exclude *string `json:"exclude,omitempty"`
	Tail    *uint32 `json:"tail,omitempty"`
	Head    *uint32 `json:"head,omitempty"`
	Count   *bool   `json:"count,omitempty"`
}

type canonicalApprovalRequest struct {
	Version        int             `json:"v"` // 1
	Action         string          `json:"action"`
	ActionRisk     string          `json:"action_risk"`
	CatalogID      string          `json:"catalog_id"`
	CatalogVersion int64           `json:"catalog_version"`
	ActionSHA256   string          `json:"action_sha256"`
	Params         json.RawMessage `json:"params"`  // catalog.CanonicalJSON(parsedParams)
	Filters        json.RawMessage `json:"filters"` // catalog.CanonicalJSON(frozenFilters)
	TargetHostIDs  []string        `json:"target_host_ids"` // ordered by tasks.position
	BatchSize      uint32          `json:"batch_size"`
	MaxFailures    uint32          `json:"max_failures"`
}
```

`request_digest = sha256(catalog.CanonicalJSON(canonicalApprovalRequest))`（32 字节）。

### 5.2 全局无环锁序与零连接池耗尽约束

**全系统严格锁序（由高到低，严禁逆序）**：

1. `pg_advisory_xact_lock_shared(418005)`（策略写锁共享态 — 终审专用；与 `persistPolicy` 的排他锁 `418005` 串行）
2. `pg_advisory_xact_lock_shared(418001)`（目录发布锁共享态 — 终审专用；与 `PublishTx` 的排他锁 `418001` 串行）
3. `LockJobPartitionCreation`（`418006` — 仅创建作业时）
4. `LockJobSubject(requester)`（`hashtextextended(requester, 418006)` — 创建作业与终审）
5. `approval_requests FOR UPDATE`
6. `jobs FOR UPDATE`
7. `hosts FOR SHARE`（按 `host_id` 升序 — 终审专用；与 `SetHostLabels`/`DeleteHost` 的 `hosts FOR UPDATE` 串行，与 `persistPolicy` 的 `SHARE` 表锁兼容）
8. `tasks` / `approval_decisions` 读写

**事务内零额外池连接规则**：
- 终审、拒绝、撤回、过期、创建事务内，一切读操作（策略版本、策略规则、当前目录、主机标签、用户/服务账号、凭据有效性、历史投票）全部经当前 `pgx.Tx`（`db.DBTX`）执行，绝不调用 `s.Store.Pool` 或 `s.refresh()`。
- 若终审在事务内读到 `currentPolicyVersion > cachedEngine.version`，直接在 `tx` 上读取 `GetPolicyVersion(ctx, tx, 0)` 并在内存编译 `authz.Engine` 进行纯内存求值，绝不取第二条连接（以 `MaxConns=1` 单连接池集成测试强制验证）。
- `Audit.Append` 使用生产独立审计连接池（`auditPoolConns=6`），不与业务连接池竞争。

### 5.3 人员级职责分离（SoD）规则

构造每个人的规范身份键集合：`personKeys(userID, verifiedEmail)`:
- 始终包含 `"uid:" + userID`
- 若 `verifiedEmail != ""`（由认证源签发并存储于 `console_users.email`），额外包含 `"email:" + strings.ToLower(strings.TrimSpace(verifiedEmail))`

检查规则（任一交集非空即拒绝）：
1. **人类审批人限定**：`approver.Subject.Kind == "service_account" || approver.User == nil` → `HUMAN_APPROVER_REQUIRED`。
2. **禁止自审批**：`personKeys(approver) ∩ personKeys(requester)` 非空 → `SELF_APPROVAL_FORBIDDEN`。
3. **服务账号 owner 与令牌签发者 SoD**：
   - 加载提交期 `requester_owner_id` 与当前库内 `service_accounts.owner_user_id`（及各自邮箱），以及令牌签发者 `requester_token_issuer_id`（及其邮箱）。
   - 若审批人命中**非 owner 的第三方令牌签发者**：**无条件拒绝** `SELF_APPROVAL_FORBIDDEN`（防止 `manage_service_accounts` + `approve_jobs` 共谋绕过）。
   - 若审批人命中提交期 owner 或当前 owner：仅当 `effectiveAllowOwnerApprove == true`（冻结约束与当前策略逻辑 AND 均为 `true`）才放行，否则 `SELF_APPROVAL_FORBIDDEN`。
4. **多人审批去重（`min_approvals > 1`）**：审批人 `personKeys(approver)` 与所有已有投票人 `personKeys(voter)` 交集非空 → `ALREADY_APPROVED_BY_ACTOR`（禁止同一自然人用双账号投两票）。
5. **不可改票**：`approval_decisions` 为只追加表（主键 `(approval_id, actor_id)`，运行时角色无 `UPDATE` 权限）；同一审批人不能覆盖既有投票，如需终止须由其他审批人拒绝或由发起人/管理员撤回。

### 5.4 关键路径流程

#### 路径 A：提交审批（`RunJob` 命中 `require_approval`）
1. 校验 `reason`、`params`、`filters`、`targets`、`expected_count`、`max_targets`、可选 `client_request_id`（`^[a-zA-Z0-9._-]{1,64}$`）与可选 `evidence`：
   - `evidence` 校验在**隔离的 `operationState` 上下文**中执行，绝不污染父 `RunJob` 的审计 `JobID`/`Version`/`Rules`；仅将 `NotFound`/`PermissionDenied` 统一折叠为 `CodeInvalidArgument (INVALID_EVIDENCE_JOB)`，`Unavailable` 原样返回。
   - `evidence.summary`（≤ 1024 字符 / 4096 字节、合法 UTF-8、无 `\x00`）经 `redact.New(nil)` 脱敏后存储；`reason` 同样严格校验合法 UTF-8 与无 `\x00`。
2. 逐台 `RequireBatch` 判定：任意 `deny` → 创建 `JOB_STATUS_DENIED`；零 `deny` 且至少一台 `require_approval` → 聚合跨主机 `EffectiveApproval`，进入审批提交流程。
3. 预写授权审计 `run_job`（`phase: "authorized"`, `decision: "require_approval"`, `action: a.Name`）。
4. 获取 `s.submitMu.RLock()`，检查 `!s.draining.Load()`：
   - 开启事务，依次取 `LockJobPartitionCreation` → `LockJobSubject(requester)`。
   - 若提供 `client_request_id`：先查 `(requester_subject_id, client_request_id)`；若已存在且 `request_digest` 相同，直接返回该既有 Job/Approval（幂等重试）；若 `request_digest` 不同，返回 `CodeAlreadyExists (CLIENT_REQUEST_ID_CONFLICT)`。
   - 检查限流：`max_pending_per_subject`（默认 10，按 `status = 1 AND expires_at > clock_timestamp()` 计）与 `max_pending_global`（默认 1000）。
   - 写入 `jobs`（`status = 8`）、`tasks`（`status = 1, dispatched = false`）与 `approval_requests`（含 `requester_credential_id`、`requester_token_issuer_id`、`requester_email`、`request_digest`）。
   - 在事务提交前追加 `request_approval` 审计（`reason: "digest=" + hex`, `decision: "require_approval"`, `resource: "approval:" + id`, `action: a.Name`），提交事务（`WithoutCancel` 5s 超时 + `jobCommitted` 校验）。
   - 释放 `s.submitMu.RUnlock()`。
5. 设置 `operationState{JobID, Resource: "approval:" + id, Action: a.Name, Outcome: "require_approval", Committed: true}`（使外层结果审计准确记录 `decision: "require_approval"` 与 `action`）。
6. 异步投递 `approval.requested` 通知（`notify_seq = 1`）。
7. `wait_seconds` 语义：省略或为 0 时立即返回 `pending_approval`；显式 `> 0` 时轮询等待至脱离 `PENDING_APPROVAL`（若被批准则继续在剩余时间内等待执行完成）。

#### 路径 B：审批通过（`ApproveRequest`）
1. `CheckRequest(ctx, true)` + 人类审批人检查 + 校验 `expected_request_digest`（必填 32 字节）与 `reason`（≤ 1024 字符、合法 UTF-8、无 `\x00`）。
2. 无锁读取不可变映射 `(job_id, requester_subject_id)`（不存在则 `APPROVAL_UNKNOWN`）。
3. 获取 `s.submitMu.RLock()`（持有至最终提交并登记 `s.activeJobs`/`s.wg` 完成，防止与 `Drain` 竞态！），检查 `!s.draining.Load()`。
4. 开启事务，严格按无环锁序加锁：
   - `pg_advisory_xact_lock_shared(418005)`（策略共享锁）
   - `pg_advisory_xact_lock_shared(418001)`（目录共享锁）
   - `LockJobSubject(tx, requester_subject_id)`
   - `SELECT ... FROM approval_requests WHERE approval_id = $1 FOR UPDATE`
   - `SELECT ... FROM jobs WHERE job_id = $2 FOR UPDATE`
   - `SELECT ... FROM hosts WHERE host_id = ANY($1) ORDER BY host_id FOR SHARE`
5. 在锁内执行全量核验（全部使用 `tx`）：
   - `approval.status != 1 || job.status != 8` → 回滚返回 `APPROVAL_NOT_PENDING`。
   - **实际墙钟过期检查**：`now := time.Now().UTC()`（不依赖事务开始时间的 `now()`），若 `!now.Before(approval.expires_at)` → 原子推进 `approval -> EXPIRED (4)`、`job -> DENIED (7)`、pending tasks → `CANCELLED (APPROVAL_EXPIRED, output_state='unavailable')`，预写 `expire_approval` 审计后提交，返回 `APPROVAL_EXPIRED`。
   - **摘要与载荷完整性核验**：常量时间校验 `expected_request_digest == approval.request_digest`；核对 `tasks` 按 `position` 排序的 `host_id` 列表与 `approval.target_hosts` 一致、`jobs` 的目录引用与 `action_sha256` 一致，重算 `canonicalApprovalRequest` 核对无偏差。
   - **SoD 校验**（第 5.3 节）。
   - **加载事务内一致的当前策略引擎**（读 `GetPolicyVersion(tx, 0)`，若与缓存版本一致复用内存引擎，否则在内存编译），校验本次审批人对每台冻结主机 + 动作拥有 `approve_jobs == "allow"` 且满足 `approval.required_approver_roles`。
   - **预写授权审计**：追加 `approve_job`（`phase: "authorized", decision: "allow", resource: "approval:"+id, job_id, action`）；失败则回滚。
   - **写入本票**：`INSERT INTO approval_decisions(...)`（并发/重复由主键拦截）。
   - **汇总有效投票并评估终审条件**：
     - 读取当前 `approval_decisions` 中全部 `decision == 1` 的赞成票（含本次）。
     - 若初步票数 `< approval.min_approvals`（尚未达到冻结门槛）：更新 `approved_count`，提交事务，释放 `submitMu.RUnlock()`，返回 `PENDING`。
     - **当票数达到冻结 `min_approvals`（可能达成终审）→ 执行完整二次复核**：
       1. **目录与动作复核（在 `tx` 上）**：
          - 校验原 `(catalog_id, catalog_version)` 签名信封仍有效未过期；
          - 校验当前活跃目录仍包含 `approval.action` 且 `currentDigest == approval.action_sha256`；任一不符 → `RECHECK_CATALOG_CHANGED`。
       2. **提交凭据与发起人当前主体复核（在 `tx` 上）**：
          - 校验 `requester_credential_id`（对应 `service_account_tokens.token_id` 或 `identity_sessions.session_id`）仍未吊销且 `expires_at > clock_timestamp()`；否则 → `RECHECK_CREDENTIAL_REVOKED`。
          - 重新加载发起人最新 `authz.Subject`（含最新角色/团队/owner）；若主体不存在 → `RECHECK_REQUESTER_INVALID`。
       3. **目标主机与最新 OPA 策略复核**：
          - 每台冻结主机必须仍为 `certificate_status == 'active'`（否则 `RECHECK_HOST_DELETED`）且 `len(authorization_labels) > 0`（否则 `RECHECK_HOST_UNLABELED`）。
          - 用当前最新策略引擎、发起人当前 `Subject`、实际当前时间 `now`、`approval.requester_source_ip` 逐台评估 `ExecuteAction`：
            - 任意主机为 `deny` → `RECHECK_POLICY_DENIED`。
            - 合并冻结约束与当前策略返回的 `require_approval` 约束（**严格单调叠加**；即使当前策略回滚为 `allow`，仍必须满足提交时冻结的约束！）：
              - `effMin = max(frozen.min_approvals, current.min_approvals)`
              - `effRoleSets = union(frozen.required_approver_roles, current.required_approver_roles)`
              - `effAllowOwner = frozen.allow_owner_approve && current.allow_owner_approve`（若当前策略无 `require_approval`，沿用 `frozen.allow_owner_approve`）
       4. **逐票重验全部赞成票**：
          - 对每一张历史赞成票与本次投票，从 `tx` 重载该投票人当前 `Subject` 与 `email`，逐一重验：SoD（含 `effAllowOwner` 与人员级去重）、逐台 `approve_jobs == "allow"`、满足 `effRoleSets`。
          - 统计仍有效的独立自然人赞成票数 `validVotes`：
            - 若 `validVotes < effMin`：
              - 若本次审批人自身不满足新收紧的 `effRoleSets` 或有效票不足且无机会满足 → 若因策略收紧或早期投票人失权导致当前不足法定票数，可选择：若当前有效票 `< effMin`，更新 `approved_count = validVotes` 保持 `PENDING` 等待补充新审批人（**或**明确返回 `RECHECK_POLICY_TIGHTENED` 拒绝执行 — 为防止已过期/失效的早期投票混淆审批进度，当达到原 `min_approvals` 但因策略收紧或早期票失效导致 `validVotes < effMin` 时，直接转 `EXECUTION_DENIED (RECHECK_POLICY_TIGHTENED)` 并要求重新发起，状态语义最清晰、零歧义！）。
       5. **复核失败处理**：
          - 事务内更新 `approval -> EXECUTION_DENIED (6)`、`job -> DENIED (7)`、pending tasks → `CANCELLED (RECHECK_DENIED, output_state='unavailable')`；
          - **提交前**追加 `approval_recheck`（`decision: "deny"`, `reason: recheckCode`）审计；
          - 提交事务，释放 `submitMu.RUnlock()`，返回 `CodeFailedPrecondition (recheckCode)`。
       6. **复核通过 → 原子消费与调度**：
          - 再次用实际墙钟校验 `time.Now().UTC().Before(approval.expires_at)`（若临界过期按过期分支处理）。
          - 若发起人为 `service_account`，校验 `CountActiveJobsBySubject(tx, requester) < 5`（若超限则回滚且不消费审批，返回 `CodeResourceExhausted / CONCURRENT_JOB_LIMIT`）。
          - 生成随机 `consumeNonce`，执行条件更新：
            - `UPDATE approval_requests SET status=2, approved_count=$2, decided_at=clock_timestamp(), decided_by=$3, decision_reason=$4, consumed_at=clock_timestamp(), consumed_by_instance=$5, consume_nonce=$6, recheck_policy_version=$7 WHERE approval_id=$1 AND status=1 AND consumed_at IS NULL`（断言 `RowsAffected == 1`）
            - `UPDATE jobs SET status=1, origin_instance=$2, policy_version=$3 WHERE job_id=$1 AND status=8`（断言 `RowsAffected == 1`）
          - **提交前**追加 `approval_recheck`（`decision: "allow"`, `reason: "digest="+hex`）审计（失败则回滚，绝不产生无审计的放行）。
          - 用 `WithoutCancel` 5s 超时提交事务；若 Commit 返回网络错误，查询 `(approval_id, status=2, consume_nonce=ourNonce)` 确认是否已落库。
          - 若已落库：在仍持有 `s.submitMu.RLock()` 期间登记 `s.activeJobs.Add(1)`、`s.wg.Add(1)` 并启动 `go s.schedule(...)`（使用冻结的 `params_json` / `filters_json` / `batch_size` / `max_failures`），再释放 `s.submitMu.RUnlock()`！
          - 异步投递 `approval.approved` 通知（递增 `notify_seq`）。

#### 路径 C：拒绝、撤回/取消与自动过期
- **拒绝（`RejectRequest`）**：仅人类审批人；必填 `reason`（1..1024 字符、UTF-8、无 `\x00`）；事务内按 `approval_requests FOR UPDATE → jobs FOR UPDATE` 加锁，校验 `PENDING`、墙钟未过期、SoD、当前策略下逐台 `approve_jobs == "allow"` 与 `required_approver_roles`、未重复投票；预写授权审计 → 插入 `approval_decisions(decision=2)` → `approval -> REJECTED (3)`、`job -> DENIED (7)`、tasks → `CANCELLED (APPROVAL_REJECTED, output_state='unavailable')` → 提交并异步通知 `approval.rejected`。
- **撤回 / 取消（`CancelApproval` 与 `CancelJob`）**：
  - `CancelJob` 在进入既有 `LockJobForCancel` 之前，先无锁查 `SELECT approval_id FROM approval_requests WHERE job_id = $1`；若存在关联审批单，先锁 `approval_requests FOR UPDATE` 再锁 `jobs FOR UPDATE`（严格遵守无环锁序！）。若审批单仍为 `PENDING` 且 `job.status == 8`，执行待审批撤回逻辑；若已批准进入 `QUEUED/RUNNING`，直接沿既有已持有的 `jobs` 锁走原取消流程。
  - **撤回权限**：发起人本人（无论是 `service_account` 还是人类 `oidc`/`ldap` 用户，即使没有 `execute_action=allow`）始终可撤回自己的 `PENDING_APPROVAL` 请求；其他用户撤回他人待审批请求须对全部目标主机拥有 `execute_action == "allow"`。
- **自动过期 Sweeper**：`job.Service.Start()` 按 `approvals.sweep_interval` 周期扫描 `WHERE status = 1 AND expires_at <= clock_timestamp() ORDER BY expires_at LIMIT 50 FOR UPDATE SKIP LOCKED`，锁序 `approval_requests → jobs → tasks`，提交前写 `expire_approval` 审计，提交后异步通知 `approval.expired`。

---

## 6. AI Agent / MCP 交互契约与 Elicitation 评估

### 6.1 MCP Elicitation 兼容性评估

- `github.com/modelcontextprotocol/go-sdk v1.8.0` 的 `StreamableHTTPOptions{Stateless: true}` 明确拒绝一切 server → client 请求（包括 `ServerSession.Elicit`），且 allowops 审批为跨身份多方职责分离（非 MCP 客户端本地交互），而 `URLElicitationRequiredError` 作为协议错误易引发客户端重试风暴。
- **定稿方案**：平铺工具与渐进式元工具（`actions_invoke_read/write/dangerous`）在 `runAction` 与 `jobs_get` 中共用 `pendingApprovalResult` 构造器，返回 **`IsError: false`** 的结构化 `pending_approval` 收据 + `console_url` + 明确禁止盲目重试的 `hint`，配合可选 `client_request_id`（幂等防重）与 `jobs_get(job_id, wait_seconds=30)` 长轮询。

### 6.2 输入扩展与 32 KiB 预算保证

- 平铺工具与 `actions_invoke_*` 共同新增两个可选顶层参数（`additionalProperties: false`）：
  - `evidence`: `{ job_ids?: string[] (1..5), summary?: string (1..1024) }`
  - `client_request_id`: `string`（`^[a-zA-Z0-9._-]{1,64}$`，用于断线或结果审计失败后的幂等安全重试）
- **32 KiB 预算裁剪**：`pendingApprovalResult` 经 `toolResult()` 测量完整编码字节数；始终保留 `job_id`、`approval_id`、`status`、`expires_at`、`console_url`、`output_trust` 核心字段，若 `required_approver_roles` 过多接近 32 KiB，自动截断并标记 `details_truncated: true`，绝不因元数据膨胀导致已提交审批单返回 `ResourceExhausted`。
- **`jobs_list` / `jobs_cancel` / `jobs_diff` / `GetJobOutput` 联动**：
  - `jobs_list` / `jobs_cancel` 的 `jobMetadata` 输出 `status: "pending_approval"` 及可选 `approval_id`。
  - `jobs_diff` 拒绝 `JOB_STATUS_PENDING_APPROVAL`（`DIFF_JOB_NOT_FINISHED`）。
  - `GetJobOutput` 对 `JOB_STATUS_PENDING_APPROVAL` 返回明确错误 `JOB_PENDING_APPROVAL`。
  - `jobs_get(job_id, wait_seconds)` 在等待后重验 `ViewOutput` 权限并返回最终摘要或审批终态。

---

## 7. 通知扩展点（`plugin/notifier`）与 `extensions/notifier/webhook`

### 7.1 `plugin/notifier` 接口

```go
package notifier

import (
	"context"
	"time"
)

type EventType string

const (
	EventApprovalRequested EventType = "approval.requested"
	EventApprovalApproved  EventType = "approval.approved"
	EventApprovalRejected  EventType = "approval.rejected"
	EventApprovalExpired   EventType = "approval.expired"
	EventApprovalCancelled EventType = "approval.cancelled"
)

type Event struct {
	Type                     EventType  `json:"type"`
	EventID                  string     `json:"event_id"`
	At                       time.Time  `json:"at"`
	ApprovalID               string     `json:"approval_id"`
	JobID                    string     `json:"job_id"`
	Action                   string     `json:"action"`
	Risk                     string     `json:"risk"`
	Requester                string     `json:"requester"`
	TargetCount              int        `json:"target_count"`
	SampleHosts              []string   `json:"sample_hosts,omitempty"`
	RequiredApproverRoleSets [][]string `json:"required_approver_role_sets,omitempty"`
	MinApprovals             int        `json:"min_approvals"`
	ApprovedCount            int        `json:"approved_count"`
	ExpiresAt                time.Time  `json:"expires_at"`
	ConsoleURL               string     `json:"console_url"`
	Actor                    string     `json:"actor,omitempty"`
	Status                   string     `json:"status"`
}

type Sender interface {
	Send(ctx context.Context, event Event) error
}
```

### 7.2 `pluginhost` 出站加固与优雅关闭

1. **`notifier` 专属严格出站策略（`egress.go`）**：
   - 允许 `POST`（`inventory`/`changes`/`knowledge` 仍严格仅 `GET`/`HEAD`）。
   - **强制 `https://`**：`notifier` 实例配置 `http://` egress 启动即拒绝。
   - **禁止一切重定向**：`notifier` 的 `checkRedirect` 无条件返回 `errEgress`（无论 `301`/`302`/`303`/`307`/`308`）。
   - **私网/回环字面 IP 不可豁免**：`notifier` 模式下 `allowedIP` 要求私网与回环字面 IP 同样须显式配置 `allow_private_egress: true`（测试环境内网/回环 `httptest.NewTLSServer` 显式开启 `allow_private_egress: true` + `ca_file`）。
2. **零凭据泄漏错误处理（`extensions/notifier/webhook`）**：
   - `webhook.Send` 捕获所有 `http.Client.Do` 错误并映射为固定静态类别（`"notifier webhook: transport error"`、`"notifier webhook: status 4xx"`、`"notifier webhook: status 5xx"`、`"notifier webhook: upstream rejected"`），**严禁**返回或记录原始 `*url.Error`、完整 URL（含钉钉 `access_token` / 企微 `key`）、响应正文或凭据。
   - 响应体最多读取 4 KiB 仅用于判定状态码与钉钉/飞书/企微业务错误码。
   - 支持格式：`json`（默认）、`slack`、`dingtalk`、`feishu`、`wecom`；支持签名：`none`、`hmac_sha256`、`bearer`、`dingtalk_timestamp`、`feishu_timestamp`；支持可选 `token_query_param` + `token_ref` 从 `Host.Credential(ref)` 注入查询令牌。
3. **优雅关闭顺序与单调状态回写**：
   - 网关关闭顺序：`srv.Shutdown` → `jobs.DrainNotifications(5s)`（在 `pluginHost` 仍打开时停止入队并限时清空通知队列）→ `jobs.Close()` → `pluginHost.Close(5s)`。
   - 审批表使用 `notify_seq` 条件更新（`UPDATE approval_requests SET notify_seq=$2, notify_status=$3, notify_error=$4 WHERE approval_id=$1 AND notify_seq < $2`），防止较慢的 `approval.requested` 通知覆盖后续 `approval.approved` 的投递状态。

---

## 8. 协议 API、CLI、Web 控制台与升级说明

### 8.1 Protobuf / CLI / Web 控制台

- 新增 [api/proto/allowops/v1/approval.proto](../api/proto/allowops/v1/approval.proto)（`ApprovalService`：`ListApprovals`, `GetApproval`, `ApproveRequest`, `RejectRequest`, `CancelApproval`），扩展 `common.proto`、`job.proto`、`policy.proto`。
- 网关挂载 `/allowops.v1.ApprovalService/`（复用 `s.Access.Middleware` 与 `job.Service`）。
- CLI 新增 `allowops approvals list|get|approve|reject`（所有外部文本字段均经控制字符/ANSI 转义输出；`approve` 默认交互确认并携带 `expected_request_digest`）；`allowops run` 新增 `--evidence-job`、`--evidence-summary`、`--client-request-id` 并正确处理 `JOB_STATUS_PENDING_APPROVAL`。
- Web 控制台新增 `/approvals/:approvalId?`（侧栏 `Run` 分组 + ⌘K 命令面板），严格区分“网关核验执行计划”与 `UntrustedBanner` 包裹的纯文本不可信理由/证据；`Policies.tsx` 支持 `require_approval` 规则表单与模拟对比；`Jobs.tsx` 支持 `JOB_STATUS_PENDING_APPROVAL`、关联审批跳转并修复 `job.reason` 纯文本渲染；重新构建嵌入式 `internal/gateway/console/dist/`。

### 8.2 升级顺序

1. 升级前确认 PostgreSQL 维护角色执行 `allowops-gateway migrate`（Schema 9 → 10），并为独立运行时数据库角色授予 `approval_sequences`（`SELECT, INSERT, UPDATE`）、`approval_requests`（`SELECT, INSERT, UPDATE`）、`approval_decisions`（`SELECT, INSERT`）。
2. 完成全部 `allowops-gateway` 实例二进制切换（旧版二进制因 `SchemaVersion` 校验无法在 Schema 10 上启动）。
3. 导出策略 `allowops policy get > rules.yaml`，按需添加 `view_approvals`、`approve_jobs` 与 `effect: require_approval` 规则，经 `allowops policy test -f rules.yaml` 试算确认后再 `allowops policy apply`。
4. 按需在 `gateway.yaml` 中配置 `approvals` 与 `notifier.webhook` 插件并重启网关生效。
