# 人工审批流与 JIT 临时提权实施计划（HITL Approval Plan）

基线分支：`feat/hitl-approval-jit`（基于 `origin/main` commit `62e4fda`）  
设计依据：[docs/hitl-approval-design.md](hitl-approval-design.md)

## 分阶段 Worktree 实施矩阵

为保持每个里程碑职责单一、可独立测试、合入零冲突，按依赖顺序分为 5 个里程碑（M1 → M2 → M3 → M4 → M5）。每个里程碑在独立 `worktree` 子会话中完成编码与本地验证，由总指挥逐阶段审查、合入主开发分支 `feat/hitl-approval-jit` 后再启动下一依赖里程碑（其中 M4 可与 M3 并行，因两者文件面几乎正交！）。

| 里程碑 | 目标范围 | 依赖 | 主要改动文件面 | 验收门禁 |
|---|---|---|---|---|
| **M1：Proto + OPA `require_approval` 策略引擎与模拟** | 扩展 Protobuf（`common.proto`, `policy.proto`, `job.proto`, 新增 `approval.proto`）并重新生成 `gen/` + `web/src/gen/`；扩展 `authz` 固定 Rego、规则校验、`EffectiveApproval`、`EvaluateBatch` 深拷贝、`DefaultRules`；扩展 `api/policy.go` 模拟/保存/回滚与 `cli/identity.go` YAML 读写；更新 `examples/policy/` | Stage 1-2 设计文档 | `api/proto/allowops/v1/*.proto`, `gen/`, `web/src/gen/`, `internal/gateway/authz/`, `internal/gateway/api/policy.go`, `internal/gateway/api/service.go`, `internal/gateway/api/job_access.go`, `internal/cli/identity.go`, `examples/policy/` | `make opa-test`; `go test -race ./internal/gateway/authz/... ./internal/gateway/api/... ./internal/cli/...` |
| **M2：DB 迁移 + 审批状态机 + Job 集成 + 审计 + Gateway 配置** | 新增 `00010_approvals.sql`（`SchemaVersion = 10`）、sqlc 查询与生成；在 `api` 增加凭据 `token_id`/`created_by_user_id` 传递与 TX 内策略/主体读取接口；在 `job` 落地完整审批状态机、无环锁序、单连接池事务二次复核、SoD（含邮箱与签发者）、`submitMu` `RWMutex`、`consume_nonce`、Sweeper、完整审计链与 `ApprovalService` Connect Handler；接入 `server.go` 与 `cmd/allowops-gateway/main.go`（`approvals` 配置节） | M1 | `internal/store/migrations/00010_approvals.sql`, `internal/store/store.go`, `internal/store/queries/*.sql`, `internal/store/db/`, `internal/gateway/reqctx/`, `internal/gateway/api/`, `internal/gateway/job/`, `internal/gateway/server/server.go`, `cmd/allowops-gateway/main.go` | `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/store/... ./internal/gateway/api/... ./internal/gateway/job/... ./internal/gateway/audit/... ./internal/gateway/server/... ./cmd/allowops-gateway/...`（含单连接池 `MaxConns=1` 与并发竞态压测） |
| **M3：MCP 交互 + `allowops approvals` CLI** | MCP `cache.go` 投影可见 `require_approval`、`AllowedActionsOnHost` 返回决策与 `actions_search` 快照绑定；平铺工具与 `actions_invoke_*` 统一支持 `evidence` / `client_request_id` 与 32 KiB 预算裁剪的非错误 `pending_approval` 收据；`jobs_get`/`jobs_list`/`jobs_cancel`/`jobs_diff` 适配；CLI 新增 `allowops approvals list/get/approve/reject`（ANSI 转义 + digest 强绑定）与 `allowops run` 适配 | M2 | `internal/gateway/mcp/`, `internal/gateway/api/mcp_actions.go`, `internal/cli/approvals.go`, `internal/cli/jobs.go`, `cmd/allowops/main.go` | `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/gateway/mcp/... ./internal/cli/...` |
| **M4：`plugin/notifier` 扩展点 + `extensions/notifier/webhook` + 异步投递接线** | 新增 `plugin/notifier` 包与 `plugintest.RunNotifierContract`；扩展 `pluginhost`（`notifier` 命名空间、`https://` 强制、允许 `POST`、禁重定向、私网字面 IP 拦截、`Host.Notify`）；实现 `extensions/notifier/webhook`（JSON/Slack/钉钉/飞书/企微 + 签名 + 零凭据泄漏错误映射）并注册至 `extensions/standard`；接入 `job.Service` 有界异步队列、`notify_seq` 单调回写与 `main.go` 优雅关闭顺序 | M2（可与 M3 并行！） | `plugin/notifier/`, `plugin/plugintest/`, `internal/gateway/pluginhost/`, `extensions/notifier/webhook/`, `extensions/standard/standard.go`, `internal/gateway/job/notify.go`, `cmd/allowops-gateway/main.go` | `go test -race -count=1 ./plugin/... ./extensions/... ./internal/gateway/pluginhost/... ./internal/gateway/job/... ./cmd/allowops-gateway/...` |
| **M5：Web 控制台 + 嵌入式构建 + 文档 + 全量验收** | 新增 `web/src/pages/Approvals.tsx`、API client/types、`navigation.ts`、`App.tsx`、命令面板；更新 `Policies.tsx`（`require_approval` 表单与模拟 diff）与 `Jobs.tsx`（`pending_approval` 状态与纯文本 `reason`）；补齐中英文 i18n 与 Vitest 测试（含 XSS/i18n 注入测试）；构建 `internal/gateway/console/dist/`；同步更新 `SECURITY.md`、`docs/design.md`、`docs/architecture-decisions.md`、`docs/plugin-architecture.md`、`website/{en,zh}/`、`examples/gateway.yaml`、`examples/policy/` 与 `CHANGELOG.md` | M3 + M4 | `web/src/`, `internal/gateway/console/dist/`, `SECURITY.md`, `docs/`, `website/`, `examples/`, `CHANGELOG.md` | `pnpm test && pnpm build`, `python3 test/ci-dist-check.py`, `website pnpm docs:check`, 全套总指挥 Go/OPA/Examples 验收命令 |

## 合并与验收纪律

1. 每个 worktree 子会话只做本地编码、生成与测试，**不 push、不开 PR、不修改其他里程碑目录**。
2. 总指挥在每个里程碑完成后：
   - 审阅子会话产出的完整 diff 与测试结果；
   - 在本 worktree 中合并提交（fast-forward / cherry-pick / patch 应用保持清晰线性提交历史）；
   - 在 M2 与 M5 后执行跨包集成测试与独立安全复审；
3. 全部 5 个里程碑合入 `feat/hitl-approval-jit` 后，总指挥独立重跑完整验收套件并确认工作区干净；**未获负责人确认前绝不 push、绝不开 PR**。
