# 插件架构阶段 A~D（排障前序上下文闭环）实施计划

状态：已吸收第二轮复核意见并定稿（2026-11-24）。详细设计见 `docs/plugin-stage0203-design.md`。

## 1. 执行策略与独立可编译保证

采用「阶段 A 基线先行 → 阶段 B/C/D 三路并行（零文件重叠、各自独立可编译可测）→ 阶段 E 公共接线与全量验收」的推进方式：

- 每个提交单独可编译并通过对应包测试。
- 接口变更（如 `plugin.Host`）与所有现有实现、测试替身（含 `internal/gateway/api/inventory_selector_test.go`、`extensions/inventory/hostlabels/hostlabels_test.go`、`internal/gateway/pluginhost/host.go`）在**同一个提交**中交付。
- 阶段 C/D 处理器依赖的新授权常量（`authz.ViewChanges`、`authz.ViewKnowledge`）、目录保留名与 `mcp.Config` 的 `Changes`/`Knowledge` 接口定义放在阶段 A 最后一笔提交（A-6）中作为共同基线，使阶段 B/C/D 在三个独立 worktree 中互不重叠且各自 `go test -race ./...` 全部通过。
- 子会话只在本地构建与测试，不 push、不合并；总指挥审核全部 diff 并独立重跑验收命令后再合入 `feat/investigation-context-plugins`。

```
feat/investigation-context-plugins (基线 9640cd8)
  │
  ├─ [阶段 A] plugin/sA-host-foundation（串行先行，验收合入）
  │     ├── [阶段 B] plugin/sB-dynamic-inventory（并行 worktree）
  │     ├── [阶段 C] plugin/sC-changes-plugins（并行 worktree）
  │     └── [阶段 D] plugin/sD-knowledge-plugin（并行 worktree）
  │           （B / C / D 独占文件集合严格互不重叠，各自独立编译测试通过，合入零冲突）
  │
  └─ [阶段 E] 公共接线、端到端闭环、文档更新与总指挥全量验收
```

## 2. 阶段 A：底座、契约测试与共享接口基线（分支 `plugin/sA-host-foundation`）

**独占文件集合**：
- `plugin/{plugin.go,plugin_test.go}`、`plugin/changes/changes.go`、`plugin/knowledge/knowledge.go`、`plugin/plugintest/{plugintest.go,plugintest_test.go}`
- `internal/redact/{redact.go,secrets_extract_test.go}`
- `internal/gateway/pluginhost/{config.go,egress.go,credential.go,credential_linux.go,credential_other.go,cache.go,host.go}` 及测试
- `internal/gateway/api/{policy.go,policy_view_inputs_rework_test.go,inventory_selector_test.go,inventory_test.go}`
- `internal/gateway/authz/{types.go,defaults.go,engine.go,engine_test.go}`
- `internal/catalog/{catalog.go,catalog_test.go}`
- `internal/gateway/mcp/service.go`（仅声明 `Changes`、`Knowledge` 接口与 `Config` 可选字段，保持零值兼容）
- `extensions/inventory/static/static_test.go`、`extensions/inventory/hostlabels/hostlabels_test.go`
- `cmd/allowops-gateway/main.go`（`configuration.Plugins` 改用 `pluginhost.ConfigList` + 测试 `cmd/allowops-gateway/plugin_config_test.go`）
- `deploy/docker/Dockerfile`

| 提交 | 内容 |
| --- | --- |
| A-1 | 扩展 `plugin/plugin.go`（`Validator`、`Cleaner`、`Cache`、`ControlPlaneChange`、`ControlPlaneChangeReader`、`Host` 新方法）、新增 `plugin/changes/changes.go` 与 `plugin/knowledge/knowledge.go`，并**同步适配所有现有宿主实现与测试替身**（`pluginhost/host.go`、`api/inventory_selector_test.go`、`hostlabels_test.go` 等），保证立即通过全仓库编译 |
| A-2 | `internal/redact/redact.go` 新增 `Redactor.LineSecrets(line)` 及单元测试 |
| A-3 | `pluginhost` 基础设施：`ConfigList`/`Config` 防回显 `UnmarshalYAML`、`egress.go`（规范化源+有效端口、跨源重定向决策表、单次解析锁定 IP 含 IPv6 IMDS/转换前缀/显式 `::1`、私有 CA）、`credential*.go`（启动期固定 `dirFD`、普通文件 `openat(O_NOFOLLOW)` 与 Linux `openat2(RESOLVE_IN_ROOT)` 投射卷）、`cache.go`（LRU+TTL+4 MiB）+ `cmd/allowops-gateway/main.go` 接入 `ConfigList` 与对应单测 |
| A-4 | `pluginhost/host.go` 完整运行时：多命名空间隔离、`controlPlaneHost` 独立具体类型、并发信号量、`refs` 引用计数释放与有界启动/关闭、脱敏 logger 包装、`MergeVisibleInventory`（原始身份关联可见组内跨源凭据传播）、`ListChanges`（跨字段脱敏+`Kind` 检查+脱敏后过滤+`HasMore`）、`SearchKnowledge`/`ReadKnowledge`（单快照 `ReadResult`+统一 `sanitizeDoc`+正文元数据凭据二次抹除+唯一章节编号+`revision`）及全套单测 |
| A-5 | `plugin/plugintest` 契约测试套件 + `extensions/...` AST 禁直连护栏测试；现有 `inventory.static`/`inventory.host_labels` 接入契约测试；`deploy/docker/Dockerfile` 补齐 `COPY plugin` 与 `COPY extensions` |
| A-6 | 共享控制面基线：`authz.ViewChanges`/`ViewKnowledge`、默认角色、`authz/engine_test.go` 角色全集、`api/policy.go` `consoleOperations` 与 `policy_view_inputs_rework_test.go`（`35/34`→`37/36`）、既有策略不自动授予回归测试、`catalog.go` 保留名称（`changes_list`/`runbooks_search`/`runbooks_read`）、`mcp/service.go` 声明可选 `Changes`/`Knowledge` 接口字段 |

**阶段 A 检查命令**：
```sh
gofmt -l $(git ls-files '*.go' | grep -v '^gen/')
go vet ./...
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 \
  ./internal/redact/... ./plugin/... ./extensions/... ./internal/gateway/pluginhost/... \
  ./internal/gateway/authz/... ./internal/gateway/api/... ./internal/catalog/... \
  ./internal/gateway/mcp/... ./cmd/allowops-gateway/...
```

## 3. 阶段 B/C/D：三路零冲突并行实施（均基于阶段 A 合入后的同一 HEAD）

### 3.1 阶段 B：动态 Inventory 插件与 `entities_search` 合并（分支 `plugin/sB-dynamic-inventory`）

**独占文件集合**：
- `extensions/inventory/k8s/{k8s.go,k8s_test.go}`
- `extensions/inventory/promtargets/{promtargets.go,promtargets_test.go}`
- `extensions/inventory/cmdbhttp/{cmdbhttp.go,cmdbhttp_test.go}`
- `internal/gateway/mcp/inventory.go`、`internal/gateway/mcp/inventory_test.go`

| 提交 | 内容 |
| --- | --- |
| B-1 | `inventory.k8s`（纯 stdlib K8s REST API、必填 `namespaces`、`/`→`_` 键映射、完整 `matchLabels`+`matchExpressions`、带凭据拒明文 HTTP、绝不读 annotations）+ `plugintest` 与 `httptest` TLS 单测 |
| B-2 | `inventory.prometheus_targets`（`/api/v1/targets?state=active`、默认零跨目标属性泄露、`instance` 去端口）+ `plugintest` 与 `httptest` TLS 单测 |
| B-3 | `inventory.cmdb_http`（只读 JSON CMDB 适配、`auth_header` 禁保留头、绝不传 `Name`、来源内重名拒绝）+ `plugintest` 与 `httptest` TLS 单测 |
| B-4 | `internal/gateway/mcp/inventory.go`：接入调用前 `authorized` 审计（fail-closed）、逐源主机可见性过滤后调用 `pluginhost.MergeVisibleInventory`、输出 `sources`/`conflicts`/`selector_conflicts`、单源兼容 `source`、首条超大实体最小身份降级预算，及完整单测（含双源同名名称被脱敏跨源传播用例） |

### 3.2 阶段 C：Changes 插件与 `changes_list` 处理器（分支 `plugin/sC-changes-plugins`）

**独占文件集合**：
- `internal/store/queries/plugin_changes.sql`、`internal/store/db/plugin_changes.sql.go`、`internal/store/db/querier.go`（如由 `sqlc generate` 更新）及 `internal/store/plugin_changes_test.go`
- `extensions/changes/allowops/{allowops.go,allowops_test.go}`
- `extensions/changes/k8srollout/{k8srollout.go,k8srollout_test.go}`
- `extensions/changes/httpfeed/{httpfeed.go,httpfeed_test.go}`
- `internal/gateway/mcp/changes.go`、`internal/gateway/mcp/changes_test.go`

| 提交 | 内容 |
| --- | --- |
| C-1 | `internal/store/queries/plugin_changes.sql` + `sqlc generate` 生成只读目录/策略变更历史查询（查 `limit+1` 判 `hasMore`，不读 `dsse`/`rules`）+ PostgreSQL 集成测试 |
| C-2 | `changes.allowops`、`changes.k8s_rollout`、`changes.http` 三个官方插件 + 各自 `plugintest.RunListerContract` 与 `httptest` TLS 单测 |
| C-3 | `internal/gateway/mcp/changes.go`：`changesTool` 定义与 `listChanges` 处理器（参数校验、单次 `Now()` 7 天窗口、`Require(ViewChanges)`、调用前 `authorized` 审计 fail-closed、32 KiB 预算）及完整单测 |

### 3.3 阶段 D：Knowledge 插件、`runbooks_*` 与 MCP Resources 处理器（分支 `plugin/sD-knowledge-plugin`）

**独占文件集合**：
- `extensions/knowledge/gitdocs/{gitdocs.go,gitdocs_test.go}`
- `internal/gateway/mcp/knowledge.go`、`internal/gateway/mcp/knowledge_test.go`

| 提交 | 内容 |
| --- | --- |
| D-1 | `knowledge.git_markdown` 本地 `dir` 模式（逐级 `openat(O_NOFOLLOW|O_NONBLOCK)`、不可变快照、单快照原子 `ReadResult`）+ 本地临时 git repo 契约与安全单测 |
| D-2 | `knowledge.git_markdown` 远程 `archive_url` 模式（`Host.HTTPClient` + gzip/tar 间 `countingReader` 限全流解压 + `max_entries` + 纯内存解压）+ `httptest` TLS 单测 |
| D-3 | `internal/gateway/mcp/knowledge.go`：`runbooksSearchTool`/`runbooksReadTool`、`searchRunbooks`/`readRunbook`（`revision`、唯一章节定位、UTF-8 边界、32 KiB 裁剪保证 `next_offset > offset`）与 MCP Resources（`listRunbookResources`/`readRunbookResource`/中间件包装器，计入 SDK 封装开销实测 `<= 32 KiB`、`authorized` 失败零调用中止）及完整单测 |

## 4. 阶段 E：总指挥合入、公共接线、端到端闭环与文档

按序合入阶段 B、C、D 后，在 `feat/investigation-context-plugins` 上完成公共接线与文档：

| 提交 | 内容 | 主要文件 |
| --- | --- | --- |
| E-1 | MCP 公共接线（`fixed.go` 暴露新工具、`cache.go` 注入 Changes/Knowledge 并注册 `ResourceTemplate` 与 Resources 中间件、`call.go` 在 `s.jobs == nil` 前分派新工具并更新只读工具判断）、`extensions/standard/standard.go` 空白导入全部 7 个新官方插件、`cmd/allowops-gateway/main.go` 注入 `ControlPlaneChanges` / `Changes` / `Knowledge` 与 `pluginHost.Close`、`web/src/pages/Policies.tsx` 补齐三个操作 | `internal/gateway/mcp/{fixed,cache,call}.go`、`extensions/standard/standard.go`、`cmd/allowops-gateway/main.go`、`web/src/pages/Policies.tsx` |
| E-2 | 端到端闭环集成测试（PostgreSQL + SeaweedFS + 真实 job/agent + 动态 Inventory + `changes.allowops` + `knowledge.git_markdown` + MCP Tools + MCP Resources 真实 HTTP 传输测试，实测最终 JSON-RPC `result <= 32768` 字节、刷新 TOCTOU、仅单命名空间部署） | `internal/gateway/mcp/investigation_e2e_test.go`、`cmd/allowops-gateway/plugin_config_test.go` |
| E-3 | 文档、示例与升级顺序说明（`docs/design.md`、`docs/architecture-decisions.md`、`docs/plugin-architecture.md`、`docs/protocol.md`、`docs/p4b-management-api.md`、`website/policies.md`、`website/zh/policies.md`、`website/mcp.md`、`website/zh/mcp.md`、`examples/gateway.yaml`、`examples/policy/read-only.yaml`、`examples/policy/maintenance.yaml`、`CHANGELOG.md`） | 上述文档与示例文件 |

## 5. 最终总指挥验收命令

```sh
gofmt -l $(git ls-files '*.go' | grep -v '^gen/')
go vet ./...
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 \
  ./internal/redact/... ./plugin/... ./extensions/... ./internal/gateway/pluginhost/... \
  ./internal/gateway/authz/... ./internal/gateway/api/... ./internal/gateway/mcp/... \
  ./internal/catalog/... ./internal/store/... ./cmd/allowops-gateway/...
make opa-test
make examples-check
(cd website && pnpm install --frozen-lockfile && pnpm docs:check)
```

未获负责人明确确认前，不 push、不开 PR。
