# 插件架构阶段 0、1 实施计划

状态：待负责人确认（2026-11-03）。设计见 `plugin-stage01-design.md`。已经过 Astra 复审一轮，复审意见的处理见设计第 12 节。

## 1. 执行方式

- 阶段 0 和阶段 1 修改的文件不重叠，并行执行。每个阶段一个独立子会话，各自使用 worktree 分支，基于本计划所在的提交。
- 子会话只在本地构建和测试，不 push，不合并。每个提交单独可编译。
- 子会话完成后报告分支、HEAD SHA、每个提交的内容和测试命令输出。总指挥读 diff、重跑第 4 节的检查命令后才合入，并更新账本 `/data/allowops-coordination/commander-ledger.md`。
- 合入目标：本地分支 `t3/e71d8333`。push 和开 PR 另行确认。

## 2. 阶段 0：builtin 名称只保留一份

分支 `plugin/s0-builtin-names`。

| 提交 | 内容 | 涉及文件 |
| --- | --- | --- |
| S0-1 | 新增 `catalog.BuiltinNames()` 和测试（字面量列表断言完整内容） | `internal/catalog/builtin.go`、新测试文件 |
| S0-2 | `AgentHello` 使用 `BuiltinNames()`；`events_test.go` 改为与 `BuiltinNames()` 比较 | `internal/agent/agent.go`、`internal/agent/events_test.go` |

完成条件：第 4.1 节命令全部通过；`rg -n '"dremio_diag"' --type go -g '!*_test.go'` 只剩 `internal/catalog` 内的命中。

## 3. 阶段 1：插件机制与 Inventory

分支 `plugin/s1-inventory`。提交按顺序：

| 提交 | 内容 | 主要文件 |
| --- | --- | --- |
| S1-1 | `plugin`、`plugin/inventory` 包 | `plugin/plugin.go`、`plugin/inventory/inventory.go` |
| S1-2 | `pluginhost`：配置解码与启动检查、`SearchInventory`、`Health` | `internal/gateway/pluginhost/` |
| S1-3 | 两个官方插件、`plugins/standard`、`examples/topology.yaml` | `plugins/`、`examples/` |
| S1-4 | `view_inventory` 操作、默认规则、`consoleOperations`、试算计数 | `internal/gateway/authz/`、`internal/gateway/api/policy.go` 及相关测试 |
| S1-5 | `api.VisibleHostnames`、`ConfigurePluginHealth`、系统状态追加插件项 | `internal/gateway/api/` |
| S1-6 | MCP 工具 `entities_search`；`mcp.Identity` 增加 `Require`、`VisibleHostnames`；`mcp.Config` 增加可选的 inventory 依赖；保留名称 | `internal/gateway/mcp/`、`internal/catalog/catalog.go` |
| S1-7 | 网关装配：`configuration.Plugins`、在 `newJobServices` 之前构造 `pluginhost`、注入 MCP 和 api、空白导入 `plugins/standard` | `cmd/allowops-gateway/main.go` |
| S1-8 | 端到端测试 | `internal/gateway/mcp/` 测试 |
| S1-9 | 文档、示例与升级说明 | 见本节下方列表 |

每个提交带上设计第 11 节中对应范围的测试。`mcp.Config` 新增字段用 `mcp` 包内定义的接口（只含 `InventorySources` 和 `SearchInventory`），为 nil 时不列出 `entities_search`，现有调用 `mcp.New` 的测试不需要修改。

S1-9 修改的文档：

- `docs/design.md`：第 6 节 ABAC 操作列表增加 `view_inventory`；第 7 节工具表增加 `entities_search`。
- `docs/architecture-decisions.md`：第 5 节默认角色表增加 `view_inventory`。
- `website/policies.md`、`website/zh/policies.md`：操作列表和默认角色表；升级说明：已有部署需手工给角色增加 `view_inventory`。
- `examples/policy/read-only.yaml`、`examples/policy/maintenance.yaml`：administrators 规则增加 `view_inventory`。
- `docs/protocol.md:180`、`docs/p4b-management-api.md:32`：操作列表和试算计数。
- `examples/gateway.yaml`：增加注释掉的 `plugins` 示例。
- `CHANGELOG.md`：新增功能和升级步骤。

## 4. 检查命令

总指挥在合入前于各分支 HEAD 重跑，记录 SHA 和日志位置。需要 Docker 的测试用 `ALLOWOPS_REQUIRE_DOCKER=1`，没有 Docker 时测试失败而不是跳过。

### 4.1 阶段 0 分支

```sh
gofmt -l $(git ls-files '*.go' | grep -v '^gen/')     # 期望无输出
go vet ./...
go test -race -count=1 ./internal/catalog/... ./internal/agent/... ./internal/executor/... ./internal/cli/...
```

### 4.2 阶段 1 分支

```sh
gofmt -l $(git ls-files '*.go' | grep -v '^gen/')
go vet ./...
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 \
  ./plugin/... ./plugins/... ./internal/gateway/pluginhost/... \
  ./internal/gateway/authz/... ./internal/gateway/api/... ./internal/gateway/mcp/... \
  ./internal/catalog/... ./cmd/allowops-gateway/...
make opa-test
make examples-check
(cd website && pnpm install --frozen-lockfile && pnpm docs:check)   # Node 24.19.0，与 .github/workflows/docs-pages.yml 一致
```

### 4.3 合入 `t3/e71d8333` 之后

```sh
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./...
```

`internal/gateway/job` 包在负载高时会超过默认 10 分钟超时。超时时加 `-timeout 40m` 单独重跑该包。

## 5. 风险与处理

| 风险 | 处理 |
| --- | --- |
| 端到端用例加入 `real_job_test.go` 夹具后运行时间增加 | 复用同一夹具实例，不另起 SeaweedFS 和 agent |
| `entities_search` 加入保留名称后，已有私有目录中的同名 action 被拒绝 | 写入 CHANGELOG；示例目录无同名 action |
| 已有部署升级后无人有 `view_inventory` | 写入 CHANGELOG 和 `website/policies.md` 的升级说明；不自动修改策略 |
| 插件不可用使控制台系统页显示 DEGRADED | 设计已接受（设计第 6.4 节） |

## 6. 不在本计划内

Changes、Knowledge、Trigger 扩展点，外部 HTTP 访问，凭据，进程外插件，自定义构建。见设计第 1 节的推迟项。
