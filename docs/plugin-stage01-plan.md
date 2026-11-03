# 插件架构阶段 0、1 实施计划

状态：待负责人确认（2026-11-03）。设计见 `plugin-stage01-design.md`。

## 1. 执行方式

- 阶段 0 和阶段 1 互不修改同一文件，并行执行。每个阶段一个独立子会话，各自使用 worktree 分支，基于 `dbb18f8`。
- 子会话只在本地构建和测试，不 push，不合并。每个提交单独可编译。
- 子会话完成后报告分支、HEAD SHA、每个提交的内容和测试命令输出。总指挥读 diff、重跑第 4 节的检查命令后才合入，并更新账本 `/data/allowops-coordination/commander-ledger.md`。
- 合入目标：本地分支 `t3/e71d8333`。push 和开 PR 另行确认。

## 2. 阶段 0：builtin 名称只保留一份

分支 `plugin/s0-builtin-names`。

| 提交 | 内容 | 涉及文件 |
| --- | --- | --- |
| S0-1 | 新增 `catalog.BuiltinNames()` 和测试（字面量列表断言完整内容） | `internal/catalog/builtin.go`、新测试文件 |
| S0-2 | `AgentHello` 使用 `BuiltinNames()`；`events_test.go` 改为与 `BuiltinNames()` 比较 | `internal/agent/agent.go`、`internal/agent/events_test.go` |

完成条件：

- `go test ./internal/catalog/... ./internal/agent/... ./internal/executor/...` 通过。
- `rg -n '"dremio_diag"' --type go` 在非测试代码中只剩 `internal/catalog` 内的命中。

## 3. 阶段 1：插件机制与 Inventory

分支 `plugin/s1-inventory`。提交按顺序：

| 提交 | 内容 | 主要文件 | 测试 |
| --- | --- | --- | --- |
| S1-1 | `plugin`、`plugin/inventory` 包 | `plugin/plugin.go`、`plugin/inventory/inventory.go` | ID 格式、重复注册、`Modules()` 排序 |
| S1-2 | `pluginhost`：配置解码、启动检查、`SearchInventory`、`Health` | `internal/gateway/pluginhost/` | 设计第 10 节 `pluginhost` 一行的全部用例，用测试内注册的假模块 |
| S1-3 | 两个官方插件和 `plugins/standard` | `plugins/` | 设计第 10 节两行插件用例 |
| S1-4 | `view_inventory` 操作、默认角色、`consoleOperations`、试算计数 | `internal/gateway/authz/`、`internal/gateway/api/policy.go` 及相关测试 | `TestDefaultRoles`、`policy_view_inputs_rework_test.go`、`make opa-test` |
| S1-5 | `api.VisibleHostnames`、`ConfigurePluginHealth`、系统状态追加插件项 | `internal/gateway/api/` | 设计第 10 节 `api` 一行 |
| S1-6 | MCP 工具 `entities_search`；`mcp.Identity` 增加 `Require`、`VisibleHostnames`；`mcp.Config` 增加可选的 inventory 依赖；保留名称 | `internal/gateway/mcp/`、`internal/catalog/catalog.go` | 设计第 10 节 `mcp` 一行；现有 golden 和工具计数不变 |
| S1-7 | 网关装配：`configuration.Plugins`、构造 `pluginhost`、注入 MCP 和 api、空白导入 `plugins/standard` | `cmd/allowops-gateway/main.go` | `decodeConfig` 对 `plugins` 节的解码测试 |
| S1-8 | 端到端测试 | `internal/gateway/mcp/` 测试 | 设计第 10 节端到端一行 |
| S1-9 | 文档与示例 | 设计第 11 节列出的文件 | `docs:check`、`examples-check` |

`mcp.Config` 新增字段用接口类型（定义在 `mcp` 包内，只含 `InventorySources` 和 `SearchInventory`），为 nil 时不列出 `entities_search`。现有调用 `mcp.New` 的测试不需要修改。

## 4. 检查命令

总指挥在合入前于各分支 HEAD 重跑，并记录 SHA 和输出位置：

```sh
gofmt -l . | grep -v '^gen/'          # 期望无输出
go vet ./...
go test -race ./internal/catalog/... ./internal/agent/... ./internal/executor/... \
  ./plugin/... ./plugins/... ./internal/gateway/pluginhost/... \
  ./internal/gateway/authz/... ./internal/gateway/api/... ./internal/gateway/mcp/... \
  ./cmd/allowops-gateway/...
make opa-test
make examples-check
(cd website && npm run docs:check)
```

合入 `t3/e71d8333` 后再跑一次 `go test -race ./...`。按记忆中的已知情况，`internal/gateway/job` 包在负载高时会超过默认 10 分钟超时，超时时加 `-timeout 40m` 单独重跑该包。

## 5. 风险与处理

| 风险 | 处理 |
| --- | --- |
| 端到端测试夹具（`real_job_test.go`）依赖 SeaweedFS 和真实 agent，启动较慢或不适合加新用例 | 子会话先评估；不适用时改用 testpg 加假 job 服务的 MCP 集成测试，用返回的 selector 调用 action 后断言 job 被受理，并在报告中说明差异 |
| `entities_search` 加入保留名称后，已有私有目录中的同名 action 被拒绝 | 发布说明中写明；示例目录无同名 action |
| 插件不可用使控制台系统页显示 DEGRADED | 设计已接受（设计第 6.4 节） |
| `VisibleHostnames` 每次调用读取全部活动主机 | 与 `ListActiveHostLabels` 现有用法相同；上千台主机时的耗时在 S1-8 中记录，不达标再优化 |

## 6. 不在本计划内

Changes、Knowledge、Trigger 扩展点，外部 HTTP 访问，凭据，进程外插件，自定义构建。见设计第 1 节的推迟项。
