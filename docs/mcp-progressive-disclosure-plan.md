# MCP 工具分层与按需发现（Progressive Disclosure）实施计划

状态：已就绪（2026-11-24）  
依据设计文档：[docs/mcp-progressive-disclosure-design.md](mcp-progressive-disclosure-design.md)  
基线开发分支：`feat/mcp-progressive-disclosure`

## 1. 阶段划分与文件边界（无文件冲突）

总体分为 4 个实施阶段 + 1 个验收合入阶段。其中 **阶段 A** 为前置基础，合入本地开发分支后，**阶段 B** 与 **阶段 C** 文件集合完全正交，可并行在独立 worktree 执行；**阶段 D** 在 B、C 合入后同步全部文档与升级说明。

| 阶段 | 分支名 | 依赖 | 涉及文件范围 | 顺序提交规划 |
|---|---|---|---|---|
| **Stage A**<br>目录元数据、发布校验与 Agent 特性 | `feat/mcp-pd-stage-a` | 基线 HEAD | `internal/catalog/catalog.go`<br>`internal/catalog/catalog_test.go`<br>`internal/catalog/metadata_test.go`（新）<br>`internal/gateway/catalogsvc/service.go`<br>`internal/gateway/catalogsvc/*_test.go`<br>`internal/gateway/api/catalogs.go`<br>`internal/gateway/api/catalogs_test.go`<br>`internal/agent/agent.go`<br>`internal/agent/metadata_test.go`（新）<br>`api/proto/allowops/v1/agent.proto`（仅注释） | 1. `feat(catalog): add signed toolset, tags, entity_kinds metadata and authoring reserved names`<br>2. `feat(agent,catalogsvc): report action_metadata feature and enforce reserved names on publish` |
| **Stage B**<br>单主机预检 API、MCP 两层缓存、渐进发现、实体推荐与网关配置 | `feat/mcp-pd-stage-b` | Stage A | `internal/gateway/api/mcp_actions.go`（新）<br>`internal/gateway/api/mcp_actions_test.go`（新）<br>`internal/gateway/mcp/service.go`<br>`internal/gateway/mcp/cache.go`<br>`internal/gateway/mcp/fixed.go`<br>`internal/gateway/mcp/call.go`<br>`internal/gateway/mcp/arguments.go`<br>`internal/gateway/mcp/actions.go`（新）<br>`internal/gateway/mcp/inventory.go`<br>`internal/gateway/mcp/*_test.go` & `testdata/server_tools_progressive_golden.json`（新）<br>`cmd/allowops-gateway/main.go`<br>`cmd/allowops-gateway/mcp_config_test.go`（新） | 1. `feat(api): add AllowedActionsOnHost single-host ABAC precheck helper`<br>2. `feat(mcp): implement two-tier cache, modes, headers, actions_search and risk-split actions_invoke`<br>3. `feat(mcp): add entities_search recommended_actions, golden tests and gateway mcp config` |
| **Stage C**<br>示例目录全量标注、校验脚本与控制台详情展示 | `feat/mcp-pd-stage-c` | Stage A（与 Stage B 并行，零文件重叠） | `examples/catalog/actions/*.yaml`（133 个）<br>`test/examples/check_examples.py`<br>`web/src/api/types.ts`<br>`web/src/pages/Catalog.tsx`<br>`web/src/i18n/locales/*.json`（及前端测试） | 1. `feat(examples): annotate all 133 catalog actions with toolset, tags, and entity_kinds`<br>2. `feat(web): display action metadata in catalog detail panel` |
| **Stage D**<br>设计/架构/官网文档与 CHANGELOG 同步 | `feat/mcp-pd-stage-d` | Stage B + Stage C | `docs/design.md`<br>`docs/architecture-decisions.md`<br>`internal/gateway/mcp/README.md`<br>`examples/gateway.yaml`<br>`website/mcp.md`, `website/zh/mcp.md`<br>`website/catalogs.md`, `website/zh/catalogs.md`<br>`website/publishing.md`, `website/zh/publishing.md`<br>`CHANGELOG.md` | 1. `docs(mcp,catalog): document progressive disclosure, action metadata, and upgrade notes` |
| **Stage E**<br>总指挥复审、全量验收与合入 | `feat/mcp-progressive-disclosure` | Stage D | 独立代码安全与契约复审；按验收清单重跑全部检查；合入本地开发分支（**不 push、不建 PR**） | 本地 fast-forward / 顺序合入 |

## 2. 各阶段详细交付要求

### 2.1 Stage A 细化要求

1. `internal/catalog/catalog.go`：
   - `Action` 增加 `Toolset string`, `Tags []string`, `EntityKinds []string`（均 `json:"...,omitempty" yaml:"...,omitempty"`）。
   - `ParseAction` 在 YAML AST 遍历中对 `toolset`、`tags`、`entity_kinds` 做严格类型检查：
     - `toolset`：须 `ScalarNode && Tag == "!!str" && Value != ""`；
     - `tags` / `entity_kinds`：须 `SequenceNode && len(Content) > 0`，且每一项须 `ScalarNode && Tag == "!!str"`（拒绝 `true`/`123`/`null`/空数组）。
   - 保留名拆分：
     - 读路径保留名 `readReservedActionNames` = 既有 5 个（`hosts_search`, `jobs_get`, `jobs_list`, `jobs_cancel`, `entities_search`）。
     - 编写/发布保留名 `authorReservedActionNames` = 既有 5 个 + 新增 4 个（`actions_search`, `actions_invoke_read`, `actions_invoke_write`, `actions_invoke_dangerous`）。
   - `validateAction(a, allowUnsupported)`：
     - 当 `!allowUnsupported`（编写路径）时检查全部 9 个保留名，并调用 `validateMetadata(a)` 校验正则 `^[a-z][a-z0-9_]{0,31}$`、数量上限 16、禁止重复。
     - 当 `allowUnsupported`（读路径 `ParsePackage`）时仅检查原有 5 个保留名，且不对 `tags`/`entity_kinds` 做长度/正则拦截，确保历史包和未来放宽限制的包均可安全读取。
   - 导出 `ValidateForPublish(p *Package) error`：检查包中所有动作不命中 `authorReservedActionNames`（且满足 `validateMetadata`）。
2. `internal/gateway/catalogsvc/service.go` 与 `internal/gateway/api/catalogs.go`：
   - 仅在 `Publish` / `PublishCatalog` 验签成功后调用 `catalog.ValidateForPublish(p)`，不放进 `Verify`。
3. `internal/agent/agent.go`：
   - `hello()` 中 `Features` 更新为 `[]string{"allow_interpreter", "exec_fallbacks", "max_targets", "action_metadata"}`。
4. 测试覆盖：
   - `internal/catalog/metadata_test.go`：合法值、边界（16 项通过、17 项拒绝）、非法字符、重复项、`null`/空串/空数组/布尔隐式转换拒绝、`ActionDigest` 变化、无字段时 `CanonicalJSON` 字节不变、编写/发布拦截新保留名而 `ParsePackage` 放行历史同名包。
   - `internal/agent/metadata_test.go`：`hello()` 上报 `action_metadata`，加载并执行带元数据动作。

### 2.2 Stage B 细化要求

1. `internal/gateway/api/mcp_actions.go`：
   - `AllowedActionsOnHost(ctx context.Context, hostname string, actions []authz.Action) (map[string]bool, error)`：
     - 单主机查询 `s.hostsWhere(ctx, s.Store.Pool, " AND h.hostname = $2", false, hostname)`；
     - `pinPolicy(ctx)` 一次；
     - 校验 `s.can(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(h))`，不存在或不可见返回空 map（无错误）；
     - 逐动作调用 `evaluate(ctx, engine, authz.Input{...})`（自动复用 `HOST_UNLABELED`），按 `s.can` 方式累加 `matchedRules`、设置 `policyVersion`，仅返回 `Decision == "allow"` 的集合。
2. `internal/gateway/mcp/`：
   - `Config` 新增 `Mode string`（`""` 默认 `"flat"`；允许 `flat`/`progressive`/`auto`）与 `AutoThreshold int`（`0` 默认 `40`；范围 `[1, 1000]`）。
   - `service.go`：认证与 `Origin` 检查后严格解析 `X-Allowops-Toolsets`（最多 1 个头、逗号拆分、去空白、非空、1~16 项、正则 `^[a-z][a-z0-9_]{0,31}$`、去重排序）与 `X-Allowops-MCP-Mode`（最多 1 个头、去空白、精确匹配 `flat` 或 `progressive`）；畸形返回 HTTP 400 并审计 `mcp/request` + `deny`。保持 `r.URL.RawQuery != ""` 返回 HTTP 400 不变。
   - `cache.go`：实现两层缓存（Tier 1 按 `versions` + singleflight 缓存已验签目录和投影引擎；Tier 2 LRU 仅按 `sha256(Actor, Subject, Versions)` 缓存 `identityView` 及 `defaultServer`；带过滤或非默认 mode 请求在 `view` 上纯内存筛选并现场组装 `*sdk.Server`，不进 LRU）。
   - `fixed.go`：定义 `actions_search`、`actions_invoke_read`、`actions_invoke_write`、`actions_invoke_dangerous`；更新 `entities_search` 描述。
   - `call.go` & `arguments.go`：抽离 `runAction(ctx, r, actionName, rawArgs, extraAllowed, state)`；`callState` 增加 `operation` 与 `mutating`；实现 `actions_invoke_<risk>` 风险强制校验、防枚举错误、审计操作名规则与 `progressive` 模式下直接调用 `<action>` 的处理。
   - `actions.go`：实现 `searchActions`（`query`/`names`/`toolset`/`tag`/`risk`/`entity_kind`/`hostname`/`include_schema`/`limit`/`next_cursor`、风险优先再按名称排序、`invoke_tool`、第一页 `toolsets` 汇总省略未标注项、完整游标绑定、32 KiB 预算与单条超限降级）。
   - `inventory.go`：在实体截断逻辑完成后，按字典序 `kind` 装入 `recommended_actions`（每 `kind` 最多 10 条、风险优先再按名称）并维护独立 `recommended_actions_truncated`。
   - 黄金测试：保留 `testdata/server_tools_golden.json` 零破坏，新增 `testdata/server_tools_progressive_golden.json` 覆盖 `progressive` 模式（admin 含 3 档 invoke 工具 + 只读角色仅含 `actions_invoke_read` + viewer 仅含 4 个固定工具）。
3. `cmd/allowops-gateway/main.go`：
   - 新增 `MCP` 配置结构体（`Mode string`, `AutoThreshold *int`），启动校验显式 0 / 越界 / 未知 mode 拒绝，传入 `mcp.New`。

### 2.3 Stage C 细化要求

1. 为 `examples/catalog/actions/*.yaml` 全部 133 个文件补齐合理的 `toolset`、`tags`、`entity_kinds`（按设计 §8.1 映射，`service` 精选 8 个核心动作、`database` 10 个、`cache` 6 个，其余按技术栈细分）。
2. 更新 `test/examples/check_examples.py` 验证全部 133 个动作均含非空 `toolset`、`tags`、`entity_kinds` 且 `toolset` 属于规范 16 集合。
3. 更新 `web/src/api/types.ts`、`web/src/pages/Catalog.tsx` 及中英文 i18n 文案，在 Catalog 动作详情侧栏展示 `toolset`、`tags`、`entity_kinds`（仅当字段存在时渲染），并确保前端 `pnpm build` / `pnpm test` / `pnpm lint`（如配置）全部通过。

### 2.4 Stage D 细化要求

同步更新全部文档，核对中英文一致与 `pnpm docs:check`：
- `docs/design.md`（§4、§7）
- `docs/architecture-decisions.md`（记录本次架构决策 A71）
- `internal/gateway/mcp/README.md`
- `examples/gateway.yaml`（补充注释化的 `mcp:` 配置示例）
- `website/mcp.md`、`website/zh/mcp.md`
- `website/catalogs.md`、`website/zh/catalogs.md`
- `website/publishing.md`、`website/zh/publishing.md`
- `CHANGELOG.md`（Unreleased 新特性 + 完整升级步骤与保留名检查说明）

## 3. 验收命令清单

每阶段子会话在各自 worktree 本地跑对应测试，总指挥在各分支 HEAD 及合入后的 `feat/mcp-progressive-disclosure` 上独立重跑全套命令：

```sh
gofmt -l $(git ls-files '*.go' | grep -v '^gen/')
go vet ./...
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/catalog/... ./internal/agent/... ./internal/gateway/catalogsvc/... ./internal/gateway/mcp/... ./internal/gateway/authz/... ./internal/gateway/api/... ./cmd/allowops-gateway/...
make opa-test
make examples-check
make build
(cd web && pnpm test -- --run && pnpm build)
(cd website && pnpm install --frozen-lockfile && pnpm docs:check)
```

## 4. 风险表与缓解措施

| 风险 | 影响 | 缓解措施 |
|---|---|---|
| 133 个示例动作批量编辑破坏 YAML 格式或既有测试（如 `examples_r5_yaml_test.go`、`check_examples.py` 字符串替换） | `go test ./internal/catalog/...` 或 `make examples-check` 失败 | 仅在 `risk:` / `description:` 之后插入 `toolset`/`tags`/`entity_kinds` 行，绝不改写现有行缩进或 `allowed_roots` 行；跑完 `go test ./internal/catalog/...` 和 `make examples-check` 实测 |
| `mcp.Identity` 新增 `AllowedActionsOnHost` 导致测试桩未实现接口 | `internal/gateway/mcp` 编译失败 | Stage B 同步更新 `internal/gateway/mcp` 内所有 `Identity` 桩（如 `inventoryIdentity`、`stubIdentity` 等） |
| `catalog.go` 拆分读/写保留名影响既有 `catalog_test.go` | 既有单测断言失败 | 明确区分 `ValidateAction`（拒 9 个）与 `ParsePackage`（拒原 5 个）+ `ValidateForPublish`（拒 9 个），保留原有 5 个测试不退化 |
| `website` 中英文锚点/链接规范不满足 `pnpm docs:check` | 文档门禁失败 | Stage D 严格沿用现有 VitePress `{#anchor}` 风格并实跑 `pnpm docs:check` |
| 前端 `web/` 静态资源被 `go:embed` 进网关，若未验证构建可能引入 TS/i18n 错误 | `web-build` 或 CI 失败 | Stage C 运行前端类型检查、测试与 `pnpm build`（并确认不提交未追踪临时产物） |
