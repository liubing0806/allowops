# 插件架构阶段 0、1 实现设计

状态：待负责人确认（2026-11-03）。上位设计见 `plugin-architecture.md`，决定见 `architecture-decisions.md` 第 22 节。本文写的是阶段 0 和阶段 1 的实际实现；与上位设计不同的地方集中列在第 9 节。

代码位置依据 commit `dbb18f8`（内容与 `b11c123` 相同，只多了文档）。

## 1. 范围

| 阶段 | 内容 |
| --- | --- |
| 0 | 主机端 builtin 名称只保留一份：`AgentHello.Capabilities.Builtins` 从 `catalog.Builtins` 生成 |
| 1 | 插件机制和 Inventory 扩展点：`plugin/` 包、`internal/gateway/pluginhost`、`gateway.yaml` 的 `plugins` 节、两个官方插件、MCP 工具 `entities_search`、授权操作 `view_inventory`、控制台系统页的插件健康状态 |

本轮不做的部分，以及开始做的条件：

| 推迟项 | 开始条件 |
| --- | --- |
| Changes、Knowledge 扩展点及 `view_changes`、`view_knowledge` | 阶段 1 合入并使用后，另写设计 |
| `Host.HTTPClient`、`egress` 白名单、`Host.Credential` | 第一个需要访问外部 HTTP 的插件 |
| `Host.Cache`、`Host.State`、Trigger 扩展点 | PL9 编排层边界确定后 |
| 可选接口 `Validator`、`Cleaner` | 第一个需要它们的插件；本轮两个插件都不需要 |
| 每实例并发上限 `max_concurrency` | 第一个访问外部系统的插件 |
| 契约测试套件 `plugin/plugintest` | 出现第一个第三方插件 |
| `allowops build` 自定义构建 | 出现第一个第三方插件 |
| 实体合并与冲突字段 `conflicts` | 实际使用中出现多个来源描述同一实体的需要 |

## 2. 阶段 0：builtin 名称只保留一份

现状：

- `internal/catalog/builtin.go:54` 的 `Builtins` map 是唯一被读取的注册表。主机端执行（`internal/executor/executor.go:289`）、目录校验（`internal/catalog/catalog.go:250`）和网关的 `unsupportedActionSchema`（`internal/gateway/mcp/schema.go:15`）都查它。
- `internal/agent/agent.go:111` 另写了一份 11 个名称的列表。网关只把它存库并在主机 API 中显示（`internal/gateway/hostconn/service.go:418`），没有代码据此做判断。

改动：

1. 在 `internal/catalog/builtin.go` 增加 `func BuiltinNames() []string`，返回 `Builtins` 的键，按字母排序。
2. `agent.go:111` 改为 `Builtins: catalog.BuiltinNames()`。`internal/agent` 已经导入 `internal/catalog`，不产生新的依赖。
3. `internal/agent/events_test.go:54` 改为断言 hello 中的列表等于 `catalog.BuiltinNames()`。
4. 在 `internal/catalog` 增加一个测试，用一份字面量列表断言 `BuiltinNames()` 的完整内容。这样误删一个处理器时测试失败。

不做：不把注册移到各 `internal/builtin/*` 包。那些包要导入 `catalog` 的类型，而 `catalog` 已导入它们，会形成循环依赖；解决循环需要拆出新包，本轮没有收益。`Builtins` 保持可修改的包级变量，5 个测试文件依赖在运行时增删条目。

列表顺序从手写顺序变为字母顺序。网关不比较顺序，无影响。

## 3. 包与文件

```
plugin/plugin.go                         Register、Lookup、ModuleID、ModuleInfo、Module、Provisioner、Host、HostInfo
plugin/inventory/inventory.go            Entity、Query、Resolver
plugins/standard/standard.go             空白导入两个官方插件
plugins/inventory/static/static.go       inventory.static
plugins/inventory/hostlabels/hostlabels.go  inventory.host_labels
internal/gateway/pluginhost/config.go    Config 类型与解码
internal/gateway/pluginhost/host.go      实例构造、Search、Health
cmd/allowops-gateway/main.go             配置字段、构造、注入
internal/gateway/api/                    VisibleHostnames、插件健康状态、consoleOperations
internal/gateway/authz/                  ViewInventory
internal/gateway/mcp/                    entities_search
internal/catalog/catalog.go:269          保留名称增加 entities_search
```

`plugin/` 和 `plugins/` 放在 `internal/` 之外（PL2）。`plugins/` 下的官方插件属于同一个 module，本轮不导入任何 `internal/` 包，以保证它们和第三方插件用同样的接口。

## 4. `plugin` 包

```go
package plugin

// ModuleID 的格式为 "<命名空间>.<名称>"，两段都匹配 ^[a-z][a-z0-9_]{0,31}$。
type ModuleID string

type ModuleInfo struct {
	ID  ModuleID
	New func() Module // 每个配置实例调用一次，返回指针，供解码配置
}

type Module interface{ Module() ModuleInfo }

// Provisioner 可选。在配置解码之后调用一次。返回错误表示实例不可用。
type Provisioner interface {
	Provision(ctx context.Context, h Host) error
}

// Host 是插件能拿到的全部网关能力。
type Host interface {
	InstanceID() string
	Logger() *slog.Logger
	// Hosts 返回当前全部活动主机。结果没有按调用者权限过滤；网关在返回给调用者之前过滤。
	Hosts(ctx context.Context) ([]HostInfo, error)
}

type HostInfo struct {
	Hostname       string
	Labels         map[string]string // 授权标签
	ReportedLabels map[string]string // 主机上报的标签
}

func Register(m Module)                       // 在 init() 中调用；ID 格式错误或重复时 panic
func Lookup(id ModuleID) (ModuleInfo, bool)
func Modules() []ModuleID                      // 已注册的模块，按字母排序
```

`Register` 只检查 ID 格式和重复。模块是否实现了命名空间要求的接口，由 `pluginhost` 在启动时检查（第 6 节）。这样新增扩展点时不需要修改 `plugin` 包的注册逻辑。

## 5. `plugin/inventory` 包

```go
package inventory

type Entity struct {
	Kind      string            // service、database、cache、queue 等，匹配 ^[a-z][a-z0-9_]{0,31}$
	Name      string            // 1~128 字节
	Attrs     map[string]string // 可选
	Hosts     []string          // 关联的主机名，可选
	Selector  string            // 主机标签选择器，可选，语法与 action 的 targets.selector 相同
	DependsOn []string          // 依赖的实体，格式 "<kind>/<name>"，可选
}

type Query struct {
	Kind  string // 精确匹配；空表示全部
	Name  string // 名称包含该子串（不区分大小写）；空表示全部
	Limit int    // 网关传入，1~100
}

type Resolver interface {
	Resolve(ctx context.Context, q Query) ([]Entity, error)
}
```

插件应按 `Query` 过滤，返回不超过 `Limit` 条。网关不依赖插件遵守：合并后再按 `Query` 过滤一次并截断。

不提供关系展开深度。agent 需要依赖的详情时，用 `DependsOn` 中的名称再查一次。

## 6. `pluginhost`

### 6.1 配置

`gateway.yaml` 新增：

```yaml
plugins:
  - id: inv-static            # ^[a-z][a-z0-9-]{0,63}$，唯一
    module: inventory.static
    disabled: false           # 默认 false
    required: false           # 默认 false；true 时实例不可用则网关拒绝启动
    timeout: 5s               # 单次调用超时，默认 5s，范围 100ms~30s
    config:
      file: /etc/allowops/topology.yaml
```

```go
type Config struct {
	ID       string        `yaml:"id"`
	Module   string        `yaml:"module"`
	Disabled bool          `yaml:"disabled"`
	Required bool          `yaml:"required"`
	Timeout  time.Duration `yaml:"timeout"`
	Config   yaml.Node     `yaml:"config"`
}
```

`cmd/allowops-gateway/main.go` 的 `configuration` 增加 `Plugins []pluginhost.Config \`yaml:"plugins"\``。外层仍由现有的 `KnownFields(true)` 严格解码。

### 6.2 启动

`pluginhost.New(ctx, configs, deps)`，在 `serve` 中 `newGatewayServer` 之前调用。`deps` 包含 logger 和一个返回 `[]plugin.HostInfo` 的函数，由 main 用 `db.Queries.ListActiveHostLabels`（`internal/store/queries/policy.sql:14`）实现。

对每个配置项依次执行：

1. 检查 `id` 格式和唯一性、`timeout` 范围。失败时网关拒绝启动。
2. `disabled: true` 的实例跳过，不构造，不出现在健康状态中。
3. `plugin.Lookup(module)`。未注册时网关拒绝启动。
4. 按模块 ID 的命名空间检查接口。本轮只有 `inventory`：`New()` 的返回值必须实现 `inventory.Resolver`。其他命名空间或接口不符时网关拒绝启动。
5. 把 `config` 节点重新编码为 YAML，再用 `KnownFields(true)` 解码到 `New()` 返回的对象。`yaml.v3` 的 `Node.Decode` 不支持 `KnownFields`，所以要重新编码。失败时网关拒绝启动。
6. 如果实现了 `Provisioner`，在 `timeout` 内调用 `Provision`。失败时：`required: true` 网关拒绝启动；否则实例标记为不可用，错误写日志，继续启动。

第 1、3、4、5 步的错误都是配置错误，不受 `required` 影响，网关一律拒绝启动。

配置修改需要重启网关生效。

### 6.3 `Search`

```go
type SourceError struct {
	Source string `json:"source"`
	Reason string `json:"reason"` // timeout | failed | panic | unavailable
}

func (h *Host) InventorySources() []string // 可用的 inventory 实例 ID，按配置顺序
func (h *Host) SearchInventory(ctx context.Context, q inventory.Query, sources []string) ([]Result, []SourceError)
```

`Result` 是 `inventory.Entity` 加上 `Source`（实例 ID）。处理步骤：

1. `sources` 为空时使用全部可用实例；包含不存在或不可用的 ID 时，调用方（MCP）在调用前已返回参数错误。
2. 每个实例在独立 goroutine 中调用 `Resolve`，`context.WithTimeout(ctx, timeout)`，`defer recover()`。
3. 超时记为 `timeout`；返回错误记为 `failed`；panic 记为 `panic`。原始错误和 panic 值只写日志（含实例 ID），不返回给调用方。
4. 丢弃字段不合格的实体：`Kind` 格式错误、`Name` 为空或超过 128 字节、`Selector` 超过 512 字节。丢弃数量写日志。
5. 按 `Query` 再过滤一次。
6. 对 `Attrs` 的值、`Name`、`Selector`、`DependsOn` 用 `redact.New(nil)` 得到的 secrets 规则逐个处理（`Redactor.Line`）。这些值都是单行字段。
7. 按 `Kind`、`Name`、`Source` 排序，截断到 `Limit`。截断时返回 `truncated: true`。

不合并不同实例返回的同名实体，每条结果带 `source`。

### 6.4 健康状态

```go
type Health struct{ ID, Module string; OK bool; Reason string }
func (h *Host) Health() []Health
```

`OK` 只反映 `Provision` 的结果。`Reason` 为固定文本 `provision failed`，具体错误在日志中。单次调用的失败通过 `source_errors` 返回，不改变健康状态。

`api.Service` 增加 `ConfigurePluginHealth(func() []pluginhost.Health)`，做法与现有的 `ConfigureJobDependencies` 相同。`dependencyHealth`（`internal/gateway/api/system.go:31`）在现有三项之后追加 `plugin:<id>`，不可用时状态为 `UNAVAILABLE`。不需要修改 proto（`DependencyHealth` 是 repeated 字段）。

后果：一个不可用的插件会让控制台系统页的总体状态显示为 DEGRADED。这是预期行为。`/health/ready`（负载均衡就绪检查）不包含插件。

## 7. 两个官方插件

### 7.1 `inventory.static`

配置：

```yaml
config:
  file: /etc/allowops/topology.yaml
```

文件格式：

```yaml
entities:
  - kind: service
    name: order-api
    attrs: {team: trade, env: prod}
    selector: service=order-api
    depends_on: [database/order-mysql, cache/order-redis]
  - kind: database
    name: order-mysql
    hosts: [db-01, db-02]
```

- `Provision` 读取并严格解码文件（`KnownFields(true)`），检查 `kind`、`name` 格式和 `(kind, name)` 唯一，文件不超过 4MB。
- 文件在启动时读取一次。修改后需要重启网关。
- `selector` 只检查长度，不检查语法。语法错误在 agent 用它调用 action 时由现有的 targets 校验报告。
- `hosts` 中不存在的主机名在返回前被可见性过滤去掉（第 8.3 节）。

### 7.2 `inventory.host_labels`

配置：

```yaml
config:
  label: service    # 必填。以 "reported." 开头时读主机上报的标签，否则读授权标签，与 selector 语法一致
  kind: service     # 可选，默认 service
```

- 每次 `Resolve` 调用 `Host.Hosts(ctx)`，按标签值分组。每个不同的值生成一个实体：`Name` 为标签值，`Hosts` 为该值下的主机名（排序），`Selector` 为 `<label>=<value>`。
- 没有该标签的主机不出现在结果中。
- 不缓存。主机表的查询在网关现有的规模下按每次调用执行；如果以后出现性能问题再加缓存。

## 8. MCP 工具 `entities_search`

### 8.1 定义

- 只有存在至少一个可用的 inventory 实例时，`fixedTools` 才包含这个工具。插件配置在进程生命周期内不变，所以工具列表缓存键不需要增加插件版本。
- 与 `hosts_search` 一样，工具对所有身份列出，权限在调用时检查。
- `ReadOnlyHint: true`。描述追加 `toolInstructions`。

参数（`additionalProperties: false`）：

| 参数 | 类型 | 说明 |
| --- | --- | --- |
| `kind` | string | 可选，精确匹配 |
| `name` | string | 可选，名称子串，不区分大小写 |
| `sources` | string 数组 | 可选，inventory 实例 ID；枚举值为当前可用实例 |
| `limit` | integer | 可选，1~100，默认 20 |

### 8.2 处理顺序

在 `execute`（`internal/gateway/mcp/call.go:149`）中与 `hosts_search` 一样，在 `s.jobs == nil` 检查之前分支：

1. 解析参数。未知参数、类型错误、`sources` 含未知 ID 时返回 `InvalidArgument` 并列出合法值。
2. `Identity.Require(ctx, authz.ViewInventory, authz.Action{}, authz.Host{})`。拒绝时返回 `PermissionDenied`。`mcp.Identity` 接口新增 `Require`，由 `api.Service.Require`（`internal/gateway/api/service.go:234`）实现。
3. `pluginhost.SearchInventory`。
4. 收集所有结果中的主机名，调用 `Identity.VisibleHostnames(ctx, names)`（第 8.3 节），从每条结果的 `hosts` 中移除不可见的主机名。原本有 `hosts`、过滤后为空且没有 `selector` 的实体整条移除。
5. 每条结果的 `hosts` 最多返回 20 个，另给 `host_count`（过滤后的总数）。
6. 组装结果并检查 32KB 上限（`resultByteLimit`）。超出时用二分法减少实体条数，设置 `truncated: true`。
7. 现有的 `call()` 写一条结果审计，`Operation` 为 `mcp/entities_search`。

结果：

```json
{
  "entities": [
    {"kind": "service", "name": "order-api", "attrs": {"team": "trade"},
     "hosts": ["app-01"], "host_count": 1, "selector": "service=order-api",
     "depends_on": ["database/order-mysql"], "source": "inv-static"}
  ],
  "truncated": false,
  "source_errors": [{"source": "inv-k8s", "reason": "timeout"}],
  "output_trust": "untrusted"
}
```

所有实例都失败时仍返回成功结果，`entities` 为空，`source_errors` 列出全部实例。

### 8.3 主机可见性

`api.Service` 新增：

```go
// VisibleHostnames 返回 names 中存在、处于活动状态、且调用者有 view_hosts 权限的主机名。
func (s *Service) VisibleHostnames(ctx context.Context, names []string) (map[string]bool, error)
```

实现：用 `activeHostLabels`（`internal/gateway/api/policy_sql.go:43`）读取活动主机及授权标签，对 `names` 中存在的每台主机调用 `s.can(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(h))`（与 `visibleHosts`，`internal/gateway/api/hosts.go:158` 相同的判定）。与 `visibleHosts` 不同，结果为空时不报错。

`Selector` 不展开为主机名，原样返回。agent 用它调用 action 时，现有的 ABAC 逐台判定。

### 8.4 授权

- `internal/gateway/authz/types.go` 增加 `ViewInventory Operation = "view_inventory"`，`engine.go:163` 的 `validOperation` 增加该值。
- 默认角色：与 `view_hosts` 相同，给 admin、operator、viewer（`internal/gateway/authz/defaults.go`）。
- 不是 action 过滤类操作，`policy.rego` 不变。
- `internal/gateway/api/policy.go:331` 的 `consoleOperations` 增加该值，策略试算覆盖它。`policy_view_inputs_rework_test.go` 中的计数从 34 改为 35（C 从 12 变为 13）。
- 带 `host_labels` 条件的规则不会授予或拒绝这个操作，与 `view_system` 等非主机操作相同。

### 8.5 保留名称

`internal/catalog/catalog.go:269` 的保留名称增加 `entities_search`。已有目录中如果有同名 action，新版本校验会拒绝该目录，需要改名后重新签名发布。示例目录中没有同名 action。

## 9. 与 `plugin-architecture.md` 的差异

| 位置 | 上位设计 | 本轮实现 | 原因 |
| --- | --- | --- | --- |
| 第 5.1 节 | `Provisioner`、`Validator`、`Cleaner` 三个可选接口 | 只有 `Provisioner`；`Provision` 带 `ctx` | 两个插件都不需要另外两个 |
| 第 5.4 节 | `Host` 含 `HTTPClient`、`Credential`、`Cache`、`State`、`Health`、`Now` | 只有 `InstanceID`、`Logger`、`Hosts` | 本轮插件不访问外部系统；健康状态由 pluginhost 根据 `Provision` 结果维护 |
| 第 5.4 节 | 凭据复用 `internal/builtin/credfile` | 待定 | `credfile.Read` 要求文件属主为 root 且权限 0600，网关镜像以 65532 用户运行（`deploy/docker/Dockerfile:25`），读不到这样的文件。第一个需要凭据的插件出现时另行设计 |
| 第 6.1 节 | `Entity` 有 `ID`、`Source`；另有 `Relation` 类型；`Query` 有 `Attrs`、`Depth` | `Entity` 用 `Kind/Name` 标识，依赖写在 `DependsOn`；`Query` 只有 `Kind`、`Name`、`Limit` | 减少类型；关系展开由 agent 多次查询完成 |
| 第 6.1 节 | 同名实体合并，冲突返回 `conflicts` | 不合并，每条结果带 `source` | 合并规则在没有实际多来源数据前难以确定 |
| 第 7.2 节 | 审计记录查询参数和结果数量 | 只写现有的结果审计（操作、结果、策略版本、命中规则） | `reqctx.AuditEvent` 是白名单，注释要求不加入请求内容（`internal/gateway/reqctx/reqctx.go:20`） |
| 第 7.2 节 | 每实例并发上限 | 只有超时 | 两个插件都只读网关自己的数据 |
| 第 11 节 | `plugintest` 契约测试套件 | 普通单元测试 | 还没有第三方插件 |

`plugin-architecture.md` 第 7.2 节关于审计的描述按本表修正。

## 10. 测试

| 范围 | 测试 |
| --- | --- |
| 阶段 0 | `BuiltinNames()` 等于字面量列表；hello 中的列表等于 `BuiltinNames()` |
| `plugin` | ID 格式、重复注册 panic、`Modules()` 排序 |
| `pluginhost` | 配置错误各一例（id 格式、重复、未注册模块、接口不符、未知 config 字段、timeout 越界）拒绝启动；`Provision` 失败时 `required` 两种取值的行为；超时、错误、panic 分别得到对应 `reason`；不合格实体被丢弃；`Limit` 截断和排序；secrets 规则作用于 `Attrs` |
| `inventory.static` | 正常文件；未知字段、重复 `(kind, name)`、超大文件拒绝；按 `Query` 过滤 |
| `inventory.host_labels` | 授权标签和 `reported.` 两种来源；无标签主机不出现 |
| `authz` | `TestDefaultRoles` 更新；viewer 允许、publisher 拒绝 `view_inventory` |
| `api` | `VisibleHostnames`：不存在的主机、无权限主机被去掉，结果为空时不报错；系统状态包含 `plugin:<id>` |
| `mcp` | 没有 inventory 实例时工具不出现，现有工具计数和 golden 文件不变；有实例时的工具 schema；参数错误；无权限；可见性过滤后移除实体；32KB 截断；`source_errors` |
| 端到端 | 在 testpg 上起网关 MCP 服务，配置 `inventory.static`：`entities_search` 返回实体，用返回的 `selector` 调用一个只读 action 并成功。优先复用 `internal/gateway/mcp/real_job_test.go` 的夹具；夹具不适用时在实现计划中说明替代方式 |

## 11. 文档

- `docs/design.md`：第 6 节 ABAC 操作列表增加 `view_inventory`；第 7 节工具表增加 `entities_search`。
- `docs/architecture-decisions.md`：第 5 节默认角色表增加 `view_inventory`。
- `website/policies.md`、`website/zh/policies.md`：操作列表和默认角色表。
- `examples/policy/read-only.yaml`、`examples/policy/maintenance.yaml`：administrators 规则增加 `view_inventory`。
- `docs/protocol.md:180`、`docs/p4b-management-api.md:32`：操作列表和试算计数。
- `examples/gateway.yaml`：增加注释掉的 `plugins` 示例；新增 `examples/topology.yaml` 作为 `inventory.static` 的示例文件。
- `docs/plugin-architecture.md`：第 7.2 节审计描述按第 9 节修正，并链接本文。
