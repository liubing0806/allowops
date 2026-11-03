# 插件架构阶段 0、1 实现设计

状态：已确认并实现（2026-11-03）。Astra（gpt-6-astra）复审设计一轮、审计实现一轮，意见的处理见第 12 节。上位设计见 `plugin-architecture.md`，决定见 `architecture-decisions.md` 第 22 节。本文写的是阶段 0 和阶段 1 的实际实现，与上位设计不同的地方集中列在第 10 节。

代码位置依据 commit `dbb18f8`（源码与 `b11c123` 相同）。

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
| 可选接口 `Validator`、`Cleaner` | 第一个需要它们的插件 |
| 每实例并发上限、`Query.Limit` 分页提示 | 第一个数据量大、需要在源端限量的插件。给 `Query` 增加字段不破坏现有插件 |
| 已编译模块列表（`plugin.Modules()`）及控制台展示 | 出现第一个第三方插件 |
| 契约测试套件 `plugin/plugintest`、`allowops build` 自定义构建 | 出现第一个第三方插件 |
| 同名实体合并、跨来源依赖引用 | 实际使用中出现多个来源描述同一实体的需要 |

## 2. 阶段 0：builtin 名称只保留一份

现状：

- `internal/catalog/builtin.go:54` 的 `Builtins` map 是唯一被读取的注册表。主机端执行（`internal/executor/executor.go:289`）、目录校验（`internal/catalog/catalog.go:250`）和网关的 `unsupportedActionSchema`（`internal/gateway/mcp/schema.go:15`）都查它。
- `internal/agent/agent.go:111` 另写了一份 11 个名称的列表。网关只把它存库并在主机 API 中显示（`internal/gateway/hostconn/service.go:418`、`internal/gateway/api/hosts_sql.go:41`），没有代码据此做判断。主机是否支持某个 action 由 `catalog.CheckHost`（`internal/agent/catalog.go:163`）通过 `Builtins` 判断。所以两份列表不一致时，后果只是主机 API 显示的能力列表不准确。

改动：

1. 在 `internal/catalog/builtin.go` 增加 `func BuiltinNames() []string`，返回 `Builtins` 的键，按字母排序。
2. `agent.go:111` 改为从 `catalog.BuiltinNames()` 生成。`internal/agent` 已经导入 `internal/catalog`。合入 main 的 Arthas 改动后，主机未安装 Arthas 时列表去掉 `jvm_arthas`，与 main 的行为一致。
3. `internal/agent/events_test.go:54` 改为断言 hello 中的列表等于 `catalog.BuiltinNames()`（两边都去掉 `jvm_arthas` 后比较；安装状态由 `arthas_test.go` 覆盖）。
4. 在 `internal/catalog` 增加一个测试，用字面量列表断言 `BuiltinNames()` 的完整内容。这样误删一个处理器时测试失败。

不做：不把注册移到各 `internal/builtin/*` 包。那些包要导入 `catalog` 的类型，而 `catalog` 已导入它们，会形成循环依赖。`Builtins` 保持可修改的包级变量，3 个测试文件在运行时增删条目（`internal/cli/builtin_parameters_test.go:33`、`internal/executor/builtin_error_text_test.go:30,121`、`internal/executor/parameter_namespaces_test.go:27,76`）。

列表顺序从手写顺序变为字母顺序。网关不比较顺序。

## 3. 包与文件

```
plugin/plugin.go                         Register、Lookup、ModuleID、ModuleInfo、Module、Provisioner、Host、HostInfo
plugin/inventory/inventory.go            Entity、Query、Resolver
plugins/standard/standard.go             空白导入两个官方插件
plugins/inventory/static/static.go       inventory.static
plugins/inventory/hostlabels/hostlabels.go  inventory.host_labels
internal/gateway/pluginhost/config.go    Config 类型与解码
internal/gateway/pluginhost/host.go      实例构造、SearchInventory、Health
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
// ctx 带超时，但取消是协作式的：插件中不响应 ctx 的阻塞操作不会被中断。
type Provisioner interface {
	Provision(ctx context.Context, h Host) error
}

// Host 是插件能拿到的全部网关能力。
type Host interface {
	InstanceID() string
	Logger() *slog.Logger
	// Hosts 返回当前全部活动主机（证书状态为 active，不代表在线）。
	// 结果没有按调用者权限过滤，网关在返回给调用者之前过滤。
	Hosts(ctx context.Context) ([]HostInfo, error)
}

type HostInfo struct {
	Hostname       string
	Labels         map[string]string // 授权标签
	ReportedLabels map[string]string // 主机上报的标签
}

func Register(m Module)                      // 在 init() 中调用；ID 格式错误或重复时 panic
func Lookup(id ModuleID) (ModuleInfo, bool)
```

`Register` 只检查 ID 格式和重复。模块是否实现了命名空间要求的接口，由 `pluginhost` 在启动时检查（第 6.2 节）。这样新增扩展点时不需要修改注册逻辑。

## 5. `plugin/inventory` 包

```go
package inventory

type Entity struct {
	Kind      string            // ^[a-z][a-z0-9_]{0,31}$
	Name      string            // 1~128 字节
	Attrs     map[string]string // 可选；键匹配 ^[A-Za-z0-9_.-]{1,64}$
	Hosts     []string          // 关联的主机名，可选
	Selector  string            // 主机标签选择器，可选，语法与 action 的 targets.selector 相同，最长 512 字节
	DependsOn []string          // 依赖的实体，格式 "<kind>/<name>"，指同一来源（同一插件实例）中的实体
}

type Query struct {
	Kind string // 精确匹配；空表示全部
}

type Resolver interface {
	// Resolve 返回全部匹配的实体。返回的数据归调用方所有，插件不得在之后修改，
	// 也不得假定调用方不修改。
	Resolve(ctx context.Context, q Query) ([]Entity, error)
}
```

- `Entity` 是 Go 接口类型，没有 YAML 或 JSON 标签。插件自己的文件格式、MCP 的输出格式各自定义字段名。
- 所有字符串字段不得包含换行符（`\n`、`\r`）。
- `Query` 没有名称条件。名称过滤由网关在脱敏之后进行（第 6.3 节）。如果插件按原始名称过滤，调用者可以用 `name=password=a`、`name=password=b` 这类条件逐字符推断被脱敏的名称。
- `Query` 没有数量限制。网关先做权限过滤，再截断（第 8.2 节），所以需要插件返回全部匹配结果。以后出现数据量大的插件时，再增加限量提示字段。
- 不提供关系展开深度。agent 需要依赖的详情时，用 `DependsOn` 中的名称和同一 `source` 再查一次。

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

`plugins` 最多 32 项。这个上限同时限定了 `source_errors` 的大小（第 8.2 节）。

### 6.2 启动

`pluginhost.New(ctx, configs, deps)`。在 `serve`（`cmd/allowops-gateway/main.go`）中，放在 `newJobServices`（第 190 行）之前调用。原因：`startJobServices`（第 194 行）会启动 agent 服务并打开监听端口，之后的失败路径需要显式关闭它们；放在之前，插件配置错误时没有需要清理的资源。

`deps` 包含 logger 和一个返回 `[]plugin.HostInfo` 的函数，由 main 用 `db.Queries.ListActiveHostLabels`（`internal/store/queries/policy.sql:14`）实现。

对每个配置项依次执行：

1. 检查 `id` 格式和唯一性、`timeout` 范围、项数上限。
2. `disabled: true` 的实例跳过，不构造，不出现在健康状态中。
3. `plugin.Lookup(module)`。未注册时报错。
4. 按模块 ID 的命名空间检查接口。本轮只有 `inventory`：`New()` 的返回值必须实现 `inventory.Resolver`。其他命名空间或接口不符时报错。
5. 解码 `config`。第 1、3 步的错误不回显未校验的值：`id` 不合法时用序号（`plugins[N]`），模块未注册时不写模块名。解码错误只保留插件 `id` 和行号（`plugin <id>: invalid config at line N`），`yaml.v3` 的原始错误会引用字段名和值。先遍历节点树，含有别名节点（`*anchor`）时报错，错误信息给出插件 `id`。然后把节点重新编码为 YAML，再用 `KnownFields(true)` 解码到 `New()` 返回的对象。重新编码是因为 `yaml.v3` 的 `Node.Decode` 不支持 `KnownFields`；拒绝别名是因为单独重新编码一个子树时，引用的锚点可能在子树之外。
6. 如果实现了 `Provisioner`，用带 `timeout` 的 ctx 调用 `Provision`。失败时：`required: true` 报错；否则实例标记为不可用，错误写日志，继续启动。

第 1、3、4、5 步的错误都是配置错误，网关拒绝启动，不受 `required` 影响。

配置修改需要重启网关生效。

### 6.3 `SearchInventory`

```go
type Result struct {
	inventory.Entity
	Source string // 实例 ID
}

type SourceError struct {
	Source string `json:"source"`
	Reason string `json:"reason"` // timeout | failed | panic
}

func (h *Host) InventorySources() []string // 可用的 inventory 实例 ID，按配置顺序
// Query 是调用者的查询条件。Name 与脱敏后的实体名称做不区分大小写的子串匹配。
type Query struct{ Kind, Name string }

func (h *Host) SearchInventory(ctx context.Context, q Query, sources []string) ([]Result, []SourceError)
```

处理步骤：

1. `sources` 为空时使用全部可用实例。未知或不可用的 ID 由调用方（MCP）在调用前拒绝。
2. 每个实例在独立 goroutine 中调用 `Resolve`，只传入 `Kind`，用 `context.WithTimeout(ctx, timeout)`，并 `defer recover()`。网关等待到超时为止，不等待不响应 ctx 的插件返回；迟到的结果丢弃。
3. 超时记为 `timeout`，返回错误记为 `failed`，panic 记为 `panic`。错误和 panic 值去掉换行、经 `Redactor.Line` 脱敏后写日志（含实例 ID），不返回给调用方。`Provision` 的错误同样脱敏后写日志；`required: true` 时网关的启动错误中也只含脱敏后的文本。
4. 深拷贝每个实体（`Attrs`、`Hosts`、`DependsOn`），后续步骤只修改拷贝。
5. 丢弃字段不合格的实体：`Kind` 格式错误、`Name` 为空或超过 128 字节、`Attrs` 键格式错误、`Selector` 超过 512 字节、任一字符串含换行符。丢弃数量写日志。
6. 按 `Kind` 再过滤一次。
7. 脱敏，使用 `redact.New(nil)` 得到的 secrets 规则：
   - `Name`：用 `Redactor.Line` 处理，然后按 `q.Name` 过滤。过滤在脱敏之后，原因见第 5 节。
   - `Attrs`：键本身经 `Redactor.Line` 处理后有变化（例如键是一个 JWT）时，删除该项。其余键值对处理字符串 `<键>=<值>`。结果仍以 `<键>=` 开头时，取其后部分再单独用 `Redactor.Line` 处理一次作为值；否则值替换为 `[REDACTED]`。这样 `password: x` 这类凭据由键名识别，`-p<密码>` 这类只在值开头才匹配的凭据由第二次处理识别。
   - `Selector`：整串、每个条件、每个条件的键和值分别经 `Redactor.Line` 处理，任一有变化时清空，只保留 `Hosts`。脱敏后的 selector 语法仍然合法，但会选中另一组主机。例如标签值 `https://u:p@x` 脱敏后为 `[REDACTED:url_credentials]x`。
   - `DependsOn` 的每一项：`/` 之后的名称部分先单独处理，再处理整项。
8. 按 `Kind`、`Name`、`Source` 排序。

`SearchInventory` 不截断。截断在 MCP 层权限过滤之后进行。

### 6.4 健康状态

```go
type Health struct{ ID, Module string; OK bool }
func (h *Host) Health() []Health
```

`OK` 只反映 `Provision` 的结果。单次调用的失败通过 `source_errors` 返回，不改变健康状态。

`api.Service` 增加 `ConfigurePluginHealth(func() []pluginhost.Health)`，做法与现有的 `ConfigureJobDependencies`（`internal/gateway/api/job_system.go:15`）相同。`dependencyHealth`（`internal/gateway/api/system.go:32`）在现有三项之后追加 `plugin:<id>`；不可用时状态为 `UNAVAILABLE`，原因为固定文本 `provision failed`。不需要修改 proto（`DependencyHealth` 是 repeated 字段）。

后果：一个不可用的插件会让控制台系统页的总体状态显示为 DEGRADED。这是预期行为。`/health/ready`（负载均衡就绪检查，`internal/gateway/server/health.go`）不包含插件。

## 7. 两个官方插件

### 7.1 `inventory.static`

配置：

```yaml
config:
  file: /etc/allowops/topology.yaml
```

文件格式（字段名由插件自己的结构体用 `yaml` 标签定义）：

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

- `Provision` 读取文件：用 `O_NONBLOCK` 打开，再检查打开的文件是普通文件。不加 `O_NONBLOCK` 时，打开一个没有写入方的 FIFO 会一直阻塞，`Provision` 的超时无法中断它。最多读 4MB，超过时报错。用 `KnownFields(true)` 严格解码，检查第 5 节的字段规则和 `(kind, name)` 唯一。
- YAML 解码错误只保留行号（`inventory file: invalid YAML at line N`）。`yaml.v3` 的原始错误会引用文件中的键和值。
- 校验错误只用序号标识实体（如 `inventory entity #2: duplicate kind and name`），不含名称、键或值。这些字段可能含有凭据，而错误会写入日志或网关的启动错误输出。
- 文件在启动时读取一次。修改后需要重启网关。
- `Resolve` 按 `Kind` 过滤，返回实体的拷贝，不返回内部缓存的 map 和 slice。
- `selector` 只检查长度，不检查语法。语法错误在 agent 用它调用 action 时由现有的 targets 校验报告。
- `hosts` 中不存在的主机名在返回前被可见性过滤去掉（第 8.3 节）。
- `examples/topology.yaml` 是示例文件，插件测试会实际加载它。

### 7.2 `inventory.host_labels`

配置：

```yaml
config:
  label: service    # 必填。以 "reported." 开头时读主机上报的标签，否则读授权标签，与 selector 语法一致
  kind: service     # 可选，默认 service
```

- 每次 `Resolve` 调用 `Host.Hosts(ctx)`，按标签值分组。`Query.Kind` 与配置的 `kind` 不同时返回空结果。每个不同的值生成一个实体：`Name` 为标签值，`Hosts` 为该值下的主机名（排序）。
- `Selector` 为 `<label>=<value>`，只在标签键和值都不含 `,`、`=`，且没有首尾空白时生成。否则不生成 selector，只返回 `Hosts`。原因：selector 语法按 `,` 拆分条件、按 `=` 拆分键值、并去掉首尾空白（`internal/gateway/api/hosts.go:55-60`），而标签值允许这些字符（`internal/gateway/api/hosts.go:285`）。拼接这样的值会选中其他主机。
- 没有该标签的主机不出现在结果中。
- `label` 名称含 `pass`、`pwd`、`secret`、`token`、`credential`、`auth` 或 `api_key`、`master_key`、`signing_key` 这类词时，`Provision` 报错。测试逐个对照 `internal/redact`：脱敏器按 `<键>=<值>` 识别为凭据的键都必须被拒绝。原因：实体名称就是标签值，网关脱敏名称时没有标签键作为上下文，`password` 标签的值会原样返回。
- 不缓存。

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
3. `pluginhost.SearchInventory`，得到全部匹配实体。
4. 可见性过滤（第 8.3 节）。
5. 截断到 `limit`，设置 `truncated`。
6. 每条结果的 `hosts` 最多返回 20 个，另给 `host_count`（过滤后的总数）。
7. 用 `toolResult` 编码，按完整的 `ToolResult` 大小与 `resultByteLimit`（32KB，`internal/gateway/mcp/output.go:14`）比较。超出时用二分法减少实体条数，设置 `truncated: true`。`source_errors` 最多 32 项（第 6.1 节），每项不超过约 100 字节，实体减到零时一定能放下。
8. 现有的 `call()` 写一条结果审计，`Operation` 为 `mcp/entities_search`。

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

所有实例都失败时仍返回成功结果：`entities` 为空，`source_errors` 列出全部实例。审计中的结果为 `allow`，表示调用被授权并完成，不表示每个来源都查询成功。

### 8.3 主机可见性

`api.Service` 新增：

```go
// VisibleHostnames 返回 names 中存在、处于活动状态、且调用者有 view_hosts 权限的主机名。
func (s *Service) VisibleHostnames(ctx context.Context, names []string) (map[string]bool, error)
```

实现：用 `activeHostLabels`（`internal/gateway/api/policy_sql.go:43`）读取活动主机及授权标签，对 `names` 中存在的每台主机调用 `s.can(ctx, authz.ViewHosts, authz.Action{}, hostAttributes(h))`，与 `visibleHosts`（`internal/gateway/api/hosts.go:158`）的判定相同。与 `visibleHosts` 不同，结果为空时不报错。

过滤规则：

1. 从每条结果的 `hosts` 中移除不可见的主机名。
2. 插件返回时 `hosts` 非空、过滤后为空的实体，整条移除，即使它有 `selector`。这类实体由主机数据派生（如 `inventory.host_labels`），调用者看不到这些主机时，也不应看到由它们的标签派生出的名称。
3. 插件返回时 `hosts` 就为空、只有 `selector` 的实体保留。这类实体由运维人员在配置中写明，`view_inventory` 授权即允许查看。

`Selector` 不展开为主机名。agent 用它调用 action 时，现有的 ABAC 逐台判定。

### 8.4 授权

- `internal/gateway/authz/types.go` 增加 `ViewInventory Operation = "view_inventory"`，`engine.go:161` 的 `validOperation` 增加该值。
- 默认规则：与 `view_hosts` 相同，给 admin、operator、viewer（`internal/gateway/authz/defaults.go`）。
- 默认规则只在首次初始化时写入数据库（`insertInitialPolicy`，`internal/gateway/api/sql.go:44`，`ON CONFLICT DO NOTHING`）。已有部署升级后，现有策略不包含 `view_inventory`，所有身份调用 `entities_search` 都会被拒绝。网关不自动修改已有策略。升级说明写明：管理员通过控制台或 `allowops policy apply` 给需要的角色增加 `view_inventory`。
- 不是 action 过滤类操作，`policy.rego` 不变。
- `internal/gateway/api/policy.go:331` 的 `consoleOperations` 增加该值，策略试算覆盖它。`policy_view_inputs_rework_test.go` 中的计数从 34 改为 35，低于上限的边界值从 33 改为 34。
- 带 `host_labels` 条件的规则不会授予或拒绝这个操作，与 `view_system` 等非主机操作相同。

### 8.5 保留名称

`internal/catalog/catalog.go:269` 的保留名称增加 `entities_search`。已有目录中如果有同名 action，新版本校验会拒绝该目录，需要改名后重新签名发布。示例目录中没有同名 action。

## 9. 并发

- `Resolve` 可能被多个 MCP 请求并发调用。插件自己保证并发安全；`inventory.static` 只读启动时加载的数据并返回拷贝，`inventory.host_labels` 不持有状态。
- `pluginhost` 对插件返回的结果先深拷贝再处理（第 6.3 节第 4 步）。
- `Redactor.Line` 不修改 `Redactor` 的状态，一个实例可以被并发使用。

## 10. 与 `plugin-architecture.md` 的差异

| 位置 | 上位设计 | 本轮实现 | 原因 |
| --- | --- | --- | --- |
| 第 2.2 节 | 两份 builtin 列表不一致会导致 action 被标记为 `unsupported` | 只影响主机 API 显示的能力列表 | 网关不读取 hello 中的列表（第 2 节） |
| 第 5.1 节 | `Provisioner`、`Validator`、`Cleaner` 三个可选接口；`Modules()` | 只有 `Provisioner`，带 `ctx`；没有 `Modules()` | 本轮没有使用者 |
| 第 5.4 节 | `Host` 含 `HTTPClient`、`Credential`、`Cache`、`State`、`Health`、`Now` | 只有 `InstanceID`、`Logger`、`Hosts` | 本轮插件不访问外部系统；健康状态由 pluginhost 维护 |
| 第 5.4 节 | 凭据复用 `internal/builtin/credfile` | 待定 | `credfile.Read` 要求文件属主为 root 且权限 0600，网关镜像以 65532 用户运行（`deploy/docker/Dockerfile:25`），读不到这样的文件 |
| 第 6.1 节 | `Entity` 有 `ID`、`Source`；另有 `Relation` 类型；`Query` 有 `Attrs`、`Depth`、`Limit` | `Entity` 用 `Kind/Name` 标识，依赖写在 `DependsOn` 且限同一来源；`Query` 只有 `Kind` | 减少类型；网关需要在权限过滤后截断，插件须返回全部匹配结果 |
| 第 6.1 节 | 同名实体合并，冲突返回 `conflicts` | 不合并，每条结果带 `source` | 没有实际多来源数据前难以确定合并规则 |
| 第 7.2 节 | 审计记录查询参数和结果数量 | 只写现有的结果审计（操作、结果、策略版本、命中规则） | `reqctx.AuditEvent` 是白名单，注释要求不加入请求内容（`internal/gateway/reqctx/reqctx.go:20`） |
| 第 7.2 节 | panic 时实例标记为 `error` | 健康状态只反映 `Provision`；panic 只体现在该次调用的 `source_errors` | 健康状态保持简单；单次失败不应长期改变状态 |
| 第 7.2 节 | 每实例并发上限 | 只有超时 | 两个插件都只读网关自己的数据 |
| 第 11 节 | `plugintest` 契约测试套件 | 普通单元测试 | 还没有第三方插件 |

`plugin-architecture.md` 的对应章节加注指向本表。

## 11. 测试

| 范围 | 测试 |
| --- | --- |
| 阶段 0 | `BuiltinNames()` 等于字面量列表；hello 中的列表等于 `BuiltinNames()` |
| `plugin` | ID 格式、重复注册 panic、`Lookup` |
| `pluginhost` 配置 | 每种配置错误各一例拒绝启动：id 格式、重复、超过 32 项、未注册模块、接口不符、未知 config 字段、config 含别名、timeout 越界；`Provision` 失败时 `required` 两种取值的行为 |
| `pluginhost` 查询 | 超时、错误、panic 分别得到对应 `reason`；不合格实体（含换行、超长、键格式错误）被丢弃；排序；`Attrs` 中 `password: x` 被脱敏；两个并发查询修改结果不影响插件内部数据（`-race`） |
| `pluginhost` 凭据 | 经 `SearchInventory`：脱敏改变的 selector 被清空（含 `inventory.host_labels` 生成的 selector）；键为 JWT 的属性被删除；`name` 条件无法匹配被脱敏的原文；错误、panic 值和 `Provision` 错误中的凭据不出现在日志和 `required` 启动错误中 |
| `inventory.static` | 加载 `examples/topology.yaml`；未知字段、重复 `(kind, name)`、非普通文件拒绝；FIFO 在 2 秒内被拒绝；恰好 4MB 的合法文件接受，多 1 字节拒绝；错误信息不含实体名称和键；按 `Kind` 过滤 |
| `inventory.host_labels` | 授权标签和 `reported.` 两种来源；无标签主机不出现；值含 `,`、`=`、首尾空白时不生成 selector；生成的 selector 经现有 selector 解析后匹配的主机与分组一致 |
| `authz` | `TestDefaultRoles` 更新；viewer 允许、publisher 拒绝 `view_inventory` |
| `api` | `VisibleHostnames`：不存在的主机、无权限主机被去掉，结果为空时不报错；系统状态包含 `plugin:<id>`；已有策略（非首次初始化）下 viewer 调用被拒绝 |
| `mcp` | 没有 inventory 实例时工具不出现，现有工具计数和 golden 文件不变；有实例时的工具 schema；参数错误；无权限；可见性过滤先于截断（`limit=1`，排序第一的实体不可见时返回第二个）；派生实体在主机全部不可见时被移除；32KB 截断；零实体加 32 个来源错误不超限；正常空结果、部分失败、全部失败 |
| 端到端 | 使用 `internal/gateway/mcp/real_job_test.go` 的夹具（PostgreSQL、SeaweedFS、真实 job 服务和 agent），配置 `inventory.static`：`entities_search` 返回实体，用返回的 `selector` 调用一个只读 action 并执行成功 |

## 12. 复审意见的处理

Astra 复审（2026-11-03，基于 `b4079c2`）。

| 意见 | 处理 |
| --- | --- |
| 先截断后过滤会漏掉可见实体，返回值无法表达截断 | 采纳。`Query` 去掉 `Limit`，插件返回全部匹配结果；MCP 先过滤后截断（第 5、8.2 节） |
| 只脱敏 `Attrs` 的值会漏掉 `password: x` | 采纳。按 `<键>=<值>` 脱敏；字符串禁止换行（第 6.3 节） |
| `host_labels` 拼接 selector 可能选错主机 | 采纳。值含 `,`、`=` 或首尾空白时不生成 selector（第 7.2 节） |
| 只减少实体不能保证 32KB | 采纳。按完整 `ToolResult` 测量；插件实例上限 32 项，使 `source_errors` 有界（第 6.1、8.2 节） |
| 默认角色不影响已有部署 | 采纳。写明只适用于首次初始化，升级说明给出手工步骤，增加测试（第 8.4 节） |
| YAML：`DependsOn` 无字段映射；跨节点别名重新编码后失败 | 采纳。`Entity` 不承担文件格式，字段名由插件定义；拒绝别名（第 5、6.2 节） |
| 验收命令不能证明完成条件 | 采纳，见实施计划第 4 节 |
| 不可见主机派生的实体仍会返回 | 采纳。原有主机全部被过滤的实体整条移除（第 8.3 节） |
| 结果所有权与并发 | 采纳。宿主深拷贝；插件返回独占数据（第 5、9 节） |
| 插件初始化位置与超时边界 | 采纳。放在 `newJobServices` 之前；说明协作式取消；静态文件限普通文件且有界读取（第 4、6.2、7.1 节） |
| 删除 `Modules()` 和 `reason=unavailable` | 采纳 |
| 修正测试文件计数和上位文档的推断 | 采纳（第 2、10 节） |
| `DependsOn` 跨来源引用有歧义 | 采纳。限定为同一来源（第 5 节） |
| 性能完成条件没有标准；`examples-check` 不检查拓扑示例 | 采纳。删除性能完成条件；示例由插件测试加载 |
| 可选：工厂返回值的反射检查；全部失败改为错误结果；提前加入并发上限等设施 | 不采纳。前者没有运行时安装入口，后两者已在设计中明确语义或列为推迟项 |

Astra 审计实现（2026-11-03，基于 `2708d6e`）。每条必须修改项都有沙箱复现，失败测试单独提交（`a2a9477`），修复在 `e8763d0`。

| 意见 | 处理 |
| --- | --- |
| 脱敏改写 selector 后会选中其他主机 | 采纳。脱敏后有变化的 selector 清空，只保留 `Hosts`（第 6.3 节） |
| 插件按原始名称过滤，可逐字符推断被脱敏的名称 | 采纳。`inventory.Query` 去掉 `Name`，网关在脱敏后过滤（第 5、6.3 节） |
| 静态文件校验错误、resolve 错误和 panic 值原样进入日志和启动错误 | 采纳。静态插件错误只用序号；宿主写日志和启动错误前脱敏（第 6.3、7.1 节） |
| `Attrs` 的键本身可以是凭据 | 采纳。键经脱敏后有变化时删除该属性（第 6.3 节） |
| FIFO 使 `Provision` 永久阻塞 | 采纳。`O_NONBLOCK` 打开后检查文件类型（第 7.1 节） |
| 4MB 测试因 YAML 解析失败而通过，不能证明大小检查；名称脱敏和 selector 测试绕过宿主 | 采纳。改为合法 YAML 的边界测试；新增经 `SearchInventory` 的测试（第 11 节） |
| 不响应 ctx 的插件在超时后留下 goroutine | 不采纳。限制已在第 6.3 节第 2 步写明；并发上限列为推迟项（第 1 节） |
| 两处字段校验代码重复 | 不采纳。插件不导入 `internal/`（第 3 节），两处规则目前一致 |

Astra 第二轮复核（2026-11-03，基于 `ebf2f30`）。上表 5 条确认关闭。新发现 2 条，失败测试 `3abbed0`，修复在其后一个提交：

| 意见 | 处理 |
| --- | --- |
| `-p<密码>` 单独作为名称时被脱敏，放在 `memo=`、`service=`、`service/` 之后不被识别，经 selector、`Attrs` 值和 `DependsOn` 返回 | 采纳。值、selector 条件和依赖名称部分单独再脱敏（第 6.3 节） |
| `yaml.v3` 解码错误引用文件中的值，进入日志和启动错误 | 采纳。只保留行号（第 7.1 节） |

PR #24 审阅（Astra，2026-11-03，基于 `97b4894`）。失败测试 `49e625a`，修复在其后一个提交：

| 意见 | 处理 |
| --- | --- |
| `inventory.host_labels` 以 `password` 这类标签分组时，标签值作为名称返回，脱敏缺少键上下文 | 采纳。凭据类标签名在 `Provision` 时拒绝（第 7.2 节） |
| 插件 `config` 解码错误引用字段名，进入启动错误 | 采纳。只保留插件 ID 和行号（第 6.2 节） |
| 可选：`plugin` 包测试注册后未清理，`-count=2` 时 panic | 采纳，测试结束时注销 |
| 可选：`VisibleHostnames` 对每台主机线性查找名称 | 采纳，改为集合查找 |
| 可选：第 2 节未写 Arthas 安装状态过滤 | 采纳（第 2 节） |

PR #24 第二轮复审（Astra，2026-11-03，基于 `0cefd2e`）。上一轮 2 条中配置解码错误确认关闭。失败测试和修复紧随其后提交：

| 意见 | 处理 |
| --- | --- |
| 凭据标签规则漏掉 `master_key`、`signing_key`、`encrypt(ion)_key` | 采纳。补齐，并增加与 `internal/redact` 对照的测试（第 7.2 节） |
| 非法 `id`、未注册的 `module` 原样出现在启动错误中 | 采纳。用序号或已校验的 ID 标识（第 6.2 节） |
| `gateway.yaml` 外层解析错误（未知锚点、未知字段、类型错误）引用原值 | 本 PR 不处理。这是整个 `gateway.yaml` 的既有行为，不限于 `plugins` 节，另行处理 |

