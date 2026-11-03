# allowops 插件架构

状态：方向已确认（2026-11-03），尚未实施。决定见 `architecture-decisions.md` 第 22 节（PL1~PL10）。图示见 [plugin-architecture.html](plugin-architecture.html)（浏览器打开；截图 [plugin-architecture.png](plugin-architecture.png)）。

本文说明三件事：

1. 现在的架构里，哪些部分已经是可扩展的，哪些是写死的。
2. 实现插件模式要新增哪些模块。
3. 以后的新功能分别对应哪类插件。

本文只讨论只读能力。写操作类 action 不在本文范围内。

## 1. 目标

- 新的数据源、触发源和知识来源都以插件方式加入，网关核心代码不需要修改。
- 插件只能读取外部系统，不能绕过签名目录在主机上执行命令。
- 插件的每次调用都经过现有的认证、ABAC（基于属性的访问控制）、审计、脱敏和输出上限。
- allowops 不自建 CMDB（配置管理数据库）。服务拓扑由 Inventory 插件从已有系统读取。

非目标：

- 不提供插件市场，也不支持运行时安装插件。
- 不用 TypeScript 重写。主机端的约束（`CGO_ENABLED=0`、支持 CentOS 7、root 辅助程序）不变，见 PL10。

## 2. 现状

依据 commit `b11c123`。

### 2.1 已经可扩展的部分

| 扩展方式 | 位置 | 说明 |
| --- | --- | --- |
| action 目录 | `examples/catalog/actions/`，签名后下发 | 声明式；新增只读诊断能力的主要方式 |
| builtin 处理器接口 | `internal/catalog/builtin.go:27` 的 `BuiltinHandler` | 基础接口加三个可选接口：`RedactingBuiltinHandler`、`ActionBuiltinValidator`、`BudgetedBuiltinHandler` |
| 主机能力协商 | `AgentHello.Capabilities.Builtins` | 不支持某个 builtin 的主机，对应 action 标记为 `unsupported` |
| 身份源 | `gateway.yaml` 的 `providers` | OIDC 可配置多个，LDAP 最多一个 |
| 对象存储 | 只依赖 S3 API | 可接任意 S3 兼容服务 |

### 2.2 写死的部分

| 位置 | 现状 | 影响 |
| --- | --- | --- |
| `internal/catalog/builtin.go:55` | `Builtins` 是一个字面量 map，列出 11 个处理器 | 新增处理器要改这个文件 |
| `internal/agent/agent.go:111` | 能力列表里又写了一遍同样的 11 个名称 | 两处不一致时，主机不会报告新处理器，对应 action 会被标记为 `unsupported`。这是从代码推断的，未复现 |
| `internal/gateway/mcp/fixed.go:5` | 固定工具只有 `hosts_search`、`jobs_get`、`jobs_list`、`jobs_cancel` | 没有入口提供拓扑、变更、知识类工具 |
| `internal/gateway/authz/types.go:5` | `Operation` 枚举写死 | 新工具需要新增授权操作 |
| `cmd/allowops-gateway/main.go` | 在 `main` 里按顺序构造各组件 | 没有插件的配置、构造和停止流程 |

### 2.3 现在的网关装配顺序

`cmd/allowops-gateway/main.go`：

```
读取 gateway.yaml（KnownFields 严格解码）
→ audit.New → api.New（身份）→ identity.Start
→ hostconn.New → output.New → job.New
→ agent.Start → jobs.Start
→ mcp.New → server.New
→ 审计检查点、审计导出、版本检查（各自的 goroutine）
→ srv.Serve
停止：srv.Shutdown → 各组件关闭
```

插件的构造放在 `job.New` 之后、`mcp.New` 之前，停止放在 `srv.Shutdown` 之后。

## 3. 两层插件

| 层 | 插件形态 | 信任边界 | 变化 |
| --- | --- | --- | --- |
| 主机端 | builtin 处理器，由签名目录中的 action 引用 | 主机端；目录签名控制能调用什么 | 改为注册表，能力列表从注册表生成（PL6） |
| 网关端 | 新增的网关插件，实现 Inventory、Changes、Knowledge、Trigger 等扩展点 | 网关进程；配置由运维人员审阅 | 新增（PL1~PL5） |

判断一个新功能放在哪一层：

- 诊断数据（文件、进程、端口、数据库、指标、日志、链路）写成 action 或主机端 builtin。集中系统（Prometheus、Loki、SkyWalking）也按这种方式，在能访问它的探针主机上执行，现有的 `prometheus_query` 就是这样。
- 用于决定“查什么、在哪查”的上下文（服务拓扑、变更记录、排查知识）和触发源，写成网关插件。这类数据要在调用 action 之前取得，查询频率高，不适合每次都经过 job。

## 4. 新增模块

```
plugin/                     公开包：注册表、Module 接口、Host 接口、通用类型
plugin/inventory/           扩展点接口：Resolver
plugin/changes/             扩展点接口：Lister
plugin/knowledge/           扩展点接口：Store
plugin/trigger/             扩展点接口：Source、WebhookSource
plugin/plugintest/          契约测试套件
plugins/standard/           官方插件集合，网关 main 空白导入
plugins/inventory/static/       inventory.static
plugins/inventory/hostlabels/   inventory.host_labels
plugins/changes/allowops/       changes.allowops（目录和策略版本）
plugins/knowledge/gitdocs/      knowledge.git_markdown
internal/gateway/pluginhost/  网关内部：配置解析、构造、健康状态、调用包装、停止
internal/gateway/mcp/         新增固定工具 entities_search、changes_list、runbooks_search、runbooks_read
internal/gateway/authz/       新增操作 view_inventory、view_changes、view_knowledge
internal/builtin/registry     主机端 builtin 注册表（阶段 0）
cmd/allowops/ 的 build 子命令  自定义构建，加入第三方插件
```

`plugin/` 和 `plugins/` 放在 `internal/` 之外。Go 不允许其他 module 导入 `internal/` 下的包，第三方插件需要导入 `plugin/`。

## 5. 插件核心机制

### 5.1 模块注册

参照 Caddy 的 `caddy.RegisterModule`：

```go
package plugin

type ModuleID string // 命名空间.名称，如 "inventory.k8s_labels"

type ModuleInfo struct {
	ID  ModuleID
	New func() Module // 每个配置实例新建一个对象
}

type Module interface{ Module() ModuleInfo }

// 可选接口
type Provisioner interface{ Provision(Host) error }        // 读取配置后初始化
type Validator interface{ Validate() error }               // 校验配置
type Cleaner interface{ Cleanup(context.Context) error }   // 停止时释放资源

// Register 在 init() 中调用。ID 重复、命名空间未知或模块没有实现该命名空间的扩展点接口时 panic。
func Register(m Module)
```

命名空间和扩展点接口一一对应：

| 命名空间 | 必须实现的接口 |
| --- | --- |
| `inventory` | `inventory.Resolver` |
| `changes` | `changes.Lister` |
| `knowledge` | `knowledge.Store` |
| `trigger` | `trigger.Source` 或 `trigger.WebhookSource` |

插件包在 `init()` 中注册：

```go
package k8slabels

func init() { plugin.Register(Module{}) }

type Module struct {
	Kubeconfig string          `yaml:"kubeconfig"`
	Namespaces []string        `yaml:"namespaces"`
	CacheTTL   plugin.Duration `yaml:"cache_ttl"`
	host       plugin.Host
}

func (Module) Module() plugin.ModuleInfo {
	return plugin.ModuleInfo{ID: "inventory.k8s_labels", New: func() plugin.Module { return new(Module) }}
}
```

网关的 `main` 用空白导入决定包含哪些插件：

```go
import _ "github.com/liubing0806/allowops/plugins/standard"
```

不使用 Go 标准库的 `plugin` 包（运行时加载 `.so`）。它要求插件和主程序使用相同的工具链和依赖版本，只支持 Linux 和 macOS（PL1）。

### 5.2 自定义构建

第三方插件参照 xcaddy 加入：

```sh
allowops build --with github.com/acme/allowops-cmdb@v1.2.0 --output allowops-gateway
```

`allowops build` 生成一个带空白导入的 `main.go`，然后执行 `go build`。规则：

- 插件依赖的 allowops 版本必须和网关版本一致，由 `go.mod` 确定。
- 官方发布的二进制只包含 `plugins/standard`。
- 网关启动时把已编译的模块 ID 和来源 module 版本写入日志，控制台系统页显示同样的列表。

### 5.3 配置

`gateway.yaml` 新增 `plugins` 节：

```yaml
plugins:
  - id: inv-static          # 实例 ID：审计、健康状态和结果来源都用它
    module: inventory.static
    config:
      file: /etc/allowops/topology.yaml
  - id: inv-k8s
    module: inventory.k8s_labels
    disabled: false
    required: false         # true：Provision 失败时网关拒绝启动；false：只标记为不健康
    egress:                 # 本实例允许访问的外部地址
      - https://k8s-api.internal:6443
    timeout: 5s             # 单次调用超时
    max_concurrency: 4      # 本实例并发调用上限
    config:
      kubeconfig: /etc/allowops/kubeconfig
      namespaces: [prod, staging]
      cache_ttl: 5m
```

启动时依次执行：

1. `id` 匹配 `^[a-z][a-z0-9-]{0,63}$` 且不重复。
2. `module` 必须在注册表里，否则拒绝启动。
3. `config` 用 `KnownFields(true)` 严格解码到模块结构体，与现有 `gateway.yaml` 的解码方式一致。
4. 调用 `Provision` 和 `Validate`，每个都有超时。
5. 同一个模块可以配置多个实例，比如两个 CMDB。

### 5.4 宿主上下文

插件只拿到 `plugin.Host`。数据库、job 服务和身份服务都不暴露给插件：

```go
type Host interface {
	InstanceID() string
	Logger() *slog.Logger
	HTTPClient() *http.Client                 // 只能访问本实例 egress 中声明的地址
	Credential(ref string) ([]byte, error)    // 按引用读取凭据文件，配置中不写明文
	Cache() Cache                             // 带 TTL，按实例隔离
	Health() HealthReporter                   // 只能写本实例的健康状态
	State() State                             // 本实例的持久键值，存 PostgreSQL；用于 Trigger 游标
	Now() time.Time
}
```

- **凭据**：复用 `internal/builtin/credfile` 的规则，检查文件权限和属主。
- **出站访问**：`HTTPClient` 在拨号前检查目标地址是否在 `egress` 中，不在时返回错误。插件自己创建的 `net.Dial` 不受这个检查约束，所以官方插件的代码审阅要检查这一点。进程外插件（第 10 节）可以从操作系统层面限制网络。
- **健康状态**：每个实例一条，状态为 `ready`、`degraded`、`error`、`disabled`，显示在控制台系统页，接入 `internal/gateway/server/health.go`。
- **每种状态只有一个写入者**：插件只写自己实例的健康状态、缓存和键值。

## 6. 扩展点接口

接口参数和返回值只用 `context.Context` 和可序列化的数据类型，不用函数值和 channel（`trigger.Source.Run` 的 `emit` 回调除外，进程外实现时改为流）。这样以后可以加一层 gRPC 适配，接口不用改（PL8）。

### 6.1 Inventory（资源解析）

```go
package inventory

type Entity struct {
	Kind     string            // service | instance | database | cache | queue | ...
	ID       string            // 在插件实例内唯一
	Name     string
	Attrs    map[string]string // env、owner、team 等
	Hosts    []string          // 关联的 allowops 主机名，可为空
	Selector string            // 或者给出主机标签选择器
	Source   string            // 插件实例 ID，由网关填写
}

type Relation struct {
	From, To string // "Kind/ID"
	Type     string // runs_on | depends_on | calls
}

type Query struct {
	Kind, Name string
	Attrs      map[string]string
	Depth      int // 关系展开层数，网关限制上限
	Limit      int
}

type Resolver interface {
	Resolve(ctx context.Context, q Query) ([]Entity, []Relation, error)
}
```

`Hosts` 和 `Selector` 可以直接作为 action 的 `targets` 传入。agent 查到服务以后，不用再猜在哪些主机上执行。

多个插件实例的结果由网关合并：

- `Kind + Name` 相同的实体视为同一个，`Attrs` 合并，`Hosts` 取并集。
- 同一个属性在不同实例中的值不同时，不自动选择，返回 `conflicts` 字段，列出每个实例的值。
- 每个实体保留所有来源实例 ID。

### 6.2 Changes（变更事件）

```go
package changes

type Change struct {
	At      time.Time
	Kind    string // deploy | config | rollout | catalog | policy | package
	Service string
	Summary string
	Actor   string
	Ref     string // 外部链接或 ID
	Source  string
}

type Query struct {
	Services []string
	From, To time.Time // 网关限制最大时间窗口
	Limit    int
}

type Lister interface {
	List(ctx context.Context, q Query) ([]Change, error)
}
```

网关按 `At` 合并所有实例的结果，返回一条时间线。

### 6.3 Knowledge（排查知识）

```go
package knowledge

type Doc struct {
	ID, Title, Summary string
	Tags               []string // 告警名、服务名
	Source             string
}

type Store interface {
	Search(ctx context.Context, query string, tags []string, limit int) ([]Doc, error)
	Read(ctx context.Context, id string) (string, error) // Markdown 正文
}
```

同一份数据也可以作为 MCP resources 提供。

### 6.4 Trigger（触发源）

```go
package trigger

type Event struct {
	Kind    string // alert | schedule | message
	Key     string // 去重键，如告警指纹
	Title   string
	Labels  map[string]string
	At      time.Time
	Payload json.RawMessage // 原始数据，标记为不可信
}

type Source interface {
	Run(ctx context.Context, emit func(Event) error) error // 长期运行；ctx 取消时返回
}

type WebhookSource interface {
	Routes() []Route // 挂在 /hooks/<instance-id>/ 下，由网关鉴权
}
```

事件产生以后如何处理（启动排查会话、交给哪个 agent），属于编排层的边界，尚未决定（PL9）。阶段 4 之前只定义接口，不提供实现。

### 6.5 以后可能增加的扩展点

| 命名空间 | 用途 | 来源 |
| --- | --- | --- |
| `auditsink` | 审计导出到 syslog、webhook、Kafka | `design.md` 第 17 节 Roadmap |
| `notifier` | 通知（审批、巡检结果）到钉钉、邮件 | `design.md` 第 17 节 Roadmap 中的人工审批 |

新增扩展点需要修改 `plugin/` 包，并记录一条决定。新增某个扩展点的实现不需要。

## 7. 接入 MCP

### 7.1 固定工具

插件不能自己注册 MCP 工具（PL3）。网关按扩展点提供固定工具：

| MCP 工具 | 扩展点 | 授权操作 | 说明 |
| --- | --- | --- | --- |
| `entities_search` | Inventory | `view_inventory` | 按类型、名称、属性查实体和关系 |
| `changes_list` | Changes | `view_changes` | 按服务和时间窗口返回变更时间线 |
| `runbooks_search` | Knowledge | `view_knowledge` | 按关键词和标签检索 |
| `runbooks_read` | Knowledge | `view_knowledge` | 读取正文 |

工具的公共参数是 `sources`，可选，用于限定插件实例 ID；省略时查询全部已启用的实例。某个扩展点没有已启用的实例时，对应工具不出现在工具列表中。

这样做的原因：

1. 工具名不随插件数量变化。现在工具列表按“身份 + 目录版本 + 策略版本”缓存（`design.md` 第 7 节），缓存键只需要再加插件配置版本。
2. 授权在网关集中处理。`authz.Operation` 新增三个操作，策略规则的写法不变。
3. agent 看到的工具语义稳定，不随部署变化。

### 7.2 一次调用的处理顺序

```
认证 → 参数校验 → ABAC 判定（view_inventory 等）→ 写审计（调用前）
→ 按 sources 选择插件实例 → 并发调用（每个实例：超时、并发上限、recover）
→ 合并结果 → 按身份过滤主机可见性 → 脱敏 → 输出上限 → 标记 output_trust: untrusted → 写审计（结果）
```

| 步骤 | 规则 |
| --- | --- |
| 超时 | 每个实例单独超时，默认 5 秒，由 `timeout` 配置 |
| 并发上限 | 每个实例单独限制，默认 4，由 `max_concurrency` 配置 |
| recover | 插件 panic 时，这次调用返回错误，该实例标记为 `error`，网关进程继续运行 |
| 部分失败 | 一个实例失败时，返回其他实例的结果，并在 `source_errors` 中列出失败的实例和错误类别 |
| 主机可见性 | Inventory 结果中当前身份无权查看的主机名被移除 |
| 脱敏 | 所有字符串字段经过 `internal/redact` 的 secrets 规则 |
| 输出上限 | 沿用单次返回上限 32KB，超出时截断并标记 `truncated` |
| 审计 | 记录工具名、插件实例 ID、查询参数、结果数量、失败实例；不记录结果正文 |

## 8. 生命周期与多实例

网关可以水平扩容，各类插件的运行规则如下：

| 插件类型 | 运行规则 |
| --- | --- |
| Inventory、Changes、Knowledge | 每个网关实例各自构造和运行，缓存在实例内存里 |
| Trigger 的 `Source`（轮询） | 用 PostgreSQL advisory lock，只在一个实例上运行，与审计导出、版本检查的做法相同 |
| Trigger 的 `WebhookSource` | 所有实例接收请求，用 `Event.Key` 在数据库中去重 |

启动顺序：在 `job.New` 之后、`mcp.New` 之前构造插件。`required: true` 的实例失败时网关退出；其他实例失败时记录健康状态并继续启动。

停止顺序：`srv.Shutdown` 之后，停止 Trigger，再对每个实例调用 `Cleanup`，每个都有超时。

配置修改需要重启网关生效，不支持热加载。

## 9. 安全规则

1. 插件不能注册在主机上执行的能力，不能调用 job 服务（PL3）。主机端执行只能通过签名目录。
2. 网关仍然不主动连接被管主机。网关只能访问插件配置中 `egress` 声明的外部地址（PL4）。
3. 插件代码与网关同进程，权限和网关相同。只编译经过审阅的插件；不信任的第三方插件等进程外机制（第 10 节）。
4. 插件返回的内容一律视为不可信数据，与主机输出同样处理。
5. 凭据只通过 `Credential(ref)` 读取，不写入配置、日志和审计。

## 10. 进程外插件（阶段 5）

- 为每个扩展点生成 gRPC 适配器，可以参照 HashiCorp go-plugin 的做法。
- 网关一侧仍然看到同一个 Go 接口，汇总、授权和审计代码不变。
- 插件进程单独持有外部系统凭据，可以用独立用户、systemd 沙箱选项或容器限制网络和文件访问。

## 11. 测试与文档

- **契约测试套件** `plugin/plugintest`：每个扩展点一个函数，例如 `RunResolverContract(t, newModule, config)`，检查：
  - `ctx` 取消后在 1 秒内返回
  - 遵守 `Limit`
  - 相同输入的结果顺序稳定
  - 配置有未知字段时拒绝
  - 不通过 `Host.HTTPClient` 以外的方式访问网络（用无网络的测试环境检查）
- **官方插件**：每个都运行契约测试，加上用 `httptest` 模拟外部系统的测试。
- **网关集成测试**：MCP 端到端调用 `entities_search`，然后把返回的 `Selector` 作为 `targets` 执行一次只读 action。
- **文档**：`docs/plugin-cookbook.md` 写新增插件的步骤和检查清单。测试检查每个注册的官方模块都有对应文档。

## 12. 实施阶段

| 阶段 | 内容 | 完成条件 |
| --- | --- | --- |
| 0 | 主机端 builtin 改为注册表；`agent.go` 的能力列表从注册表生成 | 现有测试通过；新增测试检查能力列表与注册表一致 |
| 1 | `plugin/` 包、`pluginhost`、配置解析、健康状态；Inventory 扩展点；`inventory.static`、`inventory.host_labels`；`entities_search` 和 `view_inventory` | 契约测试通过；第 11 节的 MCP 端到端测试通过 |
| 2 | Changes 扩展点；`changes.allowops`；`changes_list` 和 `view_changes` | `changes_list` 返回按时间合并的目录和策略变更 |
| 3 | Knowledge 扩展点；`knowledge.git_markdown`；`runbooks_search`、`runbooks_read` | Git 仓库中的 Markdown 可以检索和读取 |
| 4 | Trigger 扩展点 | 依赖 PL9 编排层边界的决定 |
| 5 | 进程外插件适配器；`allowops build` | 按需要开始 |

## 13. 以后的功能对应哪类插件

| 功能 | 实现方式 | 模块 ID 示例 |
| --- | --- | --- |
| 服务拓扑：静态描述 | 网关插件，Inventory | `inventory.static` |
| 服务拓扑：从主机标签推导 | 网关插件，Inventory | `inventory.host_labels` |
| 服务拓扑：K8s 工作负载 | 网关插件，Inventory | `inventory.k8s_labels` |
| 服务拓扑：Prometheus target | 网关插件，Inventory | `inventory.prometheus_targets` |
| 服务拓扑：Nacos 注册中心 | 网关插件，Inventory | `inventory.nacos` |
| 服务拓扑：已有 CMDB | 网关插件，Inventory | `inventory.cmdb_http` |
| 发布记录：Jenkins、云效流水线 | 网关插件，Changes | `changes.jenkins`、`changes.yunxiao` |
| 配置变更：Nacos、Apollo | 网关插件，Changes | `changes.nacos` |
| K8s rollout 记录 | 网关插件，Changes | `changes.k8s_rollout` |
| allowops 目录和策略变更 | 网关插件，Changes | `changes.allowops` |
| runbook：Git 仓库 Markdown | 网关插件，Knowledge | `knowledge.git_markdown` |
| runbook：钉钉文档 | 网关插件，Knowledge | `knowledge.dingtalk_docs` |
| 告警触发排查 | 网关插件，Trigger | `trigger.alertmanager_webhook` |
| 定时巡检 | 网关插件，Trigger | `trigger.schedule` |
| 审计导出到 Kafka、syslog | 网关插件，`auditsink`（以后的扩展点） | `auditsink.kafka` |
| 链路追踪：SkyWalking、Jaeger | 主机端 builtin 加 action，在可访问的探针主机上执行 | builtin `trace_query` |
| 集中日志：Loki、Elasticsearch、SLS | 主机端 builtin 加 action | builtin `loki_query` |
| 消息队列积压：Kafka、RocketMQ | 主机端 builtin 加 action | builtin `kafka_lag` |
| 远端 TCP、HTTP、TLS 证书探测 | action 或主机端 builtin | builtin `probe` |
| 本机命令类诊断（如 jmap、traceroute） | action | — |

链路追踪、集中日志、消息队列目前写成主机端 builtin，与现有的 `prometheus_query` 一致。它们有 job 记录和完整输出存储，ABAC 可以按主机标签限制。如果以后需要从网关直接查询这类系统，要新增一个扩展点（例如 `telemetry`），并按第 6.5 节记录决定。
