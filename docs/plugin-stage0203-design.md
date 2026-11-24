# 插件架构阶段 A~D（排障前序上下文闭环）实现设计

状态：已吸收独立复审（Astra）第一、二轮全部 Blocking/Major 意见并定稿（2026-11-24）。上位设计见 `plugin-architecture.md`，架构决定见 `architecture-decisions.md` 第 22 节（PL1~PL10），阶段 0/1 实现基线见 `plugin-stage01-design.md`。

代码位置依据当前分支基线 `HEAD`（`9640cd8`）。

## 1. 范围与官方插件选型

本轮实现「排障前序上下文闭环」，让 AI Agent 在发起主机探测 action 之前，能够完整回答三个核心问题：服务跑在哪/依赖谁（动态 Inventory）、近期谁发版或改了配置（Changes）、团队排查手册怎么写（Knowledge/Runbook）。

| 阶段 | 内容 |
| --- | --- |
| A | `plugin.Host` 出站安全与凭据底座（`HTTPClient` + `egress` 白名单/SSRF 与 DNS rebinding 防护 + TLS/私有 CA、`Credential(ref)` 目录根隔离与投射卷轮转、实例隔离 `Cache`、`Now`、`Validator`/`Cleaner` 生命周期与引用计数释放、`max_concurrency` 并发信号量、脱敏日志包装）、`internal/redact` 精确凭据片段提取、契约测试套件 `plugin/plugintest`、授权操作与 MCP 接口基线，以及 `deploy/docker/Dockerfile` 补齐插件目录 |
| B | 动态 Inventory 官方插件（`inventory.k8s`、`inventory.prometheus_targets`、`inventory.cmdb_http`）与 `entities_search` 跨来源实体合并、`conflicts`/`selector_conflicts` 冲突报告及调用前审计 |
| C | Changes 扩展点官方插件（`changes.allowops`、`changes.k8s_rollout`、`changes.http`）、只读控制面变更 SQL 查询与 `changes_list` 处理器 |
| D | Knowledge 扩展点官方插件 `knowledge.git_markdown`（支持本地同步目录 `dir` 与远程 Git 归档 `archive_url` 双模式）、`runbooks_search`/`runbooks_read` 与 MCP Resources 处理器 |
| E | 公共接线（`mcp/{fixed,cache,call}.go`、`plugins/standard`、`cmd/allowops-gateway/main.go`、`web/src/pages/Policies.tsx`）、端到端闭环测试、文档/示例/升级说明更新与全量验收 |

### 1.1 首批官方插件选型与取舍

选型遵循三个工程约束：零新增第三方 Go 依赖（保持 `go.mod`、`CGO_ENABLED=0` 与 `ALLOWED_LICENSES` 简洁可控）、兼容官方 `FROM scratch` + `USER 65532:65532` 网关镜像（无 shell 与外部二进制依赖）、所有网络出站强制走 `Host.HTTPClient()`。

| 扩展点 | 首批官方模块 | 选型理由 | 暂不纳入的原因 |
| --- | --- | --- | --- |
| Inventory | `inventory.k8s`、`inventory.prometheus_targets`、`inventory.cmdb_http` | 覆盖 K8s 工作负载、Prometheus 监控目标与任意自定义 CMDB HTTP 接口；全部使用 Go 标准库 `net/http` + `encoding/json`，零新依赖 | `inventory.nacos` 可由 `inventory.cmdb_http` 桥接；不引入 `k8s.io/client-go` 避免引入 50+ 传递依赖 |
| Changes | `changes.allowops`、`changes.k8s_rollout`、`changes.http` | 覆盖 allowops 自身目录发布与策略变更、K8s 工作负载发布历史、以及任意 CI/CD/配置中心 HTTP 变更源 | Jenkins/云效/Nacos 专有协议差异大，先由 `changes.http` 统一承接 |
| Knowledge | `knowledge.git_markdown` | 支持两种只读源：`dir`（本地目录 / `git-sync` sidecar / 本地 Git 检出，逐级 `openat(O_NOFOLLOW|O_NONBLOCK)` 防逃逸与防 FIFO）与 `archive_url`（GitHub/GitLab/Gitea `.tar.gz` 归档，经 `Host.HTTPClient` 下载并纯内存安全解压，兼容 `FROM scratch`） | 不调用外部 `git` 命令：网关 `scratch` 镜像无 `git` 二进制，且子进程会绕过 `Host.HTTPClient` / `egress` 并引入 `.git/hooks` 攻击面；不引入 `go-git` 避免新增大量依赖 |

本轮不做的部分：Trigger 扩展点（依赖 PL9 编排层边界）、`Host.State` 持久键值、进程外 gRPC 插件适配器（阶段 5）、`allowops build` 自定义构建。

### 1.2 包与文件布局

```
plugin/
  plugin.go                         新增 Validator、Cleaner、Cache、ControlPlaneChangeReader、Host 新方法
  changes/changes.go                Changes 扩展点：Change、Query、ListResult、Lister
  knowledge/knowledge.go            Knowledge 扩展点：Doc、SearchQuery、ReadResult、Store、ErrNotFound
  plugintest/plugintest.go          契约测试套件（Resolver / Lister / Store + TestHost）

plugins/
  standard/standard.go              空白导入全部官方插件
  inventory/k8s/                    inventory.k8s
  inventory/promtargets/            inventory.prometheus_targets
  inventory/cmdbhttp/               inventory.cmdb_http
  changes/allowops/                 changes.allowops
  changes/k8srollout/               changes.k8s_rollout
  changes/httpfeed/                 changes.http
  knowledge/gitdocs/                knowledge.git_markdown

internal/redact/redact.go           新增 LineSecrets(line) 返回脱敏文本与命中的原始凭据片段
internal/gateway/pluginhost/
  config.go                         ConfigList 与 Config 防回显 UnmarshalYAML，新增 egress、allow_private_egress、allow_cross_origin_redirects、ca_file、credentials、allow_projected_credentials、max_concurrency
  egress.go                         规范化源+有效端口、RoundTripper、跨源重定向决策表、单次解析锁定 IP 拨号、TLS/CA
  credential.go / credential_linux.go / credential_other.go
                                    启动期固定目录根 dirFD，普通文件 openat(O_NOFOLLOW) 与 Linux openat2(RESOLVE_IN_ROOT) 投射卷轮转
  cache.go                          实例隔离 LRU + TTL + 字节预算缓存
  host.go                           多命名空间隔离、controlPlaneHost 独立具体类型、并发信号量、引用计数释放与有界启动/关闭、脱敏日志、SearchInventory/MergeInventory、ListChanges、SearchKnowledge、ReadKnowledge

internal/store/queries/
  plugin_changes.sql                只读查询 catalog_versions / policy_versions 元数据（不读取 dsse / rules JSONB）

internal/gateway/authz/             ViewChanges、ViewKnowledge、默认规则与合法操作校验
internal/gateway/api/policy.go      consoleOperations 新增两项
internal/gateway/mcp/
  service.go                        Config 新增 Changes / Knowledge 接口
  fixed.go                          新增 changes_list、runbooks_search、runbooks_read
  inventory.go                      多源合并、conflicts/selector_conflicts、调用前审计、32 KiB 降级预算
  changes.go                        changes_list 处理器与 32 KiB 预算
  knowledge.go                      runbooks_search、runbooks_read（revision/章节/偏移分页）与 MCP Resources
  cache.go / call.go                Resources 模板与 middleware、调用前后审计
internal/catalog/catalog.go         保留名称增加 changes_list、runbooks_search、runbooks_read
cmd/allowops-gateway/main.go        configuration.Plugins 使用 ConfigList、注入 ControlPlaneChanges、Changes/Knowledge、停机与早期退出调用 pluginHost.Close
web/src/pages/Policies.tsx          testOperations 补齐 view_inventory、view_changes、view_knowledge
deploy/docker/Dockerfile            补齐 COPY plugin ./plugin 与 COPY plugins ./plugins
```

官方插件包 `plugins/...` 仍不导入任何 `internal/` 包，与第三方插件使用完全相同的公开契约（PL2）。给 `plugin.Host` 新增必需方法属于 1.0 之前的实验期接口演进（PL2），将在 `CHANGELOG.md` 中明确说明。

---

## 2. 阶段 A：`plugin.Host` 底座与 `plugin/plugintest`

### 2.1 `plugin` 包扩展

```go
package plugin

type Validator interface {
	// Validate 仅做纯内存配置校验，不得执行网络、磁盘或阻塞 I/O。
	Validate() error
}

type Cleaner interface {
	Cleanup(ctx context.Context) error
}

type Cache interface {
	// Get 返回值拷贝；不存在或已过期时返回 nil, false。
	Get(key string) ([]byte, bool)
	// Set 存入值拷贝；ttl <= 0 视为删除。宿主限制最大 TTL、条目数和总字节数。
	Set(key string, value []byte, ttl time.Duration)
	Delete(key string)
}

type Host interface {
	InstanceID() string
	Logger() *slog.Logger
	Hosts(ctx context.Context) ([]HostInfo, error)
	// HTTPClient 返回受本实例 egress 白名单、重定向决策表、只读方法限制与 TLS/CA 约束的客户端。
	// 未声明 egress 时仍返回非 nil 客户端，所有请求都会被拒绝。
	HTTPClient() *http.Client
	// Credential 按实例配置的逻辑引用读取凭据文件；错误不包含路径或内容。
	Credential(ref string) ([]byte, error)
	// Cache 返回实例隔离的内存 TTL 缓存。
	Cache() Cache
	// Now 返回当前 UTC 时间（便于测试注入时钟）。
	Now() time.Time
}

// ControlPlaneChange 表示 allowops 控制面自身的只读变更元数据（目录发布与策略变更）。
type ControlPlaneChange struct {
	At             time.Time
	Kind           string // "catalog" | "policy"
	CatalogID      string
	Version        int64
	ActionCount    int
	Actor          string
	Reason         string
	RolledBackFrom int64
}

// ControlPlaneChangeReader 是可选宿主能力接口，仅通过独立具体类型暴露给 changes.allowops，
// 普通插件的 Host 类型不实现该接口，绝不暴露 *store.Store、原始 DSSE 或策略规则正文（PL3）。
type ControlPlaneChangeReader interface {
	ListControlPlaneChanges(ctx context.Context, from, to time.Time, limit int) (items []ControlPlaneChange, hasMore bool, err error)
}
```

设计要点：
- `instanceHost` **不实现** `ControlPlaneChangeReader`；`pluginhost` 定义单独的具体类型 `type controlPlaneHost struct { instanceHost; reader controlPlaneReaderFunc }`，**仅**当 `c.Module == "changes.allowops" && deps.ControlPlaneChanges != nil` 时传入 `controlPlaneHost`。普通插件断言 `h.(plugin.ControlPlaneChangeReader)` 必然返回 `ok == false`。
- 宿主在调用 `deps.ControlPlaneChanges` 前独立限制时间窗（`<= 7 天`）与查询上限（`<= 1000`）。
- `Host.Logger()` 返回经过 `redactingHandler` 包装的子 logger（对消息与字符串/错误属性脱敏并去换行），官方插件在读取凭据后的错误路径仅输出固定错误类别和实例 ID。

### 2.2 `pluginhost.ConfigList`、`Config` 与外层防值回显解码

```go
type ConfigList []Config

type Config struct {
	ID                        string            `yaml:"id"`
	Module                    string            `yaml:"module"`
	Disabled                  bool              `yaml:"disabled"`
	Required                  bool              `yaml:"required"`
	Timeout                   time.Duration     `yaml:"timeout"`
	MaxConcurrency            int               `yaml:"max_concurrency"`
	Egress                    []string          `yaml:"egress"`
	AllowPrivateEgress        bool              `yaml:"allow_private_egress"`
	AllowCrossOriginRedirects bool              `yaml:"allow_cross_origin_redirects"`
	CAFile                    string            `yaml:"ca_file"`
	Credentials               map[string]string `yaml:"credentials"`
	AllowProjectedCredentials bool              `yaml:"allow_projected_credentials"`
	Config                    yaml.Node         `yaml:"config"`
}
```

外层防泄露解码（覆盖列表本身与所有元素）：
- `cmd/allowops-gateway/main.go` 的 `configuration.Plugins` 类型为 `pluginhost.ConfigList`。
- `ConfigList.UnmarshalYAML(value *yaml.Node) error` 首先检查 `value.Kind == yaml.SequenceNode`（支持 null/空列表），若将 `plugins` 整体误填为标量/映射，仅返回 `plugins: invalid configuration at line N`，绝不把 `yaml.v3` 引用的标量原值带入错误文本。
- `Config.UnmarshalYAML(value *yaml.Node) error` 拒绝别名节点，重新编码并用 `KnownFields(true)` 解码到内部别名结构体；任何字段或类型错误仅保留行号，返回 `invalid plugin configuration at line N`。

启动校验规则（失败即拒绝启动，不受 `required` 影响，错误信息仅含已校验 `id` 或序号）：
1. `max_concurrency`：默认 `4`，允许范围 `1..32`。
2. `egress`：最多 `16` 项；每项经 `params.NormalizeURL` 规范化，单独拒绝 `RawQuery != "" || ForceQuery`、通配符 `*` 及主机名末尾点 `.`，生成共享 `canonicalEndpoint`（含显式有效端口 `80`/`443`/指定端口）。
3. `ca_file`：可选；非空时须为绝对路径且至少存在一个 `https://` `egress` 条目。以 `O_RDONLY|O_CLOEXEC|O_NONBLOCK` 打开并检查普通文件，上限 `1 MiB`，解析为 PEM `x509.CertPool`。
4. `credentials`：最多 `16` 项；`ref` 匹配 `^[a-z][a-z0-9_-]{0,63}$`；路径须为非空绝对路径且非 `/`；启动时固定打开父目录 `dirFD`（见 §2.4）。

### 2.3 出站 `HTTPClient`：Egress 白名单、重定向决策表、防 SSRF 与 DNS Rebinding

1. **统一规范化源与有效端口**：
   - `canonicalEndpoint{scheme, host, port, pathPrefix string; isIPLiteral bool; ip netip.Addr}` 由配置校验与 `DialContext` 共用：`host` 为小写无括号主机名，禁止末尾点 `.` 与 `*`；`port` 始终为显式有效端口（`http`→`"80"`，`https`→`"443"`）。
   - `RoundTripper` 仅放行 `GET`、`HEAD`；规范化 `req.URL` 后要求与至少一条 `egress` 同源（`scheme + host + port`）且路径满足前缀边界匹配；`egress` 为空时直接拒绝。
2. **传输安全约束**：
   - `Transport.Proxy = nil`、`Transport.DisableCompression = true`、`Transport.MaxResponseHeaderBytes = 64 << 10`。
   - `TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}`；配置 `ca_file` 时 `RootCAs` 仅含该私有 CA，无 `insecure_skip_verify`。
   - 所有官方插件响应体均用 `io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))` 检查实际长度 `<= maxBytes`、`defer resp.Body.Close()`，且单次调用 `ctx` 截止时间覆盖至读完正文。
3. **凭据绑定与重定向决策表（唯一规则，无歧义）**：
   - 所有配置了 `credential_ref` 的官方插件在 `Validate()` 强制要求初始 URL 为 `https://`；`inventory.cmdb_http` 与 `changes.http` 的 `auth_header` 禁止为 `Accept`、`Host`、`Content-Length`、`Transfer-Encoding`。
   - `CheckRedirect(req, via)` 最多跟随 `3` 跳（`len(via) > 3` 拒绝），逐跳检查目标在 `egress` 中且禁止 `https → http` 降级，并基于初始请求 `via[0]` 与全部已走跳 `via` 判断 `leftInitialOrigin`（只要 `req` 或任一历史跳的 `(scheme, host, port)` 不同于 `via[0]` 即为真）：

   | 条件 | `allow_cross_origin_redirects: false`（默认，所有 API 插件） | `allow_cross_origin_redirects: true`（仅用于如 GitHub 归档跨源至 `codeload.github.com`） |
   | --- | --- | --- |
   | 同源跳转（`!leftInitialOrigin`）且在 `egress`、无降级 | 允许，保留原请求头 | 允许，保留原请求头 |
   | 跨源跳转（`leftInitialOrigin`）且目标不在 `egress` 或非 `https` | **拒绝**（目标零请求） | **拒绝**（目标零请求） |
   | 跨源跳转（`leftInitialOrigin`）且目标为 `egress` 中的 `https` 地址 | **拒绝**（目标零请求，即使目标在白名单内也不发送任何请求） | 允许，但**每跳均彻底替换 `req.Header` 为宿主固定常量 `http.Header{"Accept": {"*/*"}}`**（不保留初始请求的任何头——包括 `Authorization`、`Cookie`、自定义 `auth_header`、`Accept` 原值——且清除自动生成的 `Referer`；即使后续跳再回到初始源也不恢复原头） |

4. **拨号期单次 DNS 解析与 IP 策略**：
   - `DialContext` 仅允许 `tcp`/`tcp4`/`tcp6`，核对 `(host, port)` 属于实例 `egress`。域名经可注入 resolver 单次解析，每个候选 IP 先调用 `ip = ip.Unmap()`。
   - **严格判定顺序**：
     1. **无条件禁止（任何配置与字面量均不可放行）**：
        - 未指定地址（`ip.IsUnspecified()`：`0.0.0.0`、`::`）
        - 组播地址（`ip.IsMulticast()`）
        - 链路本地单播与组播（`169.254.0.0/16`、`fe80::/10`、`ip.IsLinkLocalMulticast()`）
        - 云实例元数据地址：`169.254.169.254/32`、`169.254.170.2/32`、`169.254.169.253/32`、`169.254.169.123/32`、`100.100.100.200/32`（阿里云）、`fd00:ec2::254/128`（AWS IPv6 IMDS）
        - 地址转换与隧道前缀：`64:ff9b::/96`（RFC 6052 Well-Known NAT64）、`64:ff9b:1::/48`（RFC 8215 Local NAT64）、`2002::/16`（6to4）、`2001::/32`（Teredo）、以及**非环回的废弃 IPv4-compatible IPv6（`::/96` 且 `!ip.IsLoopback()`）**
     2. **环回地址（`127.0.0.0/8`、`::1`）**：
        - 经 DNS 域名解析得到时一律拒绝；仅当 `egress` 中**字面量显式写明**该环回 IP（如 `http://127.0.0.1:18080` 或 `https://[::1]:8443`）时放行。
     3. **私网与 CGNAT（`ip.IsPrivate()` 即 RFC1918 + ULA `fc00::/7`，以及 `100.64.0.0/10`）**：
        - 字面量显式配置该 IP 或实例设置 `allow_private_egress: true` 时放行；否则拒绝。
     4. 其余公网单播 IP：放行。
   - 拨号使用校验通过的 `netip.Addr` 字面量 `net.JoinHostPort(ip.String(), port)`，绝不二次解析域名；原始域名保留给 TLS `ServerName`。

### 2.4 `Credential(ref)` 凭据读取与平台边界

严格区分两种挂载模式，并在启动期固定目录根描述符 `dirFD`：

1. **模式 1（默认，`allow_projected_credentials: false` — 普通文件）**：
   - 启动期对 `dir := filepath.Dir(absPath)` 以 `O_RDONLY|O_DIRECTORY|O_CLOEXEC` 打开并 `fstat` 校验：`dir` 属主为 `0` 或当前 `euid`，且禁止 world 写（`perm & 0o002 == 0`）。
   - 读取期在固定的 `dirFD` 上调用 `openat(dirFD, base, O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK)`：同时阻断末级符号链接、运行期父目录替换与 FIFO 阻塞。
2. **模式 2（显式开启 `allow_projected_credentials: true` — Kubernetes Projected / Secret 只读卷根单层文件）**：
   - 明确约束：**仅支持直接位于只读投射卷根下的单层文件**（如 `/var/run/secrets/kubernetes.io/serviceaccount/token`），不支持嵌套子目录中的轮转文件（避免固定到旧版本子目录）。
   - 启动期对卷根 `dir := filepath.Dir(absPath)` 以 `O_RDONLY|O_DIRECTORY|O_CLOEXEC` 打开并校验其为目录（**不要求 `perm & 0o002 == 0`**，因 K8s `emptyDir` 内存卷在容器只读挂载时目录权限位仍可能为 `0777`）。
   - 读取期在固定的卷根 `dirFD` 上调用 Linux `unix.Openat2(dirFD, base, &unix.OpenHow{Flags: unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NONBLOCK, Resolve: unix.RESOLVE_IN_ROOT})`：内核级确保 `token -> ..data/token -> ..2026_.../token` 等原子轮转符号链接绝对不逃出该卷根，同时保持非阻塞防 FIFO。
   - **平台与内核边界**：官方发布目标为 Linux（`.goreleaser.yaml` 仅构建 Linux/amd64）。`openat2` 自 Linux 5.6 起支持且无需 root 权限；若旧内核或 seccomp 禁用 `openat2`（返回 `ENOSYS`/`EPERM`），或非 Linux 平台构建（`credential_other.go` 桩实现），`allow_projected_credentials: true` 一律 fail-closed 返回 `"plugin credential: projected volume requires openat2"`。
3. **公共打开后校验（两种模式完全一致）**：
   - 先校验 `ref` 匹配 `^[a-z][a-z0-9_-]{0,63}$`；不合法时返回固定错误 `"plugin credential: invalid reference"`（绝不回显原值）。
   - 打开后的 `fd` 执行 `fstat`：必须为普通文件（`IsRegular()`）；禁止 world 权限（`perm & 0o007 == 0`）、执行位（`perm & 0o111 == 0`）和 group 写（`perm & 0o020 == 0`）。
   - 属主：`stat.Uid == uint32(os.Geteuid())` 时仅允许 `0400`/`0600`；`stat.Uid == 0` 且进程非 root（如 UID `65532`）时允许 `0440`/`0640` 且 `stat.Gid` 须匹配有效 GID 或 `os.Getgroups()` 补充组；其余拒绝。
   - 实际读取 `io.ReadAll(io.LimitReader(f, 16385))`，校验实际读取长度 `<= 16384`（不信任 `info.Size()`）。所有错误仅返回固定原因码，不含路径和内容。

### 2.5 实例隔离 `Cache`

每实例独立 `instanceCache`（`sync.Mutex` + `container/list` LRU）：`maxEntries = 256`、`maxBytes = 4 << 20`、`maxTTL = time.Hour`，`Get`/`Set` 均深拷贝 `[]byte`，基于 `Host.Now()` 判断过期。

### 2.6 生命周期、引用计数释放与有界启动/关闭

1. **命名空间隔离**：`instance` 保存 `namespace`（`"inventory"`/`"changes"`/`"knowledge"`）及对应接口；各扩展点查询与枚举严格只访问对应命名空间中 `ok == true` 的实例。
2. **引用计数资源归属（防 fd 复用竞态）**：
   - 每个实例的底层句柄集合（`dirFD` 与 `egressClient`）由 `refs atomic.Int64` 保护（初始为 `1` 代表宿主持有）。
   - 启动 `Provision` 协程或任意插件调用工作协程前先 `acquire()`（`refs.Add(1)`），在该协程的 `defer` 中执行 `release()`（`refs.Add(-1)`）；**仅当 `refs` 归零时**才真正关闭所有 `dirFD` 并调用 `CloseIdleConnections()`。
   - 因此即便 `Provision` 超时或 `Close` 等待到期时仍有迟到的工作协程在运行，也绝不会提前关闭它正在使用的 `dirFD` 而引发文件描述符编号复用漏洞。
3. **有界 `Provision` 与迟到清理**：
   - `Validator.Validate()` 为纯内存校验，同步执行，失败拒绝启动。
   - `Provision` 在带 `timeout` 的协程内执行并带 `recover()`：若在超时内失败且模块实现 `Cleaner`，立即执行 `Cleanup` 并释放宿主引用；若 `Provision` 超时，启动立即返回（`required: true` 拒绝启动，否则标记 `ok = false`）并置 `abandoned.Store(true)`——当迟到的 `Provision` 最终返回时，由该协程自身检查 `abandoned.Load()`，若实现 `Cleaner` 则带短超时执行 `Cleanup` 并最终 `release()` 释放全部句柄。
   - `pluginhost.New` 中途返回错误时，自动调用 `h.Close` 清理已构造实例。
4. **并发信号量与 `Host.Close(ctx)`**：
   - 排队获取 `inst.sem` 与执行共享同一个 `callCtx` 截止时间，槽位由工作协程 `defer` 释放。
   - `Close(ctx)` 四步：① 写锁置 `closing = true` 拒绝新调用；② `baseCancel()` 取消所有在途调用；③ 在 `min(remaining ctx, 5s)` 内等待 `inFlight.Wait()`；④ 逆序调用各已就绪实例的 `Cleaner.Cleanup`（带超时与 `recover()`）并释放宿主对各实例句柄的引用（在途协程全部退出后由最后一个释放者关闭 `dirFD` 与空闲连接）。

### 2.7 精确凭据片段提取（`internal/redact`）

在 `internal/redact/redact.go` 新增 `func (r *Redactor) LineSecrets(line string) (string, []string)`：返回脱敏后单行文本与本行被 `secrets` 规则替换掉的敏感值本体列表（不含键名/选项前缀，如 `password=s3cr3t` 提取 `s3cr3t`、`--password s3cr3t` 提取 `s3cr3t`、`Authorization: Bearer tok` 提取 `tok`、`https://u:p@h` 提取 `p` 与 `u:p@`、JWT/AK 提取整段令牌）。

### 2.8 契约测试套件 `plugin/plugintest`

- `NewHost(t, opts...) *TestHost`：默认禁网 `HTTPClient`；支持 `WithHTTPServer`、`WithHTTPClient`、`WithCredential`、`WithHosts`、`WithNow`、`WithControlPlaneChanges`、`WithExpectHTTP`。
- `RunResolverContract`、`RunListerContract`、`RunStoreContract` 验证：模块 ID 与独立 `New()`、未知配置字段拒绝、已取消 `ctx` `< 1s` 返回（含 `Store.Read`）、固定时钟与响应下结果深度相等且顺序稳定、修改返回值不污染插件、遵守 `MaxItems`/`MaxDocs`、`Store.Read` 不存在返回 `ErrNotFound` 且错误不含凭据、`ExpectHTTP` 验证经 `Host.HTTPClient` 发起且切禁网清空缓存后失败。
- 配套静态 AST 单测扫描 `plugins/...`（不含 `*_test.go`），禁止直接调用 `net.Dial*`、`http.Get`/`Post`/`Head`/`Do`、`http.DefaultClient`、`http.DefaultTransport` 或构造 `&http.Client{}`。

---

## 3. 阶段 B：动态 Inventory 插件与多源合并

### 3.1 `inventory.k8s`（`plugins/inventory/k8s`）

- 配置：`api_server`（带 `credential_ref` 须 `https://`）、`credential_ref`、`namespaces`（必填 1~64 项）、`cluster`、`workloads`（默认 `[deployment, statefulset, daemonset]`）、`entity_kind`（空时输出 `deployment`/`statefulset`/`daemonset`）、`include_pods`（默认 `true`）、`label_allowlist`、`selector_label`、`cache_ttl`（默认 30s，最大 10m）、`max_response_bytes`（默认 4 MiB，最大 16 MiB）。
- 标签键映射：将 `/` 替换为 `_`（如 `app.kubernetes.io/name` → `app.kubernetes.io_name`），校验符合 `attrPattern`，多原键碰撞时按原键字典序取首个。
- Pod 选择器：完整实现 `matchLabels` 与 `matchExpressions`（`In`/`NotIn`/`Exists`/`DoesNotExist`）；空选择器或未知操作符跳过该工作负载的 Pod 节点关联。
- 来源内唯一性：当 `entity_kind` 覆盖为统一值且同命名空间同名不同类型工作负载冲突时，名称附加 `/<workload_kind>` 保证来源内 `(Kind, Name)` 唯一。绝不读取 `annotations`、`env`、`args`。

### 3.2 `inventory.prometheus_targets`（`plugins/inventory/promtargets`）

- 配置：`address`（带 `credential_ref` 须 `https://`）、`credential_ref`、`kind`（默认 `service`）、`name_label`（默认 `job`）、`host_label`（默认 `instance`）、`cluster`、`label_allowlist`（默认空）、`cache_ttl`、`max_response_bytes`。
- 默认仅输出 `<name_label>: <value>` 与静态 `cluster` 属性，避免隐藏 target 主机标签影响可见实体属性；`host_label == "instance"` 时用 `net.SplitHostPort` 去端口。

### 3.3 `inventory.cmdb_http`（`plugins/inventory/cmdbhttp`）

- 配置：`url`（带 `credential_ref` 须 `https://`）、`credential_ref`、`auth_header`（默认 `Authorization`，禁止 `Accept`/`Host`/`Content-Length`/`Transfer-Encoding`）、`auth_scheme`（默认 `Bearer`）、`cache_ttl`、`max_response_bytes`。
- `GET <url>`（仅 `q.Kind != ""` 时传 `?kind=<q.Kind>`，绝不传 `Name`），`DisallowUnknownFields()` 解码，拒绝来源内重复 `(Kind, Name)`。

### 3.4 `entities_search` 跨来源合并、可见组内跨源凭据传播与 32 KiB 降级预算

处理顺序严格固定：

```
1. 参数校验
2. s.identity.Require(ctx, authz.ViewInventory, ...)
3. 调用前审计：Phase="authorized", Outcome="allow", Operation="mcp/entities_search"（fail-closed，失败零插件调用）
4. pluginhost.SearchInventoryRaw（或带原始关联键的 SearchInventory）：
   - 并发调用可用 inventory 实例，校验字段，来源内重复 (Kind, Name) 仅保留排序首位并记录 warn
   - 逐源实体执行 redactEntity，并在未导出字段保留：
     * rawKind, rawName（不对外输出，仅用于可见组内关联）
     * secrets（本源实体脱敏识别出的全部敏感片段）
   - 注意：此时暂不执行 q.Name 过滤（放到步骤 6 跨源凭据传播后执行，确保 A 识别的名称凭据先抹除 B 的名称再过滤！）
5. MCP 层逐源主体主机可见性过滤（VisibleHostnames）：
   - 移除不可见主机
   - 原有主机非空、过滤后为空的源实体整条丢弃（不可见实体绝不参与步骤 6，既不泄露属性也不影响可见输出）
6. 跨源凭据传播 + 脱敏后 Name 过滤 + 合并（pluginhost.MergeVisibleInventory(visible, q.Name)）：
   - 先按未导出的 (rawKind, rawName) 对【全部可见源实体】分组：
     * 汇集本组所有可见源实体的 secrets 并集，对组内每条可见源实体的 Name、Attrs、Selector、DependsOn 做二次抹除（彻底封堵 B4：即便来源 A 先将名称脱敏为 "[REDACTED]"，来源 B 仍因同属 (rawKind, rawName) 组而收到 A 的 secrets 并同步抹除其 Name 与属性！）
   - 在二次抹除后的最终公开 Name 上执行 q.Name 不区分大小写子串过滤
   - 将通过过滤的可见实体合并输出：
     * 最终 Name 含 "[REDACTED" 的实体不跨源合并（各自保留独立条目，但均已完成上一步的跨源凭据抹除）
     * 其余按 (Kind, finalName) 合并：sources 排序去重（单源同时填 source 兼容旧客户端，多源省略 source）；Attrs 一致保留、冲突入 conflicts[k][sourceID]；Hosts 取可见并集（输出前 20 + host_count）；Selector 一致保留、冲突清空并入 selector_conflicts[sourceID]；DependsOn 取并集
7. 按 (Kind, Name, Sources[0]) 稳定排序 → limit 截断（置 truncated）
8. 完整 ToolResult 32 KiB 预算控制：
   - 若直接编码 <= 32 KiB 直接返回
   - 若首条实体单独超限：依次裁剪该实体的 conflicts/selector_conflicts（置 conflicts_truncated: true）、再按需裁剪 attrs 与 depends_on（置 attrs_truncated: true），保留实体最小身份（kind, name, sources, hosts, host_count）与 truncated: true，随后再对实体条数二分裁剪确保完整编码 <= 32 KiB
9. s.call() 写入调用后 Phase="result" 审计事件
```

---

## 4. 阶段 C：Changes 扩展点与 `changes_list`

### 4.1 `plugin/changes` 接口

```go
package changes

import (
	"context"
	"time"
)

type Change struct {
	At      time.Time
	Kind    string // ^[a-z][a-z0-9_]{0,31}$
	Service string // 0~128 字节，无换行
	Summary string // 1~512 字节，无换行
	Actor   string // 0~128 字节，无换行
	Ref     string // 0~256 字节，无换行
}

// Query 仅传递与敏感文本无关的有界时间窗口与单源条数上限。
type Query struct {
	From     time.Time // UTC 起始（含）
	To       time.Time // UTC 结束（含）
	MaxItems int       // 单源上限（宿主默认 1000）
}

type ListResult struct {
	Changes []Change
	HasMore bool
}

type Lister interface {
	List(ctx context.Context, q Query) (ListResult, error)
}
```

### 4.2 `pluginhost.ListChanges` 处理规则

1. 仅并发调用 `namespace == "changes" && inst.ok` 的实例，传入 `changes.Query{From, To, MaxItems: 1000}`（不传 `Services`）。
2. 字段校验：丢弃 `At.IsZero()`、超出闭区间 `[From, To]`、`Kind` 非法、`Summary` 空/超长、任意字段超长或含 `\r`/`\n` 的记录并写计数日志。
3. **跨字段凭据脱敏**：
   - 对 `Service`、`Summary`、`Actor`、`Ref` 逐一调用 `h.redactor.LineSecrets` 收集敏感片段 `secrets`；
   - 若 `Kind` 命中任一 `secrets` 片段，**整条丢弃该记录**；
   - 再用 `secrets` 扫描并抹除其余文本字段中的裸凭据副本为 `[REDACTED]`。
4. 脱敏后按 `q.Services`（如非空，不区分大小写精确匹配 `Service`）过滤；传播任一源的 `HasMore` 为 `sourceTruncated`。
5. 稳定排序：`At` 降序 → `Source` 升序 → `Kind` 升序 → `Service` 升序 → `Actor` 升序 → `Ref` 升序 → `Summary` 升序。

### 4.3 三个官方 Changes 插件与 `changes_list`

- **`changes.allowops`**：`include_catalog` / `include_policy`（默认均 `true`，全 `false` 时 `Validate()` 报错）；`Provision` 断言 `plugin.ControlPlaneChangeReader`；SQL 查询 `internal/store/queries/plugin_changes.sql` 查 `limit+1` 判 `hasMore`，不读 `dsse`/`rules`。
- **`changes.k8s_rollout`**：`api_server`（带 `credential_ref` 须 `https://`）、`namespaces`（1~64）、查 ReplicaSet 与 ControllerRevision，仅读 `deployment.kubernetes.io/revision` 与镜像名，不读其他 annotations。
- **`changes.http`**：`url`（带 `credential_ref` 须 `https://`）、`auth_header`（禁 `Accept`/`Host`/`Content-Length`/`Transfer-Encoding`），仅传 `?from=...&to=...&limit=...`，解码 `{"changes":[...],"has_more":bool}`。
- **`changes_list` MCP 工具**：在 `s.jobs == nil` 之前分派；单次 `now := s.now().UTC()` 推导默认 24h 窗口、上限 7 天（168h）；`Require(ViewChanges)` → 调用前 `authorized` 审计（fail-closed）→ `ListChanges` → `limit` 与 32 KiB 二分裁剪 → `s.call()` 写 `result` 审计。

---

## 5. 阶段 D：Knowledge 扩展点、`runbooks_search` / `runbooks_read` 与 MCP Resources

### 5.1 `plugin/knowledge` 接口（统一不可变快照）

```go
package knowledge

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("knowledge document not found")

type Doc struct {
	ID       string   // ^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$，无 ".."
	Title    string   // 1~256 字节，无换行
	Summary  string   // 0~512 字节，无换行
	Tags     []string // 最多 32 个标签，每个 1~64 字节，无换行
	Headings []string // 最多 50 个 Markdown 标题，每个 1~128 字节，无换行
}

type SearchQuery struct {
	Query   string
	Tags    []string
	MaxDocs int // 宿主固定 1000，与插件 max_files 上限一致
}

// ReadResult 由插件从同一份不可变快照中原子返回文档元数据与正文，
// 保证宿主的公开 ID 校验、元数据凭据提取与正文脱敏针对完全相同的版本。
type ReadResult struct {
	Doc     Doc
	Content string
}

type Store interface {
	Search(ctx context.Context, q SearchQuery) ([]Doc, error)
	Read(ctx context.Context, id string) (ReadResult, error)
}
```

### 5.2 `knowledge.git_markdown`（`plugins/knowledge/gitdocs`）

- 配置（`dir` 与 `archive_url` 互斥必填）：
  - `dir` 或 `archive_url`（带 `credential_ref` 须 `https://`）、`credential_ref`、`strip_components`（默认 1，0..4）、`subdir`、`refresh_ttl`（默认 1m，最大 1h）、`max_file_bytes`（默认 512 KiB，最大 1 MiB）、`max_total_bytes`（默认 16 MiB，最大 32 MiB）、`max_archive_bytes`（默认 8 MiB，最大 32 MiB）、`max_decompressed_bytes`（默认 32 MiB，最大 64 MiB）、`max_files`（默认 1000，**最大 1000**，与宿主 `MaxDocs = 1000` 一致，避免加载的文档被截断隐藏）、`max_entries`（默认 5000，最大 20000；在 `dir` 模式为遍历目录项总数，在 `archive_url` 模式为 `tar.Reader.Next()` 返回的逻辑条目总数，物理扩展头与跳过负载全部受 `max_decompressed_bytes` 约束）。
- 本地 `dir` 模式：逐层 `unix.Openat(parentFD, name, O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC)` 与 `unix.Openat(parentFD, name, O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC)` + `fstat(IsRegular())`，杜绝根内符号链接与 FIFO，全部成功后原子切换不可变内存快照。
- 远程 `archive_url` 模式：`Host.HTTPClient()` 下载经 `io.LimitReader(maxArchiveBytes+1)` 校验；`gzip.NewReader` 与 `tar.NewReader` 之间接入 `countingReader(maxDecompressedBytes)` 限整条解压流；忽略非 `tar.TypeReg`；全部成功后原子切换不可变内存快照。
- `Search` 与 `Read` 均从同一不可变快照指针读取；`Read(ctx, id)` 原子返回该快照中的 `ReadResult{Doc, Content}`。

### 5.3 `pluginhost` 统一公开索引、单快照读取与正文跨字段脱敏

1. **统一文档公开性校验（`sanitizeDoc(doc)`）**：
   - `SearchKnowledge` 与 `ReadKnowledge` 共用同一个函数 `sanitizeDoc(doc) (cleanDoc, secrets, ok)`：
     - 校验 `ID` 格式（无 `..`、无换行）及其他字段合法性；
     - 对 `Title`、`Summary`、`Tags`、`Headings` 调用 `LineSecrets` 收集敏感片段 `secrets` 并跨字段抹除；
     - 若 `ID` 经 `Redactor.Line` 有变化或包含任一 `secrets`，返回 `ok = false`（彻底隐藏）。
2. **`SearchKnowledge`**：调用 `Store.Search(ctx, SearchQuery{MaxDocs: 1000})` 获取各源完整快照索引，经 `sanitizeDoc` 过滤与脱敏后，在宿主侧对脱敏后的 `ID`/`Title`/`Summary`/`Tags`/`Headings` 执行 `Tags` 与 `Query` 匹配，并计算全量公开索引的 `revision`（SHA-256 前 16 位十六进制）。
3. **`ReadKnowledge(ctx, source, id)`**：
   - 先做格式与 `Redactor.Line(id) == id` 快速校验（不合法直接返回 `ErrNotFound`）。
   - 调用 `Store.Read(ctx, id)` 从插件同一不可变快照取得 `ReadResult{Doc, Content}`。
   - 对返回的 `res.Doc` 执行 `sanitizeDoc` 并校验 `res.Doc.ID == id`：若 `ok == false`，立即丢弃 `Content` 返回 `knowledge.ErrNotFound`（与不存在完全不可区分，彻底消除搜索与读取之间的刷新 TOCTOU！）。
   - 限制 `len(res.Content) <= 1 MiB`；执行 `h.redactor.Stream(strings.NewReader(res.Content), &buf, maxLine)`（若失败**丢弃 `buf` 前缀**并 fail-closed 报错）。
   - **元数据凭据二次应用至正文**：将 `sanitizeDoc` 从同快照元数据中收集到的 `secrets` 再次从脱敏后的正文中全部替换为 `[REDACTED]`（防止同一凭据在摘要中被识别而裸露于正文）。
   - 计算最终脱敏正文的 `revision`（SHA-256 前 16 位十六进制），并解析全局唯一的 Markdown 章节列表 `sections`：
     - 对所有 `# .. ######` 标题按文档顺序编号（1-based）：首次出现的标题名保持原样；若标题名与此前已分配的任意显示名冲突（包含重名标题或原文恰好存在 `"Steps (2)"`），统一格式化为 `"<Title> (#<ordinal>)"` 保证全局数学唯一，且 `section` 参数精确匹配该唯一标识！

### 5.4 `runbooks_search`、`runbooks_read` 与 MCP Resources

- **授权与保留名**：`authz.ViewKnowledge = "view_knowledge"`，同步更新 `validOperation`、`defaults.go`、`authz/engine_test.go`、`consoleOperations`、`web/src/pages/Policies.tsx`；`internal/catalog/catalog.go` 新增保留名 `"runbooks_search"`、`"runbooks_read"`。
- **`runbooks_search` / `runbooks_read`**：在 `s.jobs == nil` 前分派；均执行 `Require(ViewKnowledge)` → 调用前 `authorized` 审计（fail-closed）→ 插件调用 → 完整 `ToolResult` 32 KiB 二分裁剪（`runbooks_read` 必要时裁剪 `sections` 并置 `sections_truncated: true` 确保 `!eof` 时 `next_offset > offset`）→ `s.call()` 写 `result` 审计。
  - `runbooks_read` 校验 `revision` 一致性（变化返回 `CodeFailedPrecondition`）、`offset > total_bytes` 返回 `CodeInvalidArgument`、非 UTF-8 字符边界 `offset` 返回 `CodeInvalidArgument`。
- **MCP Resources**：
  - 仅在 `len(knowledgeSources) > 0` 时启用 `Capabilities.Resources = &sdk.ResourceCapabilities{}` 并注册 `server.AddResourceTemplate(&sdk.ResourceTemplate{URITemplate: "allowops://runbooks/{source}/{+id}", ...}, s.readRunbookResource)`。
  - `AddReceivingMiddleware` 拦截 `resources/list`、`resources/templates/list`、`resources/read`：
    1. `ctx = reqctx.ForkRequestContext(ctx)`；
    2. `Require(ViewKnowledge)` → 拒绝时写 `result/deny` 审计并返回错误；
    3. 写入调用前 `authorized` 审计（fail-closed）：**若 `authorized` 审计写入失败，立即返回不可用错误、零插件调用，且不再尝试写 `result` 审计**（审计存储已不可用，保持与 `api/service.go` 一致）；
    4. 执行对应处理（`resources/read` 与 `resources/templates/list` 调 `next` 走 SDK 原生处理器；`resources/list` 兼容 `r.Params == nil` 动态构造带 `Cacheable{TTLMs: 0, CacheScope: "private"}` 与 `<indexRevision>:<offset>` 游标的响应）；
    5. 调用后无论成功或业务失败均写入 `result` 审计（fail-closed）。
  - **传输层 32 KiB 最终编码预算**：`resources/list` 与 `resources/read` 测量时**显式计入 SDK 补齐的 `resultType: "complete"`、`_meta["io.modelcontextprotocol/serverInfo"]` 与 `Cacheable` 完整 JSON 开销**，测试并在真实 HTTP JSON-RPC 响应上直接断言最终 `result` 字节长度 `<= 32768`。

---

## 6. 网关装配、容器镜像与升级顺序

1. `cmd/allowops-gateway/main.go`：`configuration.Plugins` 改为 `pluginhost.ConfigList`；注入 `ControlPlaneChanges` 闭包、`Changes`/`Knowledge` 到 MCP；`defer pluginHost.Close(shutdownCtx)` 覆盖早期退出与正常停机（在 `srv.Shutdown` 之后）。
2. `deploy/docker/Dockerfile`：补齐 `COPY plugin ./plugin` 与 `COPY plugins ./plugins`。
3. **严格升级顺序**：
   - ① 升级前检查并重命名、重签、发布任何与 `changes_list`/`runbooks_search`/`runbooks_read` 同名的有效目录 action（避免全站 MCP HTTP 503）；
   - ② 滚动升级全部 `allowops-gateway` 实例至新二进制；
   - ③ 全部网关升级完成后，管理员再通过 `allowops policy test` / `apply` 授予 `view_changes` 与 `view_knowledge`；
   - ④ 回滚二进制前须先移除策略中的 `view_changes` 与 `view_knowledge`。
   - 默认策略试算求值数由 `S × (13 + 2H + 3A + 3AH)` 更新为 `S × (15 + 2H + 3A + 3AH)`，`policy_view_inputs_rework_test.go` 边界值由 `35/34` 更新为 `37/36`。

---

## 7. 测试矩阵

覆盖阶段 A~E 全部安全红线：
- **A**：`ConfigList` 标量/元素类型错误不回显无特征凭据；重定向决策表（默认拒跨源目标零请求、开启跨源仅放行白名单 HTTPS 且替换固定 `Accept: */*` 并清 `Referer` 含自定义 `auth_header` 与 `A→B→A` 连续跳）；IP 策略逐项断言（`169.254.169.254`/`fe80::1`/`100.100.100.200`/`fd00:ec2::254`/`64:ff9b::169.254.169.254`/`64:ff9b:1::10.0.0.1`/`2002:7f00:0001::`/`::10.0.0.1` 拒绝；显式字面量 `127.0.0.1` 与 `[::1]` 放行；单次解析锁定 IP；私有 CA）；`Credential(ref)` 固定 `dirFD` 普通文件与 `allow_projected_credentials`（`token -> ..data/token` 首次+轮转+越界拒绝+不拒只读 `0777` 卷根+实际读取 >16 KiB 拒绝）；`refs` 引用计数释放与迟到 `Provision` 清理；`plugintest` 与 `plugins/...` AST 护栏。
- **B**：三个动态 Inventory 插件 `plugintest` + `httptest` TLS 单测（含带凭据拒明文 HTTP、K8s `/` 键映射与 `matchExpressions`、Prometheus 默认无跨目标泄露）；`entities_search` 合并测试（含**同名且名称本身被来源 A 脱敏时同步抹除来源 B**、隐藏 A 不影响 B、只查 B 边界、首条超大 Attrs/Conflicts 最小身份降级、调用前审计失败零插件调用）。
- **C**：三个 Changes 插件 `plugintest` + `httptest` TLS + PostgreSQL 真实库验证；`ListChanges` 跨字段凭据抹除（含命中 `Kind` 整条丢弃）、闭区间窗口、`HasMore`、`Actor` 平局排序；`changes_list` 调用前后审计与 32 KiB 预算。
- **D**：`knowledge.git_markdown` 本地临时 git repo（逐级 `openat`）与 `httptest` TLS `.tar.gz`（全流解压炸弹+`max_entries`）；单快照 TOCTOU 刷新测试（搜索后与读取间发生刷新隐藏某 ID 时 `runbooks_read` 与 `resources/read` 均返回 `NotFound`）；元数据凭据二次应用至正文；重名章节与字面 `"Steps (2)"` 全局唯一编号；`revision` 变更拒续页；`Redactor.Stream` 小 `maxLine` fail-closed 丢弃前缀；MCP Resources 真实 HTTP 传输测试（`resources/list` 省略 `params`、`Cacheable`、`resultType`、`authorized` 失败中止且零插件调用、最终 JSON-RPC `result` 实测 `<= 32768` 字节）。
- **E**：`view_changes`/`view_knowledge` 角色全集测试与既有策略不自动授予回归测试；全链路闭环端到端测试（`entities_search` → `changes_list` → `runbooks_search` → `runbooks_read` → `resources/read` → action 执行）。

---

## 8. 复审意见处理记录

### 8.1 Astra 第一轮设计复审（2026-11-24，基线 `9640cd8`）

9 项 Blocking（B1~B9）与 10 项 Major（M1~M10）均已纳入正文修订。

### 8.2 Astra 第二轮设计复核（2026-11-24，基线 `9640cd8`）

| 编号 | 残余问题 | 闭环修改 |
| --- | --- | --- |
| B1 | 跨源重定向存在两条矛盾描述，且原 `Accept` 可能承载自定义认证头 | 改为单一决策表（§2.3）：默认一律拒跨源；显式 `allow_cross_origin_redirects: true` 时仅放行白名单 HTTPS 并用宿主常量 `Accept: */*` 彻底重建 `req.Header` 且删 `Referer`；`auth_header` 禁止设为 `Accept`/`Host` 等保留头 |
| B2 | `::/96` 覆盖了显式 `::1` 环回地址 | 废弃 IPv4-compatible 规则改为 `::/96 && !ip.IsLoopback()`，显式 `[::1]` 正常走环回字面量规则（§2.3） |
| B3 | 投射卷 `emptyDir` 目录权限可能含 `0002`、嵌套子目录轮转风险、缺 `openat2` 平台边界 | 区分普通目录与投射卷根校验（§2.4）：投射模式仅支持卷根单层文件、不检查卷根 `0002`、明确 Linux >= 5.6 `openat2(RESOLVE_IN_ROOT)` 边界与旧内核/非 Linux fail-closed 行为 |
| B4 | 同名实体名称被来源 A 脱敏后被排除出合并组，导致来源 B 名称/属性未收到 A 的片段 | 在未导出字段保留 `(rawKind, rawName)`，可见性过滤后先按原始身份在可见组内传播 `secrets` 并抹除各源字段，再做 `q.Name` 过滤与公开名称合并（§3.4） |
| B5 | Changes 未检查 `Kind` 命中片段；Knowledge 正文未应用同快照元数据片段 | Changes 命中 `Kind` 整条丢弃（§4.2）；Knowledge 正文流式脱敏后再应用同快照元数据收集的 `secrets`（§5.3） |
| B6 | `publicDocs` 与 `Store.Read` 两次调用间刷新存在 TOCTOU | `Store.Read` 改为原子返回同不可变快照的 `ReadResult{Doc, Content}`，`ReadKnowledge` 直接对同快照 `Doc` 执行 `sanitizeDoc`（§5.1、§5.3） |
| B8 | `plugins` 整体误填为标量时 `yaml.v3` 仍回显原值 | 新增 `pluginhost.ConfigList` 自定义 `UnmarshalYAML` 接管整个列表解码（§2.2） |
| B9 | `max_entries` 统计 `tar.Reader.Next()` 对应逻辑条目而非物理头 | 明确 `max_entries` 为逻辑条目上限，所有物理扩展头与跳过负载由 `max_decompressed_bytes` 统一限制（§5.2） |
| M1 | Resources 未计入 SDK 补齐的 `resultType`/`_meta`；Inventory 首条超大 `Attrs` 可能退化为空 | Resources 预算显式计入 SDK 包装开销并在传输层实测 `<= 32 KiB`（§5.4）；Inventory 首条实体依次裁剪 `conflicts`、`attrs`/`depends_on` 保留最小身份（§3.4） |
| M3 | Resources `authorized` 审计失败后是否再写 `result` 审计未定 | 明确 `authorized` 失败即中止、零插件调用且不再二次写 `result`（§5.4） |
| M6 | 重名章节仍可能与字面 `"Steps (2)"` 碰撞；`max_files=5000` 与 `MaxDocs=1000` 冲突 | 章节冲突统一使用 `"<Title> (#<ordinal>)"` 保证全局唯一；`max_files` 上限与 `MaxDocs` 统一为 `1000`（§5.2、§5.3） |
| M7 | 超时/关闭后过早关闭 `dirFD` 存在 fd 复用竞态；迟到 `Provision` 缺 `Cleanup` 归属 | 引入 `refs atomic.Int64` 引用计数，由最后一个释放者关闭 `dirFD` 与连接；迟到 `Provision` 见 `abandoned` 后自调用 `Cleanup` 并 `release()`（§2.6） |
| 实施计划 | A-1 与既有桩分离不可编译；C-3/D-3 引用 E 才新增的符号 | 重排提交：A-1 同步适配全部现有实现与测试替身；授权常量、目录保留名与 `mcp.Config` 扩展接口前移至 A-6，保证每个提交独立可编译，B/C/D 三路基于 A 独立编译测试（见 `plugin-stage0203-plan.md`） |
