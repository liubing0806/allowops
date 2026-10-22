# allowops 架构讨论记录

状态：讨论已结束（2026-10-13）。本文件记录架构讨论中的决定、依据和被否决的方案。最终设计见 `design.md`。

与 `design.md` 的关系：

- 原 `design.md` 中“已确认的设计决定”1~6 和“安全要求”1~9 保留，改为由主机端（allowops-agent 和 allowops-exec）执行。决定 7（顶层 `audit_log`）被集中审计替换（见第 6、15 节）。
- 例外：安全要求 8 中“exec[0] 可在 PATH 中查找”改为只允许绝对路径（见第 9 节）；另增加脚本检查：exec[0] 文件以 `#!` 开头时按解释器处理，未声明 `allow_interpreter` 则拒绝（见第 18 节）。
- 以下内容被本文件替换：本地 stdio MCP 作为主入口；`--allow-write`、`--allow-dangerous` 启动参数；原目录结构和实施计划。

## 1. 部署形态

- 中心网关 + 主机端程序。服务器规模为上千台，agent 与主机不在同一位置。
- 主机端主动连接网关。网关不主动连接任何主机。
- 网络情况：网关不能主动访问主机，主机可以主动连接网关。MVP 不做区域中继（relay）。
- 为以后增加中继保留：
  - 主机端配置项为“上游地址”，不写死为网关。
  - 主机与网关之间 mTLS 端到端建立。
  - 网关 gRPC 服务接收普通连接，中继转发的逻辑流可直接交给同一服务。
- 区域中继和区域自治（参考 Teleport trusted cluster）列入 Roadmap。
- 网关对外只开 443 端口，按 TLS ALPN 区分主机连接、MCP、控制台 API。
- 主机或中继离线时，发往该主机的任务标记 `offline`，不排队，恢复后不补发。

### 参考 Teleport

- Teleport 许可：`/api` 目录 Apache-2.0；其余源码 AGPL-3.0；官网 Community Edition 二进制为修改版 Apache 2.0，限员工少于 100 人且年收入低于 1000 万美元的组织使用。
- allowops 参考其架构思路，不复制 Teleport 的 AGPL 代码。原因：AGPL 要求衍生作品按 AGPL 发布，与 allowops 的 MIT 许可冲突（AGPL 代码不能并入 MIT 项目）。
- 参考的部分：反向连接、单端口 ALPN 路由、join token 加短期证书、资源标签、集中审计。
- 不参考的部分：交互式 SSH 会话和会话录像，与 “No shell” 原则冲突。
- 不需要 proxy peering：allowops 的任务是“下发后返回结果”的消息模式，多实例时用 PostgreSQL 记录主机连接所在实例，用 LISTEN/NOTIFY 通知该实例下发任务。

## 2. 组件

| 组件 | 职责 |
|---|---|
| allowops-gateway | MCP 接口、控制台 API、主机注册表、ABAC 判定、批量任务调度、结果聚合、审计。内嵌 Web 控制台静态文件 |
| allowops-agent | systemd 服务，主动连接网关；验签 action 目录、再次校验参数、本地执行。`design.md` 的安全要求在这里执行 |
| allowops-exec | 随主机端安装包发布的 root 辅助程序，经 sudo 调用；验签目录、校验参数、切换到 `run_as` 用户执行（见第 9 节） |
| allowops CLI | CI 中校验、构建、签名、发布 action 目录；管理员调用网关 API |
| Web 控制台 | 主机、action 目录、策略、任务结果、审计查询 |

- 单仓库，四个二进制（网关、主机端、allowops-exec、CLI）。主机端不包含网关代码和前端资源。
- `internal/catalog`、`internal/params` 由网关、主机端、CLI 共用：网关先校验参数并快速返回错误，主机端执行前再次校验。

## 3. 技术选型

| 部分 | 选型 |
|---|---|
| 后端、主机端、CLI | Go |
| 主机与网关通信 | gRPC 双向流 + mTLS，主机主动连接 |
| 协议定义 | Protobuf + buf；connect-go 同时服务 gRPC 和浏览器 |
| agent 接入 | MCP Streamable HTTP，官方 `github.com/modelcontextprotocol/go-sdk`，无状态模式 |
| 控制台 API | Connect（protobuf），生成 TypeScript 客户端 |
| 数据库 | 只支持 PostgreSQL；pgx + sqlc + goose |
| 对象存储 | S3 兼容 API，`aws-sdk-go-v2` |
| 策略引擎 | OPA 嵌入网关（`github.com/open-policy-agent/opa/v1/rego`） |
| 控制台登录 | 通用 OIDC（`coreos/go-oidc`）+ LDAP（`go-ldap/ldap`） |
| agent 认证 | 网关为服务账号签发 API token，数据库只存 SHA-256 |
| 主机身份 | join token（单次或多次使用，见第 12 节）换取网关内部 CA 签发的短期证书，自动续期 |
| action 目录 | Git 中维护 YAML → CI 校验并签名 → 网关分发 → 主机端验签 |
| 前端 | React + TypeScript + Vite + shadcn/ui；TanStack Table、TanStack Query、React Hook Form、Zod；构建产物 `go:embed` 进网关 |
| 日志和指标 | `log/slog`、Prometheus 指标 |
| 打包 | goreleaser + nfpm |

被否决的选项及原因：

- Ant Design：用户认为样式过旧。
- Authing 远程判定：每次判定远程调用 `/api/v3/check-permission`；主机属性和调用信息需发给 Authing；SDK 出错时只打印并返回 nil；仓库最后推送 2025-01-02；客户需购买 Authing。Authing 可作为 OIDC 身份源。
- Cedar（cedar-go v1.8.0）：Go 版 schema 校验器为实验性。
- Casbin：ABAC 结构化程度较低。（原因之一“判定结果只有 allow/deny”在 MVP 去掉审批后不再成立；以后加回审批时 OPA 可直接返回三种结果。）
- Cerbos：主要以独立服务部署。
- MySQL：缺少 LISTEN/NOTIFY 和 JSONB 标签索引，需额外引入 Redis/NATS 和标签拆表。团队更熟悉 MySQL，PostgreSQL 运维经验需要补充。

## 4. 主机端

- 以低权限用户 `allowops` 运行。声明了 `run_as` 的 action 通过 `sudo -n` 调用 root 辅助程序 `allowops-exec` 执行，sudoers 只放行这一个无参数命令（见第 9 节）。
- action 定义来自中心签名目录。网关被攻破时，攻击者只能调用已签名的 action，不能新增命令。
- systemd 沙箱选项会作用于子进程（包括 sudo 执行的命令）。`NoNewPrivileges=yes` 使 sudo 无法提权，`ProtectSystem=strict` 使写操作失败。unit 只使用不影响子进程的选项。
- 主机标签分两类：
  - 上报标签（系统、内核、架构等）：主机自动上报，只用于展示和筛选。
  - 授权标签（env、业务线、机房、tier 等）：只在网关端通过控制台或 API 设置，策略只按这一类判定。CMDB 同步放第二阶段。
- 主机连接时上报支持的目录格式版本和参数类型。action 用到主机端不支持的功能时，该主机的 task 标记 `unsupported`。

## 5. 权限模型

- RBAC + ABAC。属性分四类：

| 类别 | allowops 中的对象 | 示例 |
|---|---|---|
| 主体 | agent 服务账号、控制台用户 | 角色、团队、负责人 |
| 资源 | 主机、action | 主机授权标签；action 的 risk、分类 |
| 操作 | 执行 action；控制台操作：修改策略、管理服务账号和 token、管理主机和授权标签、创建 join token、管理用户角色、发布目录、查看 job、查看输出（`view_output`）、查看审计 | — |
| 环境 | 请求上下文 | 请求时间、来源 IP |

- 判定结果：`allow`、`deny`。deny 优先于 allow。未匹配任何规则时 deny。
- MVP 不做人工审批（2026-10-13 决定），`require_approval` 判定结果和审批流列入 Roadmap。
- 原 read/write/dangerous 风险等级改为 action 属性，由策略判定。

### OPA 用法

- 规则数据存 PostgreSQL，控制台用表单编辑。
- 固定的 Rego 程序随 allowops 发布（`go:embed`），解释规则数据。高级用户以后可自写 Rego。
- 规则数据示例：

```json
{"rules": [
  {"name": "readonly-all", "roles": ["agent-readonly", "oncall"], "risks": ["read"],
   "host_labels": {}, "effect": "allow"},
  {"name": "oncall-prod-restart", "roles": ["oncall"], "actions": ["systemd_restart_service"],
   "host_labels": {"env": "prod"}, "hours": {"from": 9, "to": 21}, "effect": "allow"},
  {"name": "no-core-db", "roles": ["*"], "risks": ["write", "dangerous"],
   "host_labels": {"tier": "core-db"}, "effect": "deny"}
]}
```

- 固定 Rego 程序（草稿）：

```rego
package allowops.authz

matched contains rule if {
	some rule in data.rules
	role_ok(rule)
	action_ok(rule)
	host_ok(rule)
	time_ok(rule)
}

role_ok(rule) if "*" in rule.roles
role_ok(rule) if {
	some role in input.subject.roles
	role in rule.roles
}

action_ok(rule) if input.action.name in rule.actions
action_ok(rule) if input.action.risk in rule.risks

host_ok(rule) if {
	every k, v in rule.host_labels {
		input.host.labels[k] == v
	}
}

time_ok(rule) if not rule.hours
time_ok(rule) if {
	hour := time.clock([input.env.time_ns, "Asia/Shanghai"])[0]
	hour >= rule.hours.from
	hour < rule.hours.to
}

effects := {rule.effect | some rule in matched}

decision := "deny" if "deny" in effects
else := "allow" if "allow" in effects
else := "deny"

result := {"decision": decision, "rules": [rule.name | some rule in matched]}
```

- 网关调用：`rego.New(rego.Query("data.allowops.authz.result"), rego.Module(...), rego.Store(inmem store)).PrepareForEval(ctx)`，每台主机 `pq.Eval(ctx, rego.EvalInput(input))`。
- 规则更新：重建 store 并重新 `PrepareForEval`，用 `atomic.Pointer` 替换。多实例时用 LISTEN/NOTIFY 通知重新加载。
- 批量判定：标签完全相同的主机复用判定结果。单次判定耗时未实测，由 OPA 基准测试确认（见第 16 节）。

安全规则：

- 求值出错、结果格式不符时按 deny 处理。
- 时间从 `input.env.time_ns` 读取，不在 Rego 中调用 `time.now_ns()`，保证可重现。
- 用 OPA capabilities 禁用 `http.send`、`opa.runtime` 等内置函数。
- 审计记录判定结果、匹配规则名、策略版本。
- 控制台保存规则前用新规则对现有主机试算，显示判定结果的变化。

## 6. 数据存储

- 只支持 PostgreSQL。
- 心跳只在网关内存更新；数据库只在连接、断开时更新，另每 5 分钟写一次 `last_seen`。
- task 表和审计表按月分区。
- 审计：
  - 默认保留 1 年（可配置）。
  - 网关数据库账号对审计表只有 INSERT 和 SELECT 权限；过期分区由单独的维护账号删除。
  - 每条记录保存上一条的哈希，形成哈希链。
  - 不保存命令输出内容，保存输出对象路径和 SHA-256。
- 命令输出：
  - 存 S3 兼容对象存储（OSS、SeaweedFS、Ceph RGW、S3），默认保留 1 年（可配置），由 bucket 生命周期规则删除。
  - 对象路径 `outputs/{yyyy}/{mm}/{dd}/{job_id}/{host_id}.{stdout|stderr}.zst`，zstd 压缩。
  - 控制台读取输出经网关转发，按 ABAC 判定 `view_output` 并写审计，不使用预签名 URL。bucket 开启服务端加密。
  - 输出先在网关内存聚合并返回调用方，再异步写入对象存储。写入失败时 task 标记 `output_stored=false`，写审计和告警日志，job 结果不受影响。
  - `aws-sdk-go-v2` 新版默认计算请求校验和，部分 S3 兼容服务不支持；设为仅在需要时计算，用 SeaweedFS 和 OSS 实测。
- CA 私钥存网关主机文件（0600），以后可接 KMS，不存数据库。
- API token 为 32 字节随机数，数据库存 SHA-256。
- 开发和测试：Docker 运行 PostgreSQL 和 SeaweedFS，集成测试用 testcontainers（A29）。

容量估算（假设每天 2000 次调用、平均 50 台主机，未与实际核对）：

- 每天约 10 万条 task。输出平均 4KB 时每天约 400MB（压缩前），全部 64KB 时每天约 6.4GB。
- 审计每台主机一条、每条约 500 字节，一年约 3650 万行、约 18GB。

## 7. MCP 设计

依据：Anthropic《Writing effective tools for agents》；官方 Go SDK 文档。

### 工具

| 工具 | 作用 |
|---|---|
| `hosts_search` | 按标签选择器或主机名查询主机；返回主机、标签、在线状态、总数和标签分布 |
| `<action>` | 每个 action 一个工具，按身份过滤 |
| `jobs_get` | 查询 job 汇总；传 `host` 时分页返回该主机完整输出；支持 `wait_seconds` 长轮询 |
| `jobs_list` | 列出当前服务账号最近的 job |
| `jobs_cancel` | 取消 job：未执行批次不再执行，执行中的 task 结束进程组 |

- 每个服务账号只看到策略中可能 allow 的 action。
- action 工具公共参数：`targets`（`hosts` 列表或 `selector`）、`expected_count`、`reason`、`wait_seconds`、`batch_size`、`max_failures`、`response_format`。
- 用 `selector` 选择主机时必须带 `expected_count`，与实际数量不符时拒绝并返回实际数量。
- `batch_size`、`max_failures` 只能比 action 定义的默认值更严格。
- 同一次调用中主机判定结果不同时，整个 job 取最严格结果：任一主机 deny 则整个 job 拒绝，并返回被拒主机和规则。
- 命名：固定工具按资源加前缀；action 名按 `<对象>_<动作>` 命名（如 `nginx_view_log`），匹配 `^[a-z][a-z0-9_]{0,63}$`，不得与固定工具重名，CI 检查。
- 返回给 agent 的主机标识为全局唯一主机名；job ID 用短格式（如 `job-20261013-0042`）。
- action 和每个参数的 `description` 必填，CI 检查；公共参数说明由网关统一生成。
- 工具注解按风险等级生成：read → `readOnlyHint: true`；write → `readOnlyHint: false`、`destructiveHint: false`；dangerous → `destructiveHint: true`。
- 参数错误返回 `isError: true`，并给出合法值或实际数量。

### 执行流程和状态

```
调用 action 工具
 → 参数校验（失败：isError + 合法值）
 → 解析 targets，核对 expected_count
 → 每台主机 ABAC 判定，任一主机 deny 则整个 job 拒绝
 → allow：分批下发；失败数超过 max_failures 时停止，剩余主机标记 skipped
 → wait_seconds 内完成返回汇总，否则返回 job_id 和进度
```

- job 状态：`queued`、`running`、`succeeded`、`partially_failed`、`failed`、`cancelled`、`denied`。
- task 状态：`pending`、`running`、`succeeded`、`failed`、`timeout`、`offline`、`skipped`、`cancelled`、`unsupported`。

返回示例（`structuredContent`，同时附文本）：

```json
{
  "job_id": "job-20261013-0042",
  "status": "partially_failed",
  "summary": {"total": 120, "succeeded": 115, "failed": 3, "offline": 2},
  "groups": [
    {"exit_code": 0, "host_count": 112, "sample_hosts": ["web-01", "web-02"], "stdout": "...", "truncated": true},
    {"exit_code": 1, "host_count": 3, "sample_hosts": ["web-17", "web-33", "web-90"], "stderr": "Unit nginx.service not found."}
  ],
  "offline_hosts": ["web-07", "web-09"],
  "output_trust": "untrusted",
  "hint": "完整输出用 jobs_get(job_id, host) 读取"
}
```

- 只合并退出码、stdout、stderr 哈希完全相同的输出。按相似度合并不在 MVP 范围。

### 默认值（均可在网关配置中修改）

| 项 | 默认值 |
|---|---|
| `wait_seconds` | 默认 30，最大 120 |
| 单次返回上限 | 32KB（约 8 千到 1 万 tokens，低于 Claude Code 默认 25,000 tokens 限制） |
| 每组输出 | 前 4KB |
| `response_format` | `concise` |
| `batch_size` | 20 |
| `max_failures` | 5 |
| `reason` | 必填 |
| 每个服务账号同时运行的 job | 最多 5 个 |

### 无状态

- MCP 层使用 go-sdk `StreamableHTTPOptions.Stateless`，不读写 `Mcp-Session-Id`。
- 每个请求用 Bearer token 识别服务账号，按“服务账号 + 目录版本 + 策略版本”生成并缓存工具列表。
- job、结果存 PostgreSQL，任一网关实例都能处理 `jobs_get`、`jobs_cancel`，负载均衡不需要会话粘滞。
- 响应用 SSE 流，长轮询期间每 10 秒发进度通知，防止负载均衡器因空闲断开连接。
- 限制：不能向客户端发请求（elicitation、sampling，allowops 不使用）；不能主动推送 `tools/list_changed`，目录或策略更新后客户端下次获取工具列表时生效，调用已下线工具返回说明原因的错误。
- 主机长连接是网关唯一的实例级状态，由 PostgreSQL 记录所在实例。
- Go SDK 是否支持 MCP 规范的 tasks 功能未核实，MVP 用 job_id 加轮询。

### 评估

- MVP 不做 agent 评估（2026-10-13 决定），列入 Roadmap。原计划：在测试环境用真实运维任务测试 MCP 工具，记录准确率、调用次数、token 消耗和工具错误。

## 8. 发布与部署

- 主机端升级由运维人员负责，allowops 不做托管升级。控制台显示主机端版本分布。
- 版本兼容：网关支持当前和上一主版本的主机端；主机端版本比网关新时拒绝连接。升级顺序为先网关后主机端。
- 三个二进制使用同一 SemVer 版本号，从同一 Git tag 发布。

### 主机端发布包

- 架构：仅 amd64。
- 格式：`.deb`、`.rpm`、`.tar.gz`。`CGO_ENABLED=0` 静态编译。
- 文件布局：

```
/usr/bin/allowops-agent
/usr/libexec/allowops/allowops-exec   # root 辅助程序，属主 root，0755
/usr/lib/systemd/system/allowops-agent.service
/etc/sudoers.d/allowops               # 固定内容，0440
/etc/allowops/agent.yaml              # 上游地址、CA 指纹、上报标签（升级时保留）
/etc/allowops/catalog-keys/           # 受信任的目录签名公钥，属主 root，由运维人员分发
/var/lib/allowops/                    # 证书、私钥、已验签目录缓存，属主 allowops，0700
/var/lib/allowops-exec/               # 已见过的最高目录版本号，属主 root，0700
```

- 安装时创建 `allowops` 用户，服务设为开机启动但不立即启动；`allowops-agent join --upstream <addr> --token <token> --ca-pin sha256:<指纹>` 注册成功后启动。
- deb 把 sudo 声明为推荐依赖；rpm 用 `Requires: sudo`。
- deb/rpm 用 GPG 签名；每次发布附 `checksums.txt` 及签名、SBOM。
- sudoers 内容固定，随安装包分发，修改目录不需要更新 sudoers（见第 9 节）。

### 支持的操作系统

- CentOS 7 / RHEL 7；Rocky/Alma/RHEL 8+、Ubuntu 20.04+、Debian 11+。

CentOS 7 的限制：

| 项 | 情况 | 处理 |
|---|---|---|
| rpm 4.11 | 不支持弱依赖（4.12 起）、不支持 zstd 压缩的包 | 不声明弱依赖；包压缩用 gzip 或 xz |
| rpm 签名 | rpm 4.11 不支持 ed25519 GPG 密钥（未实测） | 包签名用 RSA 4096 |
| systemd 219 | 不支持 `StateDirectory=`（235 起） | 安装脚本创建目录；unit 只用 219 支持的选项 |
| 内核 3.10 | Go 1.24 起要求内核 3.2+；Go 1.27 要求未核实 | 测试矩阵包含 CentOS 7 虚拟机 |
| sudo 1.8.23 | 支持 `-n` 和 `""`（禁止参数）规则；早期默认配置可能含 `requiretty` | sudoers 加 `Defaults:allowops !requiretty` |
| 生命周期 | 2024-06 停止维护 | 文档说明系统安全更新由使用方负责 |

测试矩阵（amd64 虚拟机）：CentOS 7、Rocky 8、Rocky 9、Ubuntu 20.04、Ubuntu 24.04、Debian 12。验证安装、注册、执行 read 和 write 动作、卸载。

### 网关

- 发布物：容器镜像（仅 amd64）、Helm chart（OCI）、Docker Compose 文件。CLI 发布 Linux 和 macOS 二进制。
- 官方支持 Kubernetes（Helm）和 Docker Compose（单机试用，含 PostgreSQL 和 SeaweedFS）。
- 负载均衡必须为 L4 TCP 透传，mTLS 和 ALPN 在网关进程内完成。
- 数据库迁移用 `allowops-gateway migrate` 单独执行（Helm 升级前钩子）；启动时检查 schema 版本，不匹配拒绝启动；迁移采用先扩展后收缩。
- 收到 SIGTERM 后停止接收新任务，等待执行中任务结束，通知主机重连；主机重连使用带随机抖动的退避。
- CA 私钥、数据库密码、对象存储密钥通过 Secret 或文件挂载提供。
- 生产环境的 PostgreSQL 和对象存储由使用方提供并负责备份。

## 9. action 格式与签名

### 目录仓库与流程

```
catalog.yaml                         # catalog_id、schema_version、默认值
actions/nginx_view_log.yaml          # 一个 action 一个文件
actions/systemd_restart_service.yaml
```

- CI 流程：`allowops catalog validate`（schema、命名、description 必填、exec 路径和解释器规则）→ `allowops catalog build` → `allowops catalog sign` → `allowops catalog publish`（上传网关）。
- 目录包内容：`schema_version`、`catalog_id`、`version`（单调递增整数，取 UTC `YYYYMMDDHHMMSS`）、`created_at`、`expires_at`、`git_commit`、全部 action 及每个 action 的 SHA-256 摘要。

### action 格式

```yaml
name: systemd_restart_service          # 须匹配 ^[a-z][a-z0-9_]{0,63}$，建议 <对象>_<动作>
description: "重启指定的 systemd 服务。用于服务无响应或配置变更后。"   # 必填
risk: write                            # read | write | dangerous，ABAC 资源属性
idempotent: false                      # 可选，用于生成 idempotentHint
run_as: root                           # 可选。省略时以 allowops 用户直接执行
params:
  service:
    type: enum
    values: [nginx, api]
    description: "要重启的服务名"        # 每个参数必填
exec: ["/usr/bin/systemctl", "restart", "{service}"]   # exec[0] 必须是绝对路径
timeout: 30s
max_output: 16KB
batch_size: 10                         # 可选，MCP 调用只能更严格
max_failures: 1                        # 可选
redact:                                # 可选，覆盖 catalog.yaml 的全局脱敏规则（见第 13 节）
  builtin: [secrets]
```

- 与 `design.md` 相比的变化：name 规则、description 必填、`idempotent`、`run_as`、`batch_size`、`max_failures` 为新增或修改；exec[0] 只允许绝对路径，不在 PATH 中查找。
- 只允许绝对路径的原因：目录在中心校验，在不同发行版的主机上执行，同名命令可能解析到不同程序。主机上不存在 exec[0] 时，该 action 在该主机标记 `unsupported`。
- 占位符仍只能作为完整 argv 元素。
- exec 中不允许出现 `sudo`，提权只能通过 `run_as` 声明。
- 主机端加载目录时读取 exec[0] 文件开头：以 `#!` 开头的脚本（如 `zgrep`）按解释器处理，未声明 `allow_interpreter` 时该 action 在该主机标记 `unsupported`。原因：只按文件名检查时，shell 脚本可绕过解释器限制。
- 已知限制（包装命令检查）：
  - `env`、`timeout`、`nice`、`ionice`、`stdbuf`、`xargs`、`nsenter`、`chroot` 后的目标只检查 ELF 魔数（`\x7fELF`）；既非 ELF 也无 `#!` 的文件在未声明 `allow_interpreter` 时被拒绝。
  - 以 `\x7fELF` 开头的可执行文本文件会通过检查。在 `/bin/sh` 为 dash 的主机上，`execvp` 收到 ENOEXEC 后可能用 sh 执行该文件。前提是攻击者能在主机上写入可执行文件。
  - `nsenter` 不带目录的 `-r`、`--root`，以及 `-a`、`-m`、`--mount[=文件]` 进入主机无法检查的根目录或挂载命名空间，只做名称检查。`-r<目录>`、`--root=<目录>` 的目录是本机根目录时，按本机文件系统检查目标。

### 特权执行：allowops-exec

sudoers 内容固定，随安装包分发：

```
# /etc/sudoers.d/allowops
Defaults:allowops !requiretty
allowops ALL=(root) NOPASSWD: /usr/libexec/allowops/allowops-exec ""
```

- `""` 表示不允许带参数。`!requiretty` 兼容 CentOS 7 早期默认配置。
- 执行过程：
  1. allowops-agent 通过 stdin 向 allowops-exec 传 `{action, params, catalog_version}`。
  2. allowops-exec 以 root 读取目录包，用 `/etc/allowops/catalog-keys/` 中的公钥验签，检查版本未回退、目录未过期，校验参数。
  3. 切换到 `run_as` 用户执行，执行 `design.md` 中的安全要求：清空环境、超时后结束进程组、截断输出。
- 未声明 `run_as` 的 action 由 allowops-agent 直接执行，不经过 sudo。
- 安全效果：allowops-agent 进程被攻破时，攻击者只能执行已签名的 action 且参数合法，与网关被攻破时的保证相同。
- 运维效果：修改目录不需要重新分发 sudoers。`run_as` 可指定任意用户。
- 代价：增加一个 root 程序。作为单独的小二进制发布，代码量尽量小，单独写攻击测试。sudo 日志只记录 allowops-exec，具体 action 和参数由 allowops-exec 写入 journal。
- 被否决的方案：按命令生成 sudoers。int、string、path 参数只能用 `*` 通配，sudoers 的 `*` 可匹配任意附加参数；主机端被攻破时可以 root 身份任意附加参数；每次修改目录都要向上千台主机分发 sudoers。

### 签名

- 格式：DSSE 信封（in-toto 的签名封装格式）+ ed25519，只用 Go 标准库。一个目录包可带多个签名。
- 被否决：Sigstore cosign 无密钥签名依赖外部透明日志服务，内网主机无法验证。
- 私钥存放：CI（云效 Flow 或 Jenkins）凭证库，只允许受保护分支的发布流水线使用；目录合入主分支必须经过评审。风险：CI 被攻破时可以签名。
- 信任锚：主机 `/etc/allowops/catalog-keys/`（属主 root），由运维人员在安装时分发。网关也验签一次以提前发现错误，主机只信任本地公钥。
- 防回退：allowops-exec 在 `/var/lib/allowops-exec/`（属主 root）记录见过的最高版本号，拒绝更低版本。allowops-agent 同样检查。
- 过期：目录签名后默认 90 天过期（可配置）。到期前 14 天在控制台和指标中告警。过期后主机拒绝执行。作用是限制泄露的旧目录可被重放的时间。
- 轮换：先分发新公钥 → 过渡期新旧私钥同时签名 → 移除旧公钥。
- 私钥泄露：从主机信任列表删除对应公钥。网关不能吊销密钥，网关被攻破时也不能改变主机信任的密钥。

### 下发与一致性

- 主机连接网关或收到通知时拉取新目录包，验签后保存到 `/var/lib/allowops/`，向网关报告已加载版本。
- 网关下发 task 时附带 action 摘要。摘要与主机本地目录不一致时，task 标记 `unsupported`。job 执行期间目录更新时不会用错版本执行。

## 10. 单机模式

- MVP 只做网关模式，不提供原需求中的单机运行（本地 YAML、`run`、stdio MCP、本地审计、风险开关）。单机模式列入 Roadmap。
- 提供目录作者使用的试运行命令：`allowops catalog try <action> --param k=v`。
  - 在当前主机上用与主机端相同的执行器，以当前用户身份执行未签名的 action，输出原需求的 JSON 格式（`ok`、`action`、`exit_code`、`duration_ms`、`stdout`、`stderr`、`truncated`）。
  - 只用于发布前验证 action 定义：不提供 MCP，不写审计。遇到声明 `run_as` 的 action 只给警告，不提权。
  - 不需要额外权限限制：能在测试机执行该命令的人本身已有 shell。
- 原因：主要场景是上千台服务器，MVP 只维护一套权限模型和审计；试用需求由 Docker Compose 部署满足。被否决的方案 B（同时提供单机模式）需要维护两套权限模型、审计和 MCP 行为，且单机模式的安全前提（agent 没有其他 shell 工具）不受 allowops 控制。

## 11. 威胁模型

用于 SECURITY.md 和攻击测试。2026-10-13 采纳。

保护对象：主机 root 权限、目录签名私钥、网关 CA 私钥、API token、命令输出、审计完整性、策略规则。

| 编号 | 威胁 | 攻击者能力 | 措施 | 补充测试 |
|---|---|---|---|---|
| T1 | agent 失控或受提示注入（如日志中的指令） | 用合法参数调用已授权的 action | 策略、`expected_count`、分批和失败上限、并发上限；建议只读和写操作使用不同服务账号；MCP 返回标注输出为不可信数据 | MCP 层越权调用、selector 过宽 |
| T2 | API token 被盗 | 冒充该 agent | token 只存哈希、有有效期、可吊销；策略可限制来源 IP；审计 | 吊销 token、过期 token |
| T3 | 网关被攻破 | 在所有主机上调用全部已签名 action（合法参数）；读取输出 | 不能新增命令，不能改变主机信任的密钥。不做主机本地风险上限（2026-10-13 决定），此项为残余风险，文档写明 | 伪造或篡改任务、action 摘要不一致 |
| T4 | CI 或签名私钥被攻破 | 签发任意命令，即所有主机的 root | 分支保护加评审、私钥只给发布流水线、90 天过期、密钥轮换。残余风险最大，文档写明 | 篡改目录包、错误密钥签名、过期目录、版本回退 |
| T5 | 单台主机 root 被攻破 | 窃取该主机证书、伪造其输出 | 影响限于该主机；授权标签由网关端设置；网关限制主机消息大小和频率，并再次截断输出 | 超大消息、畸形消息、冒充其他主机 |
| T6 | 主机端进程被攻破（`allowops` 用户） | 以 `allowops` 用户执行任意命令；特权操作只能执行已签名 action | `allowops` 用户不加额外组；需要读日志等权限的 action 用 `run_as`，不给 `allowops` 用户加组 | allowops-exec stdin 模糊测试、超长输入、未签名 action |
| T7 | allowops-exec 漏洞 | 提权到 root | 目录文件只打开一次、读入内存后验签（防检查与使用之间被替换）；忽略环境变量，使用固定路径；状态目录不跟随软链接 | 目录文件竞态替换、软链接、环境变量注入 |
| T8 | 网络中间人；join token 泄露 | 冒充网关或主机；用泄露的 token 注册主机 | 双向 mTLS；首次注册校验 CA 指纹；join token 有效期短，多次使用的 token 有次数上限；新主机无授权标签，默认全部拒绝；主机名重复时拒绝注册 | 错误 CA 指纹、超过次数或过期的 join token、重复主机名 |
| T15 | LDAP 登录被攻击 | 暴力破解、LDAP 注入、窃听密码 | 只允许 LDAPS 或 StartTLS；过滤条件转义用户输入；登录限流；网关不保存密码 | LDAP 注入、登录限流 |
| T9 | 控制台 XSS、CSRF、会话被盗 | 以管理员身份修改策略 | 命令输出只按纯文本显示；严格 CSP；Cookie HttpOnly、SameSite=Strict，CSRF 校验；策略修改写审计并先试算 | 输出中含脚本、跨站请求 |
| T10 | 参数注入 | 执行预期外的命令 | `design.md` 安全要求 1~9 | 原攻击测试集 |
| T11 | 主机时钟偏差 | 证书或目录过期判断出错 | 生效时间允许 5 分钟偏差；偏差过大时连接失败，主机显示离线；文档要求启用 NTP | 时钟偏差边界 |
| T12 | agent 大量请求 | 网关或主机过载 | 每服务账号并发 job 上限 5；MCP 请求限流；主机端限制并发执行数 | 限流 |
| T13 | 篡改审计 | 掩盖操作痕迹 | 哈希链；网关数据库账号只有 INSERT 权限。数据库管理员仍可重写整条链，在“审计导出”议题中处理 | 删改记录后哈希链校验失败 |
| T14 | 供应链攻击 | 发布物被植入恶意代码 | 发布包签名、SBOM、依赖锁定；CI 增加 `govulncheck` | — |

不在防护范围内（SECURITY.md 写明）：

- PostgreSQL 或对象存储的管理员是恶意的。
- 安装 allowops 之前主机 root 已被攻破。
- AI 模型服务商可以看到返回给模型的命令输出（输出脱敏另行讨论）。

提示注入的处理（2026-10-13 决定）：

- MCP 返回结果中用固定字段（如 `"output_trust": "untrusted"`）标明 stdout、stderr 是不可信的主机数据，不应当作指令执行。
- 工具描述中写明同样的说明。
- 文档说明提示注入风险，并说明该措施不能完全防止。

## 12. 身份与账号

2026-10-13 确定。

### 控制台用户

- 身份源：通用 OIDC 和 LDAP。
  - OIDC 支持 Authing、Keycloak、Casdoor、Okta 等标准实现；钉钉可经 Keycloak 或 Authing 联邦接入。
  - LDAP：只允许 LDAPS 或 StartTLS；过滤条件转义用户输入；登录限流；网关不保存密码；按 LDAP 组映射角色。
- 初始管理员：网关配置 `bootstrap_admins`（OIDC email 或 LDAP 用户名），不设内置本地密码账号。
- 角色来源：OIDC `groups` 声明或 LDAP 组按 `role_mappings: {组名: 角色}` 映射；管理员也可在控制台手工指定。

### 控制台权限

- 控制台操作也由 OPA（ABAC）判定，操作列表见第 5 节。
- 网关首次启动时生成默认规则，权限等同以下五个角色：

| 角色 | 默认权限 |
|---|---|
| admin | 全部：策略、服务账号、主机、join token、用户角色 |
| operator | 管理主机（授权标签、删除）、创建 join token、查看 job |
| auditor | 查看审计、job 和命令输出 |
| viewer | 查看主机、目录和 job 摘要，不能查看命令输出 |
| publisher | 只能发布目录（供 CI 使用） |

- 防锁死：保存策略前检查，保存后若没有任何主体能修改策略则拒绝保存。
- 恢复途径：网关配置文件中的 `bootstrap_admins` 始终拥有修改策略的权限，不受策略规则影响（2026-10-13 确认）。修改配置文件需要网关主机权限。

### 服务账号

- 由有权限的控制台用户创建；属性：名称、负责人（控制台用户）、描述、策略角色。
- 建议每位工程师使用单独的服务账号，审计可对应到个人。
- token：`aops_` 前缀 + 32 字节随机数（前缀便于代码托管平台的密钥扫描识别）；只在创建时显示一次；数据库存 SHA-256。
- 有效期默认 30 天，创建时可选 1~365 天；到期前 7 天在控制台提醒。
- 一个账号可有多个 token，用于轮换；记录最后使用时间；可吊销。
- CI 发布目录使用分配了 publisher 权限的服务账号。
- Roadmap：MCP 规范的 OAuth 授权流程，工程师在浏览器登录授权后 agent 以该工程师身份调用，替代长期 token。

### 主机

- join token 可选单次或多次使用；多次使用时必须设置有效期（默认 24 小时）和最大使用次数。每台主机仍获得独立证书。
- 新注册的主机没有授权标签，任何策略都不匹配，默认全部拒绝。
- 主机名全局唯一；同名主机再次注册被拒绝，需管理员先删除旧记录。

## 13. 输出脱敏

2026-10-13 确定。

- 位置：主机端，输出离开主机前脱敏（allowops-agent 和 allowops-exec 执行）。敏感内容不经过网络和网关。
- 规则来源：签名目录。`catalog.yaml` 定义全局规则，action 的 `redact` 字段可覆盖。网关被攻破时不能关闭或放宽脱敏；修改规则需要重新签名目录。
- 不保留原始输出：对象存储、控制台、MCP 返回都只有脱敏后的输出，原始内容不离开主机。
- 实现：Go RE2 正则，匹配耗时与输入长度成线性关系。匹配内容替换为 `[REDACTED:类型]`。
- 内置规则：
  - `secrets`（默认开启）：PEM 私钥、阿里云 AccessKey（`LTAI` 开头）、AWS Access Key（`AKIA` 开头）、JWT、`Authorization: Bearer` 头、URL 中的用户名密码、`password=`/`secret=`/`token=` 等键值对。
  - `pii`（默认关闭，按 action 开启）：手机号（`1[3-9]` 开头 11 位）、18 位身份证号（校验码）、银行卡号（Luhn 校验）。
  - IP 地址和主机名不脱敏。
- 写法：

```yaml
redact:
  builtin: [secrets]          # 或 [secrets, pii]；[] 表示该 action 不脱敏
  custom:
    - name: order_token
      regex: 'otk_[A-Za-z0-9]{24}'
```

- 局限（文档写明）：个人信息规则可能误伤（如以 1 开头的 11 位订单号）；正则不能识别所有敏感内容，文档不声称“已全部脱敏”。
- 测试：每条内置规则的命中和不命中样例；输出截断边界处的敏感内容（脱敏在截断前执行，避免半截密钥漏出）。

## 14. 控制台与 CLI

2026-10-13 确定。

### 控制台

- 界面语言：中文和英文，第一版接入 i18n。
- 页面范围：

| 页面 | 内容 |
|---|---|
| 登录 | OIDC、LDAP |
| 概览 | 在线和离线主机数、最近 job 和失败数、目录过期提醒、即将到期的 token |
| 主机 | 按标签、在线状态、版本筛选；详情显示授权标签（可编辑）、上报标签（只读）、目录版本、最后在线时间；按 selector 批量设置标签；CSV 导入标签（导入前显示变更预览）；删除主机 |
| join token | 创建、列出、吊销；创建后显示安装命令 |
| 目录 | 当前版本和过期倒计时、action 列表和详情（参数、命令、风险、脱敏规则）、历史版本、各主机目录版本分布 |
| 策略 | 规则列表、表单编辑、保存前试算对比、历史版本、回滚 |
| 服务账号 | 创建、token 管理、角色、负责人；Claude Code MCP 配置示例 |
| job | 列表和筛选；详情显示每台主机的状态和输出；取消 |
| 审计 | 按时间、主体、主机、action 查询；哈希链校验 |
| 用户与角色 | 用户列表、角色分配、组到角色的映射 |
| 系统 | 网关实例、PostgreSQL 和对象存储健康状态、主机端版本分布 |

- 不在 MVP：图表仪表盘、CMDB 同步、审批。

### CLI

```
allowops login                                              # OIDC 浏览器登录或 LDAP 密码登录
allowops catalog keygen|validate|build|sign|publish|try
allowops actions list|describe <action>                     # 只显示当前身份可用的 action
allowops run <action> --selector env=prod --expected-count 12 --param k=v --reason "..."
allowops jobs list|get|output|cancel
allowops hosts list|label|delete                            # label 支持按 selector 批量设置和 CSV 导入
allowops jointoken create --uses 500 --ttl 24h
allowops policy get|apply -f rules.yaml|test                # 策略可放在 Git 中用命令发布
allowops-gateway serve|migrate
allowops-agent join|run|status
```

- 输出默认是表格，`--json` 输出 JSON。原需求“默认输出 JSON”是给 agent 用的；agent 现在用 MCP。
- `allowops run` 与 MCP 走同一流程：参数校验、`expected_count` 核对、策略判定、审计。
- 认证：
  - 服务账号 token（环境变量或配置文件），用于 CI 和脚本。
  - `allowops login`（MVP 支持）：
    - OIDC：网关作为 OIDC 客户端完成登录，通过本机回环地址回调把网关签发的 CLI 会话 token 交给 CLI。
    - LDAP：CLI 提示输入密码，经 TLS 发给网关，网关完成 LDAP 认证后签发 CLI 会话 token。
    - CLI 会话 token 保存在 `~/.config/allowops/credentials`（0600），以该人员身份按 ABAC 判定权限。
    - 会话有效期默认 7 天（可配置，2026-10-13 确定）。

## 15. 审计导出

2026-10-13 确定。用于应对威胁模型 T13（数据库管理员可重写整条哈希链）。

- MVP 导出目标：JSON Lines 文件。写到网关本地，按大小轮转，由 filebeat、fluent-bit、vector 等日志采集工具转发到其他团队管理的系统。syslog、webhook、Kafka 列入 Roadmap。
- PostgreSQL 是审计的权威来源。每条事件有递增序号 `seq`、`prev_hash`、`hash`。导出程序按序号读取，用游标记录进度，至少送达一次；外部系统不可用时从游标继续，不丢失。
- 多个网关实例时用 PostgreSQL advisory lock 保证只有一个实例导出。
- 每 5 分钟写一条检查点事件，内容为当前哈希链末尾的哈希。接收方可检查连续性；数据库管理员事后重写哈希链时，链末尾哈希与已导出的检查点不一致。
- CLI：`allowops audit export --from --to` 按时间段导出 JSON Lines；`allowops audit verify` 校验哈希链。

## 16. 测试策略

2026-10-13 确定。

### 每次提交（CI）

| 层次 | 内容 |
|---|---|
| Go 单元测试 | params、catalog、执行器、脱敏、DSSE 签名、OPA 规则（Rego 同时用 `opa test`）；`go test -race` |
| 攻击测试 | 原需求攻击测试集 + 威胁模型 T1~T15 的补充测试；每条安全要求至少一个测试 |
| 模糊测试 | Go `testing.F`：参数解析、目录 YAML、DSSE 解析、allowops-exec stdin；每个目标 30 秒 |
| 集成测试 | testcontainers 启动 PostgreSQL 和 SeaweedFS；同进程运行网关和主机端；用 go-sdk MCP 客户端端到端调用 |
| 前端 | ESLint、tsc、Vitest；检查中英文翻译 key 一致 |
| 其他检查 | `go vet`、staticcheck、`govulncheck`、构建、goreleaser 快照构建 |

### 每晚和发布前

| 层次 | 内容 | 运行位置 |
|---|---|---|
| 虚拟机矩阵 | amd64：CentOS 7、Rocky 8、Rocky 9、Ubuntu 20.04、Ubuntu 24.04、Debian 12；验证安装、注册、执行 read 和 write（经 sudo 和 allowops-exec）、卸载 | 开发者本机虚拟机，发布前手工运行（2026-10-13 决定） |
| 前端端到端 | Docker Compose 完整环境 + Playwright：登录、主机、策略、job、审计 | CI 每晚 |
| 规模测试 | 模拟器进程虚拟数千台主机，每台独立证书经 mTLS 连接 | CI 每晚或发布前 |
| OPA 基准 | 500 条规则、1000 台主机时一个 job 的判定耗时 | CI 每晚 |
| 长时间模糊测试 | 每个目标 10 分钟 | CI 每晚 |

规模测试通过标准（2026-10-13 确定）：

- 单个网关实例保持 5000 台主机连接。
- 1000 台主机的空操作 job 在 10 秒内完成下发和结果汇总（不含命令本身耗时）。
- 一个网关实例重启后，全部主机在 60 秒内重新连上。
- 另测：两个网关实例时任务路由正确；记录单实例内存占用。

agent 评估：MVP 不做，列入 Roadmap。

## 17. 许可

2026-10-13 确定。

- 许可证：MIT（见 `design.md`，A58，2026-10-21 改定）。
- 版权人：个人 liubing。`LICENSE` 为 `Copyright (c) 2026 liubing`。
- 外部贡献：MVP 不接受外部代码，CONTRIBUTING.md 说明只接受 issue 和建议。以后接受外部代码时另行说明贡献流程。
- 第三方许可证合规：
  - 用 `go-licenses` 和 `license-checker` 生成 Go 和前端依赖清单，随发布物提供 `THIRD_PARTY_NOTICES`。
  - CI 只允许 MIT、BSD、Apache-2.0、ISC、MPL-2.0 许可的依赖；GPL、AGPL 依赖直接拒绝。

## 18. 示例与文档

2026-10-13 确定。

### 示例目录 `examples/catalog/`（19 个只读 action）

命令路径兼容 CentOS 7 和较新发行版。`allowops` 用户不加 systemd-journal、docker 等组（docker 组等同 root），需要权限的示例使用 `run_as: root`。

| action | 命令 | run_as | 说明 |
|---|---|---|---|
| `systemd_service_status` | `/usr/bin/systemctl status {service} --no-pager` | — | |
| `journal_view_log` | `/usr/bin/journalctl -u {service} -n {lines} --no-pager ["--since", "{since}"]` | root | |
| `journal_grep` | `/usr/bin/journalctl -u {service} --since {since} --no-pager -g {pattern}` | root | `-g` 需要 systemd 237+，CentOS 7 不可用，文档注明 |
| `nginx_test_config` | `/usr/sbin/nginx -t` | root | |
| `disk_usage` | `/usr/bin/df -h -x tmpfs -x devtmpfs` | — | |
| `disk_dir_size` | `/usr/bin/du -sh {path}` | root | path `allowed_roots`: `/var/log`、`/data` |
| `memory_usage` | `/usr/bin/free -m` | — | |
| `ports_listening` | `/usr/sbin/ss -ltnp` | root | 显示进程名需要 root |
| `process_top` | `/usr/bin/ps -eo pid,user,%cpu,%mem,etime,comm --sort=-%cpu` | — | |
| `system_load` | `/usr/bin/uptime` | — | |
| `kernel_errors` | `/usr/bin/dmesg -T --level=err,warn` | root | |
| `docker_ps` | `/usr/bin/docker ps --all --format "{{json .}}"` | root | 每行一个 JSON |
| `docker_stats` | `/usr/bin/docker stats --no-stream --format "{{json .}}"` | root | |
| `docker_container_state` | `/usr/bin/docker inspect --format "{{json .State}}" {container}` | root | 只返回 State；完整 inspect 含环境变量 |
| `docker_logs` | `/usr/bin/docker logs --tail {lines} --timestamps ["--since", "{since}"] {container}` | root | container 按 docker 容器名规则正则校验 |
| `log_tail_file` | `/usr/bin/tail -n {lines} {path}` | root | path `allowed_roots`: `/var/log`、`/data/logs` |
| `log_grep_file` | `/usr/bin/grep -E -m {max_matches} -e {pattern} -- {path}` | root | `-e` 和 `--` 防止被当作选项；pattern 最长 200；慢正则由超时限制 |
| `log_grep_fixed` | `/usr/bin/grep -F -m {max_matches} -e {pattern} -- {path}` | root | 固定字符串匹配 |
| `log_search_dir` | `/usr/bin/grep -r -E -m {max_matches} -e {pattern} -- {path}` | root | 在日志目录递归搜索 |

- 只有完整等于 `{参数名}` 的 argv 元素是占位符；`"{{json .}}"` 等其他元素按字面值传递。
- 压缩旧日志（.gz）的搜索不在 MVP 范围（`zgrep` 是 shell 脚本）。
- 另提供：示例策略 `examples/policy/rules.yaml`；目录签名和发布流水线示例（云效 Flow、Jenkins、GitHub Actions）。

### 快速开始

- Docker Compose：网关、PostgreSQL、SeaweedFS、演示用 LDAPS、演示主机容器（运行 allowops-agent，不需要 systemd，启动后自动注册）。
- 笔记本上完成：部署 → 签名并发布目录 → 在 Claude Code 中调用 action。

### 文档

- 形式：文档站，VitePress（总指挥选择：Markdown 为主、构建快、自带本地搜索），GitHub Actions 发布到 GitHub Pages。
- 语言：`README.md`（英文）和 `README.zh-CN.md`；其他文档只写英文。
- README：定位、为什么不用受限 shell、架构图、快速开始、Claude Code 配置示例（`claude mcp add --transport http allowops https://gw.example.com/mcp --header "Authorization: Bearer aops_..."`）、许可说明（MIT）、Roadmap。
- 文档站：目录字段和参数类型、策略规则、部署（Helm、Compose、L4 透传）、主机端安装和注册、密钥轮换、CLI 参考（cobra 生成）。
- `SECURITY.md`：漏洞报告方式（GitHub private vulnerability reporting）、威胁模型、不在防护范围内的情况。
- `CONTRIBUTING.md`：目前只接受 issue 和建议。
- Claude Desktop 远程 MCP 示例暂不写：是否支持自定义请求头、能否访问内网地址未核实。

## 19. 目录结构与实施计划

2026-10-13 确定。名字检查已完成：GitHub 仓库、GitHub 用户和组织、Go 模块代理、npm、PyPI 中均未发现 `allowops`。

### 目录结构

```
cmd/
  allowops/              CLI
  allowops-gateway/
  allowops-agent/
  allowops-exec/         root 辅助程序（单独小二进制）
api/proto/allowops/v1/   Protobuf：主机与网关协议、控制台 API
gen/                     buf 生成代码（提交入库）
internal/
  catalog/    目录 schema、加载、校验、摘要、DSSE 签名验签（共用）
  params/     参数类型、校验、argv 渲染、JSON Schema（共用）
  redact/     脱敏规则（共用）
  executor/   执行、超时、进程组、截断、环境清理（共用）
  agent/      注册、mTLS 连接、目录同步、任务执行、调用 allowops-exec
  execd/      allowops-exec：stdin 协议、防回退状态、run_as、脚本检查
  gateway/
    server/     443 ALPN 分发、优雅关闭
    hostconn/   主机连接、实例路由、LISTEN/NOTIFY
    mcp/        无状态 MCP、按身份生成工具
    api/        控制台和 CLI 的 Connect 服务
    authn/      OIDC、LDAP、API token、CLI 会话、主机 CA
    authz/      OPA、Rego（go:embed）、默认规则、试算
    job/        调度、分批、聚合
    hosts/      主机注册表、标签、join token、CSV 导入
    catalogsvc/ 目录发布与分发
    audit/      哈希链、JSON Lines 导出
    output/     对象存储
  store/      PostgreSQL：sqlc 查询、goose 迁移
  cli/        cobra 命令
web/          React 控制台（pnpm、Vite）
website/      VitePress 文档站
deploy/
  compose/    Docker Compose（含演示主机）
  helm/allowops/
  packaging/  nfpm、systemd unit、sudoers、安装脚本
examples/     catalog/、policy/、pipelines/
test/         attack/、e2e/、scale/、vm/
```

### 实施计划

- 一次做完 MVP，按依赖关系并行推进，不分里程碑（2026-10-13 决定）。

| 节点 | 内容 | 依赖 | 角色 |
|---|---|---|---|
| P0 | 骨架：目录、依赖、buf、CI 基础（vet、staticcheck、test、govulncheck、许可证检查）、前端脚手架 | — | Sol |
| P1 | 共用核心：params、catalog、DSSE、redact、executor；攻击测试和模糊测试；CLI `catalog keygen/validate/build/sign/try` | P0 | Sol |
| P2 | proto：主机与网关协议、控制台 API | P0 | Astra |
| P3 | 主机端：allowops-exec、allowops-agent、打包（nfpm、systemd、sudoers） | P1、P2 | Sol |
| P4 | 网关基础：schema 和迁移、443 ALPN、CA 和 join token、主机注册表、连接路由、目录发布和分发 | P1、P2 | Sol |
| P5 | 权限与身份：OPA 和默认规则、试算、OIDC、LDAP、服务账号和 token、CLI 会话 | P4 | Sol |
| P6 | job 与 MCP：调度、分批、聚合、对象存储、无状态 MCP、CLI `run/jobs` | P3、P4、P5 | Sol |
| P7 | 审计：哈希链、JSON Lines 导出、校验 | P4 | Sol |
| P8 | 控制台：全部页面、中英文 i18n | P2（可先用模拟数据）、P5、P6 | Sol |
| P9 | 部署：Helm、Compose（含演示主机）、安装脚本 | P3、P4 | Sol |
| P10 | 测试：规模模拟器、Playwright、OPA 基准、虚拟机矩阵脚本 | P6、P8、P9 | Sol |
| P11 | 文档：README 中英文、文档站、SECURITY.md、CONTRIBUTING.md、示例和流水线 | P6、P9 | Muse 或 Sol |
| P12 | 扩展执行能力（第 20 节 D1~D9）：输出过滤、组合 action、包装命令检查、候选路径、签名脚本、内置处理器（日志检索、MySQL、Redis、HTTP）、url 参数类型、脱敏规则补充 | P1 | Sol（内置 MySQL 只读校验先由 Astra 定方案） |
| A1 | action 需求文档和通用示例规格（`docs/action-catalog-requirements.md`、`examples/catalog/`），只使用去敏清单 | 第 20 节写入后 | Sol |
| V | 全部 CI、本机虚拟机矩阵、规模测试通过标准 | 全部 | 总指挥核实 |
| REL | `gh repo create --public` 并推送；开启 private vulnerability reporting | V | 执行前问用户 |

- P3 依赖 P12 中主机端执行部分；P12 与 P2、P4 可并行。

### 任务编排

- 进度接入 agent-progress 看板（2026-10-13 决定）。
- 每个节点在独立 worktree 分支开发，基于 `main`。worker 只在本地提交，不推送、不合并。
- 总指挥在 worker 的 worktree 中重跑验证命令，核对 commit SHA 和 diff 范围，核实后在本地合入 `main`。
- 推送任何分支和创建公开仓库前都先问用户。
- worker 只接收去敏后的使用清单，不接触本机会话原文、客户主机名、公司路径和凭据（2026-10-13 决定）。

## 20. 基于实际使用的扩展（D1~D9）

2026-10-13 确定。依据：内部使用统计（不随仓库公开）。D1~D8 全部进入 MVP；D9 为脱敏规则补充。

action 的执行方式四选一：`exec`、`steps`、`script`、`builtin`。

### D1 输出过滤（替代管道）

```yaml
filters: [match, exclude, tail, head, count]   # 允许 agent 使用的过滤参数
```

- agent 可传 `match`、`exclude`（RE2，最长 200 字符）、`tail`、`head`（行数）、`count`（只返回匹配行数）。
- 主机端按“命令 stdout → 脱敏 → 过滤 → 截断”的顺序逐行处理。脱敏在过滤前，agent 不能用 `match` 探测原始敏感值。
- 原始输出扫描上限 `max_scan`，默认 256MB；超过时停止并标记。

### D2 组合 action

```yaml
steps:
  - name: load
    exec: ["/usr/bin/uptime"]
  - name: memory
    exec: ["/usr/bin/free", "-m"]
on_error: continue        # continue（默认）| stop
```

- 每个步骤遵守与 `exec` 相同的规则；按顺序执行；共用 action 的 `timeout` 和 `run_as`。
- 结果按步骤分段，分别给出退出码。

### D3 内置日志检索

```yaml
builtin: log_search
builtin_config:
  allowed_roots: [/var/log, /data/logs]
  max_files: 50
  max_scan: 1GB
```

- 参数：`path_glob`（必须落在 allowed_roots 内，每个文件 `EvalSymlinks` 后检查）、`pattern`、`fixed`（固定字符串）、`exclude`、`context`（上下文行数）、`max_matches`。
- 支持普通文件和 `.gz`，Go 实现，不调用 `grep`、`zgrep`。
- 原 Roadmap 中“压缩日志搜索”由此项覆盖。

### D4 包装命令检查（安全修正）

- `catalog validate` 和主机端识别包装命令：`docker exec`、`kubectl exec ... --`、`nsenter`、`chroot`、`env`、`timeout`、`nice`、`ionice`、`stdbuf`、`xargs`。
- 对包装命令后真正执行的命令同样做解释器检查。解释器列表补充 `awk`、`gawk`、`mawk`、`sed`（GNU sed 的 `e` 命令可执行命令）。
- 容器内命令无法在主机上检查绝对路径，按命令名检查；禁止 `docker exec -t` 和 `kubectl exec -t`。
- 例：`["/usr/bin/docker", "exec", "{container}", "jstat", "-gc", "{pid}"]` 允许；`[..., "exec", "{container}", "sh", "-c", ...]` 拒绝（除非 `allow_interpreter`）。

### D5 候选路径

```yaml
exec: ["/usr/bin/kubectl", "get", "pods", "-n", "{namespace}"]
exec_fallbacks: ["/usr/local/bin/kubectl"]
```

- exec[0] 不存在时依次尝试 `exec_fallbacks`；每个候选都必须是绝对路径并通过解释器和脚本检查。

### D6 签名脚本 action

```yaml
script:
  file: scripts/nginx_access_stats.py   # 目录仓库内路径，内容随目录包签名
  interpreter: /usr/bin/python3         # 绝对路径；声明 script 即视为 allow_interpreter
args: ["--hour", "{hour}"]
```

- 脚本内容的 SHA-256 计入 action 摘要。执行时写入私有临时目录（0500），执行后删除。Python 加 `-I`（隔离模式）。
- 脚本可执行任意逻辑，`catalog validate` 对 script action 打印警告；依靠目录评审和签名控制。
- 临时分析需要先写脚本、提交、评审、签名后才能执行。
- MVP 只在主机上执行脚本；在容器或 Pod 内执行脚本（`kubectl exec -i ... python3 -`）列入 Roadmap。

### D7 只读数据库查询

```yaml
builtin: mysql_query
builtin_config:
  credential: /etc/allowops/credentials/mysql-main.cnf   # 主机端 root 文件，0600，不进目录
  address: tcp://127.0.0.1:3306                          # 或 unix:///var/run/mysqld/mysqld.sock
  max_rows: 500
  timeout: 10s
params:
  database: { type: string, regex: '^[a-zA-Z0-9_]{1,64}$', description: "数据库名" }
  sql:      { type: string, max_len: 4000, description: "只读 SQL" }
```

- 用 SQL 解析器检查：只允许单条 SELECT、SHOW、DESC、EXPLAIN；拒绝 `INTO OUTFILE`、`LOAD_FILE`、`SLEEP`、`BENCHMARK` 等。
- 连接后 `START TRANSACTION READ ONLY`；设置 `max_execution_time`；文档要求使用只读数据库账号。
- 结果限制行数，按脱敏规则处理。
- `builtin: redis_command`：只允许 GET、MGET、HGET、HLEN、TTL、TYPE、EXISTS、STRLEN、LLEN、SCARD、ZCARD、SCAN（COUNT 有上限）、INFO；禁止 KEYS。
- 凭据只在主机上，由 allowops-exec（root）读取。
- 运行在 Docker 内且未映射端口的数据库，需在 `address` 中配置可访问的地址；按容器名自动解析地址不在 MVP 范围。
- 驱动：go-sql-driver/mysql（MPL-2.0）、go-redis（BSD-2）；SQL 解析器在实现时选择 Apache-2.0 许可的实现。

### D8 HTTP 探测

- 新参数类型 `url`：字段 `allowed_prefixes`（必填）。
- `builtin: http_get`：Go 实现，只发 GET；不跟随跳转；超时；响应大小上限；请求头由 `builtin_config` 固定。
- 返回状态码、部分响应头、响应体（脱敏、可用 D1 过滤）。

### D9 脱敏规则补充

- `secrets` 规则增加：命令行 `-p<密码>` 形式（mysql 客户端）、`MYSQL_PWD=`、`REDISCLI_AUTH=`。

### D10 执行命令的程序与程序文本（安全修正）

2026-10-22 确认。威胁：agent 只能传参数值，但模板若把参数送到会把参数当命令或代码执行的位置，参数值就成了任意命令。

- 会执行命令的程序按解释器处理，未声明 `allow_interpreter` 时拒绝；`catalog validate` 按命令名检查，主机端再按解析软链接后的路径检查。
  - 整个程序：`watch`、`script`、`busybox`、`expect`、`tclsh`、`wish`、`fish`、`parallel`、`time`、`ssh`、`scp`、`rsh`、`sshpass`、`su`、`runuser`、`pkexec`、`doas`、`sg`、`setsid`、`setpriv`、`flock`、`nohup`、`chrt`、`taskset`、`numactl`、`unshare`、`prlimit`、`runcon`、`capsh`、`cgexec`、`chpst`、`systemd-run`、`machinectl`、`start-stop-daemon`、`strace`、`ltrace`、`gdb`、`git`、`psql`、`mysql`、`mariadb`、`sqlite3`。
  - 出现特定选项时：`find` 的 `-exec`/`-execdir`/`-ok`/`-okdir`；`tar` 的 `--to-command`、`--use-compress-program`/`-I`、`--info-script`/`-F`、`--new-volume-script`、`--checkpoint-action`、`--rsh-command`、`--rmt-command`（长选项含可被接受的前缀）；`rsync` 的 `-e`/`--rsh`、`--rsync-path`、`-M`/`--remote-option`；`ip` 的 `netns exec`、`-batch`。
  - 解释器列表补充 `ksh`、`mksh`、`rbash`、`csh`、`tcsh`。
  - `busybox` 只按命令名检查：主机上普通命令可能是指向 busybox 的软链接。
- 声明 `allow_interpreter` 时，程序文本仍由签名固定。对包装命令展开后的解释器命令：
  - 占位符不能出现在解释器选项、选项值或程序文本位置（如 `bash -c {x}`、`bash {x}`、`python3 -c {x}`、`python3 -m {x}`、`perl -e {x}`、`awk {x}`、`sed -e {x}`）。
  - 程序文本之后的占位符不能紧跟以 `-` 开头的选项，参数类型也不能渲染出以 `-` 开头的值（enum 含 `-` 开头的值、int 未设 `min >= 0` 时拒绝）。
  - 有占位符时，程序文本之前出现未知选项一律拒绝，因为未知选项可能取下一个词作值。
  - 允许的写法：`["/bin/bash", "-c", "固定脚本", "_", "{x}"]`、`["/usr/bin/python3", "-c", "固定代码", "{x}"]`、`["/usr/bin/perl", "-e", "固定代码", "--", "{x}"]`。
  - 上述会执行命令的程序在 `allow_interpreter` 下也不能带占位符。
- 不覆盖：签名脚本内部的 `eval "$1"` 等写法、名单以外的程序、`docker run`/`kubectl run`。这些依赖目录评审。

### 内置处理器的执行位置

- 声明 `run_as` 或需要读取主机凭据的内置处理器在 allowops-exec 中执行；其余在 allowops-agent 中执行。
- 内置处理器的参数 schema 由 allowops 定义，目录只能通过 `builtin_config` 收紧范围。

## 21. 实施期间确认的行为（A7~A28）

2026-10-13 实施期间由 worker 提出、负责人答复。编号与计划库（beads）中的待答复条目一致。

| 编号 | 问题 | 决定 |
|---|---|---|
| A7 | 默认角色是否带 action 执行权限 | admin 默认可在所有有授权标签的主机上执行全部 action（含 dangerous），无授权标签的主机仍一律拒绝；operator、auditor、viewer、publisher 默认不带执行权限，需另加规则 |
| A8 | LDAP 登录限流 | 每个“用户名 + 来源 IP”5 分钟内最多 5 次失败，登录成功后清零；阈值可配置 |
| A9 | 执行中主机与网关断线 | 主机终止该 task 的进程组，task 标记 `offline`，不重放、不补传；已发生的副作用不保证撤销 |
| A10 | CSV 导入和批量设标签 | 预览 10 分钟有效，目标变化需重新预览；全部原子提交；显式 set/remove；selector 只支持逗号分隔的 `key=value`（全部满足） |
| A11 | 策略与多目录 | 策略按结构化规则保存，`base_version` 乐观并发；多个目录的 action 名全局唯一，发布冲突时拒绝 |
| A12 | 用户角色与 CLI 会话 | 组映射可在控制台修改并存数据库；手工角色与映射角色取并集；用户可列出、吊销自己的 CLI 会话，admin 可吊销任何人的 |
| A13 | 组合 action 输出 | `max_output` 为所有步骤 stdout+stderr 的总预算；最终退出码取首个失败步骤的退出码，否则 0；过滤分别作用于每个步骤的 stdout |
| A14 | 默认时长 | 主机证书 24 小时、单次 join token 24 小时、CSV 预览 10 分钟、目录上传暂存 1 小时；均可配置 |
| A15 | 内置处理器默认上限 | 超时 10 秒；log_search 50 个文件、扫描 256MiB、1000 条匹配、上下文最多 20 行；Redis SCAN COUNT 上限 1000；http_get 响应 64KiB；目录可用 `builtin_config` 收紧 |
| A16 | 内置处理器退出码 | log_search 无匹配、http_get 非 2xx 返回 0（状态码单独给出）；执行错误返回 1；资源上限截断返回 0 并标 `truncated` |
| A17 | 过滤参数组合 | `tail`、`head`、`count` 互斥，同时传入返回参数错误；`match`、`exclude` 可与其中之一组合；`max_scan` 按每个步骤 stdout 原始字节计 |
| A18 | 多实例审计导出 | 网关配置指定一个实例负责导出，其导出目录使用持久卷；文件和目录 fsync 成功后才推进数据库游标；该实例故障期间导出暂停，恢复后续传 |
| A19 | 审计保留删除 | 删除旧分区前在数据库保存边界 seq/hash 即可删除；校验结果注明只证明数据库内部一致；可配置为“必须有外部检查点才删除” |
| A20 | 控制台会话 | 默认 7 天，可配置 |
| A21 | job 的查看和取消权限 | 服务账号只能查看和取消自己发起的 job；控制台用户查看 job 需 `view_jobs`；取消需对 job 的全部主机重新判定原 action 的执行权限；查看输出另需 `view_output` |
| A22 | `max_failures` 计数 | 计入 `failed`、`timeout`、`unsupported`，不计 `offline` |
| A23 | job 汇总的输出预览 | task 表保存每个输出（stdout、stderr）的前 4KB；完整输出从对象存储读取 |
| A24 | MCP SDK 间接依赖的 MIT-0 许可证 | 固定 `segmentio/asm` v1.1.3（MIT）；许可证白名单不变 |
| A25 | 快速开始的对象存储 | MinIO 官方镜像已无法公开拉取，改用 SeaweedFS 公开镜像（Apache-2.0，S3 兼容） |
| A26 | 新增 `view_system`（系统页） | 默认给 admin 和 operator |
| A27 | `hosts_search` 无查询条件 | 允许，分页列出调用者可查看的全部主机，返回总数和标签分布 |
| A28 | 快速开始的身份源 | 带演示用 LDAPS 容器（账号密码在本机生成，仅用于演示） |
| A29 | 项目内对象存储 | 不再使用 MinIO；集成测试、快速开始、示例和文档统一改用 SeaweedFS；网关仍只依赖 S3 API，使用方可接任何 S3 兼容服务 |
| A35 | 身份源数量与登录入口 | 最多一个 LDAP 身份源；多个 LDAP 配置在网关启动时拒绝，登录页使用单一 LDAP 表单；OIDC 可配置多个，每个身份源一个按钮 |
| A37 | 本地测试环境（2026-10-14 补入 MVP） | Docker Compose 常驻环境：控制台和 API 只绑定 127.0.0.1；包含网关、PostgreSQL、SeaweedFS、演示用 LDAPS 和 3 台演示主机容器；一条命令启动、一条命令停止，数据卷保留；可用浏览器、CLI、MCP 客户端连接 |
| A40 | 控制台视觉风格（2026-10-20） | 控制台前端重写（UI2）：shadcn/ui Nova 样式（radix-nova）+ neutral 默认主题，不再使用 magpie 色值（A39 作废）；图标 Lucide、动画 Motion、分栏 react-resizable-panels、拖拽 dnd-kit、客户端状态 Zustand；每类能力只用一个库 |
| A41 | 前端重写与发布顺序 | UI2 及其验证 V-UI2 完成后才进行 V-MVP 和 REL-MVP |
| A58 | 项目许可（2026-10-21） | 改为 MIT，版权人 liubing；不再使用 PolyForm 二选一与商业许可（A36 作废） |

总指挥在实施中按规则自行决定的实现细节（G7~G18）记录在计划库，不改变上表和 design.md 的行为。
