# allowops 设计

状态：架构已确认（2026-10-13）；实施期间确认的行为见决定记录第 21 节。决定的依据、被否决的方案和讨论过程见 `architecture-decisions.md`（下文简称“决定记录”）。

## 1. 定位

allowops 是给 AI agent 使用的运维网关：agent 通过 MCP 调用运维人员预先定义并签名的动作（action），在上千台服务器上执行。

核心原则：**No shell. Only actions you defined.**

- agent 不能执行任意命令，只能调用签名目录中的 action，并传入经过类型校验的参数。
- allowops 不解析、不执行 shell 语法。这一点与“受限 shell”类项目（如 bornholm/leash）不同。
- 架构参考 Teleport（反向连接、单端口 ALPN、join token 加短期证书），不复制其 AGPL 代码。

## 2. 架构

图示见 [architecture-diagram.html](architecture-diagram.html)（浏览器打开；截图 [architecture-diagram.png](architecture-diagram.png)），包括部署总览、主机长连接、一次命令的执行时序、审计和示例目录中的 action。

```
 AI agent ──MCP Streamable HTTP──▶ ┌──────────── allowops-gateway ─────────────┐ ◀── 浏览器（控制台）
 运维人员 ──allowops CLI─────────▶ │ 认证 → 目录 → 参数校验 → 选主机 → ABAC      │
 CI ───────目录发布──────────────▶ │ → 分批调度 → 结果聚合 → 审计               │
                                   │ PostgreSQL        S3 兼容对象存储          │
                                   └───────────────▲────────────────────────────┘
                                                   │ gRPC 双向流 + mTLS（主机主动连接，443 端口）
                          ┌────────────────────────┴───────────┐
                    allowops-agent（低权限用户）            ...（上千台）
                          │ sudo -n（仅 run_as 的 action）
                    allowops-exec（root）：验签 → 校验 → 脱敏 → 切换用户执行
```

- 网关不主动连接任何主机。主机离线时任务标记 `offline`，不排队。
- 网关对外只开 443 端口，按 TLS ALPN 区分主机连接、MCP、控制台 API。负载均衡必须为 L4 TCP 透传。
- 网关除主机长连接外无实例级状态，可水平扩容。主机连接所在实例记录在 PostgreSQL，用 LISTEN/NOTIFY 通知该实例下发任务。
- MVP 不做区域中继；主机端配置项为“上游地址”，为以后增加中继保留。

### 组件

| 组件 | 职责 |
|---|---|
| allowops-gateway | MCP、控制台和 CLI API、主机注册表、ABAC 判定、job 调度、结果聚合、审计、目录分发；内嵌 Web 控制台 |
| allowops-agent | systemd 服务，以 `allowops` 用户运行；注册、连接网关、同步并验签目录、执行任务 |
| allowops-exec | root 辅助程序，经 sudo 调用；验签目录、校验参数、切换到 `run_as` 用户执行 |
| allowops CLI | 目录校验、构建、签名、发布、试运行；运维人员操作网关 |
| Web 控制台 | 主机、目录、策略、服务账号、job、审计、用户与角色 |

## 3. 技术选型

| 部分 | 选型 |
|---|---|
| 后端、主机端、CLI | Go（go.mod 1.27.3）；YAML `gopkg.in/yaml.v3`；CLI `cobra` |
| 主机与网关 | gRPC 双向流 + mTLS；Protobuf + buf；connect-go |
| MCP | 官方 `github.com/modelcontextprotocol/go-sdk`，Streamable HTTP，无状态模式 |
| 控制台 API | Connect（protobuf），生成 TypeScript 客户端 |
| 数据库 | 只支持 PostgreSQL；pgx + sqlc + goose |
| 对象存储 | S3 兼容 API（OSS、SeaweedFS、Ceph RGW、S3）；`aws-sdk-go-v2`；开发、测试和快速开始使用 SeaweedFS，不使用 MinIO |
| 策略引擎 | OPA 嵌入网关（`github.com/open-policy-agent/opa/v1/rego`） |
| 登录 | 通用 OIDC（`coreos/go-oidc`）+ LDAP（`go-ldap/ldap`） |
| 前端 | React + TypeScript + Vite；组件 shadcn/ui（radix-nova 样式、neutral 默认主题，组件源码在仓库内）；图标 Lucide；动画 Motion；可调分栏 react-resizable-panels；拖拽 dnd-kit；客户端状态 Zustand，服务端状态 TanStack Query；表格 TanStack Table；表单 React Hook Form + Zod；中英文 i18n；每类能力只用上述一个库，已有 shadcn/ui 组件时复用；`go:embed` 进网关 |
| 日志和指标 | `log/slog`、Prometheus |
| 打包和发布 | goreleaser + nfpm |
| 文档站 | VitePress，发布到 GitHub Pages |

模块路径：`github.com/liubing0806/allowops`。

## 4. action 目录

### 目录仓库

```
catalog.yaml                         # catalog_id、schema_version、默认值、全局脱敏规则
actions/<action_name>.yaml           # 一个 action 一个文件
```

CI 流程：`allowops catalog validate` → `build` → `sign` → `publish`。目录合入主分支必须经过评审；签名私钥存在 CI 凭证库，只给受保护分支的发布流水线使用。

目录包内容：`schema_version`、`catalog_id`、`version`（UTC `YYYYMMDDHHMMSS` 整数，单调递增）、`created_at`、`expires_at`（默认签名后 90 天）、`git_commit`、全部 action 及各自的 SHA-256 摘要。

### action 格式

```yaml
name: journal_view_log                 # ^[a-z][a-z0-9_]{0,63}$，建议 <对象>_<动作>，不得与 MCP 固定工具重名
description: "查看服务日志末尾若干行"     # 必填
risk: read                             # read | write | dangerous，ABAC 资源属性
idempotent: false                      # 可选，生成 idempotentHint
run_as: root                           # 可选；省略时以 allowops 用户直接执行
params:
  service: { type: enum, values: [nginx, api], description: "服务名" }
  lines:   { type: int, min: 1, max: 500, default: 100, description: "行数" }
  since:   { type: string, regex: '^[0-9]+ (min|hour) ago$', max_len: 16, optional: true, description: "起始时间" }
exec: ["/usr/bin/journalctl", "-u", "{service}", "-n", "{lines}", "--no-pager", ["--since", "{since}"]]
timeout: 10s
max_output: 64KB
batch_size: 20                         # 可选，MCP 调用只能更严格
max_failures: 5                        # 可选
redact:                                # 可选，覆盖全局脱敏规则
  builtin: [secrets]
```

参数类型：

| 类型 | 字段 |
|---|---|
| enum | values |
| int | min、max |
| string | regex、max_len |
| duration | max；format: `go`（默认）或 `seconds` |
| path | allowed_roots（必填） |

通用字段：`description`（必填）、`default`、`optional`。

### 格式规则

1. 可选参数：exec 元素可写成子列表，如 `["--since", "{since}"]`；子列表中任一占位符未提供时整个子列表省略。
2. 只有完整等于 `{参数名}` 的 argv 元素是占位符；其他元素（如 `"{{json .}}"`）按字面值传递。
3. duration 渲染：`format: seconds | go`，默认 `go`（如 `1h0m0s`）。
4. 解释器覆盖：单个 action 写 `allow_interpreter: true`，`catalog validate` 和主机端加载时打印警告，只对该 action 生效。
5. path 参数要求路径已存在（`filepath.EvalSymlinks` 需要）。
6. 以 `-` 开头的值：string 和 path 类型拒绝；int 按数值校验后格式化，负数是否允许由 min 决定。
7. `max_output` 的 KB、MB 按 1024 进制解释。
8. exec[0] 必须是绝对路径；exec 中不允许出现 `sudo`，提权只能用 `run_as`。
9. 主机上不存在 exec[0]、exec[0] 是 `#!` 脚本且未声明 `allow_interpreter`、或用到主机端不支持的功能时，该 action 在该主机标记 `unsupported`。
10. 执行方式四选一：`exec`、`steps`、`script`、`builtin`（见下文“扩展执行能力”）。

### 扩展执行能力

依据实际使用统计；细节见决定记录第 20 节。

| 能力 | 写法 | 说明 |
|---|---|---|
| 输出过滤 | `filters: [match, exclude, tail, head, count]` | agent 可传过滤参数；`tail`、`head`、`count` 互斥；主机端按“stdout → 脱敏 → 过滤 → 截断”逐行处理；扫描上限 `max_scan` 默认 256MB |
| 组合 action | `steps: [{name, exec}]`、`on_error: continue\|stop` | 多条固定命令顺序执行，结果分段 |
| 候选路径 | `exec_fallbacks: [...]` | exec[0] 不存在时依次尝试，均须为绝对路径 |
| 签名脚本 | `script: {file, interpreter}`、`args` | 脚本随目录签名，摘要计入 action 摘要；写入私有临时目录执行后删除；Python 加 `-I`；只在主机上执行 |
| 日志检索 | `builtin: log_search` | Go 实现，支持 `.gz`、路径通配（限 allowed_roots）、固定串或正则、排除、上下文、最大匹配数 |
| MySQL 只读查询 | `builtin: mysql_query` | 凭据在主机 `/etc/allowops/credentials/`（root，0600）；只允许单条 SELECT/SHOW/DESC/EXPLAIN；只读事务；行数和超时限制 |
| Redis 只读命令 | `builtin: redis_command` | 只允许 GET、MGET、HGET、HLEN、TTL、TYPE、EXISTS、STRLEN、LLEN、SCARD、ZCARD、SCAN、INFO |
| HTTP 探测 | `builtin: http_get`，参数类型 `url`（`allowed_prefixes` 必填） | 只发 GET，不跟随跳转，响应大小上限 |
| Prometheus 只读查询 | `builtin: prometheus_query`，`builtin_config.api` 固定 query、query_range、series、labels、label_values、alerts、rules、targets 之一 | 只发 GET，不跟随跳转；可选凭据（bearer_token，或 username 与 password）在主机 `/etc/allowops/credentials/`（root，0600），配置凭据的 action 须声明 `run_as: root`；时间范围、步长、点数、序列数和响应大小受限；输出 TSV |

- 内置处理器的参数 schema 由 allowops 定义，目录只能通过 `builtin_config` 收紧。需要读取主机凭据或声明 `run_as` 的内置处理器在 allowops-exec 中执行。

## 5. 主机端

### 执行

- allowops-agent 以低权限用户 `allowops` 运行，不加 systemd-journal、docker 等额外组。
- 未声明 `run_as` 的 action 由 allowops-agent 直接执行。
- 声明 `run_as` 的 action 经 sudo 调用 allowops-exec。sudoers 内容固定，随安装包分发：

```
# /etc/sudoers.d/allowops
Defaults:allowops !requiretty
allowops ALL=(root) NOPASSWD: /usr/libexec/allowops/allowops-exec ""
```

- allowops-exec 从 stdin 读取 `{action, params, catalog_version}`；以 root 读取目录包（只打开一次、在内存中验签），检查版本未回退、目录未过期，校验参数，脱敏，切换到 `run_as` 用户执行。忽略环境变量，状态目录不跟随软链接。
- systemd unit 不使用会影响子进程的沙箱选项（`NoNewPrivileges=yes` 会使 sudo 无法提权）。

### 安全要求（每条都要有测试）

1. 只用 `exec.Command(argv...)`，任何地方不出现 `sh -c` / `bash -c`。
2. 占位符只作为完整 argv 元素替换，不做字符串内插。
3. 拒绝以 `-` 开头的字符串参数值（防参数注入）。
4. path 类型：`filepath.EvalSymlinks` 后检查是否在 allowed_roots 内，防 `../` 和软链接逃逸。执行前再逐分量检查属主和写权限（`PATH_NOT_TRUSTED`），见 `docs/action-catalog-requirements.md` 第 4 节第 8 项。
5. 执行环境清空，只保留 `PATH=/usr/sbin:/usr/bin:/sbin:/bin`、`LANG=C.UTF-8`、`PAGER=cat`、`SYSTEMD_PAGER=`。
6. 每个动作都有超时（context），超时后结束整个进程组。
7. 输出超过 max_output 时截断，结果中 `truncated: true`。脱敏在截断前执行。
8. exec[0] 必须是绝对路径；拒绝 sh/bash/zsh/python/perl/awk/sed 等解释器和 `#!` 脚本（`allow_interpreter: true` 可覆盖并打印警告）。包装命令（`docker exec`、`kubectl exec --`、`nsenter`、`chroot`、`env`、`timeout`、`nice`、`ionice`、`stdbuf`、`xargs`）后真正执行的命令同样检查；禁止 `docker exec -t`、`kubectl exec -t`。会执行命令的程序（`watch`、`ssh`、`su`、`setsid`、`git`、`psql`、`find -exec`、`tar --to-command` 等）按解释器处理；声明 `allow_interpreter` 时，占位符仍不能提供解释器选项、程序文本或这类程序的参数。名单和规则见决定记录 D10。
9. 未知参数、缺失必填参数、类型错误一律拒绝，错误信息给出合法值。

攻击测试集：`; rm -rf /`、`$(id)`、`` `id` ``、`--output=/etc/passwd`、`../../etc/shadow`、软链接逃逸、超长字符串、换行符注入等，全部被拒绝或被当作普通字面量；另加第 11 节威胁模型列出的测试。

### 签名与信任

- 签名格式：DSSE 信封 + ed25519（Go 标准库），一个目录包可带多个签名。
- 信任锚：`/etc/allowops/catalog-keys/`（属主 root），由运维人员分发。网关也验签一次以提前发现错误。
- 防回退：allowops-exec 在 `/var/lib/allowops-exec/`（属主 root）记录最高版本号；allowops-agent 同样检查。
- 过期：默认 90 天，到期前 14 天告警，过期后拒绝执行。生效时间允许 5 分钟时钟偏差。
- 轮换：分发新公钥 → 新旧私钥同时签名 → 移除旧公钥。私钥泄露时从主机信任列表删除公钥；网关不能吊销或添加密钥。
- 下发：主机连接或收到通知时拉取新目录包，验签后保存并报告版本。task 附带 action 摘要，与本地不一致时标记 `unsupported`。

### 输出脱敏

- 主机端在输出离开主机前脱敏，规则来自签名目录（全局 + action 覆盖）。不保留原始输出。
- 内置规则：
  - `secrets`（默认开启）：PEM 私钥、阿里云 AccessKey、AWS Access Key、JWT、`Authorization: Bearer`、URL 中的用户名密码、`password=`/`secret=`/`token=` 等键值对、mysql 命令行 `-p<密码>`、`MYSQL_PWD=`、`REDISCLI_AUTH=`。
  - `pii`（默认关闭）：手机号、18 位身份证号（校验码）、银行卡号（Luhn）。
- 自定义规则：`redact.custom: [{name, regex}]`，Go RE2。替换为 `[REDACTED:类型]`。可选字段 `before_builtin`（bool，默认 false）：为 true 时该规则在内置规则之前运行（多个此类规则保持配置顺序），其余自定义规则仍在内置规则之后；用于整体替换引号字符串的规则。
- 文档写明局限：可能误伤；不能识别所有敏感内容。

### 主机身份与标签

- 注册：`allowops-agent join --upstream <addr> --token <join token> --ca-pin sha256:<指纹>`，换取网关内部 CA 签发的短期证书（如 24 小时），到期前自动续期。
- join token 可单次或多次使用；多次使用时必须设有效期（默认 24 小时）和最大次数。
- 主机名全局唯一，同名注册被拒绝。新主机无授权标签，默认全部拒绝。
- 标签：授权标签只在网关端设置（控制台、CLI、CSV 导入），策略只按授权标签判定；主机上报标签（系统、内核等）只用于展示和筛选。
- 主机连接时上报支持的目录格式版本和参数类型。

## 6. 权限与身份

### ABAC

| 类别 | 对象 |
|---|---|
| 主体 | 服务账号、控制台用户（角色、团队、负责人） |
| 资源 | 主机（授权标签）、action（risk、名称） |
| 操作 | 执行 action；控制台操作：修改策略、管理服务账号和 token、管理主机和标签、创建 join token、管理用户角色、发布目录、查看 job、查看输出、查看审计 |
| 环境 | 请求时间、来源 IP |

- 判定结果 `allow`、`deny`；deny 优先；未匹配任何规则时 deny。MVP 不做审批。
- OPA 嵌入网关：规则数据存 PostgreSQL（控制台表单编辑或 `allowops policy apply`），固定 Rego 程序（`go:embed`）判定。Rego 草稿见决定记录第 5 节。
- 求值出错按 deny；时间取自 input，不调用 `time.now_ns()`；用 capabilities 禁用 `http.send`、`opa.runtime` 等内置函数。
- 规则保存前对现有主机试算并显示变化；保存后若没有主体能修改策略则拒绝保存。
- 网关首次启动生成默认规则，权限等同 admin、operator、auditor、viewer、publisher 五个角色（定义见决定记录第 12 节）。admin 默认可在所有有授权标签的主机上执行全部 action，其余四个角色默认不带执行权限（决定记录第 21 节 A7）。
- 恢复途径：配置文件中的 `bootstrap_admins` 始终拥有修改策略的权限。

### 账号

- 控制台用户：通用 OIDC 和 LDAP（只允许 LDAPS 或 StartTLS、过滤条件转义、登录限流（每个“用户名 + 来源 IP”5 分钟内 5 次失败，成功后清零）、不保存密码）。角色由 OIDC `groups` 或 LDAP 组按 `role_mappings` 映射，或手工指定。
- 身份源数量：最多一个 LDAP 身份源，可以配置多个 OIDC 身份源；多个 LDAP 配置在启动时拒绝（决定记录第 21 节 A35）。
- 服务账号：名称、负责人、描述、策略角色。token 为 `aops_` 前缀 + 32 字节随机数，只显示一次，存 SHA-256；默认有效期 30 天（可选 1~365 天），到期前 7 天提醒；一个账号可有多个 token；记录最后使用时间；可吊销。
- CLI 会话：`allowops login`（OIDC 本机回环回调，或 LDAP 密码经 TLS 发给网关），网关签发会话 token，默认有效 7 天，保存在 `~/.config/allowops/credentials`（0600）。

## 7. MCP

### 工具

| 工具 | 作用 |
|---|---|
| `hosts_search` | 按标签选择器或主机名查询主机：主机、标签、在线状态、总数、标签分布 |
| `<action>` | 每个 action 一个工具，只列出该身份可能被允许的 action |
| `jobs_get` | job 汇总；传 `host` 时分页返回该主机完整输出；支持 `wait_seconds` |
| `jobs_list` | 当前服务账号最近的 job |
| `jobs_cancel` | 取消 job |

- action 工具公共参数：`targets`（`hosts` 或 `selector`）、`expected_count`、`reason`、`wait_seconds`、`batch_size`、`max_failures`、`response_format`。
- 用 `selector` 时必须带 `expected_count`，与实际数量不符时拒绝并返回实际数量。
- 任一主机被 deny 时整个 job 拒绝，返回被拒主机和规则。
- 工具注解：read → `readOnlyHint: true`；write → `destructiveHint: false`；dangerous → `destructiveHint: true`。
- 参数错误返回 `isError: true` 并给出合法值。
- 返回给 agent 的主机标识为主机名；job ID 为短格式（如 `job-20261013-0042`）。
- 返回中用 `"output_trust": "untrusted"` 标明 stdout、stderr 为不可信主机数据，工具描述中写明同样说明。

### 执行流程和状态

```
参数校验 → 解析 targets、核对 expected_count → 逐台 ABAC 判定（任一 deny 则拒绝）
→ 分批下发；失败数超过 max_failures 时停止，剩余主机 skipped
→ wait_seconds 内完成返回汇总，否则返回 job_id 和进度
```

- job 状态：`queued`、`running`、`succeeded`、`partially_failed`、`failed`、`cancelled`、`denied`。
- task 状态：`pending`、`running`、`succeeded`、`failed`、`timeout`、`offline`、`skipped`、`cancelled`、`unsupported`。
- 返回结果按退出码和输出哈希完全相同合并为组，示例见决定记录第 7 节。

### 默认值（可在网关配置中修改）

| 项 | 默认值 |
|---|---|
| `wait_seconds` | 默认 30，最大 120 |
| 单次返回上限 | 32KB |
| 每组输出 | 前 4KB |
| `response_format` | `concise` |
| `batch_size` / `max_failures` | 20 / 5 |
| `reason` | 必填 |
| 每个服务账号并发 job | 5 |

### 无状态

- go-sdk `StreamableHTTPOptions.Stateless`；每个请求用 Bearer token 识别身份，按“身份 + 目录版本 + 策略版本”缓存工具列表。
- 响应用 SSE，长轮询期间每 10 秒发进度通知。
- 不能推送 `tools/list_changed`；目录或策略更新后客户端下次获取工具列表时生效。

## 8. 数据存储

- PostgreSQL：主机、身份、目录版本、策略版本、job、task、审计。task 表和审计表按月分区。
- 心跳只在网关内存更新；连接、断开时写库，另每 5 分钟写 `last_seen`。
- 审计：默认保留 1 年；网关数据库账号对审计表只有 INSERT 和 SELECT；哈希链（`seq`、`prev_hash`、`hash`）；不存输出内容，存输出对象路径和 SHA-256。
- 审计导出：JSON Lines 文件（按大小轮转，由日志采集工具转发）；游标保证至少一次送达；多实例用 advisory lock 只由一个实例导出；每 5 分钟写检查点事件。CLI：`allowops audit export`、`allowops audit verify`。
- 命令输出：对象存储，路径 `outputs/{yyyy}/{mm}/{dd}/{job_id}/{host}.{stdout|stderr}.zst`；默认保留 1 年（bucket 生命周期规则）；控制台读取经网关转发并按 ABAC 判定和审计；先返回调用方再异步写入，失败时标记 `output_stored=false` 并告警。
- CA 私钥存网关主机文件（0600），不存数据库。
- 对象存储选型：网关只依赖 S3 API，使用方可接任何 S3 兼容服务。项目自身的集成测试（testcontainers）、Docker Compose 快速开始和示例统一使用 SeaweedFS（Apache-2.0，S3 网关模式），不使用 MinIO（MinIO 官方镜像已无法公开拉取；决定记录第 21 节 A25、A29）。SeaweedFS 对 bucket 生命周期规则和 `aws-sdk-go-v2` 请求校验和的支持须在集成测试中实测，不支持时在文档中写明替代做法。

## 9. 控制台与 CLI

### 控制台页面

登录、概览（含网关新版本提醒）、主机（筛选、详情、selector 批量设标签、CSV 导入并预览、删除）、join token、目录（版本、过期倒计时、action 详情、历史、版本分布）、策略（表单、试算、历史、回滚）、服务账号、job（详情、输出、取消）、审计（查询、哈希链校验）、用户与角色、系统（实例和依赖健康、主机端版本分布、实例版本不一致提示、低于网关版本的主机数）。侧栏产品名下方显示网关版本号（来自 `GetCurrentSession` 的 `gateway_version`），有新版本时旁边显示标记。界面中英文。

### CLI

```
allowops login
allowops catalog keygen|validate|build|sign|publish|try
allowops actions list|describe <action>
allowops run <action> --selector env=prod --expected-count 12 --param k=v --reason "..."
allowops jobs list|get|output|cancel
allowops hosts list|label|delete
allowops jointoken create --uses 500 --ttl 24h
allowops policy get|apply -f rules.yaml|test
allowops audit export|verify
allowops-gateway serve|migrate
allowops-agent join|run|status
```

- 输出默认表格，`--json` 输出 JSON。
- `allowops run` 与 MCP 走同一流程。
- `allowops catalog try` 在当前主机以当前用户执行未签名的 action，只用于发布前验证，输出：

```json
{"ok": true, "action": "journal_view_log", "exit_code": 0, "duration_ms": 42, "stdout": "...", "stderr": "", "truncated": false}
```

## 10. 发布与部署

- 四个二进制同一 SemVer 版本，从同一 Git tag 发布。网关支持当前和上一主版本的主机端；主机端比网关新时拒绝连接。
- 主机端：仅 amd64；`.deb`、`.rpm`、`.tar.gz`；`CGO_ENABLED=0`。支持 CentOS 7 / RHEL 7、Rocky/Alma/RHEL 8+、Ubuntu 20.04+、Debian 11+。rpm 不用弱依赖、不用 zstd 压缩，用 RSA 4096 GPG 签名；unit 只用 systemd 219 支持的选项。
- 主机端在线升级：签名目录中的升级 action（`run_as: root`、`risk: dangerous`），用 yum/apt 从内网软件源安装指定版本，再用 `systemd-run --on-active=5 --timer-property=AccuracySec=1s` 重启 `allowops-agent.service`，task 结果先回传。版本参数为 enum，只列出不高于当前网关的版本；先升级网关，再发布含新版本的目录。灰度用 job 主机选择器分批执行。软件源和包签名由运维人员维护。示例为 `examples/catalog` 的 `agent_upgrade`，不支持降级。依据见决定记录第 8 节。
- 网关新版本提醒：网关读取发布清单（发布流水线从 Git tag 生成的静态 JSON，发布到文档站），发现新版本后在控制台提醒，不下载、不安装。配置 `update_check.enabled`（默认 `false`）和 `update_check.url`（默认文档站地址，内网可改为内部地址）。开启后每 24 小时检查一次并加随机延迟，请求只带 `User-Agent: allowops-gateway/<版本>`。多实例用 advisory lock 只由一个实例请求，结果写入单行表供所有实例读取。清单只含 `version` 和 `published_at`；版本号须为严格 SemVer，发布说明链接由控制台按版本号拼成。依据见决定记录第 8 节。
- 主机端文件布局：

```
/usr/bin/allowops-agent
/usr/libexec/allowops/allowops-exec   # root，0755
/usr/lib/systemd/system/allowops-agent.service
/etc/sudoers.d/allowops               # 0440
/etc/allowops/agent.yaml              # 上游地址、CA 指纹、上报标签
/etc/allowops/catalog-keys/           # 目录签名公钥，root
/var/lib/allowops/                    # 证书、私钥、目录缓存，allowops，0700
/var/lib/allowops-exec/               # 最高目录版本号，root，0700
```

- 网关：容器镜像（仅 amd64）、Helm chart（OCI）、Docker Compose。官方支持 Kubernetes 和 Docker Compose。`allowops-gateway migrate` 单独执行（Helm 升级前钩子），迁移先扩展后收缩；SIGTERM 时停止接收新任务、等待执行中任务、通知主机重连（带随机抖动退避）。PostgreSQL 和对象存储由使用方提供并备份。
- 发布物附 `checksums.txt` 及签名、SBOM、`THIRD_PARTY_NOTICES`。

## 11. 安全

威胁模型 T1~T15（agent 失控和提示注入、token 被盗、网关被攻破、CI 或签名私钥被攻破、主机被攻破、主机端进程被攻破、allowops-exec 漏洞、中间人和 join token 泄露、控制台 XSS/CSRF、参数注入、时钟偏差、资源耗尽、审计篡改、供应链、LDAP 攻击）及对应措施和测试见决定记录第 11 节，作为 SECURITY.md 的依据。

残余风险（文档写明）：

- 网关被攻破时可在所有主机上调用全部已签名 action。
- CI 或签名私钥被攻破时可签发任意命令。
- 返回给模型的输出对 AI 模型服务商可见；提示注入不能完全防止。

不在防护范围内：恶意的 PostgreSQL 或对象存储管理员；安装前已被攻破的主机。

## 12. 测试

- 每次提交：Go 单元测试（`-race`）、`opa test`、攻击测试、模糊测试（每目标 30 秒）、testcontainers 集成测试（含 MCP 端到端）、前端 ESLint/tsc/Vitest/翻译 key 检查、`go vet`、staticcheck、`govulncheck`、许可证检查（只允许 MIT、BSD、Apache-2.0、ISC、MPL-2.0）。
- 每晚和发布前：Playwright 端到端、规模测试、OPA 基准、长时间模糊测试（每目标 10 分钟）。
- 虚拟机矩阵（CentOS 7、Rocky 8、Rocky 9、Ubuntu 20.04、Ubuntu 24.04、Debian 12）：开发者本机，发布前手工运行。
- 规模通过标准：单实例 5000 台主机连接；1000 台主机空操作 job 10 秒内完成下发和汇总；实例重启后 60 秒内全部重连。

## 13. 示例与文档

- `examples/catalog/`：通用示例 action。初版 19 个只读 action 见决定记录第 18 节；按实际使用补充的清单由节点 A1 整理成 `docs/action-catalog-requirements.md` 和示例规格。示例只用通用名称和路径；公司自己的目录放在单独的私有仓库，allowops 可用后再建。另有示例策略和目录发布流水线示例（云效 Flow、Jenkins、GitHub Actions）。
- 快速开始：Docker Compose（网关、PostgreSQL、SeaweedFS、演示用 LDAPS、演示主机容器；决定记录第 21 节 A25、A28）。
- 本地测试环境：Docker Compose 常驻运行，控制台和 API 只绑定 127.0.0.1，3 台演示主机容器，可用浏览器、CLI、MCP 客户端连接（决定记录第 21 节 A37）。
- README.md（英文）和 README.zh-CN.md；其他文档英文，VitePress 文档站。
- SECURITY.md（GitHub private vulnerability reporting、威胁模型）；CONTRIBUTING.md（只接受 issue 和建议）。

## 14. 许可

- MIT 许可，LICENSE 为标准 MIT 原文（A58，2026-10-21，取代 A36）。
- 版权人：liubing。
- MVP 不接受外部代码。

## 15. 目录结构

```
cmd/{allowops,allowops-gateway,allowops-agent,allowops-exec}/
api/proto/allowops/v1/
gen/
internal/{catalog,params,redact,executor,agent,execd,store,cli}/
internal/gateway/{server,hostconn,mcp,api,authn,authz,job,hosts,catalogsvc,audit,output}/
web/  website/
deploy/{compose,helm/allowops,packaging}/
examples/{catalog,policy,pipelines}/
test/{attack,e2e,scale,vm}/
```

各目录职责见决定记录第 19 节。

## 16. 实施计划

一次做完 MVP，按依赖并行推进。

| 节点 | 内容 | 依赖 |
|---|---|---|
| P0 | 骨架、依赖、buf、CI 基础、前端脚手架 | — |
| P1 | params、catalog、DSSE、redact、executor；攻击和模糊测试；`catalog keygen/validate/build/sign/try` | P0 |
| P2 | proto | P0 |
| P3 | allowops-exec、allowops-agent、打包 | P1、P2 |
| P4 | 网关基础：schema、443 ALPN、CA、join token、主机注册表、连接路由、目录分发 | P1、P2 |
| P5 | OPA、OIDC、LDAP、服务账号、CLI 会话 | P4 |
| P6 | job、对象存储、MCP、CLI `run/jobs` | P3、P4、P5 |
| P7 | 审计哈希链和导出 | P4 |
| P8 | 控制台 | P2、P5、P6 |
| P9 | Helm、Compose、安装脚本 | P3、P4 |
| P10 | 规模、Playwright、OPA 基准、虚拟机矩阵脚本 | P6、P8、P9 |
| P11 | 文档、示例、流水线 | P6、P9 |
| P12 | 扩展执行能力：过滤、组合、包装命令检查、候选路径、签名脚本、内置处理器、url 类型、脱敏补充 | P1 |
| P13 | 本地测试环境：Docker Compose 常驻环境，控制台和 API 只绑定 127.0.0.1，3 台演示主机，一条命令启动和停止（决定记录第 21 节 A37） | P9 |
| A1 | action 需求文档和通用示例规格（只用去敏清单） | — |
| V | 全部 CI、虚拟机矩阵、规模通过标准 | 全部 |
| REL | `gh repo create --public` 并推送，开启 private vulnerability reporting；执行前需负责人确认 | V |

## 17. Roadmap

- [静态审阅后的后续改进计划](roadmap.md)。
- 网关实例失联后，由其他实例续跑其未下发批次（MVP 当前仅收尾，不自动重放）。
- 人工审批（`require_approval`、审批流、通知）。
- 单机模式（本地 YAML、stdio MCP）。
- 区域中继和区域自治。
- MCP OAuth 授权（以工程师身份调用，替代长期 token）。
- CMDB 同步标签。
- 审计导出到 syslog、webhook、Kafka。
- agent 评估。
- 在容器或 Pod 内执行签名脚本；按容器名自动解析数据库地址。
- 接受外部贡献（贡献流程届时另行说明）。
