# P5B 身份与权限接入

实现基线：`6982fe1e13caa11486bbccd6d0d9098a1529f563`，分支 `p5b-identity-api`。按总指挥授权 rebase 到本地 main `acb19953df4454f6b8768981d533cd5227663638`，继承 P7 `00002_audit.sql`；身份迁移顺延为 00003。

## 接入边界

`internal/gateway/api.Service` 实现 PolicyService、ServiceAccountService、UserService 和 AuthService。`server.New` 通过 `WithIdentity`、`WithAudit`、`WithMCP` 选项注入 API handler、MCP 的身份中间件和 P7 Access。P7 AuditService 使用同一认证、view_audit 拦截器和结果审计，不修改主机 ALPN、hostconn 或 catalogsvc。

P4B 的 Connect handler 应先经过 `identity.Middleware`，再通过 `identity.InterceptorFor` 按每个 RPC 指定 `RPCPermission`。未列出的 RPC 拒绝。该拦截器统一认证、Cookie CSRF、ABAC 和审计。MCP handler 使用同一个中间件和 `identity.Require`；主机标签及 action 风险属性由调用方从网关存储读取。直接使用 Require 的 Cookie 请求必须提供 Origin 和 X-CSRF-Token。来源 IP 使用 TLS 连接的远端地址，忽略转发头。主机证书不会产生用户身份。

策略和用户管理采用 P5A 常量 `modify_policy`、`manage_service_accounts`、`manage_user_roles`。协议文档中的 `manage_policy`、`manage_users`、`view_job` 与 P5A 的 `modify_policy`、`manage_user_roles`、`view_jobs` 存在命名差异。本节点按任务要求使用 P5A 已声明的操作名，未修改 proto。个人会话操作按 Q6/A12 检查自身归属；跨用户操作同时要求当前有效 admin 角色和 manage_user_roles 权限。

新迁移为 `00003_identity.sql`，原迁移未修改。角色映射首次初始化后，以数据库为权威来源。手工角色不被登录同步覆盖。每次认证加载当前用户有效角色或当前服务账号属性。所有长期 token、会话 token 和 CLI 一次性 code 只存 SHA-256。OIDC 服务端事务保存短期 nonce 和提供方 PKCE verifier。

## 配置

以下是身份配置片段。P4 已有监听地址、TLS 和主机 CA 配置仍需提供。

```yaml
identity:
  origin: https://gateway.example.invalid
  bootstrap_admins: [admin@example.invalid]
  console_ttl: 168h
  cli_ttl: 168h
  login_ttl: 10m
  code_ttl: 1m
  test_ttl: 10m
  max_test_evaluations: 100000
  page_size: 50
  max_page_size: 200
  message_bytes: 1048576
  role_mappings:
    - provider_id: company
      group: ops-admin
      roles: [admin]
providers:
  - id: company
    display_name: Company OIDC
    kind: oidc
    issuer_url: https://idp.example.invalid
    client_id: allowops
    client_secret_env: ALLOWOPS_OIDC_CLIENT_SECRET
    # ca_file: /etc/allowops/provider-ca.pem
```

LDAP 提供方使用 `kind: ldap`，配置 `url`、`start_tls`、`user_base_dn`、`group_base_dn`、可选的属性名、`bind_dn` 和 `bind_password_env`。只允许 LDAPS 或 StartTLS。可选 `rate_limit.attempts/window` 沿用 P5A 限流。提供方密码和 client secret 从进程环境读取，不写入登录方法响应、错误详情或审计事件。

A35：`providers` 最多包含一个 `kind: ldap` 条目；多个 LDAP 条目会使网关启动报错，错误信息为 `only one LDAP identity source is supported`。OIDC 提供方可以有多个；控制台为每个 OIDC 提供方显示一个登录按钮，LDAP 使用单一表单。

At most one LDAP identity source is supported in `providers`. Multiple LDAP entries cause gateway startup to fail with `only one LDAP identity source is supported`. Multiple OIDC providers are allowed; the console presents one button per OIDC provider and a single LDAP form.

A20 已确定控制台默认时长为 7 天。`identity.console_ttl` 可覆盖该默认值。

## 登录与 CLI

OIDC 回调固定为 `<identity.origin>/auth/oidc/callback`。BeginOidcLogin 返回网关 start URL。浏览器访问 start 时原子绑定 HttpOnly、Secure、SameSite=Strict 的事务 Cookie，再跳转提供方。回调把 code/state 放入同源完成页的 fragment。完成页清除 fragment，再同源 POST CompleteOidcLogin，使 Strict Cookie 可参与浏览器绑定检查。已登录或已吊销的旧会话 Cookie 不阻止重新登录；公共登录入口仍校验 Origin、state、nonce 和事务 Cookie。

提供方授权码由网关兑换，网关也使用 S256 PKCE。CLI 的回环 URI 只允许回环 IP、明确端口和 `/callback` 路径。回环只收到一次性 code/state。ExchangeCliSession 检查 CLI 自己的 verifier，在事务内原子消费 code 并签发 CLI 会话。无效 nonce、state、浏览器绑定、过期 code、重复消费和错误 PKCE 均拒绝。

```sh
allowops login --gateway https://gateway.example.invalid --provider company
allowops login --gateway https://gateway.example.invalid --provider directory --username alice
allowops policy get > rules.yaml
allowops policy apply -f rules.yaml --reason 'update policy'
allowops policy test -f rules.yaml
```

测试或无图形桌面可使用 `--no-browser`。自签测试 CA 用 `--ca-file`，不支持关闭 TLS 校验。LDAP 密码由终端隐藏输入；管道输入使用 `--password-stdin`。凭证位于用户配置目录的 `allowops/credentials`（Linux 默认 `~/.config/allowops/credentials`），经 0600 临时文件原子替换。策略 get 默认输出可用于 apply 的 YAML，`get --json` 输出版本元数据；test/apply 输出试算及保存回执。

## 策略

首次初始化保存 P5A 默认规则为版本 1。每次保存和回滚均产生更高版本。试算绑定候选规范 JSON 的 SHA-256、操作者、base_version、主机身份/授权标签、主体属性/修订号、映射修订号、当前目录摘要、bootstrap_admins 和测试环境。

G28 要求执行目标具有至少一个授权标签。共享 Require、试算和保存复核对无授权标签主机统一 deny，admin 也遵循；reported 标签不满足这一前提。试算通过现有 `PolicyDecision.error_reason = HOST_UNLABELED` 返回未标记主机的诊断；即使前后判定相同也返回诊断，`changed_count` 只统计实际判定变化。

空 cases 对当前主体、当前有效目录 action、现有主机及控制台关键操作试算。超过配置的求值次数直接拒绝，不抽样。显式 cases 从数据库解析主体、主机标签和 action 风险。目标支持授权标签及 reported 标签筛选；相互冲突的重复条件拒绝。reported 标签只参与目标筛选，规则始终匹配授权标签。变化按实际 Connect JSON 信封字节和页数分页。保存在数据库锁内重新检查快照和环境；时段改变判定时要求重新试算。候选不符、版本不符、过期/已消费试算或快照变化返回 ABORTED。防锁死调用 P5A CheckPolicyUpdate，并保留 bootstrap_admins 对修改策略的权限。

服务实例使用独立 LISTEN 连接接收 allowops_policy 通知并重建引擎。重连后重新加载；每次授权也读取当前策略版本，避免通知中断期间使用旧策略。试算和保存会编译候选引擎。保存期间持有身份、主机、目录表的 SHARE 锁以保证所检查快照到提交时不变；大规模锁等待与性能未验证。

G27 允许的 P5A 最小修复：Hours 增加 IANA timezone，空值保持旧调用方的 Asia/Shanghai 行为；actions/risks 同为空时不限制 action。deny 优先、未匹配 deny、求值错误 deny 保持原行为。仅额外导出 authn.OIDC.VerifyNonce，供网关校验已签名 ID token 的事务 nonce。

## 审计与待确认事项

P7 在本节点开始时只有占位 doc.go。rebase 后已接入 `internal/gateway/audit.Appender.Append(context.Context, audit.Payload) (audit.Event, error)`，使用 `api.NewAuditor` 适配到本节点最小 `api.Auditor` 接口。`api.AuditEvent.Phase` 写入 P7 现有 `Payload.reason`，其余白名单字段对应写入。P7 源码及迁移未修改。事件采用字段白名单：主体 ID、RPC 操作、审计阶段、结果、来源 IP、实际求值策略版本与规则名，以及资源类型和持久化 ID。成功创建的目标从返回对象取得，不使用名称或凭据代替 ID。主机操作使用数据库解析的主机 ID；单主机事件同时填写 hostname。未通过授权的拒绝事件不记录目标。SetHostLabels 在数量、revision、全部目标授权及标签校验成功后才保存目标，数量不符或任一目标授权失败时只追加一条空 Resource 的拒绝结果，不记录目标数量或选择器摘要。结果为 deny 时，已有目标可能来自已授权操作或已提交后的响应失败，不能仅凭目标判定修改成功。全部 Connect 操作，包括失败登录与拒绝操作，均调用该接口。成功登录记录同步后的数据库用户 ID。请求体、token、password、code、verifier 和提供方错误原文不进入事件。

按 G27，api.New 缺少 Append 实现时拒绝启动。生产入口默认使用 P7 PostgreSQL Store 的真实 Append，并保留 P7 检查点及导出后台任务。测试可显式注入本地审计实现；没有审计绕过参数。原生网关二进制测试验证结果事件进入 P7 表；CLI OIDC login→policy get/apply/test 冒烟使用真实 Append，并验证审计链和 SavePolicy 的授权/结果两次事件。

G28 采用两阶段审计。每个写 RPC（含持久化策略试算和登录事务）在通过认证、CSRF 和 ABAC 后先 Append `phase=authorized, outcome=allow`。失败返回 UNAVAILABLE，处理函数不执行。操作结束后 Append `phase=result`；此时审计失败返回 UNAVAILABLE，并明确报告 `operation may have committed`。CLI 根据 `ErrorDetail.reason = AUDIT_RESULT_UNAVAILABLE` 显示同一提示，不回显服务器错误原文。只读及拒绝操作记录结果事件。OIDC start 的浏览器绑定写入也采用两阶段审计。该顺序不保证业务数据与审计在同一数据库事务提交。

未修改 web、HostService、JoinTokenService、目录上传发布、SystemService、hostconn、catalogsvc。未 push、合并、部署，未使用 tsh/ssh，未连接真实 OIDC、LDAP、生产或客户环境。

管理结果审计复用 P7 的 Resource 字符串。单目标仅包含 JSON 的 `type` 和 `id`。批量主机标签和 CSV 执行把全部主机 ID 分块持久化，每块包含 `batch_id`、`part`（从 1 开始）、`parts`、`total` 和白名单 `targets`。Resource 每块最多 8KiB，预留 JSON 转义及事件元数据空间，不依赖会过期的 CSV 预览。读取方须核对同一 batch_id 的块数、序号和目标总数；缺块表示审计不完整。全部块共用独立的 5 秒结果审计时限，任一块失败沿用结果审计不可用语义。业务提交与这些审计追加仍非同一事务。请求取消后结果审计保留请求值与身份，前置授权审计仍使用请求 context。

A47：匿名 OIDC 登录事务在同一数据库内跨身份源、跨网关实例共用最多 10000 条有效事务。BeginOidcLogin 在数据库共享事务锁下清理过期记录、检查容量并插入；满额返回 RESOURCE_EXHAUSTED，过期清理仍提交。有效事务不被驱逐。现有完成登录的原子消费删除会释放容量。若升级前已有超过上限的有效记录，新建会被拒绝，直到消费或过期清理将数量降至上限以下。

已提交的用户角色、策略版本和 join token 在数据库确认写入成功后，先保存请求私有的目标元数据，再执行用户/令牌重读或策略刷新。后续失败或取消仍记录该目标，RPC 错误分类保持原行为。未通过 revision 或策略试算检查的失败不会记录为已提交目标；审计 outcome 仍表示 RPC 结果，不能单独证明业务提交状态。
