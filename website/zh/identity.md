# 身份 {#identity}

人员通过 OpenID Connect（OIDC）或 LDAP 认证。服务账号使用有有效期的 Bearer
token。系统没有内置的本地密码用户。用户的有效角色是组映射角色与手动分配角色的并集。每次经过认证的请求都会读取当前的身份数据。

一个网关最多接受一个 LDAP 身份源，并支持多个 OIDC 身份源。配置多个 LDAP 条目会导致启动失败。控制台显示一个 LDAP 登录表单，并为每个 OIDC 提供方显示一个按钮。每个已配置的身份源须使用唯一的提供方 ID。

## OIDC {#oidc}

配置一个通用提供方和一个固定的网关 HTTPS 源（origin）。在身份源中注册网关回调地址`https://gateway.example.org/auth/oidc/callback`。以下内容是配置片段；网关 TLS、数据库和输出设置也必须配置。

```yaml
identity:
  origin: https://gateway.example.org
  bootstrap_admins: [admin@example.org]
  role_mappings:
    - provider_id: identity
      group: ops-admin
      roles: [admin]
providers:
  - id: identity
    display_name: Operations identity
    kind: oidc
    issuer_url: https://idp.example.org
    client_id: allowops
    client_secret_env: ALLOWOPS_OIDC_CLIENT_SECRET
```

通过进程环境变量提供提供方密钥。使用 Helm chart 时，在 `gateway.providerSecretEnv`
（`name`、`secretName`、`key`）中列出每个变量。chart 从 Kubernetes Secret 注入该变量，值不会写入 ConfigMap。网关检查 issuer、audience、nonce、state 以及绑定的浏览器事务。OIDC CLI 登录使用回环地址回调和 PKCE（Proof Key for Code Exchange，授权码交换证明密钥）。网关负责兑换提供方的授权码。CLI 收到一个短期有效、只能使用一次的代码，并用它兑换会话。token 不会出现在重定向 URL 中。把邮箱作为可信身份时，要求邮箱已验证。

```sh
allowops login --gateway https://gateway.example.org --provider identity
# Print the login URL when the CLI cannot open a browser:
allowops login --gateway https://gateway.example.org --provider identity --no-browser
```

组映射从配置初始化，之后存储在 PostgreSQL 中。修改已有映射须通过控制台或 API；使用不同的启动映射重启不会覆盖数据库。

## LDAP {#ldap}

只接受 LDAPS 或使用 StartTLS 的 LDAP。须配置证书验证、绑定身份、用户和组的基准 DN，以及目录服务的属性名。绑定密码来自一个指定名称的环境变量（在 Kubernetes 上通过`gateway.providerSecretEnv` 提供）。系统不存储用户密码。

```yaml
providers:
  - id: directory
    display_name: Operations directory
    kind: ldap
    url: ldaps://directory.example.org:636
    ca_file: /etc/allowops/directory-ca.pem
    bind_dn: cn=reader,dc=example,dc=org
    bind_password_env: ALLOWOPS_LDAP_BIND_PASSWORD
    user_base_dn: ou=people,dc=example,dc=org
    user_attribute: uid
    group_base_dn: ou=groups,dc=example,dc=org
    group_member_attribute: member
    group_name_attribute: cn
```

使用 StartTLS 时，填写目录服务的 LDAP URL 并设置 `start_tls: true`。过滤器会转义用户输入。默认限流规则允许每个用户名和来源地址在五分钟内失败五次；登录成功后该计数器清零。

```sh
allowops login --gateway https://gateway.example.org \
  --provider directory --username operator
```

CLI 从终端读取密码，输入内容不回显。自动化场景可以使用 `--password-stdin`，从密钥存储的输入流读取密码。不要把密码放在命令参数中。网关使用私有 TLS CA 时，使用 `--ca-file`；系统不提供跳过 TLS 验证的选项。

## 服务账号和会话 {#service-accounts-and-sessions}

在控制台中创建服务账号。须记录负责人、用途和明确的角色。token 只显示一次，以 SHA-256 哈希存储。默认有效期为 30 天，可配置为 1–365 天。每个客户端使用独立的 token；撤销不再使用或已泄露的 token。发布者需要 `publish_catalog`，不需要动作执行权限。读取者需要对其主机的明确执行权限和输出访问权限。

控制台和 CLI 会话的默认有效期为七天。CLI 凭据存储在用户配置目录中（Linux 上为 `~/.config/allowops/credentials`），权限模式为 0600。控制台会话使用 Secure、HttpOnly、SameSite=Strict cookie，并执行 CSRF 检查。用户可以在控制台中列出并撤销自己的 CLI 会话；管理员可以管理其他用户的会话。

MCP 在每个请求中发送 Bearer 请求头。MCP 不通过控制台 cookie 或查询参数认证。MCP OAuth 是路线图中的功能；配置客户端时使用服务账号 token。见 [MCP 客户端](mcp.md)。
