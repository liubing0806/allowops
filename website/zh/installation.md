# 安装 {#installation}

网关和主机的制品面向 Linux amd64。CLI、网关、agent 和辅助程序应使用同一个已验证的版本。安装前，使用另行信任的发布密钥校验发布包的校验和与签名。查看发布包附带的软件物料清单（SBOM）和第三方声明。

## 本地 Compose 演示 {#local-compose-demonstration}

前置条件：Linux amd64 上的 Docker Compose（使用本机 Unix socket）、Go 1.27.3、OpenSSL、Git，以及安装了 PyYAML 的 Python 3。在源码检出目录中执行：

```sh
cd deploy/compose
export COMPOSE_PROJECT_NAME=allowops-fx2-local
./quickstart-local.sh
```

脚本分别生成网关 TLS CA 和主机身份 CA、目录签名密钥，以及随机的本地凭据。脚本构建各个服务，初始化存储，通过 LDAPS 认证演示管理员，发布示例目录，并注册两台主机 agent。验证步骤检查在线状态和签名目录加载报告。验证步骤还在两台主机上运行只读的 `disk_usage` job，等待 `output_stored=true`，读取 demo-1 的完整 stdout/stderr，并将其 SHA-256 哈希与 job 汇总进行比对。脚本成功退出前，会在内存中检查 Compose 日志是否包含生成的密钥。

Compose 网络是内部网络，不发布任何主机端口。其 `.local/` 目录被 Git 忽略，包含生成的私密材料，包括 S3 凭据、SeaweedFS 加密密钥和共享的审计游标密钥。重启已有数据卷时保留该目录。不要把演示凭据复制到其他部署中。该演示不是针对每个动作的执行测试。外部工具和特权动作的依赖没有全部安装。

```sh
docker compose exec --user 65532:65532 demo-1 allowops-agent status
docker compose exec --user 65532:65532 demo-2 allowops-agent status
python3 verify.py
docker compose run --rm --no-deps admin-tool verify-job
python3 verify-secrets.py
```

后续命令使用相同的 Compose 项目名。本快速开始要求项目名以 `allowops-fx2-` 为前缀，默认值为 `allowops-fx2-local`。

[仓库中的 Compose 指南](https://github.com/liubing0806/allowops/blob/main/deploy/compose/README.md)
说明了生成的文件、服务边界和会删除数据的清理操作。

### 常驻本地环境 {#persistent-local-environment}

如需在本机通过浏览器、CLI 和 MCP 客户端访问的常驻环境，改用独立的 `allowops-local` Compose 项目：

```sh
make local-up
make local-down
```

默认情况下，网关 TLS 端口只发布在主机 IPv4 回环接口的 `8443` 端口上（`ALLOWOPS_LOCAL_PORT` 可修改主机端口）。该环境使用浏览器兼容的证书。首次启动时注册三台演示主机。`local-up` 输出控制台 URL、CA 路径、管理员登录信息、CLI 示例和 MCP 客户端示例。重复运行时复用已生成的凭据和数据卷。`local-down` 停止容器并保留数据卷。上文的仓库 Compose 指南说明了叠加配置（overlay）、重置步骤和服务边界。

## 在 Kubernetes 上部署网关 {#gateway-on-kubernetes}

使用 `deploy/helm/allowops` 中的 chart。PostgreSQL 和 S3 兼容对象存储需要另行提供。chart 在 443 端口上使用四层 TCP Service。TLS 和 ALPN（应用层协议协商）必须原样到达网关。终止 TLS 的 HTTP Ingress 无法承载主机协议。

通过已有的 Kubernetes Secret 提供以下内容：包含完整 CA 链的网关 TLS 证书、独立的主机 CA、目录公钥、运行时数据库凭据，以及单独的迁移数据库凭据。还需提供包含 `aws-credentials` 文件的 `allowops-output`，以及包含 `audit-cursor-key` 的 `allowops-audit-cursor`。`audit-cursor-key` 必须恰好是 32 个原始随机字节，由所有网关实例共享。不要把密钥放入 Helm values 和发布历史。按照 chart 的 values 和 Secret 约定，配置身份提供方、公共 HTTPS 源、输出存储的 bucket/region/endpoint 以及 S3 凭据的提供方式。身份提供方配置中，通过 `gateway.providerSecretEnv` 为 OIDC 的 `client_secret_env` 或 LDAP 的 `bind_password_env` 变量提供 Secret。TLS 证书名称必须与公共 upstream 地址一致。全新安装网关时，先授予所需的运行时数据库权限，再启动网关。

在 Helm values 中设置 `output.bucket`、`output.region` 和 `output.endpoint`。endpoint 为空时使用 AWS 区域 S3 endpoint。`output.existingSecret` / `output.credentialsKey` 选择凭据文件；`audit.cursorKeySecret` / `audit.cursorKeyKey` 选择审计游标密钥。chart 把这些文件复制为权限 0600 的普通文件，并为网关设置 `AWS_SHARED_CREDENTIALS_FILE`。

```sh
helm lint deploy/helm/allowops
helm template allowops deploy/helm/allowops -f gateway-values.yaml
helm upgrade --install allowops deploy/helm/allowops \
  --namespace allowops --create-namespace -f gateway-values.yaml
```

`gateway-values.yaml` 是运维人员提供的文件，包含非机密设置和对预先创建的 Secret 的引用。本仓库不提供该文件。迁移 hook 在安装或升级之前运行。维护和运行时使用不同的数据库角色。运行时角色不能拥有审计表，也不能继承维护权限。保留专用导出实例的数据卷。具体的 values 和数据库前置条件见 [chart 指南](https://github.com/liubing0806/allowops/blob/main/deploy/helm/allowops/README.md)。

## 网关进程 {#gateway-process}

直接管理二进制文件的部署，通过 `ALLOWOPS_DATABASE_URL` 提供数据库凭据。网关 YAML 引用 TLS 文件、主机 CA 文件和目录公钥目录。该 YAML 还提供身份和输出存储设置。S3 凭据使用 AWS SDK 的凭据链，不使用命令行参数，也不在 YAML 中写入凭据值。

```sh
allowops-gateway migrate
allowops-gateway serve --config /etc/allowops/gateway.yaml
```

使用维护角色运行迁移，然后使用运行时角色启动服务。CA 私钥必须是权限 0600 的普通文件。各网关实例共享同一个主机 CA。在对象存储上启用输出加密。SeaweedFS 进行 AES256 上传时，需要运维人员提供加密密钥。

在网关 YAML 中提供 `output.bucket` 和 `output.region`，`output.endpoint` 可选。通过 `AWS_SHARED_CREDENTIALS_FILE` 或其他受 AWS SDK 支持的凭据来源提供 AWS 凭据。将 `audit.cursor_key_file` 设置为一个私有文件，文件内容恰好是 32 个原始随机字节。所有实例使用同一个密钥，并在重启后保留该密钥。见[审计](audit.md)。

## 健康检查 {#health-checks}

网关在常规 TLS 监听器上提供 HTTPS GET `/health/live` 和 `/health/ready`。服务器处理请求期间，`/health/live` 返回 HTTP 200，结果不依赖 PostgreSQL 和输出存储。PostgreSQL 连接失败或 schema 错误时，`/health/ready` 返回 HTTP 503。输出存储失败时返回 HTTP 200，并带有 `degraded: true` 和 `output: unavailable`。此时可以继续执行，但完整输出无法持久化。

```sh
allowops-gateway health --url https://gateway.example.org/health/ready \
  --ca-file /absolute/path/gateway-tls-ca.crt
```

该命令校验 TLS，在 HTTP 200 时成功，包括存储降级的情况。该命令不检查响应正文中的降级标志。请单独监控该标志。Helm 的 startup/liveness 探针使用 `/health/live`；readiness 探针使用 pod TLS 端口 8443 上的 `/health/ready`。Kubernetes HTTPS 探针不校验服务端证书。Compose 的 CLI 健康检查使用生成的 CA 校验 TLS。Compose 中单独的 ready 服务在演示启动前检查存储。

## 主机安装包 {#host-packages}

安装已验证的本地文件。Debian/Ubuntu 使用 `.deb` 安装包；RHEL 系列使用 `.rpm` 安装包。从本地介质安装前，先安装 systemd、账号管理工具和 sudo。

```sh
sudo dpkg -i /absolute/path/allowops-agent_0.1.0_amd64.deb
# Or, on an RPM-based system:
sudo rpm -Uvh /absolute/path/allowops-agent-0.1.0-1.x86_64.rpm
sudo install -o root -g root -m 0644 /absolute/path/catalog.pub.pem \
  /etc/allowops/catalog-keys/catalog.pub.pem
sudo install -o root -g root -m 0644 /absolute/path/agent.yaml \
  /etc/allowops/agent.yaml
```

将示例版本替换为已验证版本的文件名。安装包会启用服务，但不启动服务。在 `/etc/allowops/agent.yaml` 中提供 upstream 和固定（pin）的网关 TLS CA。向网关管理员获取有使用限制的注册 token。该 token 应通过私密渠道交付，保存在权限 0600 的文件中。根据提供的网关 TLS CA 证书计算 pin 值，不要使用主机身份 CA：

```sh
ca_pin=$(openssl x509 -in /absolute/path/gateway-tls-ca.crt -outform DER \
  | openssl dgst -sha256 -r | cut -d ' ' -f 1)
sudo allowops-agent join --upstream https://gateway.example.org \
  --token-file /absolute/path/join-token.txt --ca-pin "sha256:$ca_pin"
```

配置中的 upstream 和 pin 必须与注册时一致。也可以使用 `--token-stdin`，通过 stdin 传入私密交付的 token。`--token-file`、`--token-stdin` 和旧版 `--token` 必须且只能提供其中一个。所有来源最多接受 4 KiB，会去除首尾空白，并拒绝空输入。建议使用文件或 stdin，避免 token 值出现在进程参数中。注册完成后：

```sh
sudo systemctl start allowops-agent
sudo -u allowops allowops-agent status
```

agent 以 `allowops` 账号运行，不带附加组。需要额外权限的动作应明确设置 `run_as`。安装后使用 `visudo` 检查 `/etc/sudoers.d/allowops`。

## 主机 tar 归档 {#host-tar-archive}

`.tar.gz` 发布包包含二进制文件、许可和声明，不是包管理器安装程序。将已验证的归档解压到暂存目录：

```sh
mkdir -p staging
tar -xzf /absolute/path/allowops_0.1.0_linux_amd64.tar.gz -C staging
```

在对应的源码 tag 下，如果专用账号不存在，先创建该账号，然后安装文件。以下命令假定二进制文件位于暂存目录根目录。请先检查已验证归档的目录结构。

```sh
sudo useradd --system --user-group --home-dir /var/lib/allowops \
  --no-create-home --shell "$(command -v nologin)" allowops
sudo install -d -o allowops -g allowops -m 0700 /var/lib/allowops
sudo install -d -o root -g root -m 0700 /var/lib/allowops-exec
sudo install -d -o root -g root -m 0755 /usr/libexec/allowops /etc/allowops/catalog-keys
sudo install -o root -g root -m 0755 staging/allowops-agent /usr/bin/allowops-agent
sudo install -o root -g root -m 0755 staging/allowops-exec /usr/libexec/allowops/allowops-exec
sudo install -o root -g root -m 0644 deploy/packaging/allowops-agent.service \
  /usr/lib/systemd/system/allowops-agent.service
sudo install -o root -g root -m 0440 deploy/packaging/allowops.sudoers /etc/sudoers.d/allowops
sudo visudo -cf /etc/sudoers.d/allowops
sudo systemctl daemon-reload
sudo systemctl enable allowops-agent
```

使用安装包一节中的命令，安装管理员提供的公钥和 agent YAML。然后完成注册，再启动服务。保留归档中的 LICENSE 和 THIRD_PARTY_NOTICES。不要以 root 身份运行 agent。

| 路径 | 所有者 / 权限 |
|---|---|
| `/usr/bin/allowops-agent` | root, 0755 |
| `/usr/libexec/allowops/allowops-exec` | root, 0755 |
| `/usr/lib/systemd/system/allowops-agent.service` | root, 0644 |
| `/etc/sudoers.d/allowops` | root, 0440 |
| `/etc/allowops/agent.yaml` | root, 0644 |
| `/etc/allowops/catalog-keys/` | root, 0755；公钥 root, 0644 |
| `/var/lib/allowops/` | allowops, 0700 |
| `/var/lib/allowops-exec/` | root, 0700 |

目标操作系统范围包括 CentOS/RHEL 7、Rocky/Alma/RHEL 8+、Ubuntu 20.04+ 和 Debian 11+。本指南不证明每个操作系统都已通过虚拟机测试。选择版本时，请参考该发布版本的平台验证证据。
