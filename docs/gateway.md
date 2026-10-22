# P4 网关基础

P4 使用 PostgreSQL、pgx、sqlc 和 goose。初始 schema 为版本 1，仅创建主机、join token、目录版本、网关实例及 G15 短期消息表。后续迁移先扩展再收缩；task/审计的月分区由 P6/P7 定义，本节点不预设其列或分区工具。

数据库连接从 `ALLOWOPS_DATABASE_URL` 环境变量读取。不要把密码放进命令参数或日志。启动检查 schema，只允许二进制内的 `store.SchemaVersion`（本基线为 6）；未迁移或较新的 schema 均拒绝。迁移与服务启动分别执行：

```sh
./bin/allowops-gateway migrate
./bin/allowops-gateway serve --config /etc/allowops/gateway.yaml
```

最小 YAML 配置如下。服务端 TLS 证书由部署方配置，须覆盖客户端使用的网关地址。内部主机 CA 文件均不存在时生成；只缺少一个文件时拒绝启动。多个实例必须挂载相同内部 CA，CA 私钥须为普通文件且权限 0600，不允许符号链接，不存数据库。

```yaml
address: ':443'
tls_certificate: /etc/allowops/tls.pem
tls_key: /etc/allowops/tls.key
ca_certificate: /etc/allowops/host-ca.pem
ca_key: /etc/allowops/host-ca.key
catalog_keys: /etc/allowops/catalog-keys
gateway:
  version: '0.1.0'
  certificate_ttl: 24h
  single_join_ttl: 24h
  multi_join_ttl: 24h
```

配置覆盖 `hostconn.DefaultConfig()`；未知字段拒绝。发布构建默认使用构建版本，开发版本 `dev` 默认使用 `0.1.0`，配置须提供有效 SemVer。空 `catalog_keys` 不信任任何签名密钥；P5/P6 应使用 `server.Server.Catalogs` 接入发布入口。

## 内部接口

- `hostconn.Service.CreateJoinToken(ctx,maxUses,ttl)`：返回一次 secret；ttl=0 使用单次/多次配置，负值拒绝。数据库仅存 SHA-256。`store.Store.RevokeJoinToken` 吊销新注册权限。
- `store.Store.DeleteHost(ctx,hostID)`：保留已删除身份，释放 hostname，NOTIFY 断开各实例旧连接。新注册获得新 host_id。HostService 提供按 revision 删除的管理 API。
- `catalogsvc.Service.Publish(ctx,rawDSSE)`：调用 P1 验签，限制信封/action 大小；事务内串行检查严格递增版本及全局 action 名后写入原始字节，并通知所有实例。`store.CheckActionNames` 是 A11 的集中检查点。P4B 的 CatalogService 提供上传暂存与 Connect 发布接口。
- `hostconn.Router.Send(ctx,hostID,message)`：向当前 connection_id 下发 TaskAssignment 或 CancelTask，返回 TaskCompleted 元数据；不实现 job 调度。允许同一任务的 assignment 与一次 cancel 同时等待结果。断线、替代、过期返回 offline，不重放。
- `hostconn.Hooks.OnMessage`：在连接所属实例处理主机消息；输出仅走此回调，P6 持久化到任务表及对象存储。目录报告只有所有连续页完成后才回调；`Service.CatalogReport` 返回当前连接的聚合报告。回调不得长期阻塞连接读循环。
- `hostconn.Hooks.OnDisconnect`：携带 host_id 和 connection_id，P6 按 A9 标记对应任务 offline。`Hooks.Drain` 留给 P6 等待已执行任务；收到 SIGTERM 即拒绝新派发，等待该 hook 后通知 Reconnect，再关闭连接。

数据库更新连接/断开状态，每 5 分钟刷新 last_seen；心跳只更新内存。发送阶段持有主机行共享锁，连接替代的更新必须在发送结束后提交；结果更新也要求 connection_id 仍为当前代次。LISTEN 故障时停止派发并断开当前实例所有主机，需重启服务恢复。

G18 已确认：续证更新当前证书序列号后，既有 Connect 流仍可完成已经下发的消息，直到新连接替代或原证书到期。流的截止时间绑定原证书，不因续证延长。新 TLS 握手及后续 RPC 均要求当前证书。删除主机通过 NOTIFY 立即断开既有流，原证书到期是独立的关闭条件。容器测试覆盖旧流结果、旧证书握手和后续 RPC 拒绝、跨实例替代、续证后的删除及原证书到期。

G15 消息表默认最多 1024 行、64 MiB（请求字节加每行预留 1 MiB 结果空间）；所有实例使用同一容量配置。容量检查与插入持有数据库 advisory lock。NOTIFY 只包含消息 ID；发送实例读取最终元数据，正常完成/断开后删除行。默认 1 分钟过期，每分钟清理崩溃遗留行；请求截止时间更早时使用该截止时间。不得把 TaskOutputChunk 写进该表。容量、过期及清理周期集中于 `hostconn.Config`。

Q1 本节点实施主机消息、目录/action、发送队列、消息速率、并发、标签、单主机拉取和心跳限制。队列默认 64 条及 1 MiB；目录通知使用单个可合并唤醒信号及有界发送队列。控制台分页/JSON、参数、CSV、审计等限制在所属后续节点实施。

上报标签可通过 `gateway.reported_label_count`、`reported_label_key_bytes`、`reported_label_value_bytes` 收紧；默认分别为 128 个、128 字节和 1024 字节。字节限制按 UTF-8 编码计算，超限或非法 UTF-8 拒绝，不截断标签。

发布时限制目录 ID 字节数，为最大目录块和元数据保留消息预算（消息上限减块上限减 1024 字节）；无法在块消息中表示的目录拒绝发布。单次网络写入以心跳超时为截止时间，持续背压会断开连接。

自定义 ALPN 的 HTTP/2 连接使用 `x/net/http2.ServeConn`；Go 1.27 的该实现委托给标准库。标准 `http.Server` 没有公开的 ServeConn，标准 Transport 自动选择 HTTP/2 时要求 ALPN 为 `h2`。因此这四处调用保留局部 SA1019（弃用 API）检查例外及理由，其余静态检查保持启用。

## 验证

`internal/testpg` 只连接本机 `/var/run/docker.sock`，固定 PostgreSQL 镜像 digest，端口仅绑定 `127.0.0.1`。Docker 不可用时不会读取外部 DSN；验收设置 `ALLOWOPS_REQUIRE_DOCKER=1` 使缺少 Docker 直接失败。测试同时起两个网关实例及模拟主机，二进制测试执行 migrate/serve/SIGTERM，并通过 HTTPS `/mcp` 返回 `P4 placeholder` 确认新 handler 生效。

```sh
make build
make generate
ALLOWOPS_REQUIRE_DOCKER=1 make test lint vuln licenses
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 -v ./internal/gateway/... ./internal/store/...
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 -v ./cmd/allowops-gateway -run TestGatewayCommands
```

已确认（负责人答复，见 main `9952ee8` 的 `docs/architecture-decisions.md` §21）：A9 执行中断线时 task 标记 offline，不重放，P4 提供断线 hook，业务状态归 P6；A11 多目录 action 名全局唯一，发布冲突拒绝；A14 主机证书及单次/多次 join token 默认 24h，均可配置。A10 的 CSV/批量标签行为已确认，仍不在 P4 范围。MCP、用户认证、OPA、job、审计及上传 RPC 均由后续节点实现。P4 没有剩余待确认项。

P4B 的配置、TLS CA pin、管理接口、CLI 和系统统计限制见 [管理接口说明](p4b-management-api.md) 与 [配置示例](../examples/gateway.yaml)。

## 健康检查和输出存储

现有 TLS 端口的标准 HTTPS 路由提供匿名 GET `/health/live` 和
`/health/ready`。自定义主机、注册和 MCP ALPN 路由保持原有用途。
存活检查返回 HTTP 200，表示进程可处理请求。就绪检查在两秒超时内读取
PostgreSQL 迁移版本；不可连接、版本表不可读或版本不匹配均返回 HTTP 503。
输出存储使用两秒超时的 S3 HeadBucket。不可用时就绪仍返回 HTTP 200，
响应包含 `degraded: true` 和 `output: "unavailable"`。响应不包含依赖原始错误。
输出异步写入失败时任务仍保持执行结果，`output_stored=false`。

```yaml
output:
  bucket: allowops-demo
  region: us-east-1
  endpoint: http://seaweedfs:8333
audit:
  cursor_key_file: /run/allowops/credentials/audit-cursor-key
```

bucket 和 region 必填。endpoint 为空时使用 AWS 区域 S3 地址。
网关凭据使用 AWS SDK 标准凭据链；部署文件设置
`AWS_SHARED_CREDENTIALS_FILE` 指向私有凭据文件。
SeaweedFS 的 AES256 服务端加密需要 `WEED_S3_SSE_KEY`，仅提供给
SeaweedFS 服务。配置依据见 [协议说明](protocol.md)。

`audit.cursor_key_file` 指向恰好 32 个原始随机字节的文件。文件不可读或长度
错误时拒绝启动。所有 API 实例及审计导出实例共享同一文件内容，重启时保留。
未配置时沿用审计模块生成的进程内随机密钥；启动日志明确提示
`pagination cursors will be invalid after restart or across instances`。
该缺省模式不能保证跨实例或重启后的审计分页游标有效。

scratch 网关镜像内可执行健康检查，无需 shell：

```sh
allowops-gateway health --url https://localhost:8443/health/ready \
  --ca-file /run/allowops/credentials/tls-ca.crt
```

此命令校验 TLS 证书、主机名和 HTTP 200；失败退出码非零，错误文本不包含
URL 凭据或依赖错误。使用存活路径可检查进程。命令不要求数据库环境变量。
