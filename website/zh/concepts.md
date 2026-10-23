# 概念 {#concepts}

**action（动作）** 是一个具名操作。动作具有固定的执行定义、带类型的参数、风险分级和资源限制。**目录**（catalog）是带版本、经过签名的动作集合。主机从该目录获取命令，不从 AI agent 或网关提供的命令字符串获取命令。

```text
MCP client / CLI / console → gateway → PostgreSQL and S3-compatible storage
                               ▲
                               │ outbound mutual-TLS connection
                            host agent
                               │ privileged helper when required
                            signed action
```

网关认证用户和服务账号，校验请求，选择主机。网关还执行 ABAC（基于属性的访问控制）判定，调度 job 并记录审计事件。低权限的 `allowops-agent` 维持主机连接并校验目录。`allowops-exec` 在执行特权操作前独立校验目录，并应用签名中的执行身份。该辅助程序通过固定的 sudo 规则调用，不带命令行参数。读取 root 所有凭据的数据库内置动作也使用该辅助程序。

## 主机、标签和身份 {#hosts-labels-and-identities}

主机主动连接网关，不需要主机开放入站端口。网关 TLS 和主机身份 CA（证书颁发机构）是两套独立的信任体系。注册时固定（pin）网关 TLS CA。之后的主机 RPC 使用双向 TLS 和短期主机证书。该证书带有不可变的主机 ID。

授权标签由运维人员在网关上设置。上报标签（例如操作系统信息）可以用于筛选主机清单，但不会授予访问权限。新主机没有授权标签，不能执行动作，admin 也不能在其上执行动作。主机名全局唯一。删除主机会使其身份失效。再次注册该主机名会创建新的主机 ID。

## Job 和目标 {#jobs-and-targets}

**job** 是对一组目标的一次动作调用。**task** 是在单台主机上的执行。可以指定明确的主机名，也可以指定逗号分隔的 `key=value` 条件，所有条件都必须匹配。选择器必须提供精确的 `expected_count`。数量不匹配，或任一目标被拒绝，都会在分发前拒绝整个请求。

task 分批运行。`batch_size` 和 `max_failures` 可以收紧签名中的限制。失败、超时和 unsupported 的 task 计入失败上限，离线的 task 不计入。失败数超过阈值时，跳过剩余的 task。`wait_seconds` 控制响应的等待时长，不控制动作超时。离线主机不会被排队等待以后执行。连接断开会停止该 task 的进程组。执行和输出都不会重放。

job 状态包括 `queued`、`running`、`succeeded`、`partially_failed`、`failed`、`cancelled` 和 `denied`。被拒绝的提交不会创建可执行的 job。task 状态包括 `pending`、`running`、`succeeded`、`failed`、`timeout`、`offline`、`skipped`、`cancelled` 和 `unsupported`。

MCP 动作工具向 CLI 使用的同一服务提交 job。动作调用和 `jobs_get` 返回经过授权的 job 汇总，包含计数、输出分组和离线主机。详细的 MCP 汇总会列出每个分组中的主机名。读取已存储的输出时，使用带 `host` 的 `jobs_get`；见 [MCP 工具](mcp.md)。

## 输出和审计 {#output-and-audit}

输出在离开主机之前先在主机上脱敏。之后可以对 stdout 进行过滤，两个输出流都有大小上限。汇总按相同的退出码和输出哈希分组。完整输出异步存储到 S3 兼容存储。存储失败不会把成功的动作变为失败的动作。读取预览或完整输出需要单独的输出授权。

组合动作包含有序、具名的步骤，每个步骤有独立的输出流。读取已存储的输出时，每次读取一个步骤：MCP `jobs_get` 需要同时提供 `step_index` 和 `host`，CLI `jobs output` 需要 `--step`。两者都使用从零开始的索引。读取组合动作的输出时省略索引，会返回 `INVALID_OUTPUT_STEP` 参数错误。MCP 还会返回提示，要求逐个步骤读取。单步骤动作应省略索引。汇总请求不选择输出步骤。

输出始终是不可信数据，可能包含提示注入。脱敏可能遗漏敏感数据。审计事件包含判定结果、标识符以及输出引用和哈希，不包含输出正文。这些保证的限制见[审计](audit.md)和[安全](security.md)。
