# CLI 参考 {#cli-reference}

使用同一版本中的二进制文件。`allowops --help` 和各子命令的 `--help` 是该版本接口的权威说明。网关使用另一套命令解析器。serve 在解析参数之前检查 `ALLOWOPS_DATABASE_URL`，因此查看 `serve --help` 之前须先设置该环境变量。`allowops-gateway serve --help` 和 `health --help` 都会打印参数，但以非零状态码退出。辅助程序不接受任何参数，包括 `--help`。

## 认证 {#authentication}

```sh
allowops login --gateway https://gateway.example.org --provider identity
allowops login --gateway https://gateway.example.org \
  --provider directory --username operator
```

登录参数包括 `--gateway`、`--provider`、`--ca-file`、`--no-browser`、`--username` 和 `--password-stdin`。job 和策略命令使用已保存的 CLI 凭据。主机命令和 join token 命令还接受 `--gateway`、`--ca-file`，以及用于服务账号的 `--token-env`。发布命令要求明确指定 token 环境变量。见[身份](identity.md)。

## 目录命令 {#catalog-commands}

| 命令 | 主要参数 |
|---|---|
| `allowops catalog keygen` | `--private-key`、`--public-key`；创建新文件。 |
| `allowops catalog validate [directory]` | 未提供位置参数目录时使用 `--dir`。 |
| `allowops catalog build` | `--dir`、`--out`、`--git-commit`、`--ttl`（默认 2160h）。 |
| `allowops catalog sign` | `--in`、`--out`，多个签名时重复使用 `--key`。 |
| `allowops catalog publish` | `-f`/`--file`、`--gateway`、`--ca-file`、`--token-env`、`--json`。 |
| `allowops catalog try <action>` | `--dir`，重复使用 `--param name=value`；以当前用户身份在本地执行。 |

有效期从构建时开始计算；签名时保持不变。`--out -` 写到 stdout。私钥从文件读取。见[签名与发布](publishing.md)。目前没有 `allowops actions list` 或 `actions describe` 命令；请在控制台中查看目录，或通过 MCP 工具发现动作。

## 主机和注册 token {#hosts-and-registration-tokens}

```sh
allowops hosts list --selector env=test --json
allowops hosts label host-a --set env=test --set team=ops --remove temporary
allowops hosts label --selector env=test --expected-count 2 --set team=ops
allowops hosts delete host-a
allowops jointoken create --uses 1 --ttl 1h
```

选择器是以逗号分隔的 `key=value` 条件，各条件同时满足（逻辑与）。`reported.` 开头的键用于过滤上报属性；这些键不授予任何授权。标签修改会设置或删除指定的键，保留其他键，并以原子方式校验版本号和目标数量。删除主机会使其身份失效。创建 join token 时，密钥只显示一次：须通过私密渠道传递，并避免记录命令输出。这些命令组支持 `--json` 和上文所述的远程参数。

## 执行和 job {#run-and-jobs}

```sh
allowops run systemd_service_status --selector env=test,team=ops \
  --expected-count 2 --param service=nginx --reason 'check service state' \
  --wait-seconds 30 --batch-size 2 --max-failures 0 --json
allowops jobs list --page-size 50 --json
allowops jobs get job-20261014-0001 --wait-seconds 30 --response-format detailed --json
allowops jobs output job-20261014-0001 --host host-a --stream stdout \
  --offset 0 --limit 16384 --json
allowops jobs cancel job-20261014-0001 --json
```

run 使用 `--hosts`（以逗号分隔的主机名）或 `--selector` 之一；使用选择器时必须提供`--expected-count`。`--reason` 为必填。动作输入通过重复的 `--param` 提供；整数和布尔值按类型解析，数组使用 JSON。提供参数时还需要 `view_catalog` 权限，以便 CLI 读取动作的 schema。run 支持 `--response-format concise|detailed`、等待、分批和失败控制参数。run 不提供单独的输出过滤参数；需要顶层输出过滤时使用 MCP。

返回的 job 为失败、部分失败、已取消或被拒绝时，`run` 以 1 退出。返回的 job 成功时，以 0 退出。响应为排队中或运行中时也以 0 退出，并在 stderr 中提示 job 尚未完成。使用 `--wait-seconds 0` 或响应等待在完成前结束时会出现这种情况；仅凭退出码 0 不能确定 task 成功。job 状态未指定或未知，或响应中没有 job 时，以 1 退出，并在 stderr 中报告未知状态。文本或 JSON 响应仍输出到 stdout，job 失败时也是如此。提交错误、RPC 错误和输出错误仍以非零状态码退出。这些退出规则只适用于 `run`；之后的进度使用 `jobs get` 查看。

`jobs list` 使用 `--page-token` 分页；须通过 JSON 输出获取下一页的 token。读取组合动作的输出时须提供 `--step`，值为从零开始的步骤序号；单步骤动作应省略该参数。每个已声明的步骤须分别读取；切换步骤或输出流时须重置 offset。组合动作省略步骤或提供无效序号时，返回 `INVALID_OUTPUT_STEP`。例如：

```sh
allowops jobs output job-20261014-0002 --host host-a --step 0 --stream stdout --json
allowops jobs output job-20261014-0002 --host host-a --step 1 --stream stdout --json
```

输出命令还支持 `--stream stdout|stderr`、`--offset` 和 `--limit`（默认 16384，最大 24576 字节）。JSON 使用 ProtoJSON 格式：bytes 为 Base64，64 位整数为字符串。从 `next_offset` 继续读取，直到 `eof`。表格输出包含原始输出字节；须把这些字节视为不可信数据。

MCP 动作工具使用同一个 job 服务。MCP 工具的输入是 JSON，动作参数放在 `params` 中；带 `host` 的 `jobs_get` 读取输出，组合动作使用 `step_index`。MCP 返回 `data_base64`
和数值类型的 `next_offset`；CLI JSON 返回 ProtoJSON 的 `data` 和字符串类型的 `next_offset`。汇总字段、输出分页和读取提示见 [MCP 工具](mcp.md)。

## 策略和审计 {#policy-and-audit}

```sh
allowops policy get > rules.yaml
allowops policy test -f rules.yaml
allowops policy apply -f rules.yaml --reason 'update policy'
allowops audit export --from 2026-01-01T00:00:00Z \
  --to 2026-02-01T00:00:00Z --output audit.jsonl
allowops audit verify --file audit.jsonl --from-seq 1 --to-seq 100
```

policy get 默认输出可编辑的 YAML；`--json` 包含版本元数据。apply 替换整个规则集，并在保存前执行模拟。审计导出和数据库验证直接读取 `ALLOWOPS_DATABASE_URL`；这些命令不使用网关登录凭据。本地文件验证不需要数据库。审计参数的详细说明见[审计](audit.md)。

## 网关和主机二进制文件 {#gateway-and-host-binaries}

```sh
allowops-gateway migrate
allowops-gateway serve --config /etc/allowops/gateway.yaml
allowops-gateway health --url https://gateway.example.org/health/ready \
  --ca-file /absolute/path/gateway-tls-ca.crt
sudo allowops-agent join --upstream https://gateway.example.org \
  --token-file /absolute/path/join-token.txt --ca-pin "sha256:$ca_pin"
allowops-agent run
allowops-agent status
```

migrate 不接受参数，使用维护数据库凭据。serve 使用运行时凭据，并且必须提供 `--config`。`allowops-agent run` 加载固定路径 `/etc/allowops/agent.yaml`，必须以专用用户运行；通常由 systemd 调用。`status` 报告公开身份以及连接和目录状态。注册是由管理员控制的操作，使用网关 TLS CA 指纹（pin）；`$ca_pin` 的获取方法见[安装](installation.md)。join 要求提供 `--upstream`、`--ca-pin`，并且在 `--token-file`、`--token-stdin`
和旧版 `--token` 中恰好提供一个。文件和 stdin 输入最大 4 KiB，首尾空白会被去除；空输入会被拒绝。优先使用文件或 stdin，因为旧版参数会在进程参数中暴露 token。

`health` 接受 `--url` 和可选的 `--ca-file`，验证 TLS，拒绝重定向，仅在 HTTP 200 时成功。URL 必须使用 HTTPS，路径为 `/health/live` 或 `/health/ready`。存储降级时仍返回 200，因此须单独检查端点的响应正文。health 不需要数据库凭据或登录会话。不要以交互命令方式调用 `allowops-exec`；它是固定路径、只通过 stdin 通信的特权协议端点。
