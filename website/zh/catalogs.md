# 动作目录 {#action-catalogs}

把运维目录保存在经过评审的仓库中。公开示例只是模板。发布前，请针对你的主机评审可执行文件路径、可用程序、权限和允许访问的资源。

```text
catalog.yaml
actions/systemd_service_status.yaml
scripts/                         # only when using signed script actions
```

目录配置文件标识目录，并定义共享的上限：

```yaml
catalog_id: generic-ops
schema_version: 1
defaults:
  timeout: 10s
  max_output: 64KB
  batch_size: 20
  max_failures: 5
redact:
  builtin: [secrets]
```

## 一个动作 {#an-action}

```yaml
name: systemd_service_status
description: Read the status of an allowed systemd service.
risk: read
params:
  service:
    type: enum
    description: Service selected from the signed allowlist.
    values: [nginx, api]
exec: [/usr/bin/systemctl, status, '{service}', --no-pager]
timeout: 10s
max_output: 64KB
filters: [match, exclude, tail, head, count]
max_scan: 256MB
redact:
  builtin: [secrets]
```

名称必须匹配 `^[a-z][a-z0-9_]{0,63}$`。动作名称在当前所有目录中必须全局唯一，且不能使用固定 MCP 工具的名称。描述为必填项。风险取值为 `read`、`write` 或 `dangerous`。风险是策略属性，不能证明操作没有副作用。可选的 `idempotent` 提供 MCP 幂等注解。普通命令省略 `run_as` 时，使用低权限账号执行。需要时，把 `run_as` 设置为经过评审的执行身份。

`exec`、`steps`、`script` 和 `builtin` 必须且只能使用一个。`exec[0]` 是可执行文件的绝对路径。不要在动作中使用 sudo，请使用 `run_as`。只有与 `{parameter_name}` 完全相等的 argv 元素会被替换。其他内容都按字面文本处理。`["--since", "{since}"]` 这样的可选组，在其参数缺失时整组省略。

## 参数类型 {#parameter-types}

每个参数都有描述。`default` 为省略的参数提供值，`optional: true` 允许参数缺失。未知字段、未知参数、缺少必填值和类型错误都会被拒绝。

| 类型 | 约束 |
|---|---|
| `enum` | `values` 是允许列表。 |
| `int` | `min`、`max`；保持整数值。 |
| `string` | `regex`、`max_len`；使用 Go RE2 模式。 |
| `duration` | `max`；默认 `format: go`，也可以是 `seconds`。 |
| `path` | 必填 `allowed_roots`；路径必须在主机上存在。 |
| `url` | 必填 `allowed_prefixes`；用于 HTTP 探测。 |

内置处理程序（builtin）还定义了 `bool` 和 `string_array` 输入。这些输入的 schema 由 allowops 定义。请遵循内置处理程序的定义，不要自行编造处理程序参数。CLI 中的数组使用 JSON 字符串数组，MCP 使用 JSON 数组。

以 `-` 开头的字符串值和路径值会被拒绝。路径解析和符号链接检查在主机上进行。网关校验无法确认路径在远程文件系统上是否存在。大小后缀 KB 和 MB 按 1024 的幂计算。

命令启动前，运行命令的进程会逐个检查每个已解析路径值的组成部分。使用 `run_as` 时，该进程是 root 辅助程序；否则是 agent 本身。检查从 `/` 开始，到最后一个条目结束，且不跟随链接。每个组成部分必须属于 root 或运行命令的用户，不能是符号链接，也不能允许组用户或其他用户写入。设置了 sticky 位的目录（例如 `/tmp`）可以允许组用户或其他用户写入，因为其他用户无法替换不属于自己的条目。这类目录的子条目仍会被检查。不满足上述条件时，动作以 `PATH_NOT_TRUSTED` 被拒绝，错误消息中不包含该路径。该检查防止能在允许根目录内写入的用户在检查之后把某个组成部分替换为符号链接。由此产生的结果是：如果路径位于应用以其他属主写入的目录下，或位于允许组用户或其他用户写入的目录下，该路径会被拒绝。例如，属于某个服务用户且允许组写入的日志目录会被拒绝。请让目录和文件只允许 root 或 run_as 用户写入，或者选择其他 `allowed_roots`。不检查 ACL 和挂载选项。

## 上限和脱敏 {#limits-and-redaction}

设置超时和 `max_output`。涉及扫描时，还要设置 `max_scan`。组合动作的 stdout/stderr 共享一个总输出预算。运行时调用方可以收紧分批和失败数上限，不能提高签名中的上限。stdout 按脱敏、过滤、截断的顺序处理。stderr 先脱敏，再截断。

`secrets` 默认启用，`pii` 为可选项。自定义规则使用 `redact.custom: [{name, regex}]`。动作级的脱敏配置会覆盖全局规则。因此，添加覆盖配置时，需要显式保留 `secrets`。脱敏并不完善。不要定义有意暴露凭据的动作。

在评审和构建之前先进行校验：

```sh
allowops catalog validate examples/catalog
allowops catalog try systemd_service_status --dir examples/catalog --param service=nginx
```

`try` 以当前用户身份在当前机器上执行未签名的内容。它不应用网关策略，也不会提权到 `run_as` 身份。请使用权限合适的受控测试主机。后续内容见[执行能力](execution.md)和[签名与发布](publishing.md)。
