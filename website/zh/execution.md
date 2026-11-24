# 执行能力 {#execution-capabilities}

[目录格式](catalogs.md)支持固定的命令数组，以及常见 shell 操作的有界替代方式。每项能力都是签名动作的一部分。调用方不能动态添加这些能力。

## 输出过滤器 {#output-filters}

声明 `filters: [match, exclude, tail, head, count]` 后，才允许使用这些输入。`match` 和 `exclude` 是最多 200 个字符的 RE2 模式。`tail` 和 `head` 是正整数行数，`count` 是布尔值。`tail`、`head` 和 `count` 按字段是否出现判定互斥，`count: false` 也算出现。MCP 的过滤器是顶层输入，与 `params` 分开。

过滤器作用于每个步骤脱敏后的 stdout。`max_scan` 统计每个步骤原始 stdout 的字节数。扫描上限标志和输出截断标志描述的是不同的上限。系统不保留可供以后读取的未脱敏输出。

## 顺序步骤和备用路径 {#sequential-steps-and-fallback-paths}

`steps` 按声明顺序运行一组带名称的固定 `exec` 数组（线性 DAG，不支持循环或反向跳转）。`on_error` 取值为 `continue` 或 `stop`。所有步骤共用一个动作超时和一个输出预算。最终退出码是第一个失败步骤的退出码；所有步骤均成功或按条件跳过时为零。被跳过的步骤仍然可见，并附带 `skip_reason`：`CONDITION_FALSE`（步骤的 `when` 条件未求值为真）或 `STOPPED`（因前置失败且 `on_error: stop`、超时或取消而停止）。`exec_fallbacks` 在主可执行文件不存在时提供备用的可执行文件绝对路径。它不用于在命令失败后重试。

```yaml
name: host_snapshot
description: Read uptime and memory in separate steps.
risk: read
params: {}
steps:
  - name: uptime
    exec: [/usr/bin/uptime]
  - name: memory
    exec: [/usr/bin/free, -m]
on_error: continue
timeout: 10s
max_output: 64KB
filters: [head, count]
redact:
  builtin: [secrets]
```

### 受控步骤数据传递与条件分支 {#controlled-step-dataflow-and-branching}

步骤可声明 `extract` 从更早步骤脱敏后的 stdout 中提取强类型字段，在后续步骤中以整元素占位符 `{steps.<step_name>.<var>}` 引用，并用声明式 `when` 条件控制是否执行：

- **提取器（`steps[].extract`）**：每个变量三选一声明 `regex`（单捕获组 Go RE2，支持 `match: first | exactly_one`）、`json_path`（严格 `$` 开头字段/下标路径，拒绝重复键，最大嵌套深度 32）或 `tsv`（`line`、`column`、`delimiter: tab | whitespace`），扫描字节受 `max_bytes` 限制（默认 `64KB`，上限 `1MB`）。提取运行在**脱敏之后**、**调用方输出过滤器与预算截断之前**。被脱敏规则修改过的行或 JSON 文档一律拒绝（`EXTRACT_FAILED`），JSON 解码后的标量会再做一次脱敏复检；触发 `max_scan`、管道排空超时或 `max_bytes` 溢出时同样 fail-closed 报错。
- **强类型闸门（`as`）**：提取结果必须满足显式声明的 `as` 类型：`int`（必填 `min` 与 `max`，用于 `exec` 时 `min >= 0`）、`enum`（禁止 `-` 开头的值）、`string`（必填强制整串锚定的 `regex` 与 `max_len` 1..1024）、`path`（`allowed_roots`，经 `EvalSymlinks` 解析并在消费步骤启动前做 `PATH_NOT_TRUSTED` 检查）或 `bool`。类型或前导 `-` 校验失败时即使声明 `optional: true` 也会返回 `EXTRACT_TYPE_INVALID`，且错误消息绝不回显原始值。
- **安全放置边界**：`{steps.*}` 仅允许出现在最终命令的普通参数位置；静态禁止出现在 `exec[0]`、所有包装程序选项与操作数（`env`、`timeout`、`nice`、`ionice`、`stdbuf`、`xargs`、`nsenter`、`chroot`）、`docker`/`kubectl` 全局选项/子命令/连接参数与 `exec` 目标、以及任何 `allow_interpreter: true` 动作中。可选参数组仅在产生步干净成功且 `optional: true` 未命中时省略，否则以 `EXTRACT_MISSING` 失败。
- **条件分支（`steps[].when`）**：第 0 步禁止声明 `when`。支持有界静态布尔组合（`all`、`any`、`not`，最大深度 4、最多 32 个节点），引用更早步骤的确定性事实（`prev.exit_code`、`prev.skipped`、`steps.<name>.exit_code`、`steps.<name>.skipped`、`steps.<name>.<var>`）与类型化运算符（`exists`、`eq`、`ne`、`gt`、`gte`、`lt`、`lte`、`in`）。求值采用 Kleene 三值逻辑（缺失值为 `unknown`，`not unknown` 仍为 `unknown`），仅根节点求值为 `true` 时执行步骤。`when` 是排障流程优化而非授权边界，动作中的每一步都必须在无条件执行时也安全。

```yaml
name: disk_pressure_diagnose
description: Read filesystem usage and list top-level directory sizes when usage reaches 80 percent.
risk: read
params:
  path:
    type: path
    description: Existing directory on the filesystem to diagnose.
    allowed_roots: [/, /var/log, /data]
    default: /
timeout: 20s
max_output: 64KB
on_error: stop
steps:
  - name: check_usage
    exec: [/usr/bin/df, -P, --, '{path}']
    extract:
      use_pct:
        regex: '^\S+\s+[0-9]+\s+[0-9]+\s+[0-9]+\s+([0-9]{1,3})%\s+'
        match: exactly_one
        as: {type: int, min: 0, max: 100}
  - name: top_dirs
    when: {ref: steps.check_usage.use_pct, gte: 80}
    exec: [/usr/bin/du, -x, -h, --max-depth=1, --, '{path}']
filters: []
max_scan: 256MB
redact:
  builtin: [secrets]
```

运行旧版 `allowops-agent` 或 `allowops-exec` 的主机无法加载使用 `extract` 或 `when` 的目录，见[主机必须认识的字段](publishing.md#fields-that-hosts-must-understand)。

## 签名脚本和解释器例外 {#signed-scripts-and-interpreter-exceptions}

`script: {file, interpreter}` 指定目录中的一个脚本和解释器的绝对路径。脚本的字节内容和摘要与动作一起签名。`args` 使用与 `exec` 相同的整元素占位符和可选组。主机把脚本写入私有临时目录，执行后删除。Python 以 `-I` 隔离模式运行。脚本在主机上执行，不在网关上执行。

普通 exec 动作默认拒绝解释器和带 shebang 的脚本。`allow_interpreter: true` 是按动作显式设置的例外，并会产生警告。评审时，应把它视为运行该签名解释器程序的权限。它不能让 AI agent 提供的任意解释器输入变得安全。被包装的命令也会被检查。禁止交互式 TTY 执行。

被包装命令检查的已知限制：

- 由包装程序（`env`、`timeout`、`nice`、`ionice`、`stdbuf`、`xargs`、`nsenter`、`chroot`）启动的目标，只检查 ELF 魔数字节（`\x7fELF`）。不以 `#!` 开头的非 ELF 文件会被拒绝，除非设置了 `allow_interpreter`。
- 以 `\x7fELF` 开头但不是有效 ELF 可执行文件的文件会被接受。在 `/bin/sh` 为 `dash` 的主机上，`execvp` 在遇到 `ENOEXEC` 错误后，可能通过 `sh` 运行这种可执行文本文件。利用这一点的前提是攻击者已经能在主机上写入可执行文件。
- 不带目录的 `nsenter`（`-r`、`--root`），以及 `-a`、`-m`、`--mount[=file]`，会进入主机无法检查的 root 或 mount 命名空间。这些情况下只检查命令名称。当 `<dir>` 是主机自身的根目录时，`-r<dir>` 和 `--root=<dir>` 会在主机上被检查。

## 内置处理程序 {#builtins}

| 内置处理程序 | 行为和边界 |
|---|---|
| `log_search` | 搜索允许的纯文本或 gzip 日志，限制文件数、扫描字节数、匹配数和上下文；路径通配符限定在允许的根目录内。 |
| `mysql_query` | 单条 SELECT/SHOW/DESC/EXPLAIN 语句，只读事务，限制行数、结果字节数和超时。主机凭据保存在属于 root、权限为 0600 的文件中。 |
| `redis_command` | 只读允许列表：GET、MGET、HGET、HLEN、TTL、TYPE、EXISTS、STRLEN、LLEN、SCARD、ZCARD、SCAN 和 INFO。 |
| `http_get` | 在签名的 URL 前缀范围内执行 GET；不跟随重定向；响应大小有上限。 |
| `jvm_perfdata` | 读取允许列表中 JVM（systemd 单元，或 Docker 容器与主类）的 hsperfdata，输出堆、GC、类和线程数据。不 attach，不发信号，不写目标；JVM 参数和系统属性从不输出。 |
| `jvm_arthas` | 每个动作对应一条固定的 Arthas 命令，在允许列表中的 JVM 内执行。L1 命令（12 种）读取状态，不增强任何类。L2 命令 `watch`、`trace`、`stack` 和 `monitor` 对一个类的一个方法名（包含重载，最多 `max_methods` 个）最多增强 30 秒，之后重置；`jad` 反编译一个已加载的类。L2 的类名必须以 `builtin_config.class_prefixes` 中的前缀开头；JDK 和 Arthas 的包一律拒绝。每次调用都会 attach Arthas agent、执行命令，再停止 agent，因此动作为 `risk: write`、`run_as: root`、`max_targets: 1`、`batch_size: 1`；L2 动作按名称单独授权，与 L1 分开。Arthas 文件在目标的挂载命名空间内按 SHA-256 校验。attach 之前的检查（JVM 版本、内存余量、attach 次数和间隔；L2 还包括目标 5 秒内的 CPU）和命令运行期间的监测（CPU、GC、可选的健康检查）可以拒绝或中止调用；`builtin_config` 只能收紧它们的默认值。L2 输出按 `secrets` 和 `pii` 脱敏。增强类的 L2 调用通常需要 40 到 50 秒，超过默认的 MCP 等待时间。主机需要安装 Arthas 软件包；没有它时，该动作报告为 `unsupported`。 |

使用 `builtin_config` 收紧处理程序已定义的上限和资源允许列表。即使省略 `run_as`，数据库处理程序也会使用特权辅助程序读取主机本地凭据，`jvm_perfdata` 使用它读取其他进程的文件，`jvm_arthas` 使用它以 root 身份 attach。不带 `run_as` 的 `log_search` 和 `http_get` 直接以 agent 身份运行。`log_search` 没有匹配时，以及 `http_get` 返回非成功 HTTP 状态时，退出码可能为零。请检查结果和 HTTP 状态，不要只看进程退出码。

不支持的可执行文件或功能会在主机上报告为 `unsupported`。目录加载成功不能证明每个动作都能执行。使用前，请评审源代码仓库中的[示例目录](https://github.com/liubing0806/allowops/tree/main/examples/catalog)和内置处理程序的配置参考。
