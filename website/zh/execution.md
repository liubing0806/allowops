# 执行能力 {#execution-capabilities}

[目录格式](catalogs.md)支持固定的命令数组，以及常见 shell 操作的有界替代方式。每项能力都是签名动作的一部分。调用方不能动态添加这些能力。

## 输出过滤器 {#output-filters}

声明 `filters: [match, exclude, tail, head, count]` 后，才允许使用这些输入。`match` 和 `exclude` 是最多 200 个字符的 RE2 模式。`tail` 和 `head` 是正整数行数，`count` 是布尔值。`tail`、`head` 和 `count` 按字段是否出现判定互斥，`count: false` 也算出现。MCP 的过滤器是顶层输入，与 `params` 分开。

过滤器作用于每个步骤脱敏后的 stdout。`max_scan` 统计每个步骤原始 stdout 的字节数。扫描上限标志和输出截断标志描述的是不同的上限。系统不保留可供以后读取的未脱敏输出。

## 顺序步骤和备用路径 {#sequential-steps-and-fallback-paths}

`steps` 按顺序运行一组带名称的固定 `exec` 数组。`on_error` 取值为 `continue` 或 `stop`。所有步骤共用一个动作超时和一个输出预算。最终退出码是第一个失败步骤的退出码；没有失败步骤时为零。被跳过的步骤仍然可见。`exec_fallbacks` 在主可执行文件不存在时提供备用的可执行文件绝对路径。它不用于在命令失败后重试。

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

使用 `builtin_config` 收紧处理程序已定义的上限和资源允许列表。即使省略 `run_as`，数据库处理程序也会使用特权辅助程序读取主机本地凭据。不带 `run_as` 的 `log_search` 和 `http_get` 直接以 agent 身份运行。`log_search` 没有匹配时，以及 `http_get` 返回非成功 HTTP 状态时，退出码可能为零。请检查结果和 HTTP 状态，不要只看进程退出码。

不支持的可执行文件或功能会在主机上报告为 `unsupported`。目录加载成功不能证明每个动作都能执行。使用前，请评审源代码仓库中的[示例目录](https://github.com/liubing0806/allowops/tree/main/examples/catalog)和内置处理程序的配置参考。
