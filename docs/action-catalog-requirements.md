# action 目录需求

## 1. 范围与依据

allowops 只执行运维人员预先定义、评审并签名的 action。本节点提供公开示例的需求和 YAML，不实现执行器，不生成已签名目录包。

依据为 `design.md` 第 4、5 节及扩展执行能力表，`architecture-decisions.md` 第 9、13、18、20、21 节。AC1B 按 `internal/catalog/`、`internal/params/`、`internal/builtin/` 和 `internal/executor/` 的实际字段与行为对齐。本文与 `examples/catalog/actions/` 一一对应，共 83 个 action，均为 risk: read；2026-10-22 起删除了 docker_stop、process_signal 两个写操作，并按 `action-usage-analysis.md` 第 6.5 节新增 34 个只读 action（含替换 dns_lookup 的定义）。

第 18 节的 19 个名称与使用分析的 39 个名称合并。重复名称共 7 个：`process_top`、`ports_listening`、`log_tail_file`、`docker_ps`、`docker_stats`、`docker_container_state`、`docker_logs`。同名定义按使用分析第 4 节合并，`ports_listening`、`log_tail_file` 增加 D1，`docker_logs` 增加 D1 和可选 until；其他同名定义保留对应用途。没有需要改名的冲突。

`disk_usage_paths` 查询路径所在文件系统容量，`disk_dir_size` 统计目录文件大小，两者保留。`log_search_dir` 使用固定 grep 检索未压缩目录，`log_search` 使用内置处理器检索普通和 gzip 文件，两者保留。第 20 节 D3 已取代第 18 节“压缩日志不在 MVP”的旧限制；本目录包含 gzip 日志检索需求，不使用 zgrep。

内置处理器的正式参数和配置 schema（字段结构及校验规则）由 `internal/catalog/builtin.go` 和 `builtin_adapters.go` 定义。P12D 已实现 G30 的 Redis/MySQL 收紧配置，语义见 `builtin-config.md`（含 G31、G34）；四个示例已恢复命令、键前缀、分区和库范围限制。内置参数默认值的剩余缺口见第 4 节。目录校验不检查目标主机的工具、凭据文件或外部服务，不据此宣称这些环境可执行全部 action。

## 2. 目录与通用规则

```text
examples/catalog/catalog.yaml
examples/catalog/actions/<name>.yaml
examples/catalog/scripts/nginx_access_stats.py
test/examples/check_examples.py
```

`catalog_id` 为 `generic-ops`，`schema_version: 1` 是当前唯一受支持的版本。默认值和全局规则如下，actions 中的同名字段更具体。依据：`internal/catalog/catalog.go` 的 `Config`、`Defaults`、`validateConfig`、`applyDefaults`。

| 字段 | 默认值 |
|---|---|
| timeout | 10s |
| max_output | 64KB |
| batch_size | 20 |
| max_failures | 5 |
| redact.builtin | [secrets] |

大小字段支持 KB、MB、GB（1024 进制）或整数字节，不接受 KiB、MiB、GiB；依据：`internal/catalog/size.go` 的 `ParseSize`。输出处理的 `max_scan` 位于 action 顶层，省略或为 0 时由 `internal/executor/executor.go` 的 `DefaultMaxScan` 提供 256MB，不能放入 `defaults`。日志输入扫描另有 `builtin_config.max_scan`。输出扫描上限只用于 stdout 处理，不能代替外部命令的输入扫描限制。日志内置处理器和签名脚本另外限制输入扫描量。每个 action 的 YAML 显式给出 timeout、max_output、filters、redact；写操作将 batch_size、max_failures 收紧为 1。本文所列兼容性是目标需求和已知工具条件，没有执行 CentOS 7 或远程环境验证。

### 命名、参数和执行

- name 匹配 `^[a-z][a-z0-9_]{0,63}$`，文件名与 name 一致。保留工具名不得用于 action。action 和每个参数的 description 必填；示例 YAML 的 description 使用英文。
- 执行方式恰好为 exec、steps、script、builtin 之一。exec 的首项及 exec_fallbacks 均为绝对路径；exec 不含提权命令，提权仅通过 run_as。省略 run_as 时使用 allowops 用户。
- 参数只替换完整 argv 元素 `{param}`。可选项使用子列表，缺失时省略整组；Go 格式模板按字面值传递。不执行 shell，不拼接选项或路径。
- string、path 拒绝以连字符开头的值。未知参数、缺失必填值或类型错误一律拒绝。path 必须存在，解析符号链接后按路径分量检查 allowed_roots；它不单独拒绝所有 `..` 写法。内置 log_search 额外拒绝 `..` 分量；依据：`internal/params/params.go` 的 `ResolvePath`、`internal/builtin/logsearch/logsearch.go` 的 `files`。
- 包装命令后真正执行的命令也必须通过解释器检查。Docker 示例不分配 TTY（终端）；不启用解释器覆盖。签名脚本是 D6 明确允许的例外，主机端须使用 Python -I。
- 每次执行清空环境，仅保留设计指定的变量；应用总超时并结束整个进程组。不要增加 journal 或 Docker 用户组。
- 文件读取的需求只授权普通文件或目录，不授权 FIFO、设备、socket 等特殊文件。通用 path schema 不能表达文件种类，外部文件命令仍有检查与打开之间的竞争风险，见第 4 节第 8 项。容器目录使用枚举，避免把主机 path 校验误用于容器。
- 内置参数由处理器提供，YAML 的 `params` 仅增加 string/string_array 正则或缩短字符串长度，不改类型、枚举、默认值、可选性或数值范围。内置示例的 `params: {}` 仍接受处理器参数；依据：`internal/catalog/builtin.go` 的 `ParameterDefinitions`。可选内置参数不重复声明，避免 `internal/executor/executor.go` 的二次参数校验要求显式提供它。

### 输出过滤与脱敏

filters 是允许 agent 传入的过滤参数集合，`[]` 表示不允许过滤。D1 的 match、exclude 使用 Go RE2，最多 200 字符；head、tail 为正整数行数，没有额外固定上限；count 是布尔值，为 true 时返回匹配行数。tail、head、count 互斥，即使 count=false 也算传入 count；match、exclude 可与其中之一组合。依据：A17、`internal/executor/filters.go` 的 `ParseFilters`、`parseLineCount`。

处理顺序为 stdout → 脱敏 → match/exclude → head/tail/count → 截断。过滤不能查询未脱敏内容；stderr 脱敏并截断，不过滤。组合 action 按步骤 stdout 独立过滤，所有步骤的 stdout+stderr 共用 max_output；普通 exec/script/builtin 的 stdout、stderr 分别受 max_output 限制。max_scan 按每个步骤 stdout 原始字节计，超限报告 scan_limit_reached；输出或处理器资源上限报告 truncated，处理器另报告 resource_limit_reached。依据：A13、A17、`internal/executor/executor.go` 的 `RunWithFilters`、`processOutput`、`runCommand`。上述任一上限标记均表示结果可能不全。

所有示例保留 secrets。日志、文件内容、数据库值等额外启用 pii。action 的 redact 覆盖全局规则，因此覆盖时仍显式保留 secrets；没有示例关闭脱敏。secrets 包含第 20 节 D9 的数据库命令行及环境变量规则。pii 可能误伤数字标识，正则不能识别所有敏感内容；此目录不声称输出能全部去敏。设计规定运行时 IP 地址和主机名不脱敏，公开示例不包含任何实际环境数据。

### 目录签名和权限

脚本内容的 SHA-256 必须计入 action 摘要。目录使用 DSSE（签名信封格式）和 ed25519 签名；版本单调递增，主机端检查过期、防回退和 task 摘要一致性。签名私钥与数据库凭据不进入目录。数据库示例中的 credential 仅为通用主机端文件路径，文件由 root 管理、权限 0600。

Kubernetes 示例固定读取 `/etc/kubernetes/allowops-readonly.conf`。此文件由运维人员配置，只授予所需的读取权限；禁止可执行认证插件。JVM 示例选择 Docker 容器作为一种明确执行环境，不在同一个 action 中引入未定义的 Docker/Pod 条件分支。

## 3. action 需求

### `app_config_grep`

按键名模式读取一个 properties 文件的匹配行，敏感值脱敏。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii，另有自定义规则 sensitive_property |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU grep 支持 -E、-i、-m、-e 和 --。 |
| 安全说明 | 模式只允许字母、数字、下划线、连字符、转义点和竖线，不能表达 `=`、锚点、通配符，最多 100 字符；以 -e 传入。内置 secrets 只覆盖 `password`、`secret`、`token` 后接 `=` 的写法，`db_password`、`app.secretKey`、`jwt.secret: x`、`access_key` 等不会被脱敏，因此增加自定义规则：键名中含 pass、pwd、secret、token、key、credential 且后接 `=` 或 `:` 时，整行（含键名）替换为 [REDACTED:sensitive_property]。限制：grep 的模式匹配整行而不是只匹配键名，传入值中的片段仍可用于判断某行是否存在；多行值、续行（反斜线）和不含敏感词的键下的敏感值不会被识别；match 过滤在脱敏之后执行。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/etc/app', '/opt/app/config']`；必填 | 已存在且解析后位于允许根目录内的 properties 文件 |
| `pattern` | string | `regex: ^([A-Za-z0-9_-]\|\\\.)+(\\\|([A-Za-z0-9_-]\|\\\.)+)*$`；`max_len: 100`；必填 | 不区分大小写的键名模式 |
| `max_matches` | int | `min: 1`；`max: 500`；默认 `100` | 最大匹配行数 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/grep, -E, -i, -m, '{max_matches}', -e, '{pattern}', --, '{path}']
```

### `app_config_keys`

只输出一个 properties 文件的键名，不输出值。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU grep 支持 -o、-E、-e 和 --。 |
| 安全说明 | 使用 `grep -o` 只输出每行开头的键名字符（字母、数字、下划线、点、连字符），注释行和值不会输出；比 `cut -d= -f1` 更严格，后者会输出整行注释。路径解析后检查允许根目录。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/etc/app', '/opt/app/config']`；必填 | 已存在且解析后位于允许根目录内的 properties 文件 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/grep, -o, -E, -e, '^[A-Za-z0-9_.-]+', --, '{path}']
```

### `connections_by_port`

查看一个 TCP 端口相关的连接。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 iproute ss 支持端口过滤表达式；实际选项解析需目标版本验证。 |
| 安全说明 | ss 表达式结构全部固定，只有两个完整 argv 元素替换同一个整数端口；无自由表达式或 shell 解析。root 用于显示进程名。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `port` | int | `min: 1`；`max: 65535`；必填 | TCP 源端口或目标端口 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/sbin/ss, -tnp, (, sport, '=', '{port}', or, dport, '=', '{port}', )]
```

### `crontab_list`

查看预定义操作系统账号的 crontab。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需安装 cronie；没有 crontab 时命令可能返回非零退出码。 |
| 安全说明 | 仅允许 app、nginx，不开放编辑、安装或删除 crontab；读取的命令文本可能含敏感值，输出需脱敏。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `user` | enum | `values: ['app', 'nginx']`；必填 | 预定义操作系统账号 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/crontab, -l, -u, '{user}']
```

### `disk_dir_size`

查看单个允许目录内文件占用的总大小。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | 无（基础 exec） |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU du 支持 -sh 和 --。 |
| 安全说明 | 路径必须存在，解析符号链接后检查 /var/log 或 /data 根目录；-- 防止路径被解释为选项。扫描耗时由超时约束。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data']`；必填 | 已存在且解析后位于允许根目录内的路径 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/du, -sh, --, '{path}']
```

### `disk_usage`

查看文件系统容量，排除临时文件系统。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU df 支持这些选项。 |
| 安全说明 | 固定 df 参数，不接受挂载操作或任意命令。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/df, -h, -x, tmpfs, -x, devtmpfs]
```

### `disk_usage_paths`

查看允许路径所在文件系统的容量；多路径通过多次调用完成。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU df 支持 -h 和 --。 |
| 安全说明 | 路径解析后检查 /var/log 或 /data；只查询所在文件系统容量，避免引入未定义的数组参数。与 disk_dir_size 的目录文件大小统计不同。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data']`；必填 | 已存在且解析后位于允许根目录内的路径 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/df, -h, --, '{path}']
```

### `dns_lookup`

使用主机名称解析配置查询一个主机名。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | 无（基础 exec） |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 glibc getent 支持 hosts 数据库；使用系统 NSS 配置，不要求额外 DNS 工具。 |
| 安全说明 | 主机名由正则限定为 RFC 1123 风格（标签以字母或数字开头和结尾，每个标签不超过 63 字符，总长不超过 253），不允许以连字符开头，因此不会被 getent 当成选项。该规则也允许点分数字形式。解析可能读取 hosts 或 DNS，取决于主机 NSS 配置。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `name` | string | `regex: ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`；`max_len: 253`；必填 | RFC 1123 风格主机名，不以连字符开头 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/getent, hosts, '{name}']
```

### `docker_app_config_grep`

在允许的容器内按键名模式读取一个 properties 文件的匹配行，敏感值脱敏。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii，另有自定义规则 sensitive_property |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI；容器内需有 grep。docker exec 不分配 TTY。 |
| 安全说明 | 容器名使用签名枚举。容器内路径无法在主机检查，用正则约束：限定三个根目录，每个路径段以非点字符开头，因此无 `..` 和隐藏目录段。容器内的符号链接无法由主机检查，只读取容器内 grep 的 -- 之后的单个文件。模式规则和脱敏规则同 `app_config_grep`，限制也相同。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: [api, app]`；必填 | 签名允许列表中的容器 |
| `path` | string | `regex: ^/(etc/app\|opt/app/config\|app/config)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+$`；`max_len: 200`；必填 | 容器内允许目录下的绝对文件路径 |
| `pattern` | string | `regex: ^([A-Za-z0-9_-]\|\\\.)+(\\\|([A-Za-z0-9_-]\|\\\.)+)*$`；`max_len: 100`；必填 | 不区分大小写的键名模式 |
| `max_matches` | int | `min: 1`；`max: 500`；默认 `100` | 最大匹配行数 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', grep, -E, -i, -m, '{max_matches}', -e, '{pattern}', --, '{path}']
```

### `docker_container_ls_dir`

查看应用容器内预定义目录的直接内容。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | D4 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 容器中需有 ls 二进制。 |
| 安全说明 | Docker 包装命令后的执行目标固定为 ls，禁止解释器和 TTY；容器目录使用枚举，因为主机 path 校验不能校验容器文件系统。目录挂载和链接需运维审核。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `directory` | enum | `values: ['/var/log', '/data/logs', '/etc/nginx']`；必填 | 容器内固定目录，使用枚举而非主机 path 类型 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', ls, -lah, --, '{directory}']
```

### `docker_container_state`

查看指定容器的 State 字段。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | 无（基础 exec） |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 |
| 安全说明 | 容器名按受限正则校验；只返回 State，避免完整 inspect 中的环境变量和挂载配置。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | string | `regex: ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`；`max_len: 64`；必填 | 受限 Docker 容器名 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, inspect, --format, '{{json .State}}', '{container}']
```

### `docker_dns_lookup`

在预定义应用容器内使用 getent 解析一个主机名。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | D4 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；/usr/bin/docker 缺失时标记 unsupported。容器镜像中需有 getent（glibc 镜像自带；部分精简镜像没有，此时命令返回非零退出码）。 |
| 安全说明 | Docker 包装命令后的执行目标固定为 getent hosts，禁止 TTY 与解释器；容器使用枚举，主机名由正则限定且不以连字符开头。解析结果反映容器自己的 /etc/hosts、DNS 配置和 NSS 设置，可能与主机不同。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `name` | string | `regex: ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`；`max_len: 253`；必填 | RFC 1123 风格主机名，不以连字符开头 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', getent, hosts, '{name}']
```

### `docker_file_grep`

在应用容器内按固定字符串检索一个文件，限制匹配数。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D4 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。容器内需有支持 -F、-n、-m、-e 的 grep（GNU grep 或 busybox grep）。无匹配时 grep 退出码为 1，action 报告失败。 |
| 安全说明 | Docker 包装命令后的执行目标固定为 grep，禁止解释器和 TTY；模式使用 -e，路径前使用 --，两者均不会被当作选项。容器内路径无法在主机检查，使用锚定正则限制在固定根目录内，且每个路径段以非点字符开头，无法出现 .. 段。正则不能阻止容器内已有的符号链接：根目录内指向其他位置的链接会被 grep 跟随（实测 /var/log/app/pw.log -> /etc/passwd 可读，只限该容器文件系统，不涉及主机）。输出先脱敏再过滤。脱敏只匹配 password、secret、token 后紧跟等号的形式，`secret: value`、`client_secret=value`、`api_key=value` 不被脱敏，评审时须确认允许根目录内的文件格式。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `path` | string | `regex: ^/(var/log\|data/logs\|etc/nginx)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+$`；`max_len: 256`；必填 | 容器内固定根目录下的绝对文件路径，无点段 |
| `pattern` | string | `regex: ^[^\r\n]+$`；`max_len: 200`；必填 | 不含换行的固定检索字符串 |
| `max_matches` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 匹配行数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', grep, -F, -n, -m, '{max_matches}', -e, '{pattern}', --, '{path}']
```

### `docker_file_view`

读取应用容器内固定根目录下一个文件的开头，限制行数。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D4 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。容器内需有支持 -n 和 -- 的 head。 |
| 安全说明 | Docker 包装命令后的执行目标固定为 head，禁止解释器和 TTY；路径前使用 --。容器内路径无法在主机检查，使用锚定正则限制在固定根目录内，每个路径段以非点字符开头，无法出现 .. 段。正则不能阻止容器内已有的符号链接：根目录内指向其他位置的链接会被 head 跟随（实测 /var/log/app/pw.log -> /etc/passwd 可读，只限该容器文件系统，不涉及主机）。最多读取 500 行，输出由 max_output 限制为 64KB。脱敏只匹配 password、secret、token 后紧跟等号的形式，`secret: value`、`client_secret=value`、`api_key=value` 不被脱敏，评审时须确认允许根目录内的文件格式。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `path` | string | `regex: ^/(var/log\|data/logs\|etc/nginx)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+$`；`max_len: 256`；必填 | 容器内固定根目录下的绝对文件路径，无点段 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', head, -n, '{lines}', --, '{path}']
```

### `docker_info_logging`

查看 Docker 默认日志驱动。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | 无（基础 exec） |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 |
| 安全说明 | 固定格式只返回 LoggingDriver，不开放完整 info。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, info, --format, '{{.LoggingDriver}}']
```

### `docker_inspect_config`

查看一个容器的镜像、创建时间、重启次数、网络模式、挂载、ExtraHosts 和环境变量名。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；Go 模板函数 split 和 json 须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 |
| 安全说明 | 使用 `--type container` 避免匹配同名镜像。Go 模板只取 Config.Image、Image、Created、RestartCount、HostConfig.NetworkMode、Mounts、HostConfig.ExtraHosts，Config.Env 经 `split . "="` 只保留 `=` 之前的键名，不输出值。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | string | `regex: ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`；`max_len: 64`；必填 | 受限 Docker 容器名 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, inspect, --type, container, --format,
  'Image: {{.Config.Image}} {{.Image}}{{"\n"}}Created: {{.Created}}{{"\n"}}RestartCount: {{.RestartCount}}{{"\n"}}NetworkMode: {{.HostConfig.NetworkMode}}{{"\n"}}Mounts: {{json .Mounts}}{{"\n"}}ExtraHosts: {{json .HostConfig.ExtraHosts}}{{"\n"}}EnvNames:{{range .Config.Env}} {{index (split . "=") 0}}{{end}}',
  '{container}']
```

### `docker_jar_list_entries`

列出容器内应用目录下一个 jar 的条目名。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D4 |
| 执行限制 | timeout=20s；max_output=128KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；/usr/bin/docker 缺失时标记 unsupported。容器内须有 jar（JDK 自带；仅有 JRE 的镜像不可用）（容器内命令按名称查找，无法在主机检查）。 |
| 安全说明 | 固定 jar tf，只读取 jar 目录，不解包、不写文件。jar 参数用带锚点的正则限定在 /app、/opt/app、/data/app 下且以 .jar 结尾，每个路径段首字符不是点和连字符，不会出现 .. 段，也不会被当成选项。符号链接在容器内无法检查，应用目录内的链接仍可指向容器内其他 jar 文件，只读且后缀限定为 .jar。输出为条目名，仍启用 secrets 脱敏。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `jar` | string | `regex: ^/(app\|opt/app\|data/app)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+\.jar$`；`max_len: 200`；必填 | 应用目录下的 jar 文件路径（容器内路径，正则限定） |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', jar, tf, '{jar}']
```

### `docker_jar_read_entry`

读取容器内一个 jar 中的 application 配置条目，输出脱敏，不写文件。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii；自定义规则 config_secret |
| 扩展能力 | D1、D4 |
| 执行限制 | timeout=15s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；/usr/bin/docker 缺失时标记 unsupported。容器内须有 unzip（JDK 镜像通常没有：eclipse-temurin 和 CentOS 7 JDK 镜像无 unzip，openjdk:8 的 Debian 镜像有，alpine 的 busybox unzip 支持 -p）（容器内命令按名称查找，无法在主机检查）。 |
| 安全说明 | unzip -p 把条目写到标准输出，不落盘；不使用 jar xf。entry 参数限定为 application*.properties、application*.yml、application*.yaml，可带 BOOT-INF/classes/ 前缀，不含通配符、斜线和 .. 。输出先经 secrets、pii 内置规则和自定义规则 config_secret（键名含 password、passwd、pwd、secret、token、credential、private-key、access-key、api-key，分隔符为 = 或 :，整行键值替换）脱敏，再过滤。多行值（YAML 块标量、properties 续行）的后续行不会被脱敏；脱敏不能保证识别所有敏感内容。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `jar` | string | `regex: ^/(app\|opt/app\|data/app)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+\.jar$`；`max_len: 200`；必填 | 应用目录下的 jar 文件路径（容器内路径，正则限定） |
| `entry` | string | `regex: ^(BOOT-INF/classes/)?application[A-Za-z0-9_.-]*\.(properties\|yml\|yaml)$`；`max_len: 120`；必填 | jar 内的 application*.properties、application*.yml、application*.yaml 条目名，可带 BOOT-INF/classes/ 前缀 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', unzip, -p, '{jar}', '{entry}']
redact:
  builtin: [secrets, pii]
  custom:
    - name: config_secret
      regex: '(?i)[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|credentials?|private[_.-]?key|access[_.-]?key|api[_.-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*(?:"[^"\r\n]*"|''[^''\r\n]*''|[^\s#]*)'
```

### `docker_java_class_members`

用 javap -p 列出容器内应用目录下 jar 中一个类的成员声明。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D4 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；/usr/bin/docker 缺失时标记 unsupported。容器内须有 javap（JDK 自带；仅有 JRE 的镜像不可用）（容器内命令按名称查找，无法在主机检查）。 |
| 安全说明 | 固定 javap -p，不开放 -c、-v、-constants 等选项：-c 的字节码输出含字符串常量（实测 `ldc ... // String <常量值>` 不会被 secrets 规则脱敏），因此不提供。classpath 只能是一个 jar 或一个目录通配（/app/lib/*），不接受冒号分隔的列表；类名用 Java 全限定名正则，末段不能是 class（javap 会把 xxx.class 当作文件路径读取容器内当前目录的文件）。javap 会按 jar 清单的 Class-Path 加载其他 jar，仅读取。成员声明含字段名和类型，不含常量值。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `classpath` | string | `regex: ^/(app\|opt/app\|data/app)(/[A-Za-z0-9_][A-Za-z0-9._-]*)*/(\*\|[A-Za-z0-9_][A-Za-z0-9._-]*\.jar)$`；`max_len: 200`；必填 | 一个 jar 或一个应用库目录通配（容器内路径，正则限定） |
| `class_name` | string | `regex: ^(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*(?:[A-Za-bd-z_$][A-Za-z0-9_$]*\|c(?:[A-Za-km-z0-9_$][A-Za-z0-9_$]*)?\|cl(?:[A-Zb-z0-9_$][A-Za-z0-9_$]*)?\|cla(?:[A-Za-rt-z0-9_$][A-Za-z0-9_$]*)?\|clas(?:[A-Za-rt-z0-9_$][A-Za-z0-9_$]*)?\|class[A-Za-z0-9_$]+)$`；`max_len: 200`；必填 | Java 全限定名；嵌套类用美元符；末段不能是 class |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', javap, -p, -classpath, '{classpath}', '{class_name}']
```

### `docker_logs`

读取容器日志末尾行，可指定 since 和 until。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 --until 依赖 Docker API 1.35+；旧版本需省略 until，并在目标版本验证。 |
| 安全说明 | 容器名正则、最多 500 行、固定时间戳输出；不提供 follow。时间选用相对 duration，避免自由格式解析。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | string | `regex: ^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`；`max_len: 64`；必填 | 受限 Docker 容器名 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |
| `since` | duration | `max: 24h`；`format: go`；可选 | 起始日志相对当前时间的最大年龄 |
| `until` | duration | `max: 24h`；`format: go`；可选 | 结束日志相对当前时间的最大年龄 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, logs, --tail, '{lines}', --timestamps, [--since, '{since}'], [--until, '{until}'], '{container}']
```

### `docker_ps`

查看全部 Docker 容器摘要。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 |
| 安全说明 | 固定 ps 和格式模板，不返回完整 inspect 的环境变量；模板是字面值，不是参数占位符。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, ps, --all, --format, '{{json .}}']
```

### `docker_stats`

读取 Docker 资源指标单次样本。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 |
| 安全说明 | 固定 --no-stream，避免无限输出；不开放 Docker 其他子命令。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, stats, --no-stream, --format, '{{json .}}']
```

### `dubbo_qos_get_address`

查询一个 Dubbo 服务当前可用的提供者地址。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/getAddress/{service}`；Dubbo 要求 PRIVATE 权限，默认只有来自回环地址的请求可执行；allowops 在主机上访问 127.0.0.1 满足该条件。allowed_prefixes 只含 `http://127.0.0.1:22222/getAddress`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。提供者 URL 可能带 token 参数，secrets 规则会脱敏 `token=` 起至空白前的内容（范围偏大，不会遗漏）。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/getAddress']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/getAddress/org.example.api.DemoService` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/getAddress']
  headers:
    Accept: application/json
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_get_config`

导出 Dubbo 应用当前生效的配置。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii, 自定义规则 json_credential |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/getConfig`；Dubbo 要求 PRIVATE 权限，默认只有来自回环地址的请求可执行；allowops 在主机上访问 127.0.0.1 满足该条件。allowed_prefixes 只含 `http://127.0.0.1:22222/getConfig`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。响应是 JSON，内置 secrets 规则只匹配 `key=value` 形式，不匹配 `"password": "值"`，因此增加自定义规则 json_credential；本地样例中 password、token、secret 键值和 URL 内嵌密码均已脱敏。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/getConfig']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/getConfig` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/getConfig']
  headers:
    Accept: application/json
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_live`

检查 Dubbo 进程存活状态。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/live`；Dubbo 为该命令开放匿名访问（PUBLIC）。allowed_prefixes 只含 `http://127.0.0.1:22222/live`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。输出不含凭据。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/live']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/live` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/live']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_logger_info`

查看 Dubbo 当前日志适配器和日志级别。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/loggerInfo`；Dubbo 要求 PROTECTED 权限，回环地址请求可执行。allowed_prefixes 只含 `http://127.0.0.1:22222/loggerInfo`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。输出不含凭据。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/loggerInfo']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/loggerInfo` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/loggerInfo']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_ls`

列出 Dubbo 提供者和消费者服务。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/ls`；Dubbo 要求 PROTECTED 权限，回环地址请求可执行。allowed_prefixes 只含 `http://127.0.0.1:22222/ls`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。输出不含凭据。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/ls']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/ls` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/ls']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_ps`

查看 Dubbo 服务监听端口。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/ps`；Dubbo 要求 PROTECTED 权限，回环地址请求可执行。allowed_prefixes 只含 `http://127.0.0.1:22222/ps`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。输出不含凭据。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/ps']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/ps` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/ps']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_ready`

检查 Dubbo 服务就绪状态。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/ready`；Dubbo 为该命令开放匿名访问（PUBLIC）。allowed_prefixes 只含 `http://127.0.0.1:22222/ready`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。输出不含凭据。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/ready']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/ready` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/ready']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_startup`

检查 Dubbo 启动完成状态。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/startup`；Dubbo 为该命令开放匿名访问（PUBLIC）。allowed_prefixes 只含 `http://127.0.0.1:22222/startup`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。输出不含凭据。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/startup']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/startup` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/startup']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `dubbo_qos_version`

查看运行中的 Dubbo 框架版本。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置 HTTP 客户端不依赖 curl；目标主机的 Dubbo QoS 默认监听 22222 端口（QoS 开启且未改端口时），目标版本未验证。 |
| 安全说明 | 只读 GET `/version`；Dubbo 要求 PROTECTED 权限，回环地址请求可执行。allowed_prefixes 只含 `http://127.0.0.1:22222/version`，按路径分量匹配，`/online` 等其他命令、`..` 路径和其他端口均被拒绝。Dubbo QoS 的写操作命令（online、offline、shutdown 等）同样可用 GET 触发，因此前缀限定到单个命令。输出不含凭据。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://127.0.0.1:22222/version']`；必填，无默认值 | GET URL，例如 `http://127.0.0.1:22222/version` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://127.0.0.1:22222/version']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `file_find`

在允许的根目录下按名称查找普通文件，限制目录深度。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU find 支持 -maxdepth、-type、-name。 |
| 安全说明 | 根目录使用枚举；maxdepth 为 1 到 4 的整数；-type f 固定，不输出目录和符号链接；-name 的 glob 由正则限制为字母、数字、点、下划线、连字符、星号和问号，长度最多 64，且不能以连字符开头，因此不会注入 -delete、-exec 等动作，也不含方括号和路径分隔符。只输出文件路径，不读取文件内容。输出行数由 max_output、max_scan 和过滤器限制。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `root` | enum | `values: ['/var/log', '/data/logs', '/etc/nginx']`；必填 | 预定义查找根目录 |
| `depth` | int | `min: 1`；`max: 4`；必填（有默认值时可省略）；默认 `2` | 根目录以下的最大目录深度 |
| `glob` | string | `regex: ^[A-Za-z0-9_*?.-]{1,64}$`；`max_len: 64`；必填 | 文件名 glob |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/find, '{root}', -maxdepth, '{depth}', -type, f, -name, '{glob}']
```

### `file_list`

查看允许目录的直接内容。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU ls 支持 -lah 和 --。 |
| 安全说明 | 路径解析后检查 /var/log、/data/logs、/etc/nginx；固定非递归列表，不开放任意文件系统根目录。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data/logs', '/etc/nginx']`；必填 | 已存在且解析后位于允许根目录内的路径 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/ls, -lah, --, '{path}']
```

### `file_view`

读取允许文件的开头，限制读取行数和返回字节数。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU head 支持 -n 和 --。 |
| 安全说明 | 最多读取 500 行，返回输出由 max_output 限制为 64KB；max_scan 和超时限制输出处理工作量。路径解析后检查日志和 nginx 配置目录。允许普通文件的约束如何表达见待确认。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data/logs', '/etc/nginx']`；必填 | 已存在且解析后位于允许根目录内的路径 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/head, -n, '{lines}', --, '{path}']
```

### `host_snapshot`

顺序读取主机名、时间、负载、内存、磁盘、失败的 systemd 单元、监听端口和容器摘要。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | steps |
| filters | [] |
| redact | secrets |
| 扩展能力 | D2 |
| 执行限制 | timeout=30s；max_output=128KB |
| CentOS 7 | CentOS 7 的系统命令支持所用选项；Docker 步骤另需 Docker。任一步骤程序缺失时整个 action 为 unsupported；依据：internal/catalog/host.go 的 CheckHost。 |
| 安全说明 | 每一步都是固定只读 argv，共享 root 身份和总超时；全部程序可用后，on_error: continue 保留失败步骤之后的输出和各步退出码。它不能绕过执行前的主机能力检查。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
on_error: continue
steps: [{name: hostname, exec: [/usr/bin/hostname]}, {name: time, exec: [/usr/bin/date, --iso-8601=seconds]}, {
    name: load, exec: [/usr/bin/uptime]}, {name: memory, exec: [/usr/bin/free, -m]}, {name: disk, exec: [/usr/bin/df,
      -h, -x, tmpfs, -x, devtmpfs]}, {name: failed_units, exec: [/usr/bin/systemctl, --failed, --no-pager]}, {name: ports,
    exec: [/usr/sbin/ss, -ltnp]}, {name: containers, exec: [/usr/bin/docker, ps, --all, --format, '{{json .}}']}]
```

### `hosts_entries`

读取主机 /etc/hosts 条目，可用 match 过滤。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 coreutils cat 支持 --。 |
| 安全说明 | 路径固定为 /etc/hosts，无参数；使用 match、exclude 等过滤选择条目。运行时 IP 地址和主机名不脱敏，因此未启用 pii。 |

参数：

无参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/cat, --, /etc/hosts]
```

### `http_get_local`

使用 GET 探测本机通用服务健康端点。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D8 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | D8 内置 HTTP 客户端不依赖 CentOS 7 的 curl；当前代码已注册 url 类型和 http_get，目标主机的运行兼容性未验证。 |
| 安全说明 | 只允许固定 localhost 服务的同源路径前缀，不接受请求头参数、URL 用户信息或重定向；响应体上限为 64KB，响应头上限为 64KB。DNS 解析后没有独立地址白名单检查，见第 4 节第 3 项。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `url` | url | 由 builtin_config.allowed_prefixes 提供 `['http://localhost:8080/health']`；必填，无默认值 | 受签名前缀约束的本机健康 URL |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: http_get
builtin_config:
  allowed_prefixes: ['http://localhost:8080/health']
  headers:
    Accept: text/plain
  timeout: 5s
  max_response_bytes: 64KB
```

### `journal_grep`

使用 journalctl 的内置模式选项检索服务日志。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | journalctl -g 需要 systemd 237+；CentOS 7 的默认 systemd 不支持，此 action 不兼容。CentOS 7 可改用 journal_view_log 的 D1 match 过滤，但只检索已读取的末尾行。 |
| 安全说明 | 正则作为独立 argv，禁止换行，长度不超过 200；固定日志行数并限制执行时间，防止无限扫描。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `service` | enum | `values: ['nginx', 'api']`；必填 | 预定义服务名 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |
| `since` | string | `regex: ^[0-9]{1,3} (min\|hour) ago$`；`max_len: 16`；必填 | 必填相对起始时间 |
| `pattern` | string | `regex: ^[^\r\n]+$`；`max_len: 200`；必填 | 不含换行的检索模式 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/journalctl, -u, '{service}', --since, '{since}', -n, '{lines}', --no-pager, -g, '{pattern}']
```

### `journal_view_log`

查看服务 journal 末尾日志，可收紧起始时间。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 journalctl 支持 -u、-n、--since、--no-pager。 |
| 安全说明 | 服务枚举、行数上限和相对时间正则限制输入；root 用于读取 journal，不给 allowops 增加 journal 组。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `service` | enum | `values: ['nginx', 'api']`；必填 | 预定义服务名 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |
| `since` | string | `regex: ^[0-9]{1,3} (min\|hour) ago$`；`max_len: 16`；可选 | 日志相对起始时间 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/journalctl, -u, '{service}', -n, '{lines}', --no-pager, [--since, '{since}']]
```

### `jvm_gc_stats`

查看容器内 JVM 垃圾回收指标有限样本。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | D4 |
| 执行限制 | timeout=15s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 容器内需安装包含对应诊断工具的 JDK；仅有 JRE 时不可用。 |
| 安全说明 | 包装命令后的目标固定为 jstat，禁止解释器与 TTY；pid 为容器内进程标识，样本数最多 10，间隔固定 1000 毫秒。JDK 工具对目标进程的权限依赖容器用户配置。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `pid` | int | `min: 1`；`max: 4194304`；必填 | 容器 PID 命名空间内的必填进程标识 |
| `samples` | int | `min: 1`；`max: 10`；必填（有默认值时可省略）；默认 `1` | 固定一秒间隔的样本数 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', jstat, -gc, '{pid}', '1000', '{samples}']
```

### `jvm_list`

查看容器内 JVM 标识和主类。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | D4 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 容器内需安装包含对应诊断工具的 JDK；仅有 JRE 时不可用。 |
| 安全说明 | 固定 jps -l，不使用可输出 JVM 参数和应用参数的 -v、-m；包装命令不能由参数替换。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', jps, -l]
```

### `jvm_thread_dump`

读取容器内一个 JVM 线程转储。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D4 |
| 执行限制 | timeout=20s；max_output=128KB |
| CentOS 7 | CentOS 7 需另装 Docker CLI 并运行兼容的 Docker 服务；该示例的选项是否可用须在目标版本验证。/usr/bin/docker 缺失时标记 unsupported。 容器内需安装包含对应诊断工具的 JDK；仅有 JRE 时不可用。 |
| 安全说明 | 固定 jstack，不开放 -F、远程连接或自由选项。诊断附加可能短暂影响目标 JVM，需运维审核；输出先脱敏，不保留原始转储。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `container` | enum | `values: ['api', 'app']`；必填 | 预定义应用容器 |
| `pid` | int | `min: 1`；`max: 4194304`；必填 | 容器 PID 命名空间内的必填进程标识 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/docker, exec, '{container}', jstack, '{pid}']
```

### `k8s_configmap_grep`

读取一个 ConfigMap 的 data 内容，敏感值脱敏，由 match 等过滤缩小范围。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii，另有自定义规则 sensitive_property |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 依赖目标节点的 kubectl 和只读 kubeconfig；go-template 输出须在目标版本验证。 |
| 安全说明 | 输出格式为每个键一段：`### <键>` 后接值。命名空间使用签名枚举，ConfigMap 名称用 DNS 子域名正则且不以连字符开头。脱敏规则同 `app_config_grep`，同时覆盖 `key: value` 形式。match 在脱敏之后执行，无法探测被脱敏的值。限制：多行值中不含敏感词的键下的敏感值、binaryData 不处理（模板只遍历 .data）。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: [default, app]`；必填 | 签名允许列表中的命名空间 |
| `name` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`；`max_len: 253`；必填 | ConfigMap 名称 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, configmap, '{name}', -n, '{namespace}',
  -o, 'go-template={{range $key, $value := .data}}### {{$key}}{{"\n"}}{{$value}}{{"\n"}}{{end}}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_configmap_keys`

只列出一个 ConfigMap 的 data 键名。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 依赖目标节点的 kubectl 和只读 kubeconfig；go-template 输出须在目标版本验证。 |
| 安全说明 | go-template 只输出 `$key`，不输出值。命名空间使用签名枚举，ConfigMap 名称用 DNS 子域名正则且不以连字符开头。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: [default, app]`；必填 | 签名允许列表中的命名空间 |
| `name` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`；`max_len: 253`；必填 | ConfigMap 名称 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, configmap, '{name}', -n, '{namespace}',
  -o, 'go-template={{range $key, $value := .data}}{{$key}}{{"\n"}}{{end}}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_deploy_images`

列出预定义命名空间内各 Deployment 的名称、容器镜像和就绪副本数。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，custom-columns 表达式全部固定；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。输出仅含名称、镜像和副本数。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, deployments, -n, '{namespace}',
  -o, 'custom-columns=NAME:.metadata.name,IMAGES:.spec.template.spec.containers[*].image,READY:.status.readyReplicas']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_describe_pod`

查看单个 Pod 的描述。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 describe 可能含环境变量或事件中的敏感内容；脱敏规则存在遗漏风险，签名评审需检查实际输出结构。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | 长度不超过 63 的 Pod 名称 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, describe, pod, '{pod}', -n, '{namespace}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_get`

列出预定义命名空间内的一类命名空间级资源（wide 输出）。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 资源类型和命名空间都使用枚举，不包含 secrets。configmaps 的 wide 输出只含名称、条目数和存续时间，不含键值。Node 是集群级资源，没有命名空间，由 k8s_nodes 提供，避免可选命名空间参数在该资源上被忽略。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `resource` | enum | `values: ['deployments', 'services', 'endpoints', 'ingresses', 'hpa', 'jobs', 'cronjobs', 'statefulsets', 'replicasets', 'configmaps']`；必填 | 要列出的资源类型 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, '{resource}', -n, '{namespace}',
  -o, wide]
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_nodes`

列出集群节点（wide 输出）。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | Node 是集群级资源，无命名空间，因此不能放入 k8s_get 的命名空间必填参数；本 action 无参数，argv 全部固定。 |

参数：

无参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, nodes, -o, wide]
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_pod_file_grep`

在单个 Pod 的容器内按固定字符串检索一个文件，限制匹配数。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。容器内需有支持 -F、-n、-m、-e 的 grep。无匹配时 grep 退出码为 1，action 报告失败。 |
| 安全说明 | 命名空间和容器使用枚举，Pod 名称不能以连字符开头；固定使用 `exec -n <ns> <pod> [-c <container>] --`，不使用 -i、-t，无 stdin 和 TTY；包装命令后真正执行的 grep 通过解释器检查。kubectl exec 需要 pods/exec 的 create 权限，这不是纯只读 RBAC：持有该权限的凭据理论上可在 Pod 内执行任意命令，只读 kubeconfig 的 RBAC 必须仅授予允许的命名空间，并由运维评审；allowops 的签名 argv 是唯一的约束。禁用 kubeconfig 的 exec 认证插件。模式使用 -e，路径前使用 --。容器内路径无法在主机检查，使用锚定正则限制在固定根目录内，每个路径段以非点字符开头，无法出现 .. 段；容器内已有符号链接可被跟随。脱敏只匹配 password、secret、token 后紧跟等号的形式，`secret: value`、`client_secret=value`、`api_key=value` 不被脱敏。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | 长度不超过 63 的 Pod 名称 |
| `container` | enum | `values: ['api', 'app']`；可选 | 可选预定义容器名 |
| `path` | string | `regex: ^/(var/log\|data/logs\|etc/nginx)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+$`；`max_len: 256`；必填 | 容器内固定根目录下的绝对文件路径，无点段 |
| `pattern` | string | `regex: ^[^\r\n]+$`；`max_len: 200`；必填 | 不含换行的固定检索字符串 |
| `max_matches` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 匹配行数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, exec, -n, '{namespace}', '{pod}',
  [-c, '{container}'], --, grep, -F, -n, -m, '{max_matches}', -e, '{pattern}', --, '{path}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_pod_file_view`

读取单个 Pod 容器内固定根目录下一个文件的开头，限制行数。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=15s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。容器内需有支持 -n 和 -- 的 head。 |
| 安全说明 | 命名空间和容器使用枚举，Pod 名称不能以连字符开头；固定使用 `exec -n <ns> <pod> [-c <container>] --`，不使用 -i、-t，无 stdin 和 TTY；包装命令后真正执行的 head 通过解释器检查。kubectl exec 需要 pods/exec 的 create 权限，这不是纯只读 RBAC：持有该权限的凭据理论上可在 Pod 内执行任意命令，只读 kubeconfig 的 RBAC 必须仅授予允许的命名空间，并由运维评审；allowops 的签名 argv 是唯一的约束。禁用 kubeconfig 的 exec 认证插件。容器内路径无法在主机检查，使用锚定正则限制在固定根目录内，每个路径段以非点字符开头，无法出现 .. 段；容器内已有符号链接可被跟随。最多读取 500 行，输出由 max_output 限制为 64KB。脱敏只匹配 password、secret、token 后紧跟等号的形式，`secret: value`、`client_secret=value`、`api_key=value` 不被脱敏。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | 长度不超过 63 的 Pod 名称 |
| `container` | enum | `values: ['api', 'app']`；可选 | 可选预定义容器名 |
| `path` | string | `regex: ^/(var/log\|data/logs\|etc/nginx)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+$`；`max_len: 256`；必填 | 容器内固定根目录下的绝对文件路径，无点段 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, exec, -n, '{namespace}', '{pod}',
  [-c, '{container}'], --, head, -n, '{lines}', --, '{path}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_pod_jar_list_entries`

列出 Pod 内应用目录下一个 jar 的条目名。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D4、D5 |
| 执行限制 | timeout=20s；max_output=128KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。容器内须有 jar（JDK 自带；仅有 JRE 的镜像不可用）。 |
| 安全说明 | 固定 kubectl exec ... -- jar tf，不分配 TTY，不开放 stdin。jar 参数的约束同 docker_jar_list_entries。kubectl exec 需要 pods/exec 权限，该权限能在 Pod 内执行任意命令，只读 kubeconfig 的 RBAC 须仅限相应命名空间；命令内容由本 action 固定，不由 RBAC 约束。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | 长度不超过 63 的 Pod 名称 |
| `container` | enum | `values: ['api', 'app']`；可选 | 可选预定义容器名 |
| `jar` | string | `regex: ^/(app\|opt/app\|data/app)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+\.jar$`；`max_len: 200`；必填 | 应用目录下的 jar 文件路径（容器内路径，正则限定） |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, exec, '{pod}', -n, '{namespace}', [-c, '{container}'], --, jar, tf, '{jar}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_pod_jar_read_entry`

读取 Pod 内一个 jar 中的 application 配置条目，输出脱敏，不写文件。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii；自定义规则 config_secret |
| 扩展能力 | D1、D4、D5 |
| 执行限制 | timeout=15s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。容器内须有 unzip（JDK 镜像通常没有，须在镜像中安装）。 |
| 安全说明 | 固定 kubectl exec ... -- unzip -p，不分配 TTY，不开放 stdin。参数与脱敏规则同 docker_jar_read_entry。kubectl exec 需要 pods/exec 权限，该权限能在 Pod 内执行任意命令，只读 kubeconfig 的 RBAC 须仅限相应命名空间；命令内容由本 action 固定，不由 RBAC 约束。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | 长度不超过 63 的 Pod 名称 |
| `container` | enum | `values: ['api', 'app']`；可选 | 可选预定义容器名 |
| `jar` | string | `regex: ^/(app\|opt/app\|data/app)(/[A-Za-z0-9_][A-Za-z0-9._-]*)+\.jar$`；`max_len: 200`；必填 | 应用目录下的 jar 文件路径（容器内路径，正则限定） |
| `entry` | string | `regex: ^(BOOT-INF/classes/)?application[A-Za-z0-9_.-]*\.(properties\|yml\|yaml)$`；`max_len: 120`；必填 | jar 内的 application*.properties、application*.yml、application*.yaml 条目名，可带 BOOT-INF/classes/ 前缀 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, exec, '{pod}', -n, '{namespace}', [-c, '{container}'], --, unzip, -p, '{jar}', '{entry}']
exec_fallbacks: [/usr/local/bin/kubectl]
redact:
  builtin: [secrets, pii]
  custom:
    - name: config_secret
      regex: '(?i)[A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|credentials?|private[_.-]?key|access[_.-]?key|api[_.-]?key)[A-Za-z0-9_.-]*\s*[:=]\s*(?:"[^"\r\n]*"|''[^''\r\n]*''|[^\s#]*)'
```

### `k8s_pod_java_class_members`

用 javap -p 列出 Pod 内应用目录下 jar 中一个类的成员声明。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D4、D5 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。容器内须有 javap（JDK 自带；仅有 JRE 的镜像不可用）。 |
| 安全说明 | 固定 kubectl exec ... -- javap -p，不分配 TTY，不开放 stdin，也不开放 -c 等选项（理由同 docker_java_class_members）。classpath 与类名的约束同 docker_java_class_members。kubectl exec 需要 pods/exec 权限，该权限能在 Pod 内执行任意命令，只读 kubeconfig 的 RBAC 须仅限相应命名空间；命令内容由本 action 固定，不由 RBAC 约束。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | 长度不超过 63 的 Pod 名称 |
| `container` | enum | `values: ['api', 'app']`；可选 | 可选预定义容器名 |
| `classpath` | string | `regex: ^/(app\|opt/app\|data/app)(/[A-Za-z0-9_][A-Za-z0-9._-]*)*/(\*\|[A-Za-z0-9_][A-Za-z0-9._-]*\.jar)$`；`max_len: 200`；必填 | 一个 jar 或一个应用库目录通配（容器内路径，正则限定） |
| `class_name` | string | `regex: ^(?:[A-Za-z_$][A-Za-z0-9_$]*\.)*(?:[A-Za-bd-z_$][A-Za-z0-9_$]*\|c(?:[A-Za-km-z0-9_$][A-Za-z0-9_$]*)?\|cl(?:[A-Zb-z0-9_$][A-Za-z0-9_$]*)?\|cla(?:[A-Za-rt-z0-9_$][A-Za-z0-9_$]*)?\|clas(?:[A-Za-rt-z0-9_$][A-Za-z0-9_$]*)?\|class[A-Za-z0-9_$]+)$`；`max_len: 200`；必填 | Java 全限定名；嵌套类用美元符；末段不能是 class |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, exec, '{pod}', -n, '{namespace}', [-c, '{container}'], --, javap, -p, -classpath, '{classpath}', '{class_name}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_pod_logs`

查看单个 Pod 的末尾日志。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 不启用 follow 或 exec；多个容器时须提供固定允许的容器名。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | 长度不超过 63 的 Pod 名称 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |
| `since` | duration | `max: 24h`；`format: go`；可选 | 可选相对日志起始时间 |
| `container` | enum | `values: ['api', 'app']`；可选 | 可选预定义容器名 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, logs, '{pod}', -n, '{namespace}',
  --tail, '{lines}', --timestamps, [--since, '{since}'], [--container, '{container}']]
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_pod_status`

查看一个 Pod 的 phase、所在节点，以及各容器的 imageID 和重启次数。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，Pod 名称由正则限定为 63 位小写 DNS 字符且不以连字符开头；jsonpath 表达式固定，只输出 phase、nodeName、容器名、imageID、restartCount，不读取环境变量或命令行。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `pod` | string | `regex: ^[a-z0-9]([a-z0-9.-]{0,61}[a-z0-9])?$`；`max_len: 63`；必填 | Pod 名称 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, pod, '{pod}', -n, '{namespace}',
  -o, 'jsonpath=phase={.status.phase}{"\n"}node={.spec.nodeName}{"\n"}{range .status.containerStatuses[*]}container={.name} imageID={.imageID} restartCount={.restartCount}{"\n"}{end}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_pods`

查看预定义命名空间内的 Pod 列表。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, pods, -n, '{namespace}', -o,
  wide]
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_rollout_history`

查看 Deployment 发布历史。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `deployment` | enum | `values: ['api', 'app']`；必填 | 预定义 Deployment 名称 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, rollout, history, deployment, '{deployment}',
  -n, '{namespace}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_rollout_status`

在限定等待时间内查看 Deployment 发布状态。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | D5 |
| 执行限制 | timeout=40s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 只读取和观察状态，不执行 restart、undo 或 apply；RBAC 需相应 watch 权限。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |
| `deployment` | enum | `values: ['api', 'app']`；必填 | 预定义 Deployment 名称 |
| `wait` | duration | `max: 30s`；`format: go`；必填（有默认值时可省略）；默认 `15s` | kubectl 观察时长上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, rollout, status, deployment, '{deployment}',
  -n, '{namespace}', --timeout, '{wait}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_top_nodes`

查看节点资源指标。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 top 还需要集群提供 Metrics API。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, top, nodes]
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_top_pods`

查看预定义命名空间内的 Pod 资源指标。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 top 还需要集群提供 Metrics API。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, top, pods, -n, '{namespace}']
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `k8s_warning_events`

查看 Warning 类型集群事件。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D5 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 不自带 kubectl；须安装与集群版本兼容的二进制，并提供固定的只读 kubeconfig。首选 /usr/bin/kubectl，缺失时尝试 /usr/local/bin/kubectl；缺失或功能不支持时标记 unsupported。 |
| 安全说明 | 命名空间使用枚举，资源名不能以连字符开头；只读 kubeconfig 由 root 管理，集群 RBAC 只授予所需读权限，禁用 kubeconfig 的 exec 认证插件。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `namespace` | enum | `values: ['default', 'app']`；必填 | 预定义命名空间 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/kubectl, --kubeconfig, /etc/kubernetes/allowops-readonly.conf, get, events, -n, '{namespace}', --field-selector,
  type=Warning]
exec_fallbacks: [/usr/local/bin/kubectl]
```

### `kernel_errors`

查看内核警告和错误信息。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 util-linux dmesg 支持 -T、--level；转换后的墙上时钟时间可能受休眠等影响。 |
| 安全说明 | root 用于受限内核日志读取；固定 err,warn，不允许清空或修改日志缓冲区。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/dmesg, -T, '--level=err,warn']
```

### `log_grep_file`

按扩展正则检索一个允许日志文件。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU grep 支持所用选项；没有匹配时退出码为 1。 |
| 安全说明 | 模式使用 -e，路径前使用 --；路径检查日志根目录，匹配数最多 500，超时限制扫描和正则耗时。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data/logs']`；必填 | 已存在且解析后位于允许根目录内的路径 |
| `pattern` | string | `regex: ^[^\r\n]+$`；`max_len: 200`；必填 | 不含换行的检索模式 |
| `max_matches` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 每个文件的最大匹配数 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/grep, -E, -m, '{max_matches}', -e, '{pattern}', --, '{path}']
```

### `log_grep_fixed`

按固定字符串检索一个允许日志文件。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU grep 支持所用选项；没有匹配时退出码为 1。 |
| 安全说明 | 模式使用 -e，路径前使用 --；路径检查日志根目录，匹配数最多 500，超时限制扫描和正则耗时。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data/logs']`；必填 | 已存在且解析后位于允许根目录内的路径 |
| `pattern` | string | `regex: ^[^\r\n]+$`；`max_len: 200`；必填 | 不含换行的检索模式 |
| `max_matches` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 每个文件的最大匹配数 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/grep, -F, -m, '{max_matches}', -e, '{pattern}', --, '{path}']
```

### `log_search`

检索允许路径下的普通或 gzip 日志。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D3 |
| 执行限制 | timeout=30s；max_output=64KB |
| CentOS 7 | 由 D3 内置处理器实现，不依赖 grep、zgrep 或解释器；CentOS 7 可否执行取决于主机端是否支持 D3。 |
| 安全说明 | 枚举文件前检查根目录，每个文件解析符号链接后再检查；使用 os.Root 打开并核验普通文件；限制文件数、解压后扫描字节、上下文和匹配数。fixed 默认 false，正则模式使用 RE2，fixed=true 时 pattern 和 exclude 都按固定字符串匹配。依据：internal/catalog/builtin_adapters.go 和 internal/builtin/logsearch/logsearch.go。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path_glob` | string | `regex: ^/[^\r\n]+$`；`max_len: 256`；必填 | 日志路径通配，须受内置根目录约束 |
| `pattern` | string | `regex: ^[^\r\n]+$`；`max_len: 200`；必填 | 不含换行的检索模式 |
| `fixed` | bool | 处理器提供；可省略，默认 `false` | pattern/exclude 是否使用固定字符串匹配 |
| `exclude` | string | 处理器提供；`max_len: 200`；可选 | 处理器排除模式；与 D1 的 exclude 是不同参数空间 |
| `context` | int | 处理器提供；`min: 0`；`max: 10`；可省略，默认 `0` | 每次匹配前后的上下文行数 |
| `max_matches` | int | 处理器提供；`min: 1`；`max: 500`；可省略，默认 `500` | 所选文件的总匹配数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: log_search
builtin_config:
  allowed_roots: [/var/log, /data/logs]
  max_files: 50
  max_scan: 256MB
  max_context: 10
  max_matches: 500
```

### `log_search_dir`

递归检索允许目录下的未压缩日志。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU grep 支持 -r、-E、-m；没有匹配时退出码为 1。 |
| 安全说明 | 只使用 -r，不使用会跟随目录内符号链接的 -R；入口路径解析后检查根目录。-m 是每个文件上限，整个目录的工作量由超时限制；压缩文件用 log_search。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data/logs']`；必填 | 已存在且解析后位于允许根目录内的路径 |
| `pattern` | string | `regex: ^[^\r\n]+$`；`max_len: 200`；必填 | 不含换行的检索模式 |
| `max_matches` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 每个文件的最大匹配数 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/grep, -r, -E, -m, '{max_matches}', -e, '{pattern}', --, '{path}']
```

### `log_tail_file`

查看允许日志文件的末尾行。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 GNU tail 支持 -n 和 --。 |
| 安全说明 | 路径解析后只能位于日志根目录；不接受 -f，行数不超过 500。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log', '/data/logs']`；必填 | 已存在且解析后位于允许根目录内的路径 |
| `lines` | int | `min: 1`；`max: 500`；必填（有默认值时可省略）；默认 `100` | 输出行数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/tail, -n, '{lines}', --, '{path}']
```

### `memory_usage`

查看内存和交换区占用。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | 无（基础 exec） |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 procps-ng free 支持 -m。 |
| 安全说明 | 仅输出汇总内存指标，不读取进程内存。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/free, -m]
```

### `mysql_query_readonly`

执行一条以 app 为默认数据库的只读 SQL。databases=[app] 同时限制默认库和 SQL 中的显式库名；数据库账号权限仍需限制视图等服务器内部对象。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D7 |
| 执行限制 | timeout=15s；max_output=64KB |
| CentOS 7 | 内置驱动不要求 CentOS 7 安装 mysql CLI；服务器须支持只读事务和 max_execution_time，初始化不支持这些设置时直接失败；依据：internal/builtin/mysql/mysql.go 的 beginReadOnly。目标服务器兼容性未验证。 |
| 安全说明 | 凭据仅在主机端 root 的 0600 JSON 文件中；必须使用只读数据库账号。SQL 解析器拒绝多语句、写入、导出、文件读取及未知函数，只读事务、行数和超时共同限制执行。databases 限制递归 SQL 抽象语法树（AST）中的显式库名为 app，不展开视图定义。statement_types 使用 DESCRIBE 表示 DESC，EXPLAIN 的目标类型也须允许（G31）；拒绝 ANALYZE。未配置 show_types 时，服务器级 SHOW DATABASES/PROCESSLIST/VARIABLES/STATUS 被拒绝（G34）。依据：builtin-config.md、internal/builtin/mysql/validate.go。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `database` | string | `regex: ^app$`；`max_len: 3`；必填，无默认值 | 以 app 为默认数据库；显式库名同时受 builtin_config.databases 限制 |
| `sql` | string | `regex: ^[^\r\n]+$`；`max_len: 4000`；必填 | 单条无换行只读 SQL，禁止多语句 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: mysql_query
builtin_config:
  credential: /etc/allowops/credentials/mysql-main.json
  address: unix:///var/run/mysqld/mysqld.sock
  max_rows: 200
  timeout: 10s
  databases: [app]
  statement_types: [SELECT, SHOW, DESCRIBE, EXPLAIN]
```

### `mysql_show`

执行预定义 SHOW TABLES 或 SHOW STATUS 查询。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D7 |
| 执行限制 | timeout=15s；max_output=64KB |
| CentOS 7 | 内置驱动不要求 CentOS 7 安装 mysql CLI；只读事务和超时的服务端兼容性同 mysql_query_readonly。 |
| 安全说明 | database/sql 正则分别固定默认库 app 和 SHOW TABLES/SHOW STATUS；databases=[app]、statement_types=[SHOW]、show_types=[TABLES,STATUS] 共同收紧处理器。保留 SQL 正则以拒绝 FULL/GLOBAL/SESSION/LIKE/WHERE 等变体。STATUS 是 G34 要求显式授权的服务器级 SHOW，其结果不会按 app 库过滤；凭据、只读账号、结果上限和拒绝写入要求同 mysql_query_readonly。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `database` | string | `regex: ^app$`；`max_len: 3`；必填，无默认值 | 以 app 为默认数据库；显式库名同时受 builtin_config.databases 限制 |
| `sql` | string | `regex: ^SHOW (TABLES\|STATUS)$`；`max_len: 11`；必填，无默认值 | 预定义 SHOW 语句 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: mysql_query
builtin_config:
  credential: /etc/allowops/credentials/mysql-main.json
  address: unix:///var/run/mysqld/mysqld.sock
  max_rows: 200
  timeout: 10s
  databases: [app]
  statement_types: [SHOW]
  show_types: [TABLES, STATUS]
```

### `nginx_access_stats`

统计 nginx 访问日志的请求数、状态码、方法和响应字节数，可限定日志自身时区内的一小时。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | script |
| filters | [] |
| redact | secrets |
| 扩展能力 | D6 |
| 执行限制 | timeout=30s；max_output=16KB |
| CentOS 7 | CentOS 7 默认 Python 2 不能执行；需安装 /usr/bin/python3，版本至少 3.4（-I 隔离模式），并挂载 /proc。脚本只使用 Python 标准库及 Linux 文件打开标志。 |
| 安全说明 | 只读取签名根目录下的普通日志文件；拒绝打开时的末级符号链接，打开后按文件描述符复查根目录和文件种类。最多扫描 64MB，单行最多 64KB，行数最多一百万。仅返回聚合值，不输出请求路径或原始日志。脚本须随目录签名并纳入摘要，私有临时目录执行、清理和 -I 由 D6 主机端负责。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `path` | path | `allowed_roots: ['/var/log/nginx', '/data/logs/nginx']`；必填 | 已存在且解析后位于允许根目录内的路径 |
| `hour` | string | `regex: ^[0-9]{4}-(0[1-9]\|1[0-2])-(0[1-9]\|[12][0-9]\|3[01])T([01][0-9]\|2[0-3])$`；`max_len: 13`；可选 | 可选日志自身时区小时，格式 YYYY-MM-DDTHH |
| `max_lines` | int | `min: 1`；`max: 1000000`；必填（有默认值时可省略）；默认 `100000` | 输入日志扫描行数上限 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
script:
  file: scripts/nginx_access_stats.py
  interpreter: /usr/bin/python3
args: [--path, '{path}', [--hour, '{hour}'], --max-lines, '{max_lines}', --max-bytes, '67108864']
```

### `nginx_test_config`

检查 nginx 配置语法。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | 无（基础 exec） |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 需安装 nginx；/usr/sbin/nginx -t 可用性取决于安装包。 |
| 安全说明 | 不接受配置路径或其他 nginx 选项；只检测已安装配置。读取配置和证书文件需要 root；不会执行 reload。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/sbin/nginx, -t]
```

### `ports_listening`

查看监听 TCP 端口及进程信息。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 iproute ss 支持 -ltnp。 |
| 安全说明 | 需要 root 才能查看所有进程名；固定只读 socket 列表，过滤在脱敏之后执行。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/sbin/ss, -ltnp]
exec_fallbacks: [/usr/bin/ss]
```

### `process_find`

按固定进程名查找进程标识。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 procps-ng pgrep 支持 -l、-x；没有匹配时退出码为 1。 |
| 安全说明 | 只允许 nginx、java、app，使用完整名称匹配；-l 输出名称，不使用会暴露完整命令行的 -a。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `process` | enum | `values: ['nginx', 'java', 'app']`；必填 | 允许的完整进程名 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/pgrep, -l, -x, --, '{process}']
```

### `process_top`

按 CPU 占用查看进程摘要。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 procps-ng ps 支持指定列和 --sort。 |
| 安全说明 | 只输出 comm 列，不输出完整命令行或环境变量；用 head 过滤限制返回行数。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/ps, -eo, 'pid,user,%cpu,%mem,etime,comm', --sort=-%cpu]
```

### `redis_config_get`

读取 Redis 配置中允许的非敏感参数：传入 `command=CONFIG` 和 `args=["GET","maxmemory","dir"]`。参数名按名称精确匹配，不接受通配符。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D7 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置驱动不要求 CentOS 7 安装 redis-cli；Redis 版本和 Unix socket 配置需目标环境验证。 |
| 安全说明 | commands 显式列出 CONFIG，且必须配置 config_params 才允许 CONFIG GET；只支持 GET 子命令，一次最多 16 个参数名，名称只含字母、数字和 `-`，拒绝 `*`、`?`、`[`。requirepass、masterauth、masteruser、primaryauth、aclfile、tls-key-file-pass 等名称（以 acl 开头，或含 pass、auth、user）即使写入 config_params 也在校验和执行时拒绝。action 的 args 正则再次限定为 GET 和 24 个参数名。输出按字符串数组返回，受 max_response_bytes 限制，超限时退出码 0 并标记 truncated。依据：builtin-config.md、internal/builtin/redis/redis.go 的 command、checkConfigParamName、validateCommand。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `command` | enum | builtin_config.commands 收紧为 CONFIG；必填，无默认值 | 固定 Redis CONFIG 命令 |
| `args` | string_array | 必填；每项匹配 GET 或允许的参数名之一（见 YAML）且最长 64；第一项必须是 GET，后接 1 到 16 个参数名 | GET 加参数名，例如 `["GET","maxmemory","maxmemory-policy"]` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: redis_command
builtin_config:
  credential: /etc/allowops/credentials/redis-main.json
  address: unix:///var/run/redis/redis.sock
  timeout: 5s
  max_response_bytes: 64KB
  commands: [CONFIG]
  config_params: [maxmemory, maxmemory-policy, maxmemory-samples, maxclients, timeout, tcp-keepalive, databases, appendonly, appendfsync, save, slowlog-log-slower-than, slowlog-max-len, latency-monitor-threshold, hz, dir, dbfilename, loglevel, repl-backlog-size, replica-read-only, protected-mode, port, bind, cluster-enabled, notify-keyspace-events]
```

### `redis_get`

读取一个 app: 前缀的 Redis 字符串键：传入 `command=GET` 和 `args=["app:status"]`。P12D 的 commands/key_prefixes 和 args 正则已恢复原命令与键范围限制。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | builtin |
| filters | [] |
| redact | secrets, pii |
| 扩展能力 | D7 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置驱动不要求 CentOS 7 安装 redis-cli；Redis 版本和 Unix socket 配置需目标环境验证。 |
| 安全说明 | 仅允许 GET；key_prefixes 按字面值检查 app: 前缀，args 正则和 max_len 保留原字符限制及最长 128。GET 要求一个键参数。内部 STRLEN/EXISTS/GETRANGE 仅用于读取已通过校验的键，不扩大调用方命令范围；值超过上限时返回错误并标记资源限制。依据：builtin-config.md、internal/builtin/redis/redis.go 的 validateCommand、readResponse。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `command` | enum | builtin_config.commands 收紧为 GET；必填，无默认值 | 固定 Redis GET 命令 |
| `args` | string_array | 必填；每项匹配 `^app:[A-Za-z0-9:_-]+$` 且最长 128；GET 要求恰好一个参数 | app: 前缀的键，例如 `["app:status"]` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: redis_command
builtin_config:
  credential: /etc/allowops/credentials/redis-main.json
  address: unix:///var/run/redis/redis.sock
  timeout: 5s
  max_response_bytes: 64KB
  commands: [GET]
  key_prefixes: ['app:']
```

### `redis_info`

读取 Redis INFO 的 server、memory、stats 分节：传入 `command=INFO`，可用 `args=["server"]` 选择一个允许分节。省略 args 时仅按配置顺序汇总这三个分节，不使用服务器默认分节集合。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D1、D7 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置驱动不要求 CentOS 7 安装 redis-cli；Redis 版本和 Unix socket 配置需目标环境验证。 |
| 安全说明 | 凭据仅在 root 的 0600 JSON 主机文件中；commands 仅允许 INFO，info_sections 仅允许 server/memory/stats。all/default/everything 等聚合选择器被拒绝；未传分节时仍只读取配置中的分节。max_response_bytes 限制已解码后的返回文本，不能作为读取时的内存上限。依据：builtin-config.md、internal/builtin/redis/redis.go 的 validateCommand、readConfiguredResponse。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `command` | enum | builtin_config.commands 收紧为 INFO；必填，无默认值 | 固定 Redis INFO 命令 |
| `args` | string_array | 处理器提供；可选；INFO 接受零或一个分节参数；仅允许 server/memory/stats，不区分大小写 | 选择一个允许分节；省略时汇总配置中的三个分节 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: redis_command
builtin_config:
  credential: /etc/allowops/credentials/redis-main.json
  address: unix:///var/run/redis/redis.sock
  timeout: 5s
  max_response_bytes: 64KB
  commands: [INFO]
  info_sections: [server, memory, stats]
```

### `redis_slowlog`

读取 Redis 慢日志：传入 `command=SLOWLOG`，`args=["GET","20"]` 返回最近若干条，`args=["LEN"]` 返回条数。不能清空慢日志。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | builtin |
| filters | match, exclude, tail, head, count |
| redact | secrets, pii |
| 扩展能力 | D7 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | 内置驱动不要求 CentOS 7 安装 redis-cli；Redis 版本和 Unix socket 配置需目标环境验证。 |
| 安全说明 | commands 显式列出 SLOWLOG。只支持 GET [count] 和 LEN，count 为 1..128；RESET、HELP 拒绝。慢日志的命令参数和客户端地址可能含业务数据和任意键，因此启用 pii；配置 key_prefixes 时 SLOWLOG GET 被拒绝，仅 LEN 可用。已知限制：secrets 规则只识别 `password=`、`secret=`、`token=` 形式和常见令牌格式，`secret: value` 形式的值不会被脱敏。输出为嵌套数组，受 max_response_bytes 限制。依据：builtin-config.md、internal/builtin/redis/redis.go 的 command、validateCommand。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `command` | enum | builtin_config.commands 收紧为 SLOWLOG；必填，无默认值 | 固定 Redis SLOWLOG 命令 |
| `args` | string_array | 必填；每项匹配 `^(GET\|LEN\|[1-9]\|[1-9][0-9]\|1[01][0-9]\|12[0-8])$` 且最长 8；GET 后可跟一个数量 | GET 加可选条数，或 LEN，例如 `["GET","20"]` |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
builtin: redis_command
builtin_config:
  credential: /etc/allowops/credentials/redis-main.json
  address: unix:///var/run/redis/redis.sock
  timeout: 5s
  max_response_bytes: 64KB
  commands: [SLOWLOG]
```

### `sar_cpu`

按已有日采样文件和当日时间段查看 CPU 指标。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 需安装 sysstat 并启用采样；日文件通常位于 /var/log/sa，文件格式必须与已安装 sar 兼容。 |
| 安全说明 | 日文件使用 path 类型和 /var/log/sa 根目录，不通过字符串拼接构造文件名；时间仅接受 HH:MM:SS。起止顺序的跨参数约束见待确认。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `file` | path | `allowed_roots: ['/var/log/sa']`；必填 | 已存在的 sysstat 日采样文件 |
| `start` | string | `regex: ^([01][0-9]\|2[0-3]):[0-5][0-9]:[0-5][0-9]$`；`max_len: 8`；必填（有默认值时可省略）；默认 `00:00:00` | 日文件内的起始时间 |
| `end` | string | `regex: ^([01][0-9]\|2[0-3]):[0-5][0-9]:[0-5][0-9]$`；`max_len: 8`；必填（有默认值时可省略）；默认 `23:59:59` | 日文件内的结束时间 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/sar, -u, -f, '{file}', -s, '{start}', -e, '{end}']
```

### `sar_memory`

按已有日采样文件和当日时间段查看内存指标。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | root |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=20s；max_output=64KB |
| CentOS 7 | CentOS 7 需安装 sysstat 并启用采样；日文件通常位于 /var/log/sa，文件格式必须与已安装 sar 兼容。 |
| 安全说明 | 日文件使用 path 类型和 /var/log/sa 根目录，不通过字符串拼接构造文件名；时间仅接受 HH:MM:SS。起止顺序的跨参数约束见待确认。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `file` | path | `allowed_roots: ['/var/log/sa']`；必填 | 已存在的 sysstat 日采样文件 |
| `start` | string | `regex: ^([01][0-9]\|2[0-3]):[0-5][0-9]:[0-5][0-9]$`；`max_len: 8`；必填（有默认值时可省略）；默认 `00:00:00` | 日文件内的起始时间 |
| `end` | string | `regex: ^([01][0-9]\|2[0-3]):[0-5][0-9]:[0-5][0-9]$`；`max_len: 8`；必填（有默认值时可省略）；默认 `23:59:59` | 日文件内的结束时间 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/sar, -r, -f, '{file}', -s, '{start}', -e, '{end}']
```

### `system_load`

查看运行时长和系统负载。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | [] |
| redact | secrets |
| 扩展能力 | 无（基础 exec） |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 uptime 支持无参数调用。 |
| 安全说明 | 固定汇总指标，无 agent 参数。 |

参数：

无；不接受未声明参数。

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/uptime]
```

### `systemd_service_status`

查看预定义 systemd 服务状态。

| 项 | 需求 |
|---|---|
| risk | read |
| run_as | 省略，直接使用 allowops 用户 |
| 执行方式 | exec |
| filters | match, exclude, tail, head, count |
| redact | secrets |
| 扩展能力 | D1 |
| 执行限制 | timeout=10s；max_output=64KB |
| CentOS 7 | CentOS 7 的 systemctl 支持这些选项。服务未运行时 status 可以返回非零退出码，仍保留诊断输出。 |
| 安全说明 | 只允许 nginx、api，固定 --no-pager 防止交互式分页；不开放任意 unit 或 systemctl 子命令。 |

参数：

| 名称 | 类型 | 约束 | 用途（description） |
|---|---|---|---|
| `service` | enum | `values: ['nginx', 'api']`；必填 | 预定义服务名 |

argv 或 builtin_config（与示例 YAML 一致）：

```yaml
exec: [/usr/bin/systemctl, status, '{service}', --no-pager]
```

## 4. 原待确认项的对齐结果

保留 AC1 的 10 项编号，逐项区分代码或决定已确定的行为与仍需决策的内容。以下结论只覆盖当前 schema 和本机验证范围。

1. **目录结构字段（已确定，P1）**：`schema_version` 只能为 1。`defaults` 仅含 timeout、max_output、batch_size、max_failures；全局 redact 位于 catalog 顶层。省略 timeout、batch_size、max_failures、redact 的 action 继承目录值；省略 max_output 时继承，显式 0 被拒绝。action.max_scan 未设置或为 0 时执行器使用 256MB，不参与目录 defaults 继承。依据：`internal/catalog/catalog.go` 的 `Defaults`、`validateConfig`、`applyDefaults`、`ParseAction`，`internal/executor/executor.go` 的 `DefaultMaxScan`。

2. **log_search 参数和上限（已确定，P12B）**：类型为 string/string/bool/string/int/int，分别对应 path_glob、pattern、fixed、exclude、context、max_matches；处理器默认 fixed=false、context=0，exclude 可选。`builtin_config` 仅支持 allowed_roots、max_files、max_scan、max_matches、max_context、timeout；不支持 max_pattern_len。默认 50 文件、256MB 解压后扫描、1000 匹配、20 行上下文、10s；只能收紧。本例匹配上限和默认值均为 500，上下文上限为 10。glob 使用 Go filepath.Glob，按字典序展开；不递归解释 **，匹配文件在读取前逐个检查，即使超过 max_files 也检查。无文件或无匹配成功返回 0；资源上限返回 0 并标 truncated。依据：A15、A16，`internal/catalog/builtin_adapters.go` 的 `logSearchConfig`、`logSearchHandler.Parameters`，`internal/builtin/logsearch/logsearch.go` 的 `files`、`Run`，Go 标准库 filepath.Glob。

3. **http_get 参数和配置（部分确定，P12B）**：url 为必填 url 类型，无默认值，allowed_prefixes 来自 builtin_config；配置仅支持 allowed_prefixes、headers、timeout、max_response_bytes。URL 按规范化后的同源和路径分量边界检查；拒绝用户信息、片段、点分量和编码分隔符；不跟随跳转，不使用代理。响应体计量为原始响应字节，未启用自动解压；默认及目录硬上限为 64KB，响应头上限另为 64KB。输出仅含状态码、Content-Type、Content-Length、Location 和响应体；非 2xx 也返回退出码 0，status_code 单独给出。依据：A15、A16，`internal/catalog/builtin_adapters.go` 的 `httpGetConfig`、`httpGetHandler.Parameters`，`internal/params/url.go`，`internal/builtin/httpget/httpget.go`。**待确认**：解析 DNS 后是否增加地址白名单检查。当前代码没有该检查；建议公开本机示例使用固定回环地址或明确受控的 localhost 解析，通用域名探测另行定义解析与连接地址策略。

4. **redis_command 参数和配置（已确定，P12B/P12D）**：处理器提供 command 枚举和可选 args（string_array），不提供 key、section；command 无默认值。配置支持 credential、address、db、timeout、max_response_bytes、max_scan_count，以及 P12D 的 commands、key_prefixes、info_sections。commands 同时收紧对外 command 枚举；key_prefixes 按大小写敏感的字面前缀检查键；info_sections 收紧 INFO 分节，省略分节参数时只按配置顺序汇总允许集合。redis_get 仅允许 GET/app: 前缀，args 正则和 max_len=128 保留原键字符与长度限制；redis_info 仅允许 INFO 的 server/memory/stats，拒绝 all/default/everything。大小默认及目录硬上限为 64KB，SCAN COUNT 上限为 1000。address 接受 host:port 或绝对 Unix socket URI；凭据为 root 属主、0600 的 JSON，username/password 均可省略，最大 16KB。GET 先 STRLEN 后 GETRANGE；HGET/MGET 先检查长度，检查与取值不是原子操作。超大 GET/HGET/MGET 返回错误、退出码 1，并标 resource_limit_reached/truncated；INFO/SCAN 解码后截断返回文本，退出码 0。这是当前实现的资源拒绝行为，不能把 A16 的成功截断结论用于所有 Redis 超限情况。依据：`builtin-config.md`，`internal/catalog/builtin_adapters.go` 的 `redisConfig`、`redisHandler.Parameters`，`internal/builtin/redis/redis.go` 的 `validateCommand`、`readConfiguredResponse`、`readResponse`。G30 的命令、前缀、分节配置缺口已由 P12D 实现；内置参数默认值仍不支持，见下表。

5. **mysql_query 参数和配置（部分确定，P12C/P12D）**：处理器提供必填 database/sql string，不允许改为枚举或添加默认值。本例用 `database.regex: ^app$` 固定默认库；mysql_show 保留 `sql.regex: ^SHOW (TABLES|STATUS)$`，只允许这两条精确 SQL。配置支持 credential、address、max_rows、timeout，以及 P12D 的 databases、statement_types、show_types；默认 500 行、10s，目录只能收紧。两个示例都配置 databases=[app]，数据库参数和递归 SQL AST 中的显式库名必须属于 app；不展开视图定义。mysql_show 配置 statement_types=[SHOW]、show_types=[TABLES,STATUS]，显式授权服务器级 STATUS；它的返回结果不会按 app 库过滤。mysql_query_readonly 配置 [SELECT,SHOW,DESCRIBE,EXPLAIN]，使用 DESCRIBE 表示 DESC；EXPLAIN 的目标类型也必须允许（G31）。它不配置 show_types，因此 G34 拒绝服务器级 SHOW DATABASES/PROCESSLIST/VARIABLES/STATUS，以及无法确定目标库的 SHOW。凭据为 root 属主、0600 的 JSON，username/password 两字段必填；最大 16KB。SQL 解析器只允许单条只读语句，支持 CTE、UNION、子查询；拒绝写语句、INTO、锁定读取、变量赋值、未知函数、执行注释/提示和 EXPLAIN ANALYZE。会话设置 max_execution_time 或只读事务失败时直接报错，不静默忽略。依据：`builtin-config.md`（G31、G34），`internal/catalog/builtin.go` 的 `MySQLConfig`、`ParameterDefinitions`，`internal/builtin/mysql/mysql.go` 的 `Run`、`beginReadOnly`，`internal/builtin/mysql/validate.go` 的 `databaseVisitor`、`validateStatement`。G30 的数据库和语句范围配置缺口已由 P12D 实现。**待确认**：目标部署的只读账号最低授权、视图/函数权限及 MySQL 兼容版本；代码不能确定目标数据库的权限。建议仅授权所需库表的读取权限，不授予 FILE、EXECUTE 或管理权限，逐条验证需要的 SHOW 权限；单个字段字节量没有处理器上限，应另行评估资源限制。

6. **D1/D2 输出契约（已确定）**：head/tail 接受正整数，没有额外固定上限；count 为布尔值；tail/head/count 互斥，match/exclude 可与其中之一组合。过滤只作用于脱敏后的 stdout；stderr 仅脱敏、截断。组合 action 按步骤过滤，全部步骤 stdout+stderr 共用 max_output，总退出码取首个失败步骤的退出码。max_scan 按每步原始 stdout 计，超限标 scan_limit_reached；不能仅检查 truncated 判断扫描结果是否全部返回。依据：A13、A17，`internal/executor/filters.go`、`internal/executor/executor.go` 的 `RunWithFilters`、`processOutput`、`runCommand`。

7. **D2 缺失步骤（已确定）**：`CheckHost` 在执行任何步骤之前检查全部步骤的可执行文件，任一步缺失即整个 action 为 unsupported。`on_error: continue` 仅用于通过检查后步骤执行失败的情况。host_snapshot 的 Docker 或其他程序缺失时不会执行其余步骤。依据：`internal/catalog/host.go` 的 `CheckHost`，`internal/executor/executor.go` 的 `RunWithFilters`。

8. **参数间约束和文件种类（部分确定）**：`internal/params/params.go` 的 `Definition` 没有跨参数约束，也没有普通文件/目录类型字段。sar 同日 start/end 顺序和 docker_logs 的 since/until 年龄关系不能由 schema 检查；nginx 脚本已检查实际日历小时。内置 log_search 在 `files` 和打开后检查普通文件，并使用 os.Root 限定打开路径；签名 nginx 脚本使用 O_NOFOLLOW、fstat 和打开后的路径检查。外部 head/tail/grep/du 只接受通过 path 解析的字符串，通用 path 检查没有保证打开时的文件种类，也没有消除随后路径替换的竞争。依据：`internal/params/params.go` 的 `ResolvePath`，`internal/builtin/logsearch/logsearch.go` 的 `files`、`search`，`examples/catalog/scripts/nginx_access_stats.py` 的 `main`。**待确认**：上述时间组合是否由调用方拒绝，以及外部文件命令的种类与竞争防护策略。建议先通过目录评审限制允许路径的可写主体，要求调用方检查时间顺序；需要执行器保证的部分另立节点。

9. **目标工具能力检测（待确认）**：当前 `internal/catalog/host.go` 的 `CheckHost`/`ResolveExecutable` 检查文件存在、权限、解释器和 shebang，不检测工具版本、命令选项、容器内程序或远端服务能力。journal_grep 的 -g、Docker --until、kubectl 与集群版本、JDK 工具权限、sysstat 文件版本仍需目标环境证据。本节点没有连接这些环境。建议维护最低版本与所需选项清单，在部署前运行固定、只读的能力探测；由独立节点确定“加载时 unsupported”或“执行时失败”的状态契约。

10. **写操作（已删除）**：2026-10-22 起示例目录不含任何 risk 不是 read 的 action，process_signal 和 docker_stop 已删除。写操作如需恢复，须单独评审授权范围（PID 复用、容器强制终止、Docker root 权限、容器挂载和容器内链接），本节点没有执行任何写 action。

### G30 示例收紧结果（P12D）

P12D 已实现 G30 的 Redis/MySQL 收紧配置。依据 `builtin-config.md` 的 G31、G34，以下四个示例已恢复可表达的原限制。字段默认值仍按处理器 schema 执行，不声明尚未支持的默认值。

| 示例 | 原本要求的限制 | 当前配置与参数约束 | 剩余默认值差异 |
|---|---|---|---|
| redis_get | 仅 GET；键前缀 app:；键匹配 `^app:[A-Za-z0-9:_-]+$` 且最长 128；command 默认 GET | commands=[GET]、key_prefixes=[app:]；args 的 string_array 正则和 max_len=128 保留键字符及长度限制；GET 要求恰好一个键 | command=GET 和 args 都需显式提供，不支持 command 默认值 |
| redis_info | 仅 INFO；仅 server/memory/stats；command 默认 INFO，section 默认 server | commands=[INFO]、info_sections=[server,memory,stats]；显式 args 只可选择一个允许分节；省略 args 时按配置顺序汇总这三个分节 | command=INFO 需显式提供；省略分节不会默认选择 server |
| mysql_show | 数据库仅 app；SQL 仅 SHOW TABLES/SHOW STATUS；database 默认 app，sql 默认 SHOW TABLES | databases=[app]、statement_types=[SHOW]、show_types=[TABLES,STATUS]；保留 database 和固定 SQL 正则；STATUS 按 G34 显式授权 | database=app 和 sql 都需显式提供，不支持参数默认值 |
| mysql_query_readonly | 数据库仅 app；语句仅 SELECT/SHOW/DESC/EXPLAIN；database 默认 app | databases=[app]、statement_types=[SELECT,SHOW,DESCRIBE,EXPLAIN]；EXPLAIN 目标也受 G31 检查；无服务器级 SHOW 授权；数据库账号仍约束视图等内部对象 | database=app 和 sql 都需显式提供，不支持参数默认值 |

## 5. 本地示例检查

`make examples-check` 先构建 CLI，再对原始 examples/catalog 执行 catalog validate，并断言 83 个 action 全部 valid。随后通过 catalog try 执行 system_load、disk_usage、ports_listening，要求成功、输出非空、无 stderr 且未截断；ports_listening 提供 /usr/bin/ss 作为候选路径。check_examples.py 仅依赖 Python 标准库；本机需要 uptime、df、ss 及读取 netlink socket 的权限，不会通过 sudo 提权。

日志冒烟在自动删除的临时目录复制目录，仅替换 log_search 的 builtin_config.allowed_roots。它创建普通与 gzip 测试日志，并通过 catalog try 验证逐行结果、count=3、无匹配退出码 0、max_matches=1 的 truncated/resource_limit_reached。原始示例路径和文件不被修改；try 始终以当前用户执行，run_as 不在此检查中验证。检查不运行 Redis、MySQL、HTTP、Docker、Kubernetes、DNS 或任何写 action。

选择把 examples-check 作为 `make test` 的依赖。现有 `.github/workflows/ci.yml` 已执行 make test，因此无需改动工作流即可在本机和 CI 使用同一检查；检查失败会阻止 Go 测试目标继续。脚本 action 的签名风险警告属于预期输出，不表示校验失败。

验收命令：

```sh
make build
./bin/allowops catalog validate --dir examples/catalog
make examples-check
make test lint
```

本机依赖缓存只读时，可把 GOCACHE 和 STATICCHECK_CACHE 指向 /tmp 下的任务目录，并用已有模块下载缓存的 file:// 路径作为 GOPROXY。本节点的命令、被验证的提交 SHA、公开示例敏感字面值检查与剩余待确认项随交付报告提供。
