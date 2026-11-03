# Java 诊断深化与 Arthas 引入计划

状态：已确认（2026-10-23，决定记录第 21 节 A66）。验收阈值 2026-10-24 确认（A67）。第 9 节全部按推荐选项采纳，取代 2026-10-22“不集成 Arthas”的决定。

依据：

- 2026-10-22 Arthas 调研（Arthas 4.3.5 源码 tag `arthas-all-4.3.5`），下文称“前次调研”。
- 本次对同一源码的核对，结论见第 10 节。
- 调研时的 allowops main 分支。

术语：

- 目标 JVM：被诊断的 Java 进程。
- attach：通过 HotSpot 的 Attach 机制向运行中的 JVM 加载 Java agent。
- 增强：Arthas 用 `retransformClasses` 向目标类的方法织入字节码（watch、trace、stack、monitor、tt）。
- hsperfdata：HotSpot 写在 `/tmp/hsperfdata_<用户>/<pid>` 的性能计数器文件，jstat 读取的就是它。读取它不需要 attach。
- OGNL（Object-Graph Navigation Language）：Arthas 的表达式语言，可调用任意 Java 方法。

## 1. 目标与“不影响使用”的定义

“不影响客户端”按两类对象理解：

1. 目标 JVM 及其用户：诊断期间业务请求的延迟和错误率不明显变化；诊断结束后 JVM 内不留 Arthas 端口、线程和增强代码。
2. 安装 allowops-agent 的主机：主安装包的大小和依赖不变；未启用 Arthas 的主机行为不变；主机上不需要安装 JDK。

验收阈值：2026-10-24 负责人采纳阶段 0 报告（[arthas-stage0-report.md](arthas-stage0-report.md)）第 5.1 节的建议值（A67）。状态为“估算”或“未验证”的项在阶段 2D 验收时核对，核对结果见阶段 2 验收报告（[arthas-stage2-acceptance-report.md](arthas-stage2-acceptance-report.md)）。状态列中“阶段 2 验收”之后为该报告的结论和章节；阈值没有因验收修改，建议值见该报告第 6 节。

状态的含义与报告相同：
- 实测：阈值来自阶段 0 的测量。
- 估算：阈值由测量值乘以安全系数得出，阈值本身未验证。
- 未验证：没有测量依据。

阶段 0 的测量条件：4 CPU 容器，512 MB 堆，G1，基线 p99 约 1.2 ms，1000 请求/秒。

| 项 | 阈值 | 状态 |
|---|---|---|
| L1 命令期间，压测接口的延迟 | 按“调用相关秒”（attach、命令、stop 所在的秒）判定，不按 60 秒窗口的合并 p99 判定。除 `thread -b` 外：调用相关秒的 p99 ≤ 4 倍基线 p99，最大延迟 ≤ 50 ms；其余秒的典型 p99 与基线相差在 ±5% 内（至少 3 次重复）。`thread -b`：最大延迟 ≤ 100 ms | 实测；4 倍、50 ms、100 ms 为估算。阶段 2 验收：结论待定（3.1），除 `thread -b` 外的 168 次调用中 1 次最大延迟 166.9 ms，来自一个 `Cleanup` 安全点，与调用的关系原因未查明 |
| L2 命令期间，未被观察的接口 p99 增幅 | 增强开始 10 秒后：≤ 15%，3 次以上重复的中位数 ≤ 5% | 实测，样本少 |
| L2 增强开始后的瞬态 | 影响的秒数 ≤ 5 秒；这些秒内所有接口的最大延迟 ≤ 2 秒。L2 命令的风险说明写明增强开始后 1~4 秒的整个 JVM 延迟，以及 JDK 11、21 上观察到的最长 4.12 秒暂停 | 实测；JDK 11、21 的暂停超出 2 秒，原因未查明 |
| L2 命令期间，被观察方法 p99 增幅 | 被观察方法 ≤ 1000 次/秒时 ≤ 20%，只在会话期间；更高速率不承诺 | 实测，样本少；速率上限为估算 |
| 错误率 | 不增加 | 实测 |
| 会话结束后的 Arthas 监听端口、Arthas 线程、增强类 | 均为 0。`stop` 返回后 10 秒内端口关闭，`arthas-` 线程数为 0 | 实测。阶段 2 验收：达到（3.3） |
| 目标容器内新增的 JVM 进程 | 0 | 实测。阶段 2 验收：达到（3.3） |
| L1 单次调用总时长（含 attach 和清理） | ≤ 15 秒，在 MCP `wait_seconds` 默认值 30 秒内返回 | 实测。阶段 2 验收：达到（3.2） |
| 50 次 attach/stop、3 次 Full GC 后的元空间使用量 | ≤ 基线 + 25 MB；不对提交量设阈值 | 实测；25 MB 为估算。阶段 2 验收：未达到（3.4），含 `logger` 时 +56.3~+69.5 MiB，不含 `logger` 时 +8.9~+20.0 MiB |

L1、L2 的定义见第 4 节。

## 2. 前次调研方案 A 的问题

前次调研推荐方案 A：目录 action 执行 `docker exec <容器> timeout ... java -jar arthas-boot.jar <pid> -c '<命令>'`，第二步用 arthas-client 执行 `stop`，不改 allowops 代码。按第 1 节的目标，方案 A 有以下问题：

| 问题 | 对目标 JVM 的影响 | 依据 |
|---|---|---|
| arthas-boot 本身是一个 JVM，又启动 arthas-core 子进程（另一个 JVM）执行 attach | 两个 JVM 计入目标容器的内存限额，可能触发 OOM killer 结束业务进程 | `ProcessUtils.startArthasCore`；实际内存占用未测 |
| telnet 3658 端口对 127.0.0.1 的连接默认免认证（`localConnectionNonAuth=true`） | 会话期间，同一网络命名空间的其他进程可以执行 OGNL | `AuthUtils.localPrincipal`、`arthas.properties` |
| steps 共用 action 的 context，超时后清理步骤被跳过 | 增强代码和 Arthas 服务端可能残留 | `internal/executor/executor.go` |
| 同一 JVM 上的两个调用共用一个 Arthas 服务端 | 先结束的调用执行 stop，中断另一个；后到的调用的启动参数不生效 | `ArthasBootstrap.getInstance` 已有实例时直接返回 |
| 命令语法用 regex 限定 | regex 写宽时会放行 OGNL | 前次调研 |
| 没有执行前检查和执行中的中止条件 | 内存或 CPU 已紧张的 JVM 仍会被 attach | — |
| 容器内需要 JDK 和 Arthas 包；jar 不在签名范围内 | 只有 JRE 的镜像不可用；jar 来源没有校验 | 前次调研 |

这些措施需要主机端代码，目录 action 无法表达。因此本计划改用内置处理器（前次调研方案 B 的方向），并增加第 3~6 节的限制。

## 3. 总体方案：内置处理器 `jvm_arthas`

在 allowops-exec（root）中新增内置处理器。调用方（AI agent）只能选择签名目录列出的命令和结构化参数，不能传入 Arthas 命令文本。

### 3.1 一次调用的流程

1. 加锁：按“宿主机 pid + JVM 启动时间”加主机端文件锁。锁已被占用时立即返回错误，不排队。
2. 解析目标：目标来自 builtin_config 的白名单（主机上的 systemd 服务名，或 Docker 容器名加主类）。allowops-exec 从 Docker Engine API 读取容器的 `State.Pid`，在该容器的 PID 命名空间内按主类找到 JVM。调用方不传 pid。
3. 执行前检查：见 3.2。任一项不通过即返回原因，不 attach。
4. 准备 Arthas 文件：见第 6 节。
5. attach：allowops-exec 用 Go 实现 HotSpot attach 协议，不启动 JVM。
   - 发送信号前确认以下各项，任一项不满足时拒绝，不发送信号：
     - hsperfdata 的 `sun.rt.jvmCapabilities` 首字符为 `1`（JVM 允许 attach）。
     - `/proc/<pid>/status` 的 `SigCgt` 含 SIGQUIT，或 `/tmp/.java_pid<容器内 pid>` 套接字已存在（`-Xrs` 的 JVM 不捕获 SIGQUIT，但套接字可能已存在）。SIGQUIT 的默认动作是终止进程并转储 core。
     - 目标工作目录或 `/tmp` 至少一处可写。没有 attach 文件时，SIGQUIT 使目标向标准输出打印线程转储。
   - 按 HotSpot 的查找顺序创建 `.attach_pid<容器内 pid>` 文件，发送 SIGQUIT，等待 `.java_pid<容器内 pid>` 套接字出现。套接字已存在时不发送信号。
   - 连接该套接字，发送 `load instrument false <arthas-agent.jar>=<参数>`。JDK 8 要求 attach 文件属主和连接的 uid 都等于目标 JVM 的有效 uid，因此 allowops-exec 在锁定的 OS 线程上切换到目标的有效 uid/gid 后创建 attach 文件和连接；文件只能建在该用户可以创建文件的目录中，与 HotSpot 自带的 attach 客户端相同。JDK 11 及以上接受 root 连接。
   - 参数的键名与 `arthas.properties` 相同（见第 10 节）：`telnetPort=-1`（不监听 telnet）、`httpPort=<allowops 选定的端口>`、`ip=127.0.0.1`、`password=<每次随机生成>`、`localConnectionNonAuth=false`、`disabledCommands=<本次不需要的全部命令>`、`sessionTimeout=<略大于调用时长>`。
   - `disabledCommands` 不能包含 `reset` 和 `stop`。阶段 2 实测：两者被禁用后清理无法停止服务端，HTTP API 也没有其他停止服务端的方式。
   - `localConnectionNonAuth=false` 必需。缺少它时，来自 127.0.0.1 的连接不需要密码。
   - 参数先经 URL 解码，因此密码只用字母和数字。参数总长度不超过 1024 个字符。
   - 参数 `mcpEndpoint=`（空值）不能关闭 Arthas 自带的 MCP 服务，原因未查明。关闭 MCP 依靠包内的 `arthas.properties` 删除 `arthas.mcpEndpoint` 和 `arthas.mcpProtocol` 两个键（第 6 节）。
   - 密码经 attach 套接字传递，不出现在任何进程的命令行中。阶段 0 实测：密码没有出现在标准输出、Arthas 日志、容器文件和 `/proc` 中。
   - 端口的选择方式（读取目标网络命名空间的 `/proc/<pid>/net/tcp` 选空闲端口，或传 0 后查询）在阶段 2 确定。
6. 执行：allowops-exec 在锁定的 OS 线程上进入目标网络命名空间（setns），连接 Arthas HTTP API，使用 Basic 认证。Go 代码按白名单把结构化参数拼成命令，每条命令设置 `execTimeout`（上限 60 秒）。HTTP 连接断开不终止 Arthas 作业，作业持续到 `execTimeout` 到期，因此 `execTimeout` 也是 allowops-exec 异常退出后作业的最长运行时间。返回的 JSON 转成文本后，按“脱敏 → 过滤 → 截断”处理。
7. 运行期监测：见 3.3。
8. 清理：无论成功、超时、取消还是监测中止，都按以下顺序执行：中断作业（`interrupt_job`）→ `close_session` → `reset` → `stop`。清理使用独立的时间预算，不受 action context 取消的影响。
   - 作业运行期间不能先执行 `reset`。阶段 0 实测：此时 `reset` 之后类仍处于增强状态，而 Arthas 不再记录这次增强。
   - `stop` 请求返回 `unexpected EOF` 属正常。是否停止以端口关闭和 `arthas-` 线程数为 0 判定，期限为 `stop` 返回后 10 秒（实测 3.1~3.3 秒）。
   - 最后删除注入的文件。
9. 会话记录：attach 前写入 `/var/lib/allowops-exec/arthas/`（root，0600），内容为 pid、JVM 启动时间、端口、密码、截止时间；`init_session` 之后补记会话 ID。清理成功后删除。

### 3.2 执行前检查

数据来自 `/proc` 和 hsperfdata，都不需要 attach。阈值写在 builtin_config 中，签名目录只能收紧默认值。

“默认值”列来自阶段 0 报告第 5.2 节，2026-10-24 负责人采纳（A67）。状态的含义见第 1 节。状态为“估算”或“未验证”的项在阶段 2D 验收时核对，“阶段 2 验收”之后为阶段 2 验收报告（[arthas-stage2-acceptance-report.md](arthas-stage2-acceptance-report.md)）的结论和章节。默认值没有因验收修改。

| 检查 | 默认值 | 状态 | 不通过时 |
|---|---|---|---|
| 目标是 HotSpot JVM：hsperfdata 文件存在；`SigCgt` 含 SIGQUIT，或 `/tmp/.java_pid<容器内 pid>` 已存在 | — | 实测 | 拒绝 |
| JVM 版本在已验证的范围内（hsperfdata 的 `java.property.java.version`） | Temurin 8u504、11.0.32、17.0.20、21.0.12（x86_64） | 实测 | unsupported |
| JVM 允许 attach：hsperfdata 的 `sun.rt.jvmCapabilities` 首字符为 `1`（jps 用同一计数器判断） | — | 实测 | unsupported |
| 运行时包含 `java.instrument`：`<JAVA_HOME>/lib/libinstrument.so`（JDK 8 为 `lib/amd64/libinstrument.so`）存在，或 `release` 文件的 `MODULES` 含 `java.instrument` | — | 实测 | unsupported |
| attach 文件位置：目标工作目录或 `/tmp` 至少一处可写 | — | 实测 | 拒绝 |
| 目标 JVM 中没有已存在的 Arthas 实例：没有名称以 `arthas-` 开头的线程，也没有 Arthas 监听端口。已打开的 jar 和内存映射只说明曾经加载过，不作为判据 | — | 实测 | 拒绝。已有实例会忽略 allowops 的启动参数 |
| 容器内存余量：cgroup 内存限额减去 `memory.current` | ≥ 256 MB | 实测。阶段 2 验收：达到（3.5） | 拒绝 |
| 元空间余量：`MaxMetaspaceSize` 减去已用量；未设上限时跳过 | ≥ 64 MB | 实测。阶段 2 验收：达到（3.5、3.6）；读取的 hsperfdata 计数器落后于实际使用量（第 5 节） | 拒绝 |
| 老年代使用率低于阈值，且最近 N 秒内没有 Full GC | 无默认值，阶段 2D 验收时确定 | 未验证。阶段 2 验收：结论待定，已测量依据，建议值待负责人确认（3.8） | 拒绝 |
| 目标进程 CPU 使用率（5 秒平均，相对 cgroup CPU 限额） | L2：< 50% | 未验证 | 拒绝 |
| 距同一 JVM 上次 attach 的时间 | ≥ 60 秒 | 估算。阶段 2 验收：结论待定，60 秒内内存和元空间不回落（3.9） | 拒绝 |
| 该 JVM 生命周期内的 attach 次数 | < 5 | 实测。阶段 2 验收：达到（3.9） | 拒绝 |
| `thread -b`：hsperfdata 的 `java.threads.live` | ≤ 500 | 未验证。阶段 2 验收：结论待定，1000 个线程以内 `ThreadDump` 安全点不随线程数增加（3.7） | 拒绝该命令 |

attach 次数设上限的原因：阶段 0 实测每次 attach/stop 使元空间使用量增加约 12 MB，类加载器在两次 Full GC 后才卸载；内存限额 1 GB 的容器在 14~25 次循环后被 OOM killer 结束。

### 3.3 运行期监测与中止

会话期间每秒采样以下数据：

- 目标进程 CPU（`/proc/<pid>/stat`）。
- GC 次数和时间（hsperfdata）。
- 可选的健康检查地址。它与 `http_get` 的限制相同：只发 GET，地址受 `allowed_prefixes` 限制。

任一项超过阈值时，按 3.1 第 8 步的清理顺序执行。结果中标记 `aborted_by_guard` 和触发的检查项。

- 增强开始后的 5 秒内不评估 CPU 和健康检查阈值。阶段 0 实测：增强开始后 1~4 秒内 JVM CPU 达到 178%~378%（4 CPU 容器），所有接口的延迟达到数百毫秒。这段时间内评估，每次增强都会触发中止。
- 监测不能发现阶段 0 在 JDK 11、21 上观察到的整个 JVM 暂停（最长 4.12 秒，原因未查明）：暂停期间进程 CPU 接近 0。

### 3.4 残留回收

- JVM 侧：阶段 0 实测，`sessionTimeout` 只回收空闲会话。运行中的作业不受它影响，作业结束后类仍处于增强状态。增强只由 `reset` 还原。因此 `sessionTimeout` 不能作为回收手段。
- 主机侧：每次 `jvm_arthas` 调用开始时，以及 allowops-agent 启动时，allowops-exec 检查过期的会话记录。目标仍是同一进程（pid 和启动时间一致）时，用记录中的密码连接，按 `interrupt_job`、`close_session`、`reset`、`stop` 的顺序清理，然后删除记录。
- allowops-exec 被 SIGKILL 结束时，Arthas 服务端仍在运行，但连接需要随机密码。运行中的作业持续到 `execTimeout` 到期，类保持增强，直到回收流程执行 `reset`。
- 增强已失去 Arthas 记录时（作业运行期间先执行了 `reset` 或 `stop`），恢复方法是：重新 attach，对该类执行一次 `watch ... -n 1`，再执行 `reset`。阶段 0 在 JDK 8、17 上验证。正常的清理顺序不会产生这种状态。
- 触发回收的协议形式（allowops-exec 的新请求类型，或一个固定 action）在阶段 2 设计时确定。

## 4. 命令分级

| 级别 | 命令 | allowops risk | 阶段 |
|---|---|---|---|
| L0：不 attach | 新内置 `jvm_perfdata`（读取 hsperfdata）；现有 `jvm_list`、`jvm_gc_stats`、`jvm_thread_dump` | read | 1 |
| L1：attach，不增强 | `dashboard -n 1`、`thread -n <1~10>`、`thread -b`、`thread <id>`、`memory`、`jvm`、`sc -d <类>`、`sm -d <类> [方法]`、`classloader -t`、`classloader -l`、`logger`（只列出）、`sysprop <白名单内的键>`、`version` | write | 2 |
| L2：增强 | `watch`、`trace`、`stack`、`monitor`；`jad`（触发 retransform，并输出业务源码） | write，ABAC 单独授权 | 3 |
| 禁止 | `ognl`、`vmtool`、`redefine`、`retransform`、`mc`、`groovy`、`heapdump`、`dump`、`profiler`、`jfr`、`tt`、`getstatic`、`sysenv`、`mbean`、`tee`；不带参数的 `sysprop`；带值的 `sysprop`、`vmoption`、`options`、`logger --level`；管道、重定向、后台作业 | 不提供 | — |

L1 也使用 write：

- attach 会向目标 JVM 加载代码。
- `stop` 之后，bootstrap 类路径中的 arthas-spy 类无法卸载，JVM 不能恢复到 attach 前的状态。
- risk 为 read 时，MCP 工具注解为 `readOnlyHint: true`，与上述事实不符。
- ABAC 规则按 action 名（如 `jvm_arthas_*`）单独授权。是否新增 risk 级别见第 9 节。

L2 的限制：

- 类名和方法名必须是精确名称，不允许通配符和 `-E`。
- 类名前缀必须在 builtin_config 的白名单内（如 `com.example.`）。拒绝 `java.`、`javax.`、`jdk.`、`sun.`、`com.sun.` 等前缀。
- `-n` ≤ 5，`-m 1`，`watch -x` ≤ 2；`watch -M`（结果大小上限）由 builtin_config 指定。
- watch 表达式只能从固定模板中选择，如 `{params,returnObj,throwExp}` 的子集。条件表达式只开放 `#cost > <整数>`，由 Go 代码用整数参数生成。
- 单次增强时长 ≤ 30 秒（可配置）。
- 执行后核对 Arthas 返回的 `Affect(class count, method count)`。超过 1 个类或方法数上限时，立即 `reset` 并返回错误。
- 输出启用 `secrets` 和 `pii` 脱敏。

## 5. 集群层面的限制

- 新增 action 字段 `max_targets`：job 的目标主机数超过该值时，网关拒绝。Arthas action 设为 1，同一服务一次只诊断一个实例。
- Arthas action 固定 `batch_size: 1`、`max_failures: 1`、`idempotent: false`。
- 同一 JVM 的串行执行、冷却时间、attach 次数上限由主机端检查（3.1、3.2）。
- 主机端并发：一次 Arthas 调用占用 `concurrent_tasks`（当前上限 4）中的一个，不另设上限。

## 6. Arthas 文件的分发与校验

- Arthas 文件不进 allowops-agent 主安装包。另出可选包 `allowops-arthas`（rpm、deb），安装到 `/usr/share/allowops/arthas/<版本>/`，属主 root。
- 包内只放 `arthas-agent.jar`、`arthas-core.jar`、`arthas-spy.jar`、`logback.xml` 和删除 `arthas.mcpEndpoint`、`arthas.mcpProtocol` 两个键后的 `arthas.properties`。阶段 0 实测：只删 `mcpEndpoint` 或在参数中传空值，MCP 服务仍会启动；缺少 `logback.xml` 时，Arthas 向目标进程的标准输出打印 DEBUG 日志和 `[ERROR] can not find arthas logging config`（报告第 3.1 节变体 g）。不放 arthas-boot、arthas-client 和 async-profiler 原生库。
- 版本固定，来源为 Maven Central 的 `arthas-packaging-<版本>-bin.zip`。各文件的 SHA-256 写入签名目录的 builtin_config，allowops-exec 使用前校验。不联网下载。
- 包内不能有 `commands` 目录：Arthas 从 `<arthas 目录>/commands` 加载外部命令。
- 包内的 `SHA256SUMS` 列出各文件的 SHA-256。builtin_config 使用其中 3 个 jar、`arthas.properties` 和 `logback.xml` 的值。
- 只有安装了该包的主机上报 `jvm_arthas` 能力。未安装的主机上，该 action 为 `unsupported`。
- 目标在容器内时，JVM 只能加载其挂载命名空间内可见的文件。有两种方式：
  1. 预装（推荐）：运维把同一版本的文件放进镜像，或以只读卷挂载到固定路径。allowops-exec 经 `/proc/<pid>/root` 读取并校验 SHA-256，不写容器文件系统。
  2. 注入：allowops-exec 把文件复制到目标容器的临时目录，属主为目标用户，结束后删除。容器内的符号链接可能把写入引向宿主机路径，因此写入必须使用 `openat2(RESOLVE_IN_ROOT)`（Linux 5.6 起）或同等的逐级解析（如 `cyphar/filepath-securejoin`，BSD-3-Clause）。CentOS 7（内核 3.10）上能否安全实现未验证；验证前，CentOS 7 只支持预装。
- 创建 attach 文件（`.attach_pid`）同样使用上述安全路径解析。
- 许可：Arthas 为 Apache-2.0，在许可证白名单内。可选包附带 NOTICE，`THIRD_PARTY_NOTICES` 补充条目。

## 7. 安全模型的变化

allowops-exec 新增以下能力。SECURITY.md 的威胁模型已更新（T6、T7 和 “Java diagnostics with Arthas” 一节；T5 不涉及），安全审阅已完成：

- 向目标进程发送 SIGQUIT。
- 在目标挂载命名空间内创建文件（attach 文件；注入方式下的 jar，注入方式尚未实现）。
- 进入目标网络命名空间建立 TCP 连接。
- 以目标 JVM 的 uid/gid 连接 attach 套接字。
- 向目标 JVM 加载代码。

安全审阅后增加的措施：

- Arthas HTTP 响应的状态行和头部也计入读取上限（响应体上限加 64 KiB）。目标网络命名空间内应答的进程不可信。
- 只连接由目标 JVM 自己持有的监听套接字：连接前比对 `/proc/<pid>/net/tcp`、`tcp6` 中该端口监听套接字的 inode 与 `/proc/<pid>/fd`。同一命名空间内抢先绑定该端口的进程收不到密码。
- attach 文件以目标 JVM 的有效 uid/gid 创建（第 3.1 节第 5 步），不再由 root 创建后改属主。

残余风险（已写入 SECURITY.md）：

- 会话期间，同一网络命名空间内的进程可以连接 Arthas 端口，但执行命令需要随机密码。该命名空间内有 `CAP_NET_RAW` 的进程可以从回环流量中获取密码；JVM 自身的 attach 记录（如 JFR 的 `jdk.JavaAgent` 事件）也含密码。密码只在会话期间有效，只能执行本次命令、`reset` 和 `stop`。
- 监听套接字检查与连接之间，JVM 可能关闭监听，另一个进程可能在这一刻绑定该端口。
- 同一网络命名空间内的进程可以占用配置范围内的端口，使调用和清理失败。
- 能写目标文件系统中 Arthas 目录的人可以让 JVM 在 attach 时加载其代码：文件可以在 SHA-256 校验后被替换，Arthas 还会加载该目录下 `commands` 目录中的 jar，后者不校验。allowops-exec 不检查该目录的属主和权限，该目录应只允许 root 写入。
- 配置的 JVM 没有运行或不发布 hsperfdata 时，同一容器或 unit 内主类相同的其他进程会被 attach，调用报告该进程的结果。
- L2 的输出含真实业务数据，脱敏规则不能识别所有敏感内容。
- attach 后 arthas-spy 类常驻目标 JVM，直到进程退出。

## 8. 分阶段计划

每个阶段单独评审、合并。测试和验证只在本地环境进行。

### 阶段 0：本地测试环境与实测（不写产品代码）

内容：

- 本地 Docker Compose 环境：
  - 示例 Spring Boot 应用，JDK 8、11、17、21 各一个镜像。
  - 另加：只有 JRE 的精简镜像、带 `-XX:+DisableAttachMechanism` 的镜像、只读根文件系统的镜像。
  - 压测工具（wrk 或 k6）持续施加负载。
  - 采集 p50/p99 延迟、错误率、进程 CPU、GC、元空间、线程数和安全点日志（JDK 9+ 用 `-Xlog:safepoint`，JDK 8 用 `-XX:+PrintSafepointStatistics`）。
- 用一个最小 attach 程序（或 jattach）按 3.1 的参数加载 Arthas 4.3.5，实测以下项目：
  1. agent 参数中的 `password`、`localConnectionNonAuth`、`mcpEndpoint`、`disabledCommands`、`sessionTimeout` 是否生效；密码是否写入日志。
  2. 只有 JRE 的镜像能否运行 arthas-core。
  3. stop 后线程、端口、类加载器是否回收；50 次 attach/stop 的元空间增量。
  4. 会话超时或 HTTP 连接断开后，增强作业是否终止、增强代码是否还原。
  5. attach 本身、L1 各命令、L2 各命令对 p99 的影响（被观察方法分别为 1k、10k QPS）；retransform 引起的停顿时长。
  6. 只读根文件系统和没有 HOME 的容器中，Arthas 日志（`~/logs/arthas/`）的行为。
  7. 已存在 Arthas 实例的检测方式。
  8. 对照：方案 A（arthas-boot）在容器内的内存占用。
- 输出：实测报告写入 docs，并给出第 1 节阈值和 3.2 检查阈值的建议值。实测报告：[arthas-stage0-report.md](arthas-stage0-report.md)。

完成条件：上述 8 项都有数据和结论；负责人确认阈值。

状态：已完成。8 项的数据和结论于 2026-10-23 完成；阈值于 2026-10-24 由负责人采纳（A67）。实测对本计划的修正已写入 3.1~3.4 节和第 6 节。

### 阶段 1：不 attach 的 JVM 读取

内容：

- 新内置 `jvm_perfdata`：读取 hsperfdata，输出堆和各代使用量、GC 次数和时间、已加载类数、线程数、JVM 版本、运行时长。JVM 参数原文可能含密钥，不输出。
- 目标解析（主机服务；Docker 容器名加主类）和安全路径解析，供阶段 2 复用。
- 示例 action 和 `action-catalog-requirements.md` 条目。

完成条件：

- PerfData 解析的单元测试覆盖 JDK 8、11、17、21 的样本文件。
- 攻击测试：容器内的符号链接、伪造的 hsperfdata 文件、pid 复用。
- 在本地 4 个 JDK 版本的容器中实测：目标 JVM 没有收到信号，没有创建 attach 套接字，标准输出中没有线程转储。
- 只有 JRE 的镜像中可用。现有基于 jstat 的 action 在这种镜像中不可用。

### 阶段 2：Arthas L1 命令

内容：

- `jvm_arthas` 框架：锁、执行前检查、attach、HTTP 会话、清理、会话记录与回收、运行期监测、预装文件校验。
- L1 命令。
- 网关的 `max_targets` 字段。
- `allowops-arthas` 可选包。
- SECURITY.md 更新和安全审阅。

完成条件：

- 单元测试和攻击测试：命令只能由白名单生成；参数中的 `;`、`|`、`>`、换行、引号和 OGNL 片段都被拒绝。
- 本地验收：达到第 1 节阈值；会话结束后 Arthas 端口和线程为 0；目标容器内没有新增进程。
- 故障测试：
  - action 超时、job 取消、`kill -9` 结束 allowops-exec 之后，回收机制都能停止 Arthas。
  - 同一 JVM 的两个并发调用中，第二个被拒绝。
  - 人为提高目标 CPU 时，监测中止会话并完成清理。
- 执行前检查：每个拒绝条件各有一个测试用例。

### 阶段 3：Arthas L2 命令

内容：watch、trace、stack、monitor、jad；第 4 节的 L2 限制；ABAC 示例策略（只授权指定角色，可按时间段限制）。

完成条件：

- 在 1k、10k QPS 两档负载下达到第 1 节的 L2 阈值。
- 每次调用结束后，Arthas 报告的增强类数为 0。
- `Affect` 超过上限时自动 reset，有对应测试。
- 脱敏测试覆盖 Arthas 的对象输出格式（`@String[...]`、表格）。

### 以后评估（不在本计划内）

- Kubernetes Pod：allowops-agent 运行在节点上时，经 CRI 套接字解析容器的 pid，流程与 Docker 相同。
- profiler（加载 async-profiler 原生库）和 JFR：涉及原生代码加载和文件写入，单独评估。
- 人工审批（roadmap 已列）完成后，L2 改为需要审批。

## 9. 负责人确认的事项

2026-10-23 负责人全部按推荐选项采纳（A66）。第 7 项的阈值：2026-10-24 负责人采纳阶段 0 报告第 5 节的建议值（A67），数值见第 1 节和 3.2 节。


1. 是否撤销 2026-10-22 的不集成决定，按本计划从阶段 0 开始。
2. 是否用内置处理器替代前次调研的方案 A（推荐替代，原因见第 2 节）。
3. risk 映射：L1、L2 都用 write，并按 action 名授权（推荐）；或新增 risk 级别（需要修改 catalog、MCP schema、OPA 规则和控制台）。
4. Arthas 文件来源：预装（推荐，也是 CentOS 7 上唯一的方式）；注入在安全路径解析验证后再开放。
5. 是否新增 action 字段 `max_targets`。
6. 首批目标：主机上的 JVM 和 Docker 容器；Kubernetes 以后评估。
7. 第 1 节的验收阈值（阶段 0 之后确认）。

## 10. 本次源码核对（Arthas 4.3.5）

| 结论 | 位置 |
|---|---|
| agent 参数格式为 `<arthas-core.jar 路径>;key=value;...`，先做 URL 解码 | `agent/.../AgentBootstrap.java` 的 `main`、`decodeArg` |
| agent 参数的键加上 `arthas.` 前缀后作为配置，与 `arthas.properties` 的键名相同 | `ArthasBootstrap.getInstance(Instrumentation, String)` |
| 目标 JVM 中已有 Arthas 实例时，`getInstance` 直接返回该实例，新参数不生效 | 同上 |
| `telnetPort`、`httpPort` 小于 0 时不监听，等于 0 时使用随机端口 | `ArthasBootstrap.java` 375~383 行、450~467 行 |
| `localConnectionNonAuth` 为 true 时，来自 127.0.0.1 的连接免认证；为 false 时按用户名和密码认证 | `security/AuthUtils.java`、`Configure.isLocalConnectionNonAuth` |
| `mcpEndpoint` 为空时不启动 MCP 服务。阶段 0 实测：包内 `arthas.properties` 含 `arthas.mcpEndpoint` 时，参数 `mcpEndpoint=` 不生效，MCP 服务仍启动，原因未查明 | `ArthasBootstrap.java` 487~492 行 |
| 只有在监听 0.0.0.0 且未设密码时，Arthas 才生成密码并写入日志；用户指定的密码在这段代码中不写日志 | `ArthasBootstrap.java` 415~426 行 |
| watch 有 `-M/--sizeLimit` 选项 | `WatchCommand.java` 99 行 |
| arthas-boot 用 `ProcessBuilder` 启动 arthas-core 子进程执行 attach | `boot/.../ProcessUtils.startArthasCore` |

以上是源码阅读的结论。运行行为见阶段 0 报告；与上表不一致的一行已在表中注明。
