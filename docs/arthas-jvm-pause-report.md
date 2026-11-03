# 阶段 0 中整个 JVM 暂停的原因调查

状态：阶段 0 报告 3.5.6 记录的整个 JVM 暂停，其机制已在受控实验中确认，阶段 0 的事件由这一机制造成属于推断；主机一侧慢提交的来源只查明一部分。结论见第 1 节，对阶段 3 的建议见第 7 节，建议都标为“建议，待负责人确认”。

- 对象：[arthas-stage0-report.md](arthas-stage0-report.md)（下称“阶段 0 报告”）3.5.6 节。阶段 0 在 JDK 11、21 的 `l2:watch@p10k` 运行中观察到整个 JVM 暂停，最长 4.12 秒，原因未查明。
- 测量日期：2026-10-25。测量脚本在 `test/jvm-arthas/`。产品代码（`internal/` 等）和 `docs/java-diagnostics-arthas-plan.md` 没有改动。
- 原始数据：保存在执行测量的本地主机上，不进仓库。下文的数据路径都相对原始数据目录。

术语：

- 安全点（safepoint）：HotSpot 停止所有 Java 线程后执行 VM 操作（GC、类重定义等）的状态。VM 线程（`VM Thread`）负责开始和结束安全点、执行 VM 操作。
- 统一日志：HotSpot 的 `-Xlog` 日志。写文件时，打印日志的线程自己调用 `write()`，每行一次，写完才返回（JDK 17 起可用 `-Xlog:async` 改为由单独的线程写）。
- journal：ext4 的元数据日志。内核线程 jbd2 周期性地把一个事务的元数据块写入 journal，这个过程称为提交。
- hsperfdata：JVM 的性能数据文件 `/tmp/hsperfdata_<用户>/<pid>`，以共享方式映射到 JVM 的内存，JVM 直接写这段内存。`jps`、`jstat` 和产品的预检（阶段 2 验收报告 3.6）读取它。
- 暂停事件：连续的若干秒，`hot`、`ping`、`work`、`db` 四个流每秒的 p99 都大于 200 ms。与阶段 0 报告的“JVM 暂停”定义一致：所有接口同时受影响。
- 日志写入缺口：安全点日志中，一行日志的打印时刻到下一个计时步骤之间多出的时间（计算方法见 4.1）。
- p10k：阶段 0 报告 3.5.1 的负载，被观察方法每秒调用 10000 次。

## 1. 结论

1. 阶段 0 的 22 个暂停事件（JDK 11 20 个、JDK 21 2 个）都有同一特征：时间丢失在 VM 线程写一行安全点日志的位置。JVM 报告的 VM 操作本身只用了 0.2~8.4 ms（4.1）。
2. 机制已在受控实验中确认（4.3、4.4）：
   - JVM 日志文件所在的文件系统暂停写入时，VM 线程在 `write()` 中等待，安全点不能开始或结束。JDK 11、17、21 都重现了阶段 0 的特征。JDK 17、21 的写入在所有 Java 线程停止之后，最大延迟与 VM 线程等待的时长相差不超过 20 ms；JDK 11 的写入在安全点开始之前，影响取决于等待期间是否有线程需要 GC。
   - hsperfdata 所在的文件系统暂停写入时，JDK 11、17、21 每次都出现约 4 秒的整个 JVM 暂停，等待的线程在 hsperfdata 的写缺页中。加 `-XX:+PerfDisableSharedMem` 后没有暂停。
   - 日志文件在 tmpfs 上时没有暂停；用 `-Xlog:async` 时只有日志线程等待，请求没有延迟。
3. 本机的 `/`（JVM 日志和容器 `/tmp` 所在）和 `/data` 在 112 分钟的测量中有 40 次追加写入等待 0.2 秒以上，最长 2.55 秒。其中 37 次是写入者在 `do_get_write_access` 中等待 journal 提交（4.6）。
4. 自然条件下捕获到 1 次暂停事件（JDK 21，0.92 秒，没有 Arthas 作业）的内核栈：两个 JVM 线程在写 hsperfdata 时以同一路径等待，主机探针在 `/` 上同时等待 0.918 秒（4.5）。
5. 判断：阶段 0 的事件是 VM 线程写安全点日志时等待 `/` 的 journal 慢提交造成的。依据是缺口的位置、受控实验的重现和本机的慢提交；阶段 0 没有记录事件时 VM 线程的内核栈，这一判断属于推断（第 5 节）。
6. 慢提交的来源只查明一部分：有负载记录的 38 次等待中 21 次（55%）前后 2 秒内有 NVMe 盘缓存刷新变慢（单次平均可达 0.5~2.1 秒），随机对照为 21%；其余的原因未查明（4.6）。
7. 与 Arthas 的关系：这一机制不需要 Arthas，没有 Arthas 调用时也出现了（4.1、4.5）。`watch@p10k` 作业期间安全点的频率是前窗口的 4.7~14 倍，VM 线程写日志的次数随之增加，这与阶段 0 的暂停集中在作业期间相符。Arthas 是否提高暂停的发生概率未验证。
8. 对阶段 3：这类暂停来自测试主机的 I/O，不是 Arthas 增强本身的耗时。建议把测试 JVM 的日志和 `/tmp` 放到 tmpfs 上（第 7 节，待负责人确认；`/tmp` 放在 tmpfs 上未单独测量）。增强开始瞬态（作业开始后 1~4 秒，JVM CPU 299%~359%）是另一个现象，仍需单独处理。没有证据支持按 JDK 版本拒绝。

## 2. 背景

阶段 0 报告 3.5.6 的观察：

- 59 次运行中有 3 次出现整个 JVM 暂停（JDK 11 `l2:watch@p10k` 重复 1、4，JDK 21 重复 1），延迟 0.03~4.12 秒，影响所有接口。
- JDK 11 的时间丢失在 `Application time` 行和 `Entering safepoint region` 行之间；JDK 21 的时间丢失在安全点的清理阶段。
- 主机上的 k3s 慢 SQL、系统日志的间隔与部分暂停同时出现。主机上的 `fsync` 探测有 1 秒以上的耗时，但对应时段 JVM 没有暂停。
- 当时没有捕获暂停期间阻塞线程的内核栈。

## 3. 环境和方法

### 3.1 环境

- 主机：Intel Core i5-14600K（20 个逻辑 CPU），125 GiB 内存，内核 6.18.54-1-lts，Docker 29.8.2。
- 存储：一块 NVMe 盘（ZHITAI Ti600 4TB，I/O 调度器 `none`）。`/` 为 `nvme0n1p6`，`/data` 为 `nvme0n1p3`，都是 ext4，挂载选项 `noatime`，journal 为默认的 ordered 模式。仓库和容器的 `/tmp`（overlay 的上层目录）都在 `/`。
- JDK：Temurin 11.0.32.1+1、17.0.20.1+1、21.0.12.1+1；Arthas 4.3.5；示例应用与阶段 0 相同（Spring Boot 2.7.18，`-Xms512m -Xmx512m -XX:+UseG1GC`，容器内存 2 GiB）。
- JVM 日志参数与阶段 0 相同：`-Xlog:safepoint*=info`、`gc*`、`redefine+class*` 写入 `/logs`，`/logs` 绑定到主机上仓库内的目录（在 `/`）。
- CPU：JVM 容器 cpuset 4-7，负载生成器 8-9，各个探针 12-15。独立的 Docker Compose 项目 `jvm-arthas-pause`，端口前缀 25，镜像 `jvmarthas/app-pause:*`。
- 其他进程：每次运行前记录 CPU 4-9 上的进程和其他 `jvm-arthas-*` 容器（原始数据 `others.txt`、`natural/others.txt`，另每 15 秒记录全部容器 `containers-all.txt`）。
  - 每次都有 k3s-server（CPU 4，进程生命周期平均 5.7%）。
  - 自然条件的运行期间，前几次运行的空闲 JVM 容器没有删除，仍在 cpuset 4-7 上（与阶段 0 相同），没有负载。
  - 20:39 前后另一个测试环境的容器 `jvm-arthas-logger-log4j2-17-1` 短暂运行（cpuset 4-7）。
  - 受控实验开始前的一次记录中，CPU 5、6 上有 python3 和 mysqld（生命周期平均 31.9%、24.8%），之后的记录中没有。

### 3.2 实验

| 实验 | 脚本 | 内容 | 次数 |
|---|---|---|---|
| 阶段 0 数据重新分析 | `pause_logwrite.py` | 阶段 0 的 82 个安全点日志，找出日志写入缺口 | — |
| 自然条件 | `run_pause.sh natural`（`bench.py --watch`） | 与阶段 0 相同的 `l2:watch@p10k` 流程，每次 267 秒，JVM 日志在 `/`；同时运行 `pause_watch.py` 和 `host_io_probe.py` | JDK 11 3 次、JDK 21 3 次、JDK 17 1 次、JDK 11 `noop@p10k` 1 次 |
| 设备挂起 | `run_pause.sh stall`、`stall2`（`exp_logstall.py`） | 一个专用的小 ext4 文件系统，其块设备每 30 秒挂起 6 秒，请求在挂起期间不完成；没有 Arthas，p10k 负载 | 每次运行 3 次挂起（`stall2` 6 次），见 4.3 |
| 文件系统冻结 | `run_pause.sh freeze` | 同上，改为 `fsfreeze` 冻结 4 秒：所有写入和共享映射的写缺页都等待 | 每次运行 3 次冻结，见 4.4 |
| 单个写入者 | `exp_jbd2_suspend.py` | 在设备挂起期间，一个模仿 JVM 日志的写入者每秒追加 3 行，同时采样 jbd2 的内核栈 | 6 次挂起 |
| 主机探针 | `host_io_probe.py`、`host_io_summary.py` | 在 `/` 和 `/data` 上每 10 ms 追加一行，记录 50 ms 以上的写入及写入者和 jbd2 的内核栈；每秒记录磁盘的写入量、缓存刷新次数和耗时、各 cgroup 的写入量 | 20:39~22:31 连续记录 |

设备挂起和文件系统冻结所用的文件系统建在 zram 上（`stallfs.sh`），与主机的 NVMe 盘无关。五种情况：

- `disk`：JVM 日志文件在被挂起或冻结的文件系统上。
- `tmpfs`：JVM 日志文件在容器内的 tmpfs 上，JVM 在被挂起的文件系统上没有文件。
- `async`：同 `disk`，加 `-Xlog:async`（JDK 17、21）。
- `hsperf`：JVM 日志文件在 tmpfs 上，容器的 `/tmp`（含 hsperfdata）在被挂起或冻结的文件系统上。
- `hsperf-off`：同 `hsperf`，加 `-XX:+PerfDisableSharedMem`（性能数据留在普通内存中，不写文件）。

`pause_watch.py` 每 20 ms 读取 JVM 每个线程的状态和系统调用，线程在写类系统调用（`write`、`pwrite64`、`writev`、`fsync`、`fdatasync`、`msync`）中或在不可中断睡眠（D 状态）中持续 100 ms 以上时，记录线程名和内核栈。它只读 `/proc`，不接触 JVM。

## 4. 结果

### 4.1 阶段 0 数据：缺口的位置

HotSpot 写一行统一日志的过程：先取时间并格式化行首（安全点日志的时刻就是这里取的），再调用 `write()`，`write()` 返回后才继续。

- JDK 11：VM 线程开始安全点时，先取得 `Threads_lock`、让 G1 的并发线程暂停，再打印 `Application time` 行，之后才更新安全点计时器、通知 Java 线程停止（`safepoint.cpp` 的 `SafepointSynchronize::begin()`、`runtimeService.cpp` 的 `record_safepoint_begin()`）。所以写这一行时的等待不计入 JVM 报告的停顿时间，表现为 `Application time` 与 `Entering safepoint region` 之间的间隔。这期间 Java 线程仍在运行，需要 GC 的线程（`G1CollectForAllocation`）等待这个 VM 操作。
- JDK 17、21：VM 线程在所有 Java 线程停止之后执行清理任务，清理任务每完成一步打印一行（`updating inline caches`、`safepoint cleanup tasks`）。写这些行时的等待计入安全点的清理阶段，这期间所有 Java 线程都已停止。

`pause_logwrite.py` 按上述位置计算缺口：JDK 11 为两行之间的间隔减去 JVM 报告的到达安全点时间；JDK 17、21 为清理阶段减去各步骤自己报告的用时，并给出缺口前的一行。

阶段 0 的 82 个安全点日志中：

| JDK | 缺口 ≥ 20 ms | 位置 | 缺口 (ms) | JVM 报告的停顿或安全点内其余阶段 (ms) |
|---|---|---|---|---|
| 11 | 20 个（`l2:watch@p10k` 重复 1：13 个，重复 4：7 个） | `Application time` 行之后 | 26~4116 | 报告的停顿 0.2~8.4；到达安全点 ≤ 0.2 |
| 11 | 3 个（`noop@p10k` 2 个，`exp_iostall.py` 1 个，都没有 Arthas） | 同上 | 45、46、73 | 0.1~0.2 |
| 21 | 2 个（`l2:watch@p10k` 重复 1） | 清理阶段，`updating inline caches` 行之后 | 1883、423 | 到达 0.0，其余 < 6 |
| 17 | 1 个（`l1c:sm` 预热中，JVM 运行 6.2 秒） | 同上 | 202 | — |

- 这 26 个缺口中，JDK 11 的 20 个和 JDK 21 的 2 个就是阶段 0 报告 3.5.6 的 22 个暂停事件，每次运行的个数和安全点原因一致。阶段 0 报告 JDK 11 的时长从 `Application time` 行算到安全点结束，比缺口多出 JVM 报告的停顿时间。
- 另有一种不同的特征：到达安全点阶段 20 ms 以上，JDK 17 有 17 个（最长 410 ms），JDK 21 有 1 个。它们是 Java 线程到达安全点慢，不是日志写入缺口，本报告没有调查。
- 阶段 2 验收的 39 个安全点日志中，50 ms 以上的缺口有 26 个，都有同样的特征（JDK 11 在 `Application time` 行之后，JDK 17、21 在 `updating inline caches` 行之后）。阶段 2 验收报告 3.1 中 166.9 ms 的那次停顿（JDK 21 `l1all` 重复 2，JVM 运行 344.258 秒，清理阶段 166.2 ms）是其中之一。

安全点的频率（阶段 0 的 `l2:watch@p10k`，每个窗口 60 秒）：

| JDK | 运行 | 前窗口（次/秒） | 作业期间（次/秒） | 后窗口（次/秒） | 作业期间安全点日志（行/秒） |
|---|---|---|---|---|---|
| 11 | 重复 1~5 | 0.50~1.12 | 5.28~5.85 | 0.62~1.08 | 52.8~58.5 |
| 17 | 重复 1、2 | 0.27~0.32 | 2.83~3.90 | 0.25~0.28 | 11.4~15.8 |
| 21 | 重复 1~5 | 0.20~0.25 | 2.17~2.40 | 0.20~0.27 | 8.8~9.7 |

- 作业期间增加的主要是 `G1CollectForAllocation`：JDK 11 重复 2 和 JDK 21 重复 2 的前窗口各 8 次，作业期间各 112 次。JDK 11 另有 174 次 `RevokeBias`。
- 每行安全点日志是一次 `write()`。作业期间 JDK 11 每秒写安全点日志的次数是 JDK 21 的约 6 倍。JDK 11 的事件多于 JDK 21 是否由此造成，未验证。

### 4.2 内核路径：单个写入者

在设备挂起的文件系统上，一个写入者每秒追加 3 行（不调用 `fsync`），共 6 次 6 秒的挂起（原始数据 `mech/jbd2-suspend-test.txt`）：

- 6 次中 4 次有追加写入等待：0.73、1.33、1.37、2.38 秒。
- 6 次中 jbd2 都停在 `jbd2_journal_commit_transaction+0x1126`。
- 追加写入要更新文件的修改时间，这需要取得 inode 所在块的 journal 写访问（`ext4_dirty_inode` → `jbd2_journal_get_write_access` → `do_get_write_access`）。当正在提交的事务正在把这个块写入 journal 时，写入者等待提交写完这个块。
- 有 2 次没有等待。追加写入是否等待，取决于写入时这个块是否正处于被提交的状态。
- 提交前用提交的脚本版本又运行 2 次挂起，2 次都等待（1.34、2.36 秒，`mech/jbd2-suspend-test-2.txt`）。

### 4.3 受控实验：设备挂起

每次运行 3 次 6 秒挂起（`stall2` 为 6 次），没有 Arthas，p10k 负载。

| JDK | 日志位置 | 挂起次数 | 暂停事件 | JVM 线程等待（≥ 100 ms） | 安全点日志缺口 |
|---|---|---|---|---|---|
| 11 | `disk` | 3 | 1 次，最大延迟 3142 ms，JVM CPU 18% | VM 线程 `write` 4.32 秒，内核栈 `do_get_write_access` ← `ext4_dirty_inode` | `Application time` 行之后 4300 ms，报告的停顿 0.2 ms |
| 17 | `disk` | 3 + 6 | 3 次（6 次挂起的运行中），最大延迟 943、3721、1185 ms，JVM CPU 2%~10% | VM 线程 `write` 0.92、3.71、1.18 秒，内核栈同上 | 清理阶段，`updating inline caches` 行之后 930、3699、1181 ms |
| 21 | `disk` | 3 + 6 | 2 次（6 次挂起的运行中），最大延迟 1283、3505 ms，JVM CPU 2%~6% | VM 线程 `write` 1.28、3.49 秒（第 2 次的内核栈见下） | 同上，1282、3497 ms |
| 11 | `tmpfs` | 3 | 0 | 0 | 0 |
| 21 | `tmpfs` | 3 | 0 | 0 | 0 |
| 17 | `async` | 3 | 0 | `AsyncLog Thread` `write` 1.10 秒，同一内核栈 | 0 |
| 21 | `async` | 3 | 0 | `AsyncLog Thread` `write` 2.85 秒，同一内核栈 | 0 |
| 11 | `hsperf` | 3 | 0 | 0 | 0 |
| 17 | `hsperf` | 3 | 0 | 0 | 0 |
| 17 | `hsperf-off` | 3 | 0 | 0 | 0 |

- JDK 11 `disk` 的事件重现了阶段 0 JDK 11 的特征：缺口在 `Application time` 行之后，JVM 报告的停顿只有 0.2 ms。
- JDK 17、21 `disk` 的 5 个事件重现了阶段 0 JDK 21 的特征：缺口在清理阶段的 `updating inline caches` 行之后，最大延迟与 VM 线程等待的时长相差不超过 20 ms。
- JDK 21 第 2 次的 VM 线程等待在 `folio_wait_writeback` ← `ext4_da_write_begin`：等待正在回写的页。测试设备（zram）要求稳定页（`stable_writes=1`），主机的 NVMe 盘不要求（`stable_writes=0`），这条路径只说明测试设备上的情况。两次等待写的是同一个文件描述符（安全点日志）。
- JDK 21 第 1 次事件的同一时刻，`VM Periodic Task Thread` 在 hsperfdata 的写缺页中等待 0.60 秒（`ext4_page_mkwrite` → `do_get_write_access`）；主机探针在 `/` 上同时等待 2.55 秒。这次运行的 `/tmp`（hsperfdata）在 `/` 上。
- `async` 的两次等待说明：写日志的线程等待时，`-Xlog:async` 下等待的是单独的日志线程，请求没有延迟。
- JDK 11 `tmpfs` 在运行开始的第 1 秒有一个 447 ms 的秒（JVM CPU 326%），是负载开始时 JVM 的预热，与挂起无关。
- 一次挂起是否使 VM 线程等待是概率性的（4.2）：`disk` 的 VM 线程等待次数为 JDK 11 3 次中 1 次，JDK 17 9 次中 3 次，JDK 21 9 次中 2 次。这些次数不足以比较 JDK 版本之间的差异。

### 4.4 受控实验：文件系统冻结

冻结期间每次写入都等待，与 journal 的状态无关。每次运行 3 次 4 秒冻结。

| JDK | 日志位置 | 冻结次数 | 暂停事件（最大延迟，JVM CPU） | JVM 线程等待（≥ 100 ms） | 安全点日志 |
|---|---|---|---|---|---|
| 11 | `disk` | 3 | 1 次（345 ms，17%） | 2 次冻结中 VM 线程 `write` 3.29、3.65 秒 | `Application time` 行之后 3302、3649 ms，报告的停顿 0.1 ms |
| 17 | `disk` | 3 | 2 次（2426、1929 ms，10%~16%） | 2 次冻结中 VM 线程 `write` 2.41、1.93 秒 | 清理阶段，`updating inline caches` 行之后 2410、1928 ms |
| 21 | `disk` | 3 | 3 次（3402、3721、1662 ms，11%~12%） | 3 次冻结中 VM 线程 `write` 3.39、3.71、1.65 秒 | 同上，3397、3712、1645 ms |
| 11、17、21 | `tmpfs` | 各 3 | 0 | 0 | 未取回（见下） |
| 17 | `async` | 3 | 0 | 2 次冻结中 `AsyncLog Thread` `write` 各 3.19 秒 | 没有缺口 |
| 21 | `async` | 3 | 0 | 0 | 没有时刻在冻结期间的日志行 |
| 11 | `hsperf` | 3 | 3 次（4029、4029、5015 ms，2%~15%） | 每次冻结：`VM Periodic Task Thread`、Tomcat 工作线程、VM 线程在写缺页中等待 3.33~4.05 秒 | 未取回 |
| 17 | `hsperf` | 3 | 3 次（各 4029 ms，2%~4%） | 每次冻结：`VM Periodic Task Thread`、Tomcat 工作线程 3.99~4.05 秒；1 次另有 C1 编译线程 | 未取回 |
| 21 | `hsperf` | 3 | 3 次（3989~4029 ms，71%~77%） | 每次冻结：`VM Periodic Task Thread`、Tomcat 工作线程 3.99~4.03 秒；1 次另有 VM 线程和 C1 编译线程 | 1 次 `Cleanup` 安全点到达阶段 4018 ms |
| 17、21 | `hsperf-off` | 各 3 | 0 | 0 | 没有缺口 |

- `disk`：VM 线程的内核栈为 `percpu_rwsem_wait` ← `vfs_write`，即冻结的写入等待。JDK 17、21 的最大延迟与 VM 线程的等待时长相差不超过 20 ms，JVM CPU 降到 10%~16%：所有 Java 线程停在安全点。
- `disk` 中没有 100 ms 以上等待的冻结：JDK 11 第 2 次冻结的 4 秒内没有日志行，VM 线程没有写日志；JDK 17 第 3 次冻结中，前后两个安全点相隔 6.98 秒，VM 线程在冻结结束前 0.04 秒才写日志，等待约 40 ms。
- JDK 11 的两次等待都在 `Cleanup` 安全点开始前，影响较小。第 3 次冻结时，等待结束后紧接着是一个 `G1CollectForAllocation` 安全点：需要 GC 的线程在等待期间提出请求，随后等待，最大延迟 345 ms。第 1 次冻结的 3.29 秒内没有超过 200 ms 的秒。阶段 0 的 20 个 JDK 11 事件中 15 个是 `G1CollectForAllocation`，与此相符。
- `hsperf`：冻结前内核把脏页写回，共享映射的页随之变为只读，下一次写这段内存时发生写缺页，缺页在冻结中等待。所以每次冻结都有线程等待。等待的线程包括 Tomcat 工作线程和 VM 线程，整个 JVM 的请求都延迟约 4 秒。
- `hsperf-off`：`-XX:+PerfDisableSharedMem` 下没有线程等待，没有暂停事件。
- `tmpfs`、`hsperf` 的 JVM 日志文件没有取回：`docker cp` 读不到容器 tmpfs 挂载中的文件，脚本已改为 `docker exec cat`（`hsperf-off` 起使用；JDK 21 `hsperf` 在运行结束前手工取回）。这些运行的延迟和线程数据不受影响。

### 4.5 自然条件

8 次运行，每次 267 秒，流程与阶段 0 相同（前窗口 60 秒，两个 `watch` 作业，`stop`，后窗口 60 秒），JVM 日志在 `/`。主机探针同时运行。

| JDK | 运行 | 暂停事件 | 增强开始瞬态（作业 1 开始后，最大延迟，JVM CPU） | JVM 线程等待（≥ 100 ms） | 运行期间 `/` 上的探针等待（≥ 100 ms） |
|---|---|---|---|---|---|
| 11 | `l2:watch@p10k` 重复 1 | 0 | 735 ms，351% | 0 | 0 |
| 11 | 重复 2 | 0 | 1460 ms，348% | 0 | 0 |
| 11 | 重复 3 | 0 | 579 ms，299% | 0 | 0（`/data` 上 1 次 0.13 秒） |
| 11 | `noop@p10k` | 0 | — | Tomcat 线程 0.17 秒，写 hsperfdata | 2 次，0.17、0.23 秒（`/data` 上 1 次） |
| 17 | `l2:watch@p10k` 重复 1 | 0 | 377 ms，315% | 0 | 2 次，0.11、0.20 秒 |
| 21 | 重复 1 | 1 次，0.92 秒（见下） | 没有超过 200 ms 的秒 | 2 个线程 0.90~0.92 秒，写 hsperfdata | 1 次，0.92 秒 |
| 21 | 重复 2 | 0 | 672 ms，359% | 0 | 0（`/data` 上 3 次，0.30~0.99 秒） |
| 21 | 重复 3 | 0 | 没有超过 200 ms 的秒 | 0 | 1 次，0.15 秒（`/data` 上 5 次） |

JDK 21 重复 1 的暂停事件（2026-10-25 20:48:08，前窗口开始后 188 秒，`stop` 后约 70 秒，没有 Arthas 作业）：

- 四个流的最大延迟 924 ms，事件期间 JVM CPU 48%。
- 两个 JVM 线程处于 D 状态：一个 Tomcat 工作线程（`http-nio-8080-exec`）0.92 秒，`VM Periodic Task Thread` 0.90 秒。
- 两者的内核栈相同：缺页（`asm_exc_page_fault` → `do_wp_page` → `ext4_page_mkwrite`）→ 更新文件修改时间（`file_update_time`）→ `ext4_dirty_inode` → `do_get_write_access`。示例应用的 JVM 进程中，唯一的共享可写文件映射是 hsperfdata（在运行中的 JVM 上用 `/proc/<pid>/maps` 核对）。
- 主机探针在 `/` 上的追加写入同时等待 0.918 秒，内核栈同为 `do_get_write_access`，jbd2 停在 `jbd2_journal_commit_transaction+0x1126`。
- 主机 I/O 压力（`/proc/pressure/io` 的 full，每 0.5 秒）在事件前 1.6 秒到事件中为 17%~79%，事件前 2 秒和事件后为 0%~1%；内存压力为 0；脏页 2~29 MB。
- 安全点日志没有缺口。其余线程在这 0.92 秒内的状态没有记录。其他三个接口为何同时延迟，原因未查明。

自然条件的 7 次 L2 运行中没有出现安全点日志缺口（≥ 100 ms）。这期间 `/` 上 200 ms 以上的探针等待只有 3 次（0.92、0.20、0.23 秒），其中 1 次正好遇到 JVM 写 hsperfdata。阶段 0 的 `fsync` 探测在 `/` 上 2100 秒内有 98 次 0.3 秒以上。两者的测量方式不同：`fsync` 等待整个提交，追加写入只在碰到正被提交的块时等待，所以不能直接比较。

### 4.6 主机：journal 的慢提交

主机探针从 20:39 到 22:31 记录了 112 分钟（`summaries/host_io_summary.txt`）：

- 追加写入等待 200 ms 以上 40 次：`/` 上 29 次，`/data` 上 11 次。最长 2.55 秒，0.5 秒以上 9 次。
- 40 次中 37 次写入者在 `do_get_write_access`，jbd2 在 `jbd2_journal_commit_transaction+0x1126`。另 3 次：1 次在 `__filemap_get_folio`（2.55 秒那次），1 次在 `wait_transaction_locked`，1 次没有记录到内核栈。
- 没有记录到“有请求在途但 100 ms 以上没有请求完成”的磁盘停顿。磁盘的缓存刷新请求可能不计入在途请求数，这一项不能排除刷新本身慢。
- 受控实验期间（21:18~22:28）的 33 次等待中，7 次落在挂起或冻结期间（前后各 0.5 秒），这些期间占 12% 的时间。挂起或冻结测试设备是否影响 `/` 和 `/data`，未验证。

慢提交与磁盘负载（有每秒负载记录的 38 次等待）：

- 缓存刷新：磁盘平均每秒 32 次缓存刷新。有刷新的秒中，单次平均刷新耗时的中位数 0.7 ms，第 99 百分位 503 ms，最大 2120 ms。38 次等待中 21 次（55%）在前后 2 秒内有一个刷新总耗时 500 ms 以上的秒；随机时刻的对照比例为 21%。
- 写入量：38 次等待中 7 次（18%）在之前 2.5 秒内有 20 MB/s 以上的写入，随机时刻的对照比例也是 18%。写入量与慢提交没有关联。100 MB/s 以上的只有 2 次，在 21:00 的 timeshift 每日快照期间。
- 一次 30 秒的跟踪采样（`mech/fsync-flush-sample.txt`）中，`/` 上调用 `fsync` 的进程有 `sshd-session`（40 次）、`containerd`（38）、`dockerd`（36）、`qemu-system-x86`（30）、`ThreadPoolForeg`（10）、`JournalWriter`（9）等；磁盘收到 168 个刷新请求和 55 个带 FUA 标志的写入。

慢提交与缓存刷新变慢有关联，但 38 次中 17 次附近没有慢刷新。这 17 次的原因未查明。

## 5. 原因的判断

已确认（有直接证据）：

1. HotSpot 的统一日志在打印线程中同步写文件。VM 线程写日志时等待，安全点就不能开始或结束（JDK 源码，4.1；冻结实验，4.4）。
2. JVM 线程写 hsperfdata 时发生写缺页，缺页等待期间整个 JVM 的请求延迟（冻结实验，4.4）。
3. ext4 追加写入和共享映射的写缺页都要更新 inode，需要 journal 写访问；提交慢时它们在 `do_get_write_access` 等待（4.2、4.3、4.5、4.6）。
4. 本机 `/` 和 `/data` 的 journal 提交在本次测量期间多次需要 0.2 秒以上，最长约 2.5 秒（4.6）。
5. 自然条件下，这种等待使 JVM 线程（经 hsperfdata）等待 0.92 秒，同时出现所有接口的暂停事件（4.5）。

推断（依据充分，但没有直接记录）：

6. 阶段 0 的 22 个事件是 VM 线程写安全点日志时在 journal 上等待。依据：缺口位置与日志写入一致（4.1）；同样的缺口位置在受控实验中重现（4.3、4.4）；阶段 0 的日志在 `/`，阶段 0 在 `/` 上测到 0.3 秒以上的 `fsync` 98 次；阶段 0 有 3 个事件与 k3s 慢 SQL 或系统日志的间隔同时出现（系统日志在 `/`，k3s 的数据库在同一块盘的 `/data` 分区）。缺少的证据：阶段 0 没有记录事件时 VM 线程的内核栈。

未查明：

7. `/` 和 `/data` 的慢提交中，一部分与 NVMe 缓存刷新变慢同时出现，其余的原因未查明（4.6）。
8. 同一次慢提交是否让 JVM 等待，取决于 JVM 的写入是否碰到正被提交的块（4.2）。阶段 0 的 `fsync` 探测在 1 秒以上的耗时期间 JVM 没有暂停，与此相符，但没有逐次核对。
9. Arthas 是否提高暂停的发生概率：作业期间安全点频率提高 4.7~14 倍（4.1），VM 线程写日志的次数和“所有线程等待 GC”的时刻都随之增加；暂停次数太少，不能比较有无作业时的发生率。

## 6. 已排除或不支持的假设

| 假设 | 结论 | 依据 |
|---|---|---|
| `RedefineClasses`（retransform）安全点耗时长 | 排除 | 阶段 0 每次只有 1 次，15.0~41.4 ms；22 个事件的安全点原因是 `G1CollectForAllocation`、`Cleanup`、`RevokeBias` |
| GC 或其他 VM 操作本身耗时长 | 排除 | JDK 11 报告的停顿 0.2~8.4 ms；JDK 21 安全点内除清理阶段外 < 6 ms |
| Java 线程到达安全点慢 | 排除（对这 22 个事件） | JDK 11 到达安全点 ≤ 0.2 ms；JDK 21 0.0 ms |
| CPU 争用 | 排除 | 阶段 0 JDK 11 重复 4 的一个 3.01 秒采样周期内 JVM CPU 时间增加 0 tick，可运行等待 0 秒；本次的暂停事件期间 JVM CPU 为 2%~77%（容器最多 400%），增强开始瞬态为 299%~359% |
| 内存压力、页回收 | 不支持 | 自然条件的事件期间内存压力为 0，脏页 2~29 MB（4.5） |
| 磁盘请求不完成（设备停止响应） | 不支持 | 主机探针没有记录到在途请求 100 ms 以上无完成的情况（4.6） |
| 某个 JDK 版本特有的缺陷 | 不支持 | JDK 11、17、21 都在 VM 线程的日志写入等待时出现整个 JVM 暂停（4.3、4.4）；写入的位置因版本而不同（4.1） |
| 只在有 Arthas 时出现 | 排除 | 阶段 0 的 `noop@p10k` 和 `exp_iostall.py` 有 45~73 ms 的缺口；阶段 0 JDK 11 有 5 个事件在 `stop` 之后；本次 JDK 21 的事件在 `stop` 后约 70 秒 |

## 7. 对阶段 3 的影响和可选措施

影响：

- 在本机上，JDK 11、17、21 的 L2 测量都可能遇到 0.2~4.1 秒的整个 JVM 暂停。它来自主机的 I/O，与增强本身的耗时无关。
- 不处理时，阶段 3 的延迟阈值判断会混入这类暂停，阈值判定可能因此为“未达到”或“结论待定”（阶段 2 验收项 1 即是这种情况，见 4.1）。
- 客户的 JVM 如果把 GC 日志写到磁盘，或 `/tmp` 在磁盘上（hsperfdata 默认开启），也会遇到同样的暂停，与是否使用 Arthas 无关。L2 作业期间 GC 更频繁，JVM 写日志和等待 GC 的时刻更多。

可选措施（建议，待负责人确认）：

1. 测试环境的 JVM 日志放在 tmpfs 上（`compose.pause.yaml` 的 `JA_LOGDIR=/logs-tmpfs`，或修改 `compose.yaml`）。`tmpfs` 的 6 次设备挂起和 9 次冻结中没有暂停事件（4.3、4.4）。
2. JDK 17、21 的测试 JVM 加 `-Xlog:async`。JDK 11 没有这个选项，只能用第 1 项。
3. 测试 JVM 的 `/tmp` 放在 tmpfs 上（例如 compose 的 `tmpfs: /tmp`），hsperfdata 的写缺页不再经过 ext4 和 journal。本次没有单独测量这一配置。不建议用 `-XX:+PerfDisableSharedMem`：它在冻结实验中消除了暂停，但 hsperfdata 文件不再存在，产品的预检读取 hsperfdata（阶段 2 验收报告 3.6），`jps` 也看不到这个 JVM。
4. 每次延迟测量同时运行 `host_io_probe.py`，把主机探针等待 200 ms 以上的秒标记出来，在阈值判断中单独列出，不计入 Arthas 的影响。
5. 阈值判断中把“日志写入缺口”与增强开始瞬态分开：用 `pause_logwrite.py` 列出缺口，缺口覆盖的秒单独列出。
6. 不按 JDK 版本拒绝：本次的证据不支持（第 6 节）。
7. 增强开始瞬态（作业开始后 1~4 秒，最大延迟 377~1460 ms，JVM CPU 299%~359%）是 Arthas 增强本身的影响，仍需在阶段 3 单独处理。可选方向：限制一次增强的类数；对调用频繁的方法限制 `watch` 的次数（`-n`）或使用条件表达式。这些方向未测量，它们针对瞬态，不针对本报告的暂停。
8. 产品文档可以说明：目标 JVM 的日志或 `/tmp` 在慢磁盘上时，诊断期间 GC 频率提高会增加暂停的机会；可用 `-Xlog:async`（JDK 17 起）。

## 8. 限制和未验证项

- 自然条件下只捕获到 1 次暂停事件，经 hsperfdata；没有捕获到 VM 线程写安全点日志时的自然等待。
- 设备挂起和冻结是人为的极端条件：前者让请求 6 秒不完成，后者让所有写入 4 秒等待。它们说明 JVM 在写入等待时的行为，不说明本机慢提交的频率。
- 设备挂起下每个 JDK 只有 3~9 次挂起，不足以比较版本之间的发生率。
- `-Xlog:async` 在日志写入长时间等待时会丢弃超出缓冲区的日志行（JDK 的行为，本次没有测量丢弃）。
- 慢提交的部分原因未查明（4.6）。这块 NVMe 盘的缓存刷新延迟是否属于该型号的正常表现，未验证。
- 自然条件 JDK 21 事件中，除两个等待线程外，其余线程的状态没有记录（`pause_watch.py` 的线程快照是在这次运行之后加入的）。
- 受控实验中 `tmpfs`、`hsperf` 的运行（JDK 21 `hsperf` 冻结除外）没有安全点日志（4.4）。
- `/tmp` 放在 tmpfs 上的配置（第 7 节第 3 项）没有单独测量。
- 受控实验期间的 hsperfdata 在 `/` 上（`hsperf`、`hsperf-off` 除外），JVM 可能同时受到 `/` 上慢提交的影响（4.3 中 JDK 21 的一例）。

## 9. 脚本和复现

测量脚本在 `test/jvm-arthas/`：

- `compose.pause.yaml`：独立的镜像标签，`JA_JAVA_EXTRA`（附加 JVM 参数）、`JA_LOGDIR`（`/logs` 或容器内 tmpfs `/logs-tmpfs`）、`JA_LOGS_HOST`（挂载到 `/logs` 的主机目录）。`compose.pause-tmp.yaml`：把 `JA_TMP_HOST` 挂载到容器的 `/tmp`。
- `scripts/run_pause.sh natural | stall | freeze | stall2`：按顺序运行第 3.2 节的实验，设置 `COMPOSE_PROJECT_NAME=jvm-arthas-pause`、`JA_PORT_PREFIX=25`，每次运行前记录其他进程。`JA_OUT` 指定原始数据目录。
- `scripts/stallfs.sh setup | stall <秒> | freeze <秒> | dev | teardown`：zram 上的 device-mapper 设备和 ext4 文件系统（需要 sudo）。
- `scripts/exp_logstall.py`：一次设备挂起或冻结实验。
- `scripts/exp_jbd2_suspend.py`：单个写入者的 journal 实验。
- `scripts/pause_watch.py`：JVM 线程在写入或 D 状态中的等待及内核栈（需要 sudo）；`bench.py --watch` 启动它。
- `scripts/host_io_probe.py`：主机探针（需要 sudo）；`scripts/host_io_summary.py`：探针等待及其前后的磁盘负载。
- `scripts/pause_logwrite.py <毫秒> <safepoint.log 或目录>...`：日志写入缺口。
- `scripts/pause_summary.py [--host <host_io.jsonl>] <运行目录>...`：每次运行的暂停事件、缺口和线程等待。

复现顺序（需要 sudo，不运行 `make real-test`）：

```bash
cd test/jvm-arthas
scripts/stallfs.sh setup
JA_OUT=<原始数据目录> scripts/run_pause.sh stall
JA_OUT=<原始数据目录> scripts/run_pause.sh freeze
python3 scripts/pause_summary.py <原始数据目录>/stall
scripts/stallfs.sh teardown
COMPOSE_FILE=compose.yaml:compose.pause.yaml COMPOSE_PROJECT_NAME=jvm-arthas-pause docker compose --profile jre --profile variants down -v --remove-orphans
```

原始数据目录的内容：`natural/`（自然条件，含主机探针 `host_io*.jsonl`）、`stall/<jdk>/<日志位置>[-freeze]/rep<k>/`（受控实验）、`mech/`（单个写入者实验、跟踪采样）、`summaries/`（各脚本的输出，含阶段 0 和阶段 2 验收数据的缺口扫描）。
