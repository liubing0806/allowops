# PERF1：1000 主机空操作 job 性能

状态：**部分完成**。两处内部锁优化与全部指定功能检查已完成。
普通 `make scale` 一次通过（job 6.626 秒、重连 18.304 秒），
另一次失败（job 21.596 秒、重连 60.999 秒）。当前证据不能支持稳定达到规模标准的结论。
G70 已决定保持单任务事务，不实施批量事务。总指挥将在其他 worker 结束后安排低干扰复测。
本 worker 的代码、测量和功能验证交付已完成，规模验收等待 G70 复测。

## 范围和复现

分支 `perf1-job-dispatch`。按任务要求从 `fbded819d6d2e4f46da7ac8fa5fb4444e200cab8`
快进到 P10A `d1bc285033849d086d4e789537f1f6a8d9365e40`。
测试只使用本机进程和本地 Docker 临时 PostgreSQL、SeaweedFS。
没有连接线上或客户服务器，没有使用 SSH/Teleport，没有部署、push 或合入其他分支。

机器：Intel Core i5-14600K，20 逻辑 CPU，125.5 GiB RAM，
`go1.27.2-X:nodwarf5 linux/amd64`。本机有其他 Go、Java 和浏览器测试进程。
本任务的规模测试与本任务的功能测试串行执行。

未修改产品代码时执行 `make scale`，复现以下失败：

```text
RESULT online actual=5000 database=5000 threshold=5000 hold_seconds=50 pass=true session_errors=24
RESULT job actual_seconds=55.003085 threshold_seconds=10 targets=1000 batch_size=20 pass=false error=<nil>
job status=JOB_STATUS_SUCCEEDED total=1000 counts=[status:TASK_STATUS_SUCCEEDED count:1000]
RESULT reconnect actual_seconds=26.439546 online=5000 database=5000 threshold_seconds=60 pass=true
scale acceptance threshold failed; product code unchanged
make: *** [Makefile:28: scale] Error 1
```

开始 load average：`40.65 / 34.00 / 22.92`；结束：`18.91 / 26.59 / 22.73`。
5000 主机均完成目录加载。RSS 为 7,016,320 KiB（6.69 GiB）。
上次 P10A 的 13.163447 秒来自另一负载条件，不能将本次差值解释为代码退化。

## 本轮全部规模运行

下表负载均为 1 / 5 / 15 分钟 load average。所有运行都使用默认 batch_size=20，
5000 连接保持和目录加载均通过，1000 个任务均成功。插桩运行与普通 `make scale` 分开列出。

| 类型 / 源码 | job 秒 | 重连秒 | 开始负载 | 结束负载 | 阈值结果 |
| --- | ---: | ---: | --- | --- | --- |
| 普通，P10A `d1bc285` | 55.003085 | 26.439546 | 40.65 / 34.00 / 22.92 | 18.91 / 26.59 / 22.73 | job 失败 |
| 插桩，产品代码未优化，工具 `ceee278` | 54.502029 | 23.629345 | 14.75 / 23.51 / 21.95 | 17.34 / 22.25 / 21.82 | job 失败 |
| 普通，优化 `0119427` | 6.625579 | 18.303620 | 23.55 / 24.83 / 23.19 | 16.96 / 20.88 / 21.92 | 三项通过 |
| 插桩，优化 `0119427` | 37.190042 | 69.928739 | 19.47 / 20.78 / 21.81 | 17.53 / 19.37 / 20.98 | job、重连失败 |
| 普通复测，优化 `0119427` | 21.596199 | 60.999261 | 20.62 / 22.72 / 22.06 | 16.64 / 22.31 / 22.29 | job、重连失败 |

三次普通运行的日志分别为 `perf1-baseline.log`、`perf1-after.log`、`perf1-repeat.log`。
全部日志位置见文末。负载不同，不能把以上数据换算成排除环境影响的加速比。

## 测量依据和方案选择

测量工具提交：`ceee278`。工具位于 `test/perfprofile/`。
通过 Go source overlay 插入 profile 和 pgx tracer，正常产品构建不包含插桩。
无新网络监听端口、不改 PostgreSQL 设置、不记录 SQL 参数。
详细方法见 [测量工具说明](perfprofile/README.md)。

命令：

```sh
python3 test/perfprofile/run.py /tmp/perf1-profile-before > /tmp/perf1-profile-before.log 2>&1
```

优化前插桩运行：job **54.502029 秒**，1000 任务成功；5000 连接、目录加载通过；
重连 **23.629345 秒**通过。load average 开始 `14.75 / 23.51 / 21.95`，
job 开始 `24.62 / 24.27 / 22.37`，运行结束 `17.34 / 22.25 / 21.82`。
profile 包含 CPU、heap、block、mutex、SQL 累计/最大时延、连接池获取时延、
200 ms PostgreSQL 阻塞者采样。

| 测量项 | 优化前数据 | 判断 |
| --- | ---: | --- |
| CPU profile | 54.52 秒窗口内累计 CPU 28.59 秒 | 不足一个逻辑 CPU 持续满载；等待是重要因素 |
| `OnMessage` map mutex | block profile 中 Lock 累计 554.13 秒；mutex profile 归因 589.91 秒 | 跨任务共享锁包含 SQL 和事务提交，形成可移除串行等待 |
| 下发预留 `jobs ... FOR UPDATE` | 1001 次（包含 finish），累计 114.700 秒，平均 114.586 ms，最大 1976.303 ms | 不同任务预留争用同一 job 排他锁 |
| COMMIT | 8004 次，累计 97.295 秒，平均 12.156 ms，最大 2269.272 ms | 写前日志等待延长锁持有时间 |
| mailbox 容量 advisory lock | 1000 次，累计 16.041 秒 | 仍需保留全局容量原子性 |
| 审计 advisory lock | 1002 次，累计 1.190 秒 | 本轮证据不支持优先修改审计实现 |
| 创建任务 INSERT | 1000 次，累计 0.137 秒 | 本轮不改批量写入 |
| scheduler 全量任务读取 | 51 次，累计 0.086 秒 | 本轮不改查询结构 |
| 最后预览读取 | 1 次，2.144 ms | 汇总查询本身不是主要等待 |
| 数据库连接池获取 | 313995 次，累计 29380.076 秒，平均 93.569 ms | 大量 goroutine 等待池；池被锁等待中的事务占用 |
| 主机有效性检查 | 270527 次，SQL 累计 33.041 秒 | 5000 连接每秒检查与 job 共享连接池，放大排队 |

上述累计时间来自并发调用，不能相加得到 job 墙钟时间，也不能直接换算为墙钟占比。
SQL 时延包括服务器等待、网络和读取结果，不包括连接池获取。
block profile 包含 5000 长连接的正常等待，不能把全局 block 总量当作异常等待。
CPU 中 GC 扫描和内存清零也占有样本，但本任务未优化连接内存。

PostgreSQL 等待采样：`LWLock/WALWrite=470`、`IO/WalSync=257`、
`Lock/tuple=519`、`Lock/transactionid=55`、`Lock/advisory=81`。
阻塞关系采样中，job 预留等待者的阻塞链上可见其他预留者及其 `commit`；
mailbox 和审计等待者的持有者也可见 `commit`。
job 阻塞链事务年龄最大 1.928 秒，mailbox 为 1.705 秒。
事务年龄只是锁持有时间的上界；等待链中的阻塞者不一定是最终持锁事务。
这些证据支持“慢提交期间持有过宽的锁，继而占用数据库连接池”的结论，
不支持将总耗时全部归因于某一种 PostgreSQL 等待。

候选方案与取舍：

- 采用：map 锁只保护 map，任务状态另用每任务互斥锁；避免不同任务等待同一锁。
- 采用：预留只读取 job，使用 `FOR SHARE`；取消、结束和恢复的排他锁仍与之冲突。
- 不采用：批量创建任务、重写汇总查询；测量收益不足。
- 不修改：batch_size、并发上限、超时、主机检查频率、数据库配置、审计实现和连接内存管理。

## 测试先行与实现边界

失败测试单独提交：`064734e`。在未优化实现上，两个测试分别报告：

```text
fast task blocked behind unrelated slow task SQL; want independent progress
fast reservation blocked behind unrelated slow reservation; want concurrent reservations
```

测试在临时 PostgreSQL 中用触发器与 advisory lock 控制单个任务 SQL 的等待，
验证另一任务可独立继续。测试同时检查重复启动拒绝、generation 绑定、
进行中的预留阻止取消取得排他锁、预留提交后排他锁可取得。
首次运行下发测试时，夹具只设置 connection_id，触发
`ERROR: new row for relation "hosts" violates check constraint "hosts_check" (SQLSTATE 23514)`；
已补齐 instance_id 后重跑，随后才记录上述预期失败。

实现提交：`011942757d4c8b3a7c014f03ac436504c3d0dc25`。
仅改 `internal/gateway/job/events.go` 和 `internal/gateway/job/scheduler.go`，共增加 12 行、删除 4 行。
任务行锁保留；每任务内存互斥锁保留 Go 内存同步；连接绑定和首个终态结果规则不变。
审计顺序/完整性、A21 授权、A22 失败计数、A23 输出规则的实现均未修改。
定向测试加 `-race -count=1` 已通过。

## 5000 连接内存构成（只调查）

优化前插桩运行，GC 前 RSS 为 6,184,444 KiB（5.90 GiB），
GC 后 RSS 为 6,204,300 KiB（5.92 GiB），VmSwap 为 0。
此处是同版本的新采样，用于解释原 6.29 GiB 量级；并非对原进程的追溯采样。

| Go 内存项 | GiB |
| --- | ---: |
| HeapAlloc（存活堆） | 2.976 |
| HeapInuse | 3.087 |
| HeapSys | 6.775 |
| HeapIdle | 3.689 |
| HeapReleased | 0.220 |
| StackInuse | 0.193 |
| Sys | 7.012 |

堆采样总计 3057.74 MiB；`compress/flate` 的 `newFastEnc`、`fastGen.reset`、
`NewWriter`、`compressor.init` 四项 flat 合计 2547.23 MiB，占 83.30%。
主要调用路径是 `hostconn.Service.Connect` 发送消息，经 Connect gzip 压缩池创建/重置 flate 压缩器。
`Server.Serve` 为每条 TLS 连接调用 `handler`，重新构造 Connect handler 和各自的压缩池。
Connect handler 对象也有贡献，例如 gRPC handler flat 60.01 MiB、Connect handler 52.51 MiB。

存活压缩器状态、尚未归还的空闲堆和 goroutine 栈共同解释高 RSS 的主要组成。
Go 的虚拟堆统计不等同于物理驻留页，不能直接相加与 RSS 精确对账。
本次 profile 不支持把 HTTP/2 读缓冲认定为主要内存来源。
本任务没有改变压缩、handler 生命周期、GC 配置或连接内存限制。

## 优化后规模与功能验证

普通规模验收命令 `make scale`，验证产品提交
`011942757d4c8b3a7c014f03ac436504c3d0dc25`：

| 项目 | 优化前 | 优化后 | 优化后状态 |
| --- | ---: | ---: | --- |
| 5000 连接保持 50 秒 | 5000 | 5000 | 通过 |
| 目录加载 | 5000 | 5000 | 通过 |
| 1000 主机 job | 55.003085 秒 | 6.625579 秒 | 通过，1000 任务成功 |
| 重启及全部重连 | 26.439546 秒 | 18.303620 秒 | 通过 |
| 网关 RSS | 6.69 GiB | 6.13 GiB | 只调查，未实施连接内存优化 |

优化后开始 load average：`23.55 / 24.83 / 23.19`；结束：`16.96 / 20.88 / 21.92`。
本机仍有其他 worker，负载并未固定。上述为同场景前后实测，不是排除了环境因素的加速比。
优化后插桩复测并未达到阈值：job **37.190042 秒**，重连 **69.928739 秒**。
5000 连接保持、目录加载、1000 任务成功仍通过。开始 load average
`19.47 / 20.78 / 21.81`，job 开始 `17.83 / 19.61 / 21.23`，
结束 `17.53 / 19.37 / 20.98`。实际失败输出：

```text
RESULT job actual_seconds=37.190042 threshold_seconds=10 targets=1000 batch_size=20 pass=false error=<nil>
RESULT reconnect actual_seconds=69.928739 online=5000 database=5000 threshold_seconds=60 pass=false
scale acceptance threshold failed; product code unchanged
```

该固定失败文案来自 P10A 测试；本轮实际运行的是优化后的 source overlay 构建。
重连阶段另有 `ERROR task disconnect update failed` 日志，具体数据库错误未被现有日志输出。

| profile 对比 | 优化前 | 优化后 |
| --- | ---: | ---: |
| OnMessage map mutex 的 block 累计等待 | 554.13 秒 | 0.435 ms |
| 1000 次预留 job 行锁 SQL 累计 | 114.700 秒（含一次 finish） | 0.273 秒（共享锁） |
| COMMIT 次数 | 8004 | 8004 |
| COMMIT 平均/最大时延 | 12.156 / 2269.272 ms | 29.346 / 2789.857 ms |
| mailbox advisory lock 累计等待 | 16.041 秒 | 175.055 秒 |
| 审计 advisory lock 累计等待 | 1.190 秒 | 57.846 秒 |
| CPU 累计 | 28.59 秒 | 21.66 秒 |

mailbox 与提交的占比口径：

| 项目 | 优化前插桩 | 优化后插桩 |
| --- | ---: | ---: |
| 全部 SQL 客户端累计时延（不含连接池获取） | 326.597 秒 | 596.273 秒 |
| mailbox 容量锁获取累计时延 / 上述总量 | 16.041 秒 / 4.91% | 175.055 秒 / 29.36% |
| COMMIT 累计时延 / 上述总量 | 97.295 秒 / 29.79% | 234.888 秒 / 39.39% |
| 审计锁获取累计时延 / 上述总量 | 1.190 秒 / 0.36% | 57.846 秒 / 9.70% |

这些比例是并发 SQL 累计时延占比，不是 job 墙钟时间占比。
COMMIT 客户端耗时包含 WAL 等待、服务端处理、网络和进程调度，不能全部标为纯 WAL 时间。
优化后 PostgreSQL 活跃等待共有 2827 个连接样本，
`IO/WalSync=182`、`LWLock/WALWrite=1417`，合计 1599（56.56%）；
全部 advisory 锁等待为 1177（41.63%，含 mailbox 与审计）。
因此 WAL 是主要服务器等待类型，但纯 WAL 墙钟秒数及其独占比例**未测得**。

两处目标锁竞争已消除，但提交和 mailbox 全局容量锁成为剩余主要等待。
未减少任何事务提交或审计操作。不能把普通验收的 6.63 秒当作所有负载下的保证。
复测结束附近 `/proc/pressure/io` 的 `full avg60=31.73`、`some avg60=38.31`，
`vmstat` 两个一秒采样显示 CPU iowait 9% 和 8%，其中一秒 swap-out 17300 KiB/s。
这些是共享机器 I/O 压力证据，尚不足以隔离插桩、应用并发变化和其他进程各自的影响。
最后一次普通 `make scale` 复测（没有产品插桩）退出码 2：

```text
RESULT online actual=5000 database=5000 threshold=5000 hold_seconds=50 pass=true session_errors=15
RESULT job actual_seconds=21.596199 threshold_seconds=10 targets=1000 batch_size=20 pass=false error=<nil>
RESULT reconnect actual_seconds=60.999261 online=5000 database=5000 threshold_seconds=60 pass=false
make: *** [Makefile:28: scale] Error 1
```

该次 1000 任务全部成功，5000 目录加载通过；RSS 5,774,244 KiB（5.51 GiB）。
开始 load average `20.62 / 22.72 / 22.06`，结束 `16.64 / 22.31 / 22.29`。
每秒采样覆盖构建、连接准备、job、重连和清理全过程，1 分钟负载范围 10.07–35.61，
I/O 压力 `full avg60` 范围 14.10%–34.00%；这些范围不等同于仅 job 阶段的指标。
未继续通过反复运行挑选更好的结果。

运行产物核对：本次复测重启前，从本 worktree 的网关进程 `/proc/2759901/exe`
读取 SHA-256：`5dc41ec607d6c0b69028adc9b4459790d1ec4179f6b9ac51977d987d16616966`。
重启后的进程在二次采样前已经退出，未取得重启后的进程 digest，未宣称该项核对通过。

验证命令及结果（产品提交均为 `011942757d4c8b3a7c014f03ac436504c3d0dc25`）：

| 命令 | 结果 |
| --- | --- |
| `make scale` | 首次优化后退出码 0；最后复测退出码 2，实际差异见上文 |
| `make build test lint vuln licenses` | 退出码 0 |
| `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/gateway/job -run 'TestTaskEventsProgressIndependently\|TestDispatchReservationsShareJobLock' -v` | 两项定向测试通过（实现内容提交前验证） |
| `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/... ./cmd/...` | 退出码 0，所有包通过，无 race 报告 |

`make test` 的全仓库 race 测试通过。包括 API 包（299.675 秒）、job 包（215.179 秒）、
audit 包（57.826 秒）、hostconn 包，以及 agent、执行器、store 和攻击测试。
强制 Docker 的无缓存复验也全部通过，job 包用时 148.911 秒。
四个可执行文件构建成功，51 个示例 action 校验通过。
本次新增、默认标签排除的工具另经 `go vet -tags=perfprofile ./test/perfprofile`
和 Python AST 语法检查通过；`git diff --check` 通过。
`go vet`、staticcheck、govulncheck、许可证检查均通过。
许可证工具同时提示无法继续检查部分汇编/C 文件内的额外依赖，退出码仍为 0。

范围外发现：govulncheck 报告 0 个调用可达漏洞、0 个已导入包漏洞，
另有模块级 [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932)：
`golang.org/x/crypto@v0.58.0` 中未使用的 `openpgp` 包已不再维护且存在设计安全问题。
工具明确说明当前代码没有调用该漏洞路径。未修改依赖。

## G70 决定与后续复测

总指挥已决定：**保持单任务事务，先安排低干扰复测，不实施批量事务**。
默认 batch_size、并发上限、超时、PostgreSQL 持久性要求均未修改。
低负载复测由总指挥在其他 worker 结束后安排，本 worker 不再运行规模测试。

批量方案的理论收益与边界（未实现）：

- 假设仍使用现有 20 个任务一批，将这 1000 条 mailbox 写入按批提交，
  mailbox 事务及容量锁获取次数可从 1000 降为 50，该类串行提交次数减少 95%。
- 其他事务保持现状时，本次 profile 的 8004 次 COMMIT 可降至约 7054 次，整体减少约 11.87%。
  这只估算次数，不表示总 SQL/WAL 工作量或墙钟耗时同幅减少；每任务记录和结果写入仍存在。
- 当前没有 mailbox 持锁事务内 COMMIT 的独立时长分布，且普通运行耗时波动明显。
  不能据此承诺节省多少墙钟秒数，也不能承诺批量方案一定低于 10 秒。
- 当前每任务独立事务，一个提交失败不回滚其他已经提交的 mailbox。
  合并为一笔事务后，一次提交失败会影响整批最多 20 个任务；若按所提方案处理，
  整批均按下发失败处理。部分任务容量不足、连接变化和取消竞争也需要单独设计与验证。
  G70 未授权这种失败范围变化，本次不实施。

建议低干扰复测 **串行 3 次**，每次执行原始 `make scale`，保留全部结果，不挑选最优值。
下列命令从仓库根目录执行；返回非零表示至少一次未通过：

```sh
python3 - <<'PYRUN'
from pathlib import Path
import subprocess

failed = False
for trial in range(1, 4):
    path = Path(f"/tmp/perf1-g70-{trial}.log")
    with path.open("w") as log:
        log.write("before IO pressure: " + Path("/proc/pressure/io").read_text())
        log.flush()
        result = subprocess.run(["make", "scale"], stdout=log, stderr=subprocess.STDOUT)
        log.write("after IO pressure: " + Path("/proc/pressure/io").read_text())
    print(f"trial={trial} exit={result.returncode} log={path}")
    failed |= result.returncode != 0
raise SystemExit(1 if failed else 0)
PYRUN
```

原测试会输出起止负载、运行 SHA、内存、三项规模指标与数据库等待样本。
建议三次都满足 job <10 秒、5000 连接通过、重连 ≤60 秒后再完成该窗口的规模验收，
同时汇报三个原始值、最小值、中位数和最大值。三次样本不能证明任意负载下的保证。
不要同时运行 profile 或功能测试；保持本轮相同默认配置和依赖镜像。
若低干扰下仍失败，保留失败证据，再由总指挥决定下一轮方案，不先改默认值。

RSS 构成调查已完成，压缩器/连接内存优化不属于本任务实施范围。

## 改动文件

- `internal/gateway/job/events.go`：每任务内存互斥锁，缩短共享 map 锁范围。
- `internal/gateway/job/scheduler.go`：预留使用共享 job 行锁，保留与取消的互斥。
- `internal/gateway/job/concurrency_test.go`：两项受控 SQL 阻塞复现与取消锁验证。
- `test/perfprofile/profile.go`：仅测量构建使用的 profile、SQL 和连接池 tracer。
- `test/perfprofile/run.py`：生成 source overlay 并运行本地规模场景。
- `test/perfprofile/README.md`：测量方法、重现命令与时延统计边界。
- `test/PERF1-results.md`：测量、验证、失败与待决定事项。

## 本地证据

- `/tmp/perf1-baseline.log`：未修改产品代码的普通规模失败。
- `/tmp/perf1-profile-before.log`：优化前 profile 运行和锁持有者采样。
- `/tmp/perf1-profile-before/`：原始 CPU/heap/block/mutex、SQL、内存及 source overlay。
- `/tmp/perf1-red.log`、`/tmp/perf1-red-dispatch.log`：失败测试证据。
- `/tmp/perf1-green.log`：定向 race 测试通过。
- `/tmp/perf1-after.log`：优化后普通规模测试。
- `/tmp/perf1-profile-after.log`、`/tmp/perf1-profile-after/`：优化后插桩复测，包含超阈值记录。
- `/tmp/perf1-checks.log`：build/test/lint/vuln/licenses。
- `/tmp/perf1-race.log`：强制 Docker 的无缓存 race 验证。
- `/tmp/perf1-vuln-verbose.log`：不可达模块级漏洞详情。
- `/tmp/perf1-repeat.log`、`/tmp/perf1-repeat-resources.jsonl`：普通规模复测及每秒负载、I/O、内存压力采样。
- `/tmp/perf1-running-binary.jsonl`：复测重启前实际运行产物的 SHA-256。

这些临时路径为本机复查材料。可用已提交的测量脚本重新生成。
