# P10A 本地验证报告（2026-10-14）

状态：测试实现完成。规模指标 2/3 通过。六个发行版的虚拟机验证通过，Debian 12 按 G63 补验通过。
分支：`p10a-scale`。基线：`main f563b3f9952e35159ba03daafbd80aeb15963282`。
没有修改产品代码，没有 push、合并、部署到共享环境或推送镜像。
没有连接线上或客户业务系统。SSH/SCP 仅连接本任务 QEMU 的本机转发端口。

## 被验证的提交

| 验证范围 | commit SHA |
| --- | --- |
| 三项规模实测 | `1aaa57a14719f68a514a8f5a41a6be0fb4a51e19` |
| OPA、常规检查、Ubuntu 24.04/20.04、Rocky 9、CentOS 7 | `c01cb9b1080ecd8a7c5cddc4f97a633a0927fea6` |
| Rocky 8 复测、RHEL 平台 Python 选择 | `5660d596ce4fb30ddff83ec069500588807b154b` |
| G63 Debian 12、下载边界及 SHA-512 不匹配测试 | `e39746ccd3d2a2ccd53a02b8c640fecf0e5624a5` |

规模实测后的代码提交仅修改虚拟机代码、测试及其说明。
`git diff 1aaa57a HEAD -- test/scale test/harness Makefile` 为空。
G63 将 Debian 镜像地址限定为获准的 UMU URL，清单仍只从 cloud.debian.org 获取。
全部产品代码相对于指定基线保持不变。本次报告提交仅修改本文件。

## 改动文件

* `Makefile`：独立的 scale、bench-opa、vm 目标。
* `test/harness/gateway.go`：本机网关子进程、CA、签名目录和隔离依赖夹具。
* `test/scale/scale_test.go`、`test/scale/README.md`：规模模拟器、测量方法和基准说明。
* `test/vm/images.py`、`test/vm/test_images.py`：官方下载、checksum 校验和解析测试。
* `test/vm/run.sh`、`test/vm/vm_test.go`、`test/vm/README.md`：虚拟机矩阵、业务断言与运行说明。
* `test/P10A-results.md`：验证证据和待决定事项。

## 规模实测

命令：`make scale`。退出码 2，原因是 job 耗时超过阈值。
网关使用默认配置，job 批次上限为 20。
模拟器和网关运行于不同的本机进程。PostgreSQL、SeaweedFS 使用项目已有固定 digest 的 Docker 夹具。

```text
RESULT online actual=5000 database=5000 threshold=5000 hold_seconds=50 pass=true session_errors=0
catalog_loaded=5000 threshold=5000
gateway VmRSS: 6592556 kB
RESULT job actual_seconds=13.163447 threshold_seconds=10 targets=1000 batch_size=20 pass=false error=<nil>
job status=JOB_STATUS_SUCCEEDED total=1000 counts=[status:TASK_STATUS_SUCCEEDED count:1000]
RESULT reconnect actual_seconds=12.784958 online=5000 database=5000 threshold_seconds=60 pass=true
scale acceptance threshold failed; product code unchanged
FAIL github.com/liubing0806/allowops/test/scale
make: *** [Makefile:28: scale] Error 1
```

每台模拟主机独立生成密钥，经真实 Join 获得证书，以双向 TLS 认证（mTLS）建立 gRPC 双向流。
模拟器拉取并验证签名目录，发送加载报告和心跳。
空操作不启动系统命令，报告零执行时长、两个空输出 EOF 和 SHA-256。
网关执行真实授权、调度、消息校验、结果持久化和汇总。
授权标签只写入本任务生成的隔离数据库，Join 本身不授予标签。

5000 个连接保持 50 秒，超过默认 45 秒心跳超时。
1000 个任务全部成功，已收到完成汇总，但耗时 13.16 秒，大于 10 秒。
重连计时包含 SIGTERM 停止、启动新进程和全部主机重新建立流。
输出保存与审计使用真实 SeaweedFS/PostgreSQL；job 汇总计时不等待独立的后台输出保存任务。

运行环境：Intel Core i5-14600K，20 个逻辑 CPU，物理内存 134792994816 字节。
Go：`go1.27.2-X:nodwarf5 linux/amd64`。
网关驻留内存（RSS）6592556 KiB，约 6.29 GiB。

```text
12:19:11 up 6 days, 3:40, 10 users, load average: 6.23, 7.76, 6.83
12:20:49 up 6 days, 3:42, 10 users, load average: 10.12, 8.70, 7.26
```

本机同时有其他 worker 活动。本任务的常规测试和 QEMU 在规模测试之后启动。
官方镜像下载与规模测试重叠。结果适用于当时的共享机器负载，不代表空闲机器结果。

每 200ms 采样 PostgreSQL 活跃连接。下表是累计连接样本数，不是耗时或百分比。

| 等待类型/事件 | 样本数 |
| --- | ---: |
| CPU/running | 16 |
| Client/ClientRead | 20 |
| IO/WalSync | 57 |
| LWLock/WALWrite | 86 |
| Lock/advisory | 35 |
| Lock/transactionid | 18 |
| Lock/tuple | 122 |

已观察到数据库锁和写前日志（WAL）等待。
源码中下发锁定 job 行（`internal/gateway/job/scheduler.go`），结果事件锁定 task 行（`internal/gateway/job/events.go`），审计追加使用事务 advisory lock（`internal/gateway/audit/store.go`）。
这些证据尚不足以确认唯一主导瓶颈。没有采集网关 CPU/堆 pprof，没有增加产品测试钩子。

建议另立性能任务，采集 SQL 时延、锁持有者及网关 profile，再评估减少数据库往返、缩短预留事务和 WAL 存储时延。
优化须保留取消、连接绑定和审计顺序。应先核实 HTTP/2 缓冲的内存贡献，再调整连接内存限制。
当前证据不能证明增加批次大小即可达到阈值。

## OPA 基准

命令：`make bench-opa`。退出码 0。

```text
BenchmarkBatchPolicy500Rules1000Hosts-20  475  2721343 ns/op  8548281 B/op  7911 allocs/op
BenchmarkBatchPolicy500Rules1000Hosts-20  480  2622280 ns/op  8547992 B/op  7911 allocs/op
BenchmarkBatchPolicy500Rules1000Hosts-20  472  2763369 ns/op  8548124 B/op  7911 allocs/op
PASS
```

复用 P5A 已有 Go benchmark，500 条规则、1000 台主机，三次耗时为 2.72、2.62、2.76 毫秒。
用例使用相同规则条件和相同主机标签，包含现有规则合并和批次内缓存。
结果不代表 500 个不同条件与 1000 个不同标签集合的判定时延。

## 虚拟机矩阵

```sh
PATH=/tmp/p10a-tools/usr/bin:$PATH VM_DISTROS=ubuntu2404,ubuntu2004,rocky9,centos7 make vm
PATH=/tmp/p10a-tools/usr/bin:$PATH VM_DISTROS=rocky8 make vm
PATH=/tmp/p10a-tools/usr/bin:$PATH VM_DISTROS=debian12 make vm
```

以上三个命令的最终验证均退出码 0，执行 commit 见上表。
前五个发行版使用官方镜像。Debian 使用 G63 授权的官方入口指定托管地址。
六个发行版均使用 cloud-init 和 QEMU/KVM，2 vCPU、2048 MiB 内存。
每台安装本地构建的 deb/rpm，经 Join 连接本机网关，等待签名目录加载。
检查安装后服务已启用且尚未启动、运行用户、helper 权限、状态目录所有者和固定 sudoers。
拒绝带参数的 sudo helper 调用。随后执行现有示例 `system_load` 和签名的 `root_identity`。
后者通过 sudo/helper 返回 UID `0`。最后卸载，检查二进制、单元及 sudoers 移除，并停止本任务 QEMU。

| 发行版 | 状态 | system_load | root_identity | 子测试总耗时 |
| --- | --- | ---: | ---: | ---: |
| Ubuntu 24.04 | 通过 | 60.53ms | 50.68ms，输出 `0\n` | 41.85s |
| Ubuntu 20.04 | 通过 | 59.23ms | 49.80ms，输出 `0\n` | 38.13s |
| Rocky 9 | 通过 | 180.75ms | 302.73ms，输出 `0\n` | 53.26s |
| CentOS 7 | 通过 | 89.32ms | 97.78ms，输出 `0\n` | 95.30s |
| Rocky 8 | 通过 | 86.23ms | 93.89ms，输出 `0\n` | 29.52s |
| Debian 12 | 通过（G63） | 55.94ms | 69.69ms，输出 `0\n` | 50.30s |

日志摘要：

```text
PASS cloud-init and local SSH
service state after install: LoadState=loaded ActiveState=inactive
PASS install, systemd and sudoers
PASS join and systemd start
PASS action=system_load job=JOB_STATUS_SUCCEEDED
PASS action=root_identity job=JOB_STATUS_SUCCEEDED stdout="0\n"
PASS uninstall
--- PASS: TestMatrix/ubuntu2404 (41.85s)
--- PASS: TestMatrix/ubuntu2004 (38.13s)
--- PASS: TestMatrix/rocky9 (53.26s)
--- PASS: TestMatrix/centos7 (95.30s)
--- PASS: TestMatrix/rocky8 (29.52s)
--- PASS: TestMatrix/debian12 (50.30s)
```

G63 Debian 12 补验：

* 镜像仅从 `https://chuangtzu.ftp.acc.umu.se/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2` 下载。
* SHA512SUMS 仅从 `https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS` 获取，拒绝清单重定向。
* 镜像 SHA-512 与该官方清单一致，另以本机 `sha512sum` 核对得到相同结果。
* 镜像保留于 `/tmp/allowops-vm-images/debian12/`，没有加入仓库。

```text
verified debian12 image_host=chuangtzu.ftp.acc.umu.se manifest_host=cloud.debian.org sha512=a09170d17e13af43da61774666f520e3bbec0f8bd96b4db37c15f3426fb327ccad950b80dbe78c09aa5ca90ce5015e99334b0ba5188fd4018736bc3fb5f0882c
PASS action=system_load job=JOB_STATUS_SUCCEEDED elapsed=55.938086ms
PASS action=root_identity job=JOB_STATUS_SUCCEEDED elapsed=69.689131ms stdout="0\n"
PASS uninstall
--- PASS: TestMatrix/debian12 (50.30s)
15:47:33 up 6 days, 7:09, 10 users, load average: 5.17, 6.30, 4.20
```

先提交失败测试 `c8a6fba9e7eb3e87c3e13cc74a8aa86336816e40`，再修改下载代码。
原代码测试的实际差异：镜像请求地址是 cloud.debian.org，期望是 G63 指定的 chuangtzu.ftp.acc.umu.se。
修改后的六个 Python 测试通过。其中负向测试使用与官方清单不匹配的镜像，断言 `sha512 mismatch` 异常及镜像删除。
CLI 在该异常后退出，`run.sh` 停止于镜像获取步骤，不启动 QEMU；该情况记为未验证。
真实 Debian 镜像校验相符，本次没有发生校验不一致。

已校验的官方镜像 SHA-256：

```text
CentOS 7:     284aab2b23d91318f169ff464bce4d53404a15a0618ceb34562838c59af4adea
Rocky 8:      e56066c58606191e96184de9a9183a3af33c59bcbd8740d8b10ca054a7a89c14
Rocky 9:      92c206cc6f790c61583247eefe87890f8828420662c17cacf247cec78ab4eec8
Ubuntu 20.04: 18f2977d77dfea1b74aee14533bd21c34f789139e949c57023b7364894b7e5e9
Ubuntu 24.04: 6a81c37564db9b1ee84e141922625e1d7c5b389b99bb3c572e0243607d5bb4d2
```

Rocky 8 大镜像接近单次超时前，停止了已核实属于本任务的 curl。
从同一官方地址以 HTTP Range 继续下载，校验完整文件后写入缓存。脚本随后再次校验缓存镜像。
Rocky 8 没有使用第三方镜像。Debian 的唯一托管地址例外由 G63 授权。
主机缺少 qemu-img/mkisofs；工具在 `/tmp` 解包，校验 Arch 包元数据 SHA-256 和发行版签名后执行。没有安装或修改主机软件包。

## 常规检查和安装包来源

`ALLOWOPS_REQUIRE_DOCKER=1 make build test lint vuln licenses`：退出码 0。
`make test` 包含 `go test -race ./...` 和示例检查。
此前 `1aaa57a` 的非缓存执行也通过；`c01cb9b` 复查复用了部分未变化包的有效 Go 测试缓存。
规模和虚拟机代码由 build tag 排除，没有进入默认耗时路径。

以下针对性检查通过：

```sh
go vet -tags=scale,vm ./test/harness ./test/scale ./test/vm
go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 -tags=scale,vm ./test/harness ./test/scale ./test/vm
python3 -m unittest discover -s test/vm -p 'test_*.py'
bash -n test/vm/run.sh
git diff --check
```

G63 补验的六个 Python 测试通过，覆盖清单解析、官方清单与获准镜像地址分离，以及 SHA-512 不匹配停止和删除镜像。
本轮 `make vm` 重新构建本机二进制；完整 Go 测试、静态检查、漏洞和许可证检查沿用 c01cb9b 的通过证据。
G63 没有修改 Go、Makefile、依赖、公共夹具或规模代码，没有重复运行这些未变化检查。
本地安装包构建退出码 0：

```sh
GO_LICENSES_VERSION=v2.0.1 go run github.com/goreleaser/goreleaser/v2@v2.18.3 \
  release --snapshot --clean --skip=sign,publish,docker,sbom
```

`go version -m dist/allowops-agent_linux_amd64_v1/allowops-agent` 确认：

```text
CGO_ENABLED=0 GOOS=linux GOARCH=amd64
vcs.revision=c01cb9b1080ecd8a7c5cddc4f97a633a0927fea6
vcs.modified=false
rpm sha256 e6dece5606e6c390eda14d409a59429753e8af5feeadb80158d981733730d4a0
deb sha256 fdd11ab5ec1a49bfe71d418c4434e5497019accf0d513eb5db9858703c8a048a
```

二进制来源和来宾 action 结果分别记录，版本元数据没有代替行为验证。
标准漏洞扫描报告 0 个可达漏洞。详细结果另有未导入的模块级记录 `GO-2026-5932`：
所需模块 `golang.org/x/crypto@v0.58.0` 中未使用的 `openpgp` 包停止维护，未列出修复版本。
工具报告导入包中的漏洞数也是 0。此项在任务范围外，没有修改依赖。
许可证检查退出码 0，并提示无法检查汇编文件的额外依赖。

## 日志与待决定事项

原始本地日志：`/tmp/p10a-scale-final.log`、`/tmp/p10a-bench-final.log`、
`/tmp/p10a-vm-final-matrix.log`、`/tmp/p10a-vm-rocky8-final.log`、`/tmp/p10a-vm-debian12.log`、
`/tmp/p10a-checks.log`、`/tmp/p10a-checks-final.log`、`/tmp/p10a-vuln-details.log`、`/tmp/p10a-package-c01cb9b.log`。
G63 补验日志：`/tmp/p10a-g63-debian12.log`、`/tmp/p10a-g63-tests-before.log`、`/tmp/p10a-g63-tests-final.log`、`/tmp/p10a-g63-SHA512SUMS`。

待总指挥决定：是否另立 job 性能优化任务。Debian 托管地址事项已按 G63 执行并验证。
如需增加网关 pprof 测试入口，应先确认授权。
两个网关的任务路由、不同标签/不同条件的 OPA 基准不在本次派发范围内，未验证。
