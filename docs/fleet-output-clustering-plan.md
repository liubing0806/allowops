# 机群输出去噪归一化聚类、异常优先排序与跨 Job 基线对比实施计划

状态：已确认（2026-11-24）。详细设计见 [`docs/fleet-output-clustering-design.md`](fleet-output-clustering-design.md)（已吸收独立复审全部 21 条意见）。

## 1. 执行策略

- 分三个依赖递进的里程碑（M1 → M2 → M3），每个里程碑在独立 `worktree` 子会话中实现，本地构建与测试通过后由总指挥逐行审阅 diff、重跑验证命令再合入当前开发分支 `feat/fleet-output-clustering`。
- 每个提交保持独立可编译、测试通过；**未经负责人确认，不 push、不开 PR**。
- 分支与依赖关系：
  - **M1（`feat/fleet-cluster-m1-engine`）**：纯逻辑核心引擎 `internal/gateway/cluster`，无外部包改动，基于设计/计划提交启动。
  - **M2（`feat/fleet-cluster-m2-job-proto`）**：Protobuf、sqlc、网关 `internal/gateway/job` 汇总/排序/线性裁剪与 `DiffJobs` RPC，基于 M1 合入后的 `feat/fleet-output-clustering` 启动。
  - **M3（`feat/fleet-cluster-m3-mcp-cli-docs`）**：`catalog` 保留名、`internal/gateway/mcp`、`internal/cli`、中英文文档与 `CHANGELOG.md`，基于 M2 合入后的 `feat/fleet-output-clustering` 启动。

## 2. 里程碑 M1：归一化词法引擎、聚类排序与有界 Diff 核心库

分支：`feat/fleet-cluster-m1-engine`（独立 worktree）。

| 提交 | 内容 | 涉及文件 |
|---|---|---|
| M1-1 | 单遍 `O(N)` 词法归一化器（零 `regexp`）：`[REDACTED:...]` 保护、主机名替换、时间戳/UUID/IP（可配）/Hex/PID/时长/百分比/字节/数字、版本号与语义状态码保护、空白规范化、截断尾行丢弃、JSON/NDJSON 统一模式、安全 `label`/`unit` 清洗与有限浮点提取 | `internal/gateway/cluster/doc.go`、`internal/gateway/cluster/normalize.go`、`internal/gateway/cluster/json.go`、`internal/gateway/cluster/normalize_test.go` |
| M1-2 | 两遍确定性聚类（Tier 0 无损优先 + Tier 1/2 成功聚类 + 溢出桶）、数值分布统计（min/p50/p95/max、MAD 离群主机、智能样本选择）与统一 Anomaly-First 三层排序、主机守恒校验 | `internal/gateway/cluster/cluster.go`、`internal/gateway/cluster/stats.go`、`internal/gateway/cluster/rank.go`、`internal/gateway/cluster/cluster_test.go` |
| M1-3 | 有界跨 Job Diff 引擎（按 `host_id` 对齐、`replaced_hosts`、状态跃迁退化优先、模式跃迁聚合与前 K 条有界行级 Diff、显著数值漂移检测与 finite float 不变式） | `internal/gateway/cluster/diff.go`、`internal/gateway/cluster/diff_test.go` |
| M1-4 | 真实运维命令样本测试（`df -h`、`free -m`、`uptime`、`docker ps`、`systemctl status`、`jvm_perfdata`、`log_query` JSON）、对抗与 Fuzz 测试、1000 主机基准测试（`BenchmarkNormalizePreview`、`BenchmarkCluster1000Hosts`、`BenchmarkDiff1000Hosts`） | `internal/gateway/cluster/ops_samples_test.go`、`internal/gateway/cluster/bench_test.go`、`internal/gateway/cluster/fuzz_test.go` |

**M1 验收标准**：
- `grep -rn '"regexp"' internal/gateway/cluster/` 无非测试命中（零正则依赖）；
- `go test -race -count=1 ./internal/gateway/cluster/...` 全部通过；
- `go test -bench=. -benchmem ./internal/gateway/cluster/...` 验证 `BenchmarkCluster1000Hosts` < 50ms/op 且所有输出浮点有限。

## 3. 里程碑 M2：Protobuf 扩展、sqlc 与 `internal/gateway/job` 汇总 / `DiffJobs`

分支：`feat/fleet-cluster-m2-job-proto`（基于合入 M1 后的 `feat/fleet-output-clustering`）。

| 提交 | 内容 | 涉及文件 |
|---|---|---|
| M2-1 | `api/proto/allowops/v1/job.proto` 增量扩展（`grouping`、`GroupSeverity`、`MetricVariance`、`JobSummary` 守恒元数据、`DiffJobs` RPC 及消息）、`internal/store/queries/job.sql` `ListJobTaskPreviews` 补选 `host_id`；运行 `make generate` 更新 `gen/`、`web/src/gen/`、`internal/store/db/` | `api/proto/allowops/v1/job.proto`、`internal/store/queries/job.sql`、`gen/...`、`web/src/gen/...`、`internal/store/db/...` |
| M2-2 | `job.Service` 接入 `cluster`：支持 `grouping: exact\|normalized`、两遍聚类与 Anomaly-First 排序、无输出终态分组与主机守恒、线性 `O(G)` 32 KiB 预算裁剪与 `GroupBytes` 模板共享预算、并发分析信号量 | `internal/gateway/job/summary.go`、`internal/gateway/job/validation.go`、`internal/gateway/job/service.go`、`internal/gateway/job/queries.go`、`internal/gateway/job/sql.go`、`internal/gateway/job/summary_test.go` |
| M2-3 | 实现 `JobService.DiffJobs`（`job.Client`、`ConnectService` 同步扩展）：复用 `s.authorize` 双 Job `view_jobs` + `view_output` 逐主机鉴权、未完成/拒绝/跨 action 校验、双 Job 审计（`JobID=target` + `Resource="job:<base>"`）、线性 32 KiB 裁剪与完整权限/多租户/替换主机/规模测试 | `internal/gateway/job/diff.go`、`internal/gateway/job/client.go`、`internal/gateway/job/connect.go`、`internal/gateway/job/service.go`、`internal/gateway/job/diff_test.go` |

**M2 验收标准**：
- `buf lint` 与 `buf breaking`（或 `make generate && git diff --exit-code`）干净；
- `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/gateway/job/... ./internal/gateway/output/... ./internal/gateway/api/...` 全绿（含 120+ 主机 32 KiB 预算、主机守恒等式、1000 组裁剪基准、跨租户权限拒绝、审计校验）；
- `cd web && pnpm typecheck`（或 `pnpm exec tsc --noEmit`）通过，验证 `wire.check.ts` 正常。

## 4. 里程碑 M3：MCP 工具、CLI、保留名与全套文档

分支：`feat/fleet-cluster-m3-mcp-cli-docs`（基于合入 M2 后的 `feat/fleet-output-clustering`）。

| 提交 | 内容 | 涉及文件 |
|---|---|---|
| M3-1 | `catalog.validateIdentity` 保留名增加 `jobs_diff`；`mcp.JobService` 及测试 fake 同步补齐 `DiffJobs`；`jobs_get` 与 action 工具增加可选 `grouping` 参数（校验互斥与 schema 描述）；`mcp/summary.go` 映射新字段并在单组折半循环中同步缩减模板预览（保持 `native_summary_golden.json` 零破坏） | `internal/catalog/catalog.go`、`internal/gateway/mcp/job.go`、`internal/gateway/mcp/fixed.go`、`internal/gateway/mcp/schema.go`、`internal/gateway/mcp/arguments.go`、`internal/gateway/mcp/call.go`、`internal/gateway/mcp/summary.go`、相关单测与 golden 更新 |
| M3-2 | MCP 新增固定只读工具 `jobs_diff`（参数校验、映射、32 KiB 预算强制、结果审计 `mcp/jobs_diff`、单测与真实 SeaweedFS+Agent 端到端测试） | `internal/gateway/mcp/diff.go`、`internal/gateway/mcp/diff_test.go`、`internal/gateway/mcp/real_job_test.go`、`internal/gateway/mcp/testdata/*.json` |
| M3-3 | CLI `allowops run --grouping`、`allowops jobs get --grouping` 与 `allowops jobs diff <base> <target>`（表格与 `--json` 输出 + 单测） | `internal/cli/jobs.go`、`internal/cli/jobs_diff_test.go` |
| M3-4 | 同步更新架构文档、中英文 VitePress 文档与 `CHANGELOG.md`（含升级说明：`exact` Anomaly-First 默认顺序变化与 `jobs_diff` 保留名） | `docs/design.md`、`website/mcp.md`、`website/zh/mcp.md`、`website/concepts.md`、`website/zh/concepts.md`、`CHANGELOG.md` |

**M3 验收标准**：
- `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/catalog/... ./internal/gateway/mcp/... ./internal/cli/...` 全绿；
- `make examples-check` 通过；
- `(cd website && pnpm install --frozen-lockfile && pnpm docs:check)` 通过。

## 5. 总指挥最终验收清单

全部里程碑合入 `feat/fleet-output-clustering` 后，由总指挥独立重跑以下全部命令并核验结果：

```sh
gofmt -l $(git ls-files '*.go' | grep -v '^gen/')
go vet ./...
ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/gateway/cluster/... ./internal/gateway/job/... ./internal/gateway/mcp/... ./internal/gateway/output/... ./internal/gateway/api/... ./internal/cli/... ./internal/catalog/...
go test -bench=. -benchmem ./internal/gateway/cluster/...
make examples-check
(cd website && pnpm install --frozen-lockfile && pnpm docs:check)
```

确认无未提交残留、无未声明的 golden 漂移，向负责人汇报所有提交、基准数据与验收结果，等待确认后再决定是否 push 与开 PR。
