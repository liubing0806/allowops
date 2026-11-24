# 组合动作步骤受控数据传递与条件分支实施计划

依据设计文档：[docs/step-dataflow-design.md](step-dataflow-design.md)（已通过独立安全复审并修订至 Rev 2）。
目标分支：当前开发分支 `feat/step-dataflow-branching`（未获确认前不 push、不开 PR）。

---

## 里程碑拆分与依赖顺序

采用串行依赖的 3 个工程里程碑（M1 → M2 → M3）+ 1 个总指挥收口验收里程碑（M4），每个工程里程碑在独立 `worktree` 子会话中实现、自测并本地提交，经总指挥核验 diff 与测试后按顺序合入当前开发分支：

```text
M1 (catalog schema + static security validation + params placeholders)
  │
  ▼
M2 (redact line-taint + executor extract/3VL when + execd/agent/gateway integration)
  │
  ▼
M3 (test/attack adversarial suite + 3 example actions + examples-check)
  │
  ▼
M4 (commander diff audit + independent security review + full test suite + docs sync)
```

---

## M1：Catalog Schema、严格解码与静态安全校验

**目标**：完成 `internal/params` 和 `internal/catalog` 的数据结构、严格 YAML/JSON 解码、规范化 JSON 与全套静态安全校验（含 C1/H1/H3/M1/M3/M6/L2/L3）。

### 改动范围
1. **`internal/params/params.go`**：
   - 新增 `StepPlaceholder(s string) (stepName, varName string, ok bool)`。
   - 扩展 `Placeholder(s string) (string, bool)` 统一识别 `{name}` 与 `{steps.<step>.<var>}`（对后者返回 `"steps.<step>.<var>", true`）。
   - 确认 `ValidateTemplate` 与 `Render` 对 `"steps.<step>.<var>"` 键自然工作且不破坏任何既有参数行为。
2. **`internal/catalog/step_dataflow.go`**（新文件）：
   - 定义 `TSVExtractor`、`ExtractType`、`StepExtractor`、`StepCondition`、`ConditionValue`、`JSONPathSegment`。
   - 为 `TSVExtractor`、`ExtractType`、`StepCondition`、`ConditionValue` 实现严格 `UnmarshalYAML(*yaml.Node)` 与 `UnmarshalJSON`（拒绝浮点截断、字符串/布尔混入整数、`null`、以及显式 `line: 0`）。
   - 实现 `ParseJSONPath(expr string) ([]JSONPathSegment, error)`（严格校验 `^\$`、点号键、数组下标 `0..9999`、引号键，1..16 段）。
   - 实现 `ExtractType.AsParamDefinition(name string) params.Definition` 与 `ExtractType.Validate(...)`（`int` 必填 `min`/`max` 且 `min <= max`；`enum` 禁止 `-` 开头；`string` 必填 `regex`+`max_len ∈ [1,1024]` 且校验 `^(?:...)$` 编译；`path` 必填 `allowed_roots`；`bool` 无额外约束）。
   - 实现 `validateStepExtract`（变量名合法且不为 `exit_code`/`skipped`；单步 ≤ 16、全局 ≤ 64；`regex`/`json_path`/`tsv` 三选一；`regex` ≤ 256 字符无 CR/LF/NUL 且 `NumSubexp() == 1`；`match` 仅限 `regex` 且 ∈ `{"", "first", "exactly_one"}`；`max_bytes ≤ 1MB`）。
   - 实现 `validateStepCondition`（最大深度 4、最大节点 32；组合节点与叶子节点互斥；`ref` 精确语法与前序步骤存在性；运算符与静态类型严格匹配；`enum` 字面量必须在 `as.values` 中；`path` 仅允许 `exists`；`in` 1..32 项）。
3. **`internal/catalog/catalog.go`**：
   - `Step` 增加 `When *StepCondition` 与 `Extract map[string]StepExtractor`（均 `omitempty`）。
   - `validateSteps` 集成 Step 0 禁 `when`、`allow_interpreter: true` 禁 `{steps.*}`、有序前序步骤表与 `stepDefs`、引用 `int` 的 `min >= 0` 检查、`validateStepCondition`、`validateStepExtract` 与 `checkStepPlaceholders`。
   - `actionWarnings` 对非 `read` 风险且使用 `extract`/`when` 的动作输出评审警告。
4. **`internal/catalog/command.go` & `internal/catalog/host.go`**：
   - 实现 `checkStepPlaceholders(argv []string) error`（C1：禁止 `{steps.*}` 出现在 `argv[0]`、所有包装命令选项/操作数、`docker`/`kubectl` 全局选项/子命令/`exec` 目标与选项、以及 `docker`/`kubectl` 子命令后的凭据/端点选项值）。
   - `ResolveExecutable` 增加内部 `ResolveExecutableWithDefs` 供 `CheckHost`（按步构建真实 `stepDefs`）和 `executor` 使用，确保软链接解析到解释器时复核真实类型定义。
5. **单元测试**：
   - `internal/params/step_placeholder_test.go`
   - `internal/catalog/step_dataflow_test.go`：覆盖 YAML/JSON 严格解码、`CanonicalJSON` 往返与 `ActionDigest`、`eq: 0`/`eq: false`/`eq: ""`/`exists: false` 防 `omitempty` 丢失、全部静态拒绝项（C1/H1/H3/L2/L3/DAG/深度/节点数/保留名）、旧版 `Step` 结构 `strictJSON` 必拒收测试。

### M1 验收标准
- `go test -race -count=1 ./internal/params/... ./internal/catalog/...` 全绿。
- 既有 `Action`（无 `when`/`extract`）的 `CanonicalJSON` 与 `ActionDigest` 零变化。

---

## M2：脱敏行污染标记、执行器流式提取与 3VL 条件求值、Helper/Agent/Gateway 全链路集成

**目标**：打通主机端与网关端运行时闭环，完整落实脱敏后/过滤前流式提取、行污染标记、JSON 二次脱敏、Kleene 3VL、可选组严格省略、显式跳过原因与网关事件校验。

### 改动范围
1. **`internal/redact/redact.go`**：
   - 新增 `LineTracked(line string) (string, bool)`，返回脱敏后文本及是否被任意规则或 PEM 规则改写。
   - 新增 `StreamTracked(input io.Reader, maxLine int, emit func(line string, modified bool) error) error`（现有 `Stream` 直接委托它实现，零逻辑重复）。
2. **`internal/executor/`**：
   - `step_dataflow.go`（新文件）：
     - 固定原因错误：`ErrExtractFailed`（`EXTRACT_FAILED`）、`ErrExtractTypeInvalid`（`EXTRACT_TYPE_INVALID`）、`ErrExtractMissing`（`EXTRACT_MISSING`），以及 `ReasonOf(err)`、`KnownReason(code)`。
     - `stepExtractSink`：挂接在 `Redactor.StreamTracked` 与 `filterWriter` 之间；
       - `regex`（`first`/`exactly_one`）与 `tsv`（`tab`/`whitespace`）逐行流式匹配（O(1) 内存），跟踪 `max_bytes` 溢出与行污染标记 `modified`；
       - `json_path` 共享单缓冲（上限取本步 `max(max_bytes) ≤ 1MB`）、记录文档内任一行是否 `modified`；
       - `Finalize`：严格单值 JSON 解码（深度 ≤ 32、拒重复键）、路径求值、JSON 解码后对值及 `lastKey=value` 执行 `redactor.LineTracked` 二次复检、`[REDACTED:` 兜底检查、复用 `internal/params` 强类型校验（`string` 按 `^(?:...)$` 锚定；`path` 经 `ResolvePath` 但错误不包装原始路径）。
     - `evalCondition`：实现 Kleene 三值逻辑（`triFalse`/`triTrue`/`triUnknown`）。
   - `executor.go`：
     - `StepResult` 新增 `SkipReason string`（`json:"skip_reason,omitempty"`）。
     - `streamStdout` 改用 `r.StreamTracked`，先喂给 `extractSink`（若非 nil），再写入 `filterWriter`。
     - `runCommand` 返回输出不完整标记（`ScanLimitReached || errors.Is(waitErr, exec.ErrWaitDelay)`）。
     - `runSteps` 集成 `when` 求值（`SkipReason: "CONDITION_FALSE"` vs `"STOPPED"`）、产生步状态跟踪、可选组严格省略检查、步骤变量前导 `-` 统一拒绝、渲染后 `CheckCommand`、步骤执行前对引用到的提取 `path` 变量执行 `CheckPathTrusted`、以及命令成功退出且输出完整时执行 `extractSink.Finalize`（提取失败置 `r.ExitCode = -1`）。
3. **`internal/execd/`**：
   - `wire.go`：`wireStep` 增加 `SkipReason string`（`json:"skip_reason,omitempty"`）。
   - `exec.go`：`ExecutionReason` 增加 `executor.ReasonOf(err)`。
4. **`internal/agent/`**：
   - `agent.go`：`Features` 增加 `"step_extract"`, `"step_when"`。
   - `task.go`：跳过步骤把 `step.SkipReason` 写入 `stepResult.Reason`；`taskStatus` 透传 `executor.ReasonOf(err)` 与 `params.ErrPathNotTrusted`。
   - `runner.go`：`helperReason` 透传 `executor.KnownReason(reason)` 与 `"PATH_NOT_TRUSTED"`。
5. **`internal/gateway/job/events.go`**：
   - `validateStepCompleted`：区分 `Reason == "CONDITION_FALSE"`（仅当 `a.Steps[i].When != nil`）与 `Reason == "STOPPED"` / `""`（需先前存在非 `SUCCEEDED` 且非 `SKIPPED` 的失败或 `CANCELLED`/`TIMEOUT`）。
   - `validateStepsAggregate`：全部步骤为 `SUCCEEDED` 或 `SKIPPED` 时聚合退出码 `0`、聚合状态 `SUCCEEDED`。
6. **单元测试与集成测试**：
   - `internal/redact/tracked_test.go`
   - `internal/executor/step_dataflow_test.go`
   - `internal/execd/execution_reason_test.go` & `wire` 测试
   - `internal/agent/step_dataflow_test.go`（含 `features` 上报、条件跳过事件流、提取错误原因透传、旧目录加载测试）
   - `internal/gateway/job/onmessage_test.go` & `rf_a04_test.go` 新增条件跳过与聚合退出码测试

### M2 验收标准
- `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/redact/... ./internal/executor/... ./internal/execd/... ./internal/agent/... ./internal/gateway/job/...` 全绿。

---

## M3：对抗攻击测试、示例组合动作与 `examples-check`

**目标**：构建全面对抗攻击回归套件并交付 3 个高价值示例组合动作。

### 改动范围
1. **`test/attack/step_dataflow_test.go`**：
   - 完整实现设计文档第 7 节全部 12 类对抗攻击测试（含 C1 `nsenter -t` / `docker -H` / `kubectl --server` / `docker exec` / `kubectl exec`、H1 负数/选项注入、H2 PEM 吞行 + `not` + 失败步可选组、H3 `allow_interpreter` + `tar`/`ip`、M1 `exactly_one`、M2 部分脱敏污染 + JSON `\u0070assword`、M3 未锚定正则、M4 `max_scan` 截断、T10 路径逃逸/TOCTOU/过滤器隔离、T12 洪水与深层/重复键 JSON、旧版 `Step` `strictJSON` 拒收）。
2. **`examples/catalog/actions/`**：
   - `disk_pressure_diagnose.yaml`
   - `top_process_diagnose.yaml`
   - `docker_container_diagnose.yaml`
3. **`test/examples/check_examples.py`**：
   - 更新动作数校验（`133` → `136`）。
   - 新增 `top_process_diagnose` 与 `disk_pressure_diagnose`（指向 `/` 或本地临时目录）的真实 `catalog try` 端到端冒烟验证（验证提取、条件跳过/执行与 `steps` 结果结构）。

### M3 验收标准
- `go test -race -count=1 ./test/attack/...` 全绿。
- `make examples-check` 全绿。

---

## M4：总指挥代码复审、文档同步与全量验收

**目标**：总指挥复审全量 diff、加派独立安全复审子代理审查最终代码、更新全部文档并执行全套验收命令。

### 改动范围
1. **文档同步更新**：
   - `SECURITY.md`（补充步骤提取不可信数据边界、包装命令限制、非授权边界说明与 `/proc/<pid>/cmdline` 残余风险）
   - `docs/design.md`（更新组合 action 能力、安全要求与 `features`）
   - `docs/architecture-decisions.md`（追加组合步骤数据流与条件分支架构决策记录）
   - `website/execution.md`、`website/zh/execution.md`
   - `website/catalogs.md`、`website/zh/catalogs.md`
   - `website/publishing.md`、`website/zh/publishing.md`（补充 `step_extract`、`step_when` 特性与 agent/execd 同步升级要求）
   - `CHANGELOG.md`
2. **独立代码安全复审**：
   - 派独立 Review 子代理审查合并后的完整代码与攻击测试，修复全部高/中危及合理意见。
3. **全套验收命令**：
   ```sh
   gofmt -l $(git ls-files '*.go' | grep -v '^gen/')
   go vet ./...
   ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/catalog/... ./internal/params/... ./internal/executor/... ./internal/execd/... ./internal/agent/... ./test/attack/...
   make examples-check
   (cd website && pnpm install --frozen-lockfile && pnpm docs:check)
   ```
   （外加 `ALLOWOPS_REQUIRE_DOCKER=1 go test -race -count=1 ./internal/redact/... ./internal/gateway/job/...` 确保网关与脱敏全量通过。）
4. **交付状态**：所有提交合入当前分支 `feat/step-dataflow-branching`，**不 push、不开 PR**，等待负责人最终确认。
