# AllowOps 仓库协作

## 组件入口

| 目录 | 职责 |
| --- | --- |
| `cmd/allowops/` | 运维命令行客户端 |
| `cmd/allowops-gateway/` | 网关服务与数据库迁移入口 |
| `cmd/allowops-agent/` | 主机注册、连接网关与接收任务 |
| `cmd/allowops-exec/` | 主机侧执行辅助程序，通过标准输入接收请求 |
| `web/` | 网关控制台，构建产物写入 `internal/gateway/console/dist/` |
| `deploy/` | Compose 与 Helm 部署配置、安装包脚本 |
| `test/` | 跨组件测试、端到端场景与仓库检查脚本 |

## 验证入口

各代码块从仓库根目录执行。按改动涉及的组件选择验证命令。

### Go 程序与策略

目标定义见 [Makefile](Makefile)。

```sh
make lint
make test
make opa-test
make build
make cross-check
make helm-check
```

`lint` 包含 Python 脚本检查、仓库卫生检查、Go AST 静态门禁（`make guardrails`）、`go vet` 和 `staticcheck`。`test` 校验示例目录并启用 Go 竞态检测。
`opa-test` 运行 Open Policy Agent（OPA）授权策略测试。`build` 将四个程序写入 `bin/`。`cross-check` 检查四平台 CLI 交叉编译。`helm-check` 运行 Helm 渲染矩阵与 Schema 覆盖校验。

### 控制台与端到端测试

控制台命令及 Node.js、pnpm 版本见 [web/package.json](web/package.json)。

```sh
cd web && pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

涉及控制台、网关与主机代理的联动时，使用本机 Docker Unix 套接字运行端到端测试。

```sh
make e2e
```

### 仓库卫生与发布

```sh
python3 test/repo-hygiene-check.py
python3 test/repo-hygiene-check.py --include-untracked
python3 test/test_repo_hygiene_check.py
```

默认扫描 Git 已跟踪文件。`--include-untracked` 同时扫描未被忽略的新文件。修改检查规则时运行上述自测。
发布或内部推广前执行以下门禁。[路线图](docs/roadmap.md) 的“当前去向”标有未修复安全事项时，门禁逐项报告并返回非零状态。

```sh
python3 test/repo-hygiene-check.py --release-gate
```

## 缺陷修复

1. 在对应的测试套件中复现缺陷，先单独提交能显示实际与预期差异的失败测试。
2. 做最小修复，重跑同一测试并确认原断言通过。
3. 运行受影响组件的验证命令，记录提交 SHA、命令和结果。

## 共享边界与交付

- 并行修改 `internal/store/migrations/` 前统一迁移序号与执行顺序。
- 并行修改 `deploy/helm/allowops/` 前统一模板参数与渲染后的配置字段。
- 变更全局配置结构时先对齐字段名、类型、默认值和读取方，再拆分并行任务。
- 本地凭据保存在 Git 忽略的文件中。测试、测量和调试的临时代码留在本地工作区或本地调试分支。
- 执行 `git push` 前取得用户对目标分支的明确同意。
