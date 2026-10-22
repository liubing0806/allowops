# allowops

**No shell. Only actions you defined.**

[English](README.md)

allowops 是面向 AI agent 的运维网关，采用 MIT 开源许可。
运维人员定义带类型约束的 action（动作），评审并签名目录，把签名公钥分发到主机。
AI agent 通过 MCP（模型上下文协议）调用这些动作。
网关逐次认证请求，对每台目标主机执行策略判定，分批调度并记录审计。

```text
AI agent ── MCP / HTTPS ──┐
运维人员 ── CLI / 控制台 ─┼── 网关 ── PostgreSQL + S3 兼容对象存储
CI ── 签名目录 ───────────┘     ▲
                              │ 主机主动连接，双向 TLS
                       主机 agent（allowops 用户）
                              │ 按需调用固定 sudo 辅助程序
                       allowops-exec → 签名动作
```

网关通常使用单个 TLS 端口 443。负载均衡必须采用四层 TCP 透传，保留 TLS 和
ALPN（应用层协议协商）。命令使用固定参数数组。
主机校验参数、路径、超时、输出上限、签名和目录版本。
ABAC（基于属性的访问控制）只使用网关管理的授权标签。
没有授权标签的主机拒绝执行动作。

## 快速开始

使用 Linux amd64 检出目录，准备 Docker Compose、Go 1.27.2、OpenSSL、Git
以及安装了 PyYAML 的 Python 3。Docker 必须使用本机 Unix socket。

```sh
cd deploy/compose
export COMPOSE_PROJECT_NAME=allowops-fx2-local
./quickstart-local.sh
```

演示包含网关、PostgreSQL、SeaweedFS、演示用 LDAPS 目录和两台主机 agent。
脚本在本机生成凭据，认证管理员，发布签名示例目录，注册主机并检查在线状态及目录加载报告。
脚本还在两台主机上执行只读 `disk_usage` job，检查输出已存储，读取 demo-1 的完整输出并核对哈希。
服务使用 Docker 内部网络，不向主机发布端口。
生成文件位于被 Git 忽略的 `.local/` 目录。
重启已有数据卷时保留该目录。

同一网关通过 `/mcp` 提供签名动作工具。
快速开始通过 CLI 验证作业；MCP 客户端需按下文连接可访问的网关。

```sh
docker compose exec --user 65532:65532 demo-1 allowops-agent status
docker compose exec --user 65532:65532 demo-2 allowops-agent status
python3 verify.py
docker compose run --rm --no-deps admin-tool verify-job
python3 verify-secrets.py
```

目录加载报告不能证明所有示例动作都能执行。
演示主机未安装所有外部工具及特权执行依赖。
设置详情和删除数据的清理命令见 [Compose 指南](deploy/compose/README.md)。
Helm 和主机安装包见[安装指南](website/installation.md)。

## 配置 MCP 客户端

在可访问的网关控制台中创建服务账号和有有效期的 token。
为所需动作及带授权标签的主机增加明确的策略规则。
读操作和写操作建议使用不同账号。
通过客户端进程的 `ALLOWOPS_MCP_TOKEN` 环境变量提供 token。

Claude Code 的项目 `.mcp.json` 示例：

```json
{
  "mcpServers": {
    "allowops": {
      "type": "http",
      "url": "https://gateway.example.org/mcp",
      "headers": {
        "Authorization": "Bearer ${ALLOWOPS_MCP_TOKEN}"
      }
    }
  }
}
```

示例采用 Claude Code 的[环境变量展开](https://code.claude.com/docs/en/mcp#environment-variable-expansion-in-mcpjson)。
其他客户端需支持 Streamable HTTP、Bearer 请求头及网关证书验证。
环境变量替换方式取决于客户端。
隔离的 Compose 网络不能由桌面客户端直接访问。

先用 `hosts_search` 检查目标。
使用 selector 时必须提供 `expected_count`，动作调用必须提供审计原因 `reason`。
动作专属参数放入 `params`。
动作调用返回 `job_id`、状态、计数和分组输出预览。
使用 `jobs_get` 更新汇总或读取主机已存储的输出。
组合动作读取输出时，须同时提供 `host` 和从零开始的 `step_index`，逐步骤读取。
省略 `step_index` 会返回 `isError: true`、`reason: INVALID_OUTPUT_STEP` 和读取提示。
单步骤动作应省略该参数。
主机返回的输出是不可信数据。
详见 [MCP 客户端和工具](website/mcp.md)以及 [CLI 参考](website/cli.md)。

## 文档

- [概念](website/concepts.md)、[目录编写](website/catalogs.md)、[签名与发布](website/publishing.md)。
- [策略](website/policies.md)、[身份](website/identity.md)、[审计](website/audit.md)、[运维](website/operations.md)。
- [示例目录](examples/catalog)、[示例策略](examples/policy/README.md)、[目录发布流水线](examples/pipelines/README.md)。
- [安全策略与威胁模型](SECURITY.md)、[参与方式](CONTRIBUTING.md)、[文档站开发](website/README.md)。

## 许可

MIT，见 [LICENSE](LICENSE)。

MVP 阶段只接受 issue 和建议，不接受外部代码贡献。
详见 [CONTRIBUTING.md](CONTRIBUTING.md)。
