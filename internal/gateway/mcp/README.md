# P6M：无状态 MCP 服务与依赖调查

使用官方 `github.com/modelcontextprotocol/go-sdk v1.8.0` 的 Streamable HTTP Stateless handler，挂在 P4 的 `/mcp` 和 MCP ALPN 路由。所有请求由 P5B 重新验证 Authorization: Bearer，支持服务账号和 CLI 会话；cookie、查询参数凭据和 MCP 会话头不参与认证。

工具列表按完整身份属性（含内部 actor ID、Kind、roles、teams、owner、email）、所有有效目录版本与摘要、策略版本缓存。缓存无 TTL；默认最多 128 项，LRU 淘汰，可由 `Config.CacheEntries` 调整。目录或策略版本改变时替换旧缓存；认证吊销和角色变化在使用缓存前检查。预判仅用于展示，忽略主机、时间和来源 IP；deny 只有在这三类条件均不存在时才用于隐藏 action，身份条件继续保留。调用仍由 P6 做完整 ABAC。

G50：请求带 `_meta.progressToken` 时，每 10 秒发送对应的 `notifications/progress`，progress 为持续等待的秒数；没有 token 时每 10 秒写入 `: keepalive` SSE 注释。SDK 未导出注释写入接口，使用串行 ResponseWriter 包装；工具处理开始后提交 SDK 已设置的 SSE 响应头，保证等待期间注释能及时发出。`Config.ProgressInterval` 可在测试中缩短。无 `tools/list_changed` 能力，更新在下次 `tools/list` 生效。

G49：六个 JobService 方法自行认证、授权和审计；MCP 复用 RunJob/CancelJob 的 authorized，不重复写前审计。每次工具调用另记 result，覆盖参数错误、未知工具、拒绝和关联 job ID。hosts_search 只记 result。未知工具不将客户端提供的名称写入审计。

网关启动入口直接注入 P6 的 `job.Client`。RunJob/GetJob 返回的原生汇总是唯一分组来源；已删除 G53 临时回退和 MCP 的任务分组逻辑。MCP 只做字段映射、传输字节预算和分页，不再调用 ListTasks/GetJobOutput 拼出 action 汇总。A21 认证与权限全部由 P6 判定。

A27：不传 selector 和 hostname 时，分页列出调用者可查看的全部主机，包含总数与标签分布。该入口仍集中在 `emptyHostSearch`；所有主机可见性沿用 P5B ListHosts 的逐主机判定。固定工具省略 arguments 时视为 `{}`；显式传入空字符串的可选查询字段按 inputSchema 返回参数错误。

## 数据边界

- G40：action 参数在 `params` 对象；公共参数和 action 声明的 filters 在顶层。
- `params.JSONSchema` 的 NUL 安全模式使用等价的 `\x00` 转义，以兼容 SDK 使用的 Go JSON Schema 验证器；签名 regex 保持原值。builtin 的签名 regex 收紧同时应用于 schema 和参数预检。
- 网关只检查主机路径的语法和 allowed_roots 前缀，不检查网关文件系统；路径存在性和符号链接必须在主机执行时检查。
- `JobService` 方法均为 `(context.Context, *v1.XRequest) (*v1.XResponse, error)`：RunJob、GetJob、ListJobs、ListTasks、CancelJob、GetJobOutput。
- 权限集中在 P6；MCP 已删除 A21 草稿判定。jobs_cancel 只调用 CancelJob，不附加 GetJob/view_jobs。任何主机输出由 GetJobOutput 执行 view_output 判定；汇总无输出权限时省略输出预览。jobs_list 显式限当前 actor。
- G57：只映射 P6 的 groups/offline_hosts/output_trust/truncated，游标绑定身份、job、格式及原生汇总快照。counts 覆盖整个 job；groups/offline_hosts 为当前页。detailed 返回各组主机名，不生成 tasks。单个大组的主机名也可跨页。P6 已省略的分组无法由 MCP 恢复，保留其 truncated 标记并在工具描述说明。
- G39/G42：每组 stdout+stderr 预览合计最多 4KiB；concise 列前两个主机名，detailed 列当前页的组内主机名。结果 JSON（含 structuredContent、相同内容的 text，以及 SDK 的 serverInfo/resultType 元数据）合计不超过 32KiB。JSON 转义膨胀时会继续缩短预览，并标 truncated。
- G55：单台主机的标签超预算时保留主机名、在线状态和可容纳的排序标签前缀，在该 host 对象中标 labels_truncated=true；标签分布沿用 label_counts_truncated。完整标签可缩小 selector 范围或在控制台/CLI 查看。
- G54：deny 不创建 job；超过结果字节预算时返回可容纳的完整 denied_hosts 前缀（含规则）、denied_count、details_truncated=true。
- A33：jobs_get 的可选 step_index 仅与 host 使用。省略保持 nil，由 P6 判断是否为组合 action；组合 action 返回 INVALID_ARGUMENT/INVALID_OUTPUT_STEP，MCP 补充 step_index 必填及需逐步骤读取的提示，工具结果 isError=true。参数定义和错误提示集中在 step.go；MCP 不拼接步骤输出。
- G43：主机输出用 data_base64、encoding=base64、next_offset、eof。按字节续读可保留被分页切开的 UTF-8 字符和非文本字节；结果字节预算引起分页时不修改主机端 truncated 标记。

## SDK 依赖路径

`go mod why -m github.com/segmentio/asm` 在仓库里显示 OPA → jwx → asm 路径。JWX 的该导入受 `jwx_asmbase64` 标签控制；默认 `go list -deps -test ./...` 未纳入 asm。基线 004ed29 的 `make licenses` 在独立 `/tmp` 源码副本中 exit 0。

在只导入官方 SDK 的临时模块中，同一命令确认实际路径：

```text
github.com/modelcontextprotocol/go-sdk/mcp
github.com/modelcontextprotocol/go-sdk/internal/json
github.com/segmentio/encoding/json
github.com/segmentio/asm/base64
```

这不是 jsonschema 的可选功能。`github.com/google/jsonschema-go v0.4.3` 的模块依赖没有 segmentio。SDK 的内部 JSON decoder 无可选构建标签；`go list -deps -tags=purego ./...` 仍包含 asm。使用原始 AddTool、不使用 schema 自动推导或关闭 CGO，都不能移除该 JSON 包的 Go 导入。

已核查官方稳定版本 v0.8.0、v1.0.0、v1.1.0、v1.2.0、v1.3.0、v1.3.1、v1.4.1、v1.5.0、v1.6.1、v1.7.0、v1.8.0。v1.3.0 及此前所核查版本没有 segmentio 导入；v1.3.1 引入它。官方 [v1.3.1 发布说明](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.3.1) 明确该变更修复 JSON 字段名大小写不敏感的安全问题。旧版 Stateless 仍读取 Mcp-Session-Id；新版的传输资源上限及修复见 [v1.8.0 发布说明](https://github.com/modelcontextprotocol/go-sdk/releases/tag/v1.8.0)。

## 可选方案与代价

| 方案 | 已有证据 | 代价与限制 |
|---|---|---|
| 保持 SDK v1.8.0，允许 MIT-0（未采用） | 选中的 asm v1.2.1 LICENSE 为 MIT No Attribution；原许可证检查未识别 9 个 asm 包 | 需要负责人决定 MIT-0，并解决检查器识别问题。当前 classifier v2.0.0 的许可证模板没有 MIT-0；仅增加白名单尚不能证明检查通过 |
| 官方 SDK v1.8.0，明确替换为官方 asm v1.1.3 | asm v1.1.3 是 MIT；encoding v0.5.4 声明依赖 asm v1.1.3。临时模块使用 replace 后 `go build ./...`、原白名单的 go-licenses check 及 `go test -race -count=1 ./...` 均 exit 0。官方 SDK 客户端完成本机 Stateless HTTP 的 tools/list、tools/call，中文、NUL 和 HTML 字符往返一致 | 需要批准依赖替换并验证平台和功能兼容性；受影响范围是整个模块。兼容性测试仅覆盖独立 echo 工具；尚未验证 P6M 认证/Job 链路、其他构建标签及跨平台行为 |
| 采用官方 SDK v1.3.0 | 源码不导入 segmentio，具有 Streamable HTTP 与 Stateless | 缺少 v1.3.1 的安全修复和后续传输修复；需要会话头适配。当前不建议采用，未修改依赖版本 |
| purego、关闭 CGO 或不使用 schema 自动推导 | purego 的实际依赖列表仍有 asm；JSON decoder 导入无条件 | 无法消除许可证问题 |

A24 已答复：仓库用独立依赖提交固定 `segmentio/asm v1.1.3`（MIT），使用 replace 避免模块版本选择回到 MIT-0；SDK 保持 v1.8.0，许可证白名单不变。所有验证均在本机完成，未连接业务或客户服务器。

临时兼容性探针保存在 `/tmp/allowops-p6m-sdk-probe/probe_test.go`，该模块仅在自己的 go.mod 中替换 asm。测试修正了 v1.8.0 `Client.Connect` 的第三个参数后通过；没有将临时替换写入当前仓库。

## 官方依据与最小导出改动

工具命名、描述、concise/detailed、分页和可纠正参数错误依据 Anthropic [Writing effective tools for agents](https://www.anthropic.com/engineering/writing-tools-for-agents)。注解和 structuredContent/text 契约依据 [MCP tools 规范](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)；进度 token 和递增数值依据 [MCP progress 规范](https://modelcontextprotocol.io/specification/2025-11-25/basic/utilities/progress)。

P5B 新导出 `PolicySnapshot`（展示预判读取结构化策略）、`ForkRequestContext`（隔离同一 HTTP 批次中可变授权/审计上下文）、`RequestAuditInfo`（仅现有审计字段白名单）。`AuditEvent` 增加 JobID 并映射到 P7 已有字段；原认证、ABAC、API 和审计行为不变。网关主程序只替换 MCP placeholder handler，未修改 P4 ALPN 路由。
