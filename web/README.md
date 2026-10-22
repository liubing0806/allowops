# Web 控制台

控制台通过同源 Connect API 读取和修改网关数据。`src/api/index.ts` 导出真实客户端。登录支持网关配置的 OIDC 和 LDAP 身份源。未登录时进入登录页；登出调用网关 Logout 并清除页面查询缓存。

UI2（A40）使用 shadcn/ui Nova 样式（`components.json` style `radix-nova`、baseColor `neutral`、iconLibrary `lucide`）。`src/components/ui/` 下的组件源码通过 shadcn CLI 加入仓库，不手写同类组件。主题为 Nova neutral 默认主题，深浅色均支持；`src/index.css` 只保留 Nova token，不保留 magpie 色值。每类能力只用一个库：shadcn/ui（Radix）、lucide-react、TanStack Query/Table、react-hook-form+zod、i18n、zustand。Motion、分栏、拖拽未引入。客户端主题偏好与主机筛选由 zustand 管理（筛选离开页面重置，不持久化），服务端状态继续由 TanStack Query 管理。各页面保留全部接口调用、请求字段、校验、权限提示，不按角色隐藏按钮，由 API 判权；未新增功能与文案。

## 生成与构建

需要 Node.js 24.19.0 或更高版本、pnpm 10.33.2，以及项目要求的 Go 工具链。在仓库根目录执行：

```sh
make generate
make web-build
make build
```

`make generate` 先按锁文件安装前端依赖，再生成 Go、TypeScript 和 SQL 代码。`buf.gen.yaml` 使用本地 `protoc-gen-es`。生成器和 Protobuf 运行库固定为 2.16.0，Connect-ES 和 connect-web 固定为 2.2.0。Connect-ES v2 直接使用 protoc-gen-es 生成的服务描述，不再使用独立的 protoc-gen-connect-es 插件。生成的 TypeScript 文件位于 `src/gen/allowops/v1/`，纳入版本控制。

`make web-build` 将 Vite 产物写入 `internal/gateway/console/dist/`。产物纳入版本控制，Go 构建直接通过 `go:embed` 内嵌这些文件。修改前端后应先运行 `make web-build`，再构建网关。网关在已有的 h2、http/1.1 控制台路由提供页面，不修改主机和 MCP 的 ALPN 路由。`pnpm dev` 没有配置网关代理；本任务验证使用网关提供的同源页面。

路由使用 React.lazy 代码分割。带内容哈希的 `/assets/` 文件缓存一年；首页和 SPA 路由使用 `no-cache`。不存在的静态资源返回 404。页面使用同源脚本、样式和请求的 Content Security Policy（CSP）。构建检查拒绝把 Vitest 测试模块或测试夹具加入生产产物。

## API 与会话

`src/api/connect.ts` 使用生成的服务描述创建 Connect 客户端。页面保留 ProtoJSON 模型：uint64 使用十进制字符串，bytes 使用 Base64，枚举使用符号名，时间和时长使用 protobuf JSON 格式。生成的描述负责请求解析和响应编码。服务端分页由适配层按原过滤条件继续读取，页面沿用每页 10 条的表格分页。Job 列表例外：适配层只读取一页，Jobs 页每次请求 10 条，用 `next_page_token` 翻页，更换筛选条件后回到第一页。

浏览器通过 `credentials: same-origin` 携带 P5B 的 Secure、HttpOnly、SameSite=Strict 会话 Cookie。前端不读取或存储 Cookie。每次写操作先读取 GetCurrentSession，再发送返回的 `X-CSRF-Token`。Origin 由浏览器在同源 POST 请求上设置；网关 identity.origin 配置必须与页面的 HTTPS origin 一致。公开的 OIDC/LDAP 登录接口不要求已有会话。OIDC 登录地址使用浏览器文档导航，继续执行网关的 `/auth/oidc/start` 和回调流程。

网关异常文本不直接显示。界面使用中英文错误 key 显示认证、权限、并发冲突、限流和服务不可用结果。结果审计失败时显示操作可能已经提交的提示。明文 token 只在创建后的弹窗显示；LDAP 密码提交后清空。LDAP 登录成功和登出时清除查询缓存，避免显示上一身份的数据。

UI-NOTICE（L5/A46）：共享通知在当前打开的最上层弹窗内容中显示，关闭通知不关闭弹窗。确认、表单和密钥弹窗复用同一个通知状态与显示组件，保留 Radix 的背景隐藏、指针限制和焦点约束。打开新弹窗（包括嵌套弹窗）时清除旧通知；弹窗内新产生的通知在关闭弹窗后恢复到上一层弹窗或全局位置。普通重渲染和通知更新不会清除新通知。错误使用 `alert`，成功使用 `status`；操作成功或失败时是否关闭弹窗仍由原调用链决定。jsdom 回归覆盖可访问角色、关闭交互、焦点约束、中英文拒绝及嵌套弹窗；真实 API、浏览器辅助功能树和同尺寸截图需要另行验证。

现有页面全部使用真实 API：登录、概览、主机、join token、目录、策略、服务账号、job 详情/输出/取消、审计、用户与角色、系统。目录分布请求携带所选目录的 catalog_id；版本选择同时匹配目录标识和版本。

A34 暂定行为：已登录用户可以尝试读取 job 输出，网关按 view_output 的 ABAC 策略决定权限；无权限时显示提示。输出按钮的启用条件集中在 Jobs.tsx 的 canOutput，保留 pending/offline 状态的原有限制。其他页面未发现按用户角色硬编码的按钮启用条件。

A35：最多配置一个 LDAP 身份源，可配置多个 OIDC 身份源。网关在现有 ConfigureProviders 配置校验中拒绝多个 LDAP，启动错误为 `only one LDAP identity source is supported`。登录页保留一个 LDAP 表单，不提供 LDAP 身份源选择框；每个 OIDC 身份源仍对应一个按钮。其余表单默认值沿用 P8A。

A35: At most one LDAP identity source is supported; multiple OIDC identity sources are allowed. The gateway rejects multiple LDAP entries during provider configuration. The login page has one LDAP form without an identity-source selector and one button per OIDC provider.

G61：exec 保留命令展示；steps、script、builtin 显示只读执行配置 JSON。省略 params 时显示空表。省略 redact 时显示“未指定（使用目录全局规则）”/“Not set (catalog defaults apply)”。渲染测试直接读取 examples/catalog 的 host_snapshot、nginx_access_stats、redis_get YAML 示例。测试中的 YAML 解析器只作为开发依赖。

## 本地验证

在 `web/` 执行：

```sh
CI=true pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm build
```

测试夹具只位于 `src/test/fixtures/`，通过 Vitest 替换页面的 API。真实客户端测试单独验证网络请求、Cookie 模式、CSRF、大整数、字节、枚举、分页和安全错误。页面测试覆盖中英文 key 一致、多个 OIDC 入口、单个 LDAP 表单、登出和 API 权限拒绝。页面单元测试不证明全部真实业务接口的运行结果。

网关集成测试使用本机 testcontainers PostgreSQL 和 P5B 格式的控制台会话夹具，通过真实 HTTPS 获取 SPA 首页和入口脚本，验证读接口、带 CSRF 的写接口以及不带 CSRF 的写请求被拒绝。静态资源测试覆盖 CSP、缓存、含点主机名路由和静态文件 404。浏览器视觉检查由后续 P10B 使用 Playwright 执行。

失败回归测试独立提交 `cb3be45`。基线实际结果：客户端测试预期网络调用至少一次或两次，实际均为 0；HTTPS 首页预期 200，实际 `404 page not found`。交付消息记录通过检查的 commit SHA。

目录定义的失败回归测试独立提交 `cee496c`。修复前实际抛出 `Cannot convert undefined or null to object` 和 `Cannot read properties of undefined (reading 'map')`。

登录身份切换的失败回归测试独立提交 `b8db06f`。修复前新身份查询尚未返回，页面仍显示上一身份缓存的“在线主机”数据。
