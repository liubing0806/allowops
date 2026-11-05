# 控制台改版：设计交接

状态：设计原型已完成（2026-11-04），待开发。本文给负责实现的开发者（包括 Claude Code）使用：说明改版目标、设计规范、每个页面要做什么、现有 API 能覆盖哪些、需要后端补什么，以及建议的拆分顺序。

## 1. 目标

现有控制台功能完整，但视觉和交互是传统后台表单式。改版目标：

- **现代、安静的界面**：参考 [t3code](https://github.com/pingdotgg/t3code)（`apps/web/src/index.css`）和 [magpie](https://github.com/yetone/magpie)（`internal/gui/assets/app.css`）的做法——中性灰底、侧栏与页面同色、细分隔线、8px 圆角、单一靛蓝强调色、等宽字体展示标识符、状态点表达状态、完整暗色主题。
- **以 agent 为中心**：运维人员最关心的是"agent 能在哪台主机上做什么、做了什么、被拒绝了什么"。每个页面都要把这个答案摆到最前面，而不是只罗列字段。
- **不改变安全语义**：未设授权标签默认拒绝、拒绝优先、预览后再应用、token 只显示一次、主机输出不可信——这些行为和提示一个都不能丢。

## 2. 原型在哪里

- `prototypes/` 目录下是 11 个原型文件（10 个页面 + 1 个共用侧栏），格式是 Claude 设计画布的 `.dc.html`。它们依赖画布运行时，**不能直接用浏览器打开**，也**不能直接搬进 `web/`**。阅读方式：看 `<x-dc>` 里的结构和行内样式，看底部 `class Component` 里的 `renderVals()` 了解交互和派生逻辑。
- 可交互版本在仓库所有者的 Claude 设计画布中（私有链接，需要所有者分享）。

| 原型文件 | 页面 | 对应实现 |
|---|---|---|
| `Sidebar.dc.html` | 共用侧栏 | `web/src/App.tsx` 中的 Layout / 导航 |
| `Overview.dc.html` | 概览 | `web/src/pages/Overview.tsx` |
| `Main.dc.html` | 主机 | `web/src/pages/Hosts.tsx`（以及 `HostDetail`） |
| `Jobs.dc.html` | Job | `web/src/pages/Jobs.tsx`（以及 `JobDetail`） |
| `Catalog.dc.html` | 目录 | `web/src/pages/Catalog.tsx` |
| `Policies.dc.html` | 策略 | `web/src/pages/Policies.tsx` |
| `ServiceAccounts.dc.html` | 服务账号 | `web/src/pages/ServiceAccounts.tsx` |
| `JoinTokens.dc.html` | Join token | `web/src/pages/JoinTokens.tsx` |
| `Audit.dc.html` | 审计 | `web/src/pages/Audit.tsx` |
| `Users.dc.html` | 用户与角色 | `web/src/pages/Users.tsx` |
| `System.dc.html` | 系统 | `web/src/pages/System.tsx` |

原型中的主机、job、用户、token、调用次数、服务限制数值等都是**示例数据**，实现时一律来自 API。

## 3. 设计规范

### 3.1 颜色

在 `web/src/index.css` 现有 shadcn 变量上改值，不新增平行体系。原型使用的取值：

| 用途 | 浅色 | 暗色 | 对应变量 |
|---|---|---|---|
| 页面底色 | `#FAFAFA` | `#0B0B0D` | `--background` |
| 侧栏 | `#F4F4F5` | `#0F0F12` | `--sidebar` |
| 卡片 / 表格 | `#FFFFFF` | `#141417` | `--card` |
| 浮层（半透明） | `rgba(255,255,255,.97)` | `rgba(24,24,28,.97)` | `--popover` |
| 主要分隔线 | `#E4E4E7` | `#27272C` | `--border` |
| 次要分隔线（行间） | `#F0F0F2` | `#1D1D21` | 新增 `--border-subtle` |
| 正文 | `#18181B` | `#EDEDF0` | `--foreground` |
| 次要文字 | `#52525B` | `#B4B4BC` | 新增 `--foreground-2` |
| 弱化文字 | `#6B6B74` | `#8E8E98` | `--muted-foreground` |
| 胶囊 / 分段控件轨道 | `#F1F1F3` | `#1F1F24` | `--muted` |
| 强调色 | `#4F46E5` | `#A5B4FC` | `--primary`、`--ring` |
| 强调浅底 | `#EEEDFD` | `#25264A` | `--accent` |
| 选中行底 | `#F5F5FF` | `#17182A` | 新增 `--selection` |

状态色（新增语义变量 `--success` / `--warning` / `--info` / `--destructive` 及各自的 `-soft` 底色）：

| 语义 | 用在 | 浅色文字 / 底 | 暗色文字 / 底 |
|---|---|---|---|
| success | 在线、允许、成功、有效 | `#16A34A` / `#EAF7EE` | `#4ADE80` / `#132A1C` |
| warning | 无授权标签、即将到期、部分失败、版本落后 | `#B45309` / `#FEF3E2`（点用 `#F59E0B`） | `#FBBF24` / `#33280F` |
| info | 运行中 | `#2563EB`（点用 `#3B82F6`） | `#60A5FA` |
| destructive | 拒绝、失败、删除、吊销 | `#DC2626` / `#FDECEC` | `#F87171` / `#3A1A1C` |
| neutral | 离线、已取消、已过期 | `#A1A1AA`（点） | 同 |

所有文字与底色组合须满足 4.5:1；上表的文字色已按此选取，替换时请复核。

### 3.2 字体

- 界面：Geist；中文回退 `-apple-system, "PingFang SC", "Noto Sans SC", system-ui`。
- 标识符（主机名、标签、action、job ID、token ID、哈希、命令、版本号）：Geist Mono。
- **自托管字体**（如 `@fontsource-variable/geist`、`@fontsource-variable/geist-mono`），不要像原型那样从 Google Fonts 加载——网关常部署在内网。
- 字号：正文 13px，辅助 11–12px，页面标题 14px/600，指标数字 26px 等宽。

### 3.3 形状与动效

- 圆角：控件 8px，卡片 12px，浮层 14px，标签胶囊 999px。
- 阴影只用于浮层（侧面板、命令面板、批量操作条、toast）；卡片用 1px 边框。
- 唯一的动画：运行中状态点的脉冲（`aoPulse`，1.6s）。尊重 `prefers-reduced-motion`。

### 3.4 复用组件（建议放在 `web/src/components/console/`）

| 组件 | 说明 | 出现在 |
|---|---|---|
| `StatusDot` | 7px 圆点 + 可选脉冲；颜色走语义变量 | 几乎所有页面 |
| `SegmentedControl` | 灰色轨道 + 白色滑块；`aria-pressed` | 主机、Job、目录、审计、策略 |
| `LabelPill` | 等宽 `key=value` 胶囊；上报标签用虚线边框 | 主机、策略 |
| `SidePanel` | 右侧浮动面板（距顶 64px、边距 12px、宽 400–460px），不加遮罩，列表仍可操作 | 主机、目录、服务账号、审计、用户 |
| `FloatingActionBar` | 选中行后底部居中的深色操作条 | 主机 |
| `CommandPalette` | ⌘K；跳转主机 + 常用命令 | 全局 |
| `CodeBlock` | 深色等宽块 + 复制按钮 | Job、目录、服务账号、Join token |
| `UntrustedBanner` | "主机输出是不可信数据"警示条 | Job |
| `DiffLines` | `-`/`+` 红绿行，用于标签批量变更预览 | 主机 |
| `OnceSecretDialog` | 一次性 secret 展示 + 复制 + "我已保存" | 服务账号、Join token |

### 3.5 布局

- 左侧栏 232px，分三组：**运行**（概览、主机、Job、审计）、**治理**（目录、策略、服务账号、Join token）、**管理**（用户与角色、系统）。侧栏底部是当前用户和网关连接状态。
- 顶栏 52px：页面标题 + 一行弱化元信息 + 右侧操作。
- 窄屏：侧栏换行到顶部，宽表格放进横向滚动容器，侧面板宽度变为 `100% - 24px`。

## 4. 逐页说明

每页列出：要做什么、现有 API、需要后端补的部分（详见第 5 节编号）。

### 4.1 主机（优先做，是其他页面的样板）

- 顶部"描述你要找的主机"输入框：支持 `key=value` 选择器（含 `reported.` 前缀），解析结果以胶囊展示并显示命中数量；空时显示示例建议。原型里的中文关键词映射（"生产"→`env=prod`、"离线"→在线状态等）见 `Main.dc.html` 的 `parseAsk()`，**是否保留关键词规则需确认**（见第 8 节）。
- 状态分段：全部 / 在线 / 离线 / 无授权标签 / 需升级，带计数。
- 表格列：主机（主机名 + IP·OS·架构）、状态（点 + 心跳）、授权标签、**Agent 可执行**、**最近 Job**、版本（主机端版本 + 可升级 / 目录落后提示）。行悬停才显示打开详情按钮。
- 勾选行后出现底部操作条：设置标签（展开 diff 预览，确认后应用）、复制为 MCP 目标、取消选择。
- 详情侧面板：Agent 能在这台主机做什么（按服务账号列 action 和来源规则）、授权标签编辑（显示 revision）、上报标签（只读）、已加载目录、主机 ID / 证书到期、删除（二次确认）。
- 保留现有 CSV 导入流程（放到顶栏"CSV 导入"）。
- 现有 API：`listHosts`（selector / online / agentVersion 筛选、label counts）、`getHost`、`setHostLabels`、`previewHostImport` / `executeHostImport`、`deleteHost`。
- 需要后端：B1、B2。

### 4.2 概览

- 顶部一句话总结（过去 24 小时调用 / 允许 / 拒绝 / 运行中 job / 需注意的主机），由前端用数字拼接，**不是模型生成**。
- 4 个指标卡（在线主机、运行中 job、24h 失败 job、被拒绝的调用），可点击跳转。
- 需要处理：目录 14 天内到期、token 7 天内到期、无授权标签主机、主机端低于网关、网关有新版本；每条有跳转和"稍后"。
- 最近 job、Agent 活动（审计流的人话版本）。
- 现有 API：`listHosts`、`listJobs`、`listCatalogs`、`listServiceAccountTokens`、`getSystemStatus`、`getAgentVersionDistribution`、`listAuditEvents`。
- 需要后端：B3（拒绝计数、调用计数）。

### 4.3 Job

- 左列表右详情。列表项：状态点、action、主体·原因、按 task 状态分段的进度条、时间。
- 详情：状态徽标、取消 job（运行中才显示；确认文案沿用 `job.cancelHint`）、元信息（主体、原因、目录版本、策略版本、时间）、**Agent 发起的 MCP 调用**代码块、主机执行结果表、输出查看器（stdout/stderr 切换、组合 action 的 step 切换、不可信警示、分页读取）。
- 被拒绝的 job 显示匹配的拒绝规则。
- 现有 API：`listJobs`、`getJob`、`listTasks`、`getJobOutput`（含 `step_index`）、`cancelJob`。
- 需要后端：B4（MCP 调用代码块需要 targets / expected_count / params）。

### 4.4 目录

- 当前目录卡：ID、版本、签名状态、格式版本、来源提交、信封大小、过期倒计时进度条（14 天内转为警告色）。
- 主机目录版本分布：分段条 + 图例 + 主机示例。
- Action 列表：风险分段（只读 / 写入 / 危险）、搜索；点击打开详情侧面板：参数（类型、约束、默认值）、固定命令数组或内置执行器、运行用户、超时、输出上限、脱敏规则、输出过滤、幂等、谁能调用。
- 版本历史视图。顶栏"复制发布命令"（`allowops catalog publish -f catalog.dsse.json --gateway …`）。
- 现有 API：`listCatalogs`、`listActions`、`getAction`、`getCatalogDistribution`。
- 需要后端：B5（"谁能调用"）。

### 4.5 策略

- 左侧规则卡片列表（序号、允许 / 拒绝、名称、角色 / 操作 / action / 风险 / 标签 / 时段胶囊；已修改的规则显示橙点），底部添加规则。
- 右侧规则编辑表单 + 判定分段 + 删除。
- **试算卡片**：主体、操作、action、目标选择器 → 每台主机"原判定 → 新判定 + 匹配规则"，判定改变的行着色，并给出汇总句（"N 台主机判定改变：x 台变为允许，y 台变为拒绝"）。显示"保留策略管理员：是 / 否"。
- 保存条件：有修改 + 试算未过期 + 填写变更原因 + 保留管理员。修改后试算立即标记过期（沿用 `error.stalePolicy` 文案）。
- 版本历史浮层：每个历史版本可"试算回滚到 vN"，把历史规则载入草稿走同样的试算 / 保存流程。
- 判定语义已与 `internal/gateway/authz/policy.rego` 对齐：任一拒绝规则命中即拒绝；无规则命中即拒绝；`execute_action` 对无授权标签主机直接拒绝。**前端不要自行实现判定**，一律调用 `testPolicy` / `getPolicyTestChanges`。
- 现有 API：`getPolicy`、`listPolicyHistory`、`testPolicy`、`getPolicyTestChanges`、`savePolicy`、`rollbackPolicy`。
- 需要后端：无。

### 4.6 服务账号

- 卡片网格，每个 agent 一张：名称、描述、角色、24h 调用、有效 token 数（含即将到期提示）、最后使用、负责人 / 团队；正在调用时状态点脉冲。
- 顶部提示：读写分离账号、token 走 `ALLOWOPS_MCP_TOKEN`。
- 详情侧面板：负责人、角色、团队、创建时间、**这个 agent 能做什么**（一句话 + 去策略试算的链接）、token 列表（状态、到期、最后使用、两次点击吊销）、创建 token（描述 + 1–365 天）、Claude Code `.mcp.json` 示例（与 README 一致）+ 复制。
- 创建 token 后弹出一次性 secret 对话框，附 `export ALLOWOPS_MCP_TOKEN=…`。
- 现有 API：`listServiceAccounts`、`createServiceAccount`、`listServiceAccountTokens`、`createServiceAccountToken`、`revokeServiceAccountToken`。
- 需要后端：B3（24h 调用数）、B5（"能做什么"摘要，可与 B1 共用）。

### 4.7 Join token

- 创建区：最大使用次数、有效期（小时）、三个预设（单台 1h / 一批 24h / 扩容 72h）。
- 创建后在同一卡片展开三步：① 以 0600 保存 secret 到文件；② `allowops-agent join --upstream … --token-file … --ca-pin …`；③ 提醒新主机默认拒绝、去主机页设置标签。每步有复制按钮；secret 只显示一次。
- 列表：使用次数进度条、创建 / 到期（含相对时间）、状态（有效 / 即将到期 / 已用尽 / 已过期 / 已吊销）、两次点击吊销（沿用 `join.revokeHint`）。
- 现有 API：`listJoinTokens`、`createJoinToken`、`revokeJoinToken`。
- 需要后端：无。

### 4.8 审计

- 筛选：判定分段（全部 / 允许 / 拒绝）、主体、主机、action、时间范围。
- 表格：序列号、时间、主体、操作、主机、action、判定、匹配规则、哈希缩写；点击行打开详情。
- 详情侧面板：一句话描述事件、匹配规则、策略版本、job / task、输出引用，以及前一条 / 本条 / 后一条的哈希链可视化。
- 顶栏"校验哈希链"展开序列号范围输入，结果沿用 `audit.verified` / `audit.invalid` 和 `audit.internalOnly` 文案。
- 现有 API：`listAuditEvents`、`verifyAudit`。
- 需要后端：B6（按判定筛选）。

### 4.9 用户与角色

- 角色卡片（内置角色说明 + 人数）。
- 用户表：头像、姓名、用户名·邮箱、身份源、组、映射角色、手工角色、有效角色。点击打开"分配角色"侧面板：来自组映射的角色勾选但锁定，底部实时显示并集预览。
- 组到角色映射编辑：身份源、组名、角色，增删行，有未保存修改提示。
- 现有 API：`listUsers`、`listRoles`、`setUserRoles`、`getRoleMappings`、`saveRoleMappings`。
- 需要后端：无。

### 4.10 系统

- 网关版本卡：当前版本、新版本 + 发布说明链接、更新检查状态、实例版本不一致警告。
- 网关实例卡：状态、版本、连接主机数、启动时间、最后心跳、依赖健康（PostgreSQL、对象存储，异常时显示原因）、排空说明。
- 主机端版本分布条 + "N 台低于网关" + 跳转主机页"需升级"筛选。
- 服务限制（来自 `GetSystemStatus` 的 limits 字段）。
- 顶栏"刷新健康状态"。
- 现有 API：`getSystemStatus`、`listGatewayInstances`、`getAgentVersionDistribution`。
- 需要后端：无。

### 4.11 全局

- ⌘K 命令面板：按主机名跳转主机详情；命令包括"查看无授权标签的主机""查看需要升级的主机""切换明暗主题"。
- 主题：沿用 `web/src/lib/theme-store.ts`（light / dark / system），顶栏提供切换。
- i18n：所有新增文案进 `web/src/locales/zh-CN.json` 和 `en.json`，沿用现有 key 风格；能复用的现有 key 不要新建。
- 登录页（`Login.tsx`）未出原型，按同一规范调整即可。

## 5. 后端需求清单

| 编号 | 需求 | 用在 | 建议 |
|---|---|---|---|
| B1 | 每台主机"哪些服务账号能执行哪些 action，来自哪条规则" | 主机列表"Agent 可执行"列、主机详情 | 新增按主机批量评估的只读接口（基于现有 `authz.batch`），或在 `GetHost` 返回；列表页可只返回 action 数和账号列表 |
| B2 | 每台主机最近一个 task（action、主体、状态、时间） | 主机列表"最近 Job"列 | `Host` 增加 `last_task` 摘要，或新增按主机批量查询最近 task 的接口 |
| B3 | 时间窗口内的调用 / 允许 / 拒绝计数，可按主体分组 | 概览指标、服务账号卡片 | 基于审计表的聚合接口（如 `GetAuditStats(time, group_by=subject)`） |
| B4 | job 的目标描述（selector 或主机列表）、`expected_count`、参数 | Job 详情"Agent 发起的 MCP 调用" | `Job` 增加这些字段；参数需考虑脱敏后再返回，且受 `view_output` 或单独权限约束 |
| B5 | 某个 action / 服务账号的"谁能调用 / 能做什么"摘要 | 目录 action 详情、服务账号详情 | 可由前端调用 `testPolicy` 组合得出；若性能不够再加专用接口 |
| B6 | 审计按判定（allow / deny）筛选 | 审计页、概览 Agent 活动 | `AuditQuery` 增加 `decision` 字段 |

B1–B6 都不影响第一阶段（纯前端改版），没有这些数据时对应列 / 卡片先隐藏或显示"—"。

## 6. 建议拆分（每项一个 PR）

1. **设计基础**：`index.css` 颜色 / 暗色变量、自托管字体、第 3.4 节组件、侧栏和顶栏布局、⌘K 命令面板。
2. **主机页**（不含 B1、B2 的列）——作为后续页面的样板。
3. **Job 页**（不含 B4 的 MCP 调用块）。
4. **策略页**（试算对比、保存门槛、回滚）。
5. **目录、服务账号、Join token**。
6. **审计、用户与角色、系统、概览**（概览先用现有 API 能算的数字）。
7. **后端 B1–B6**，每项单独 PR，完成后补上对应前端。

## 7. 验收要求

- `make build` 与 `make test lint` 通过；`web/src/pages/*.test.tsx` 现有测试全部保持通过，测试里依赖的文案和行为变化要同步修改测试并说明原因。
- 安全相关行为不变：无授权标签默认拒绝提示、批量标签先预览后应用并校验 revision、策略保存前必须试算、token / join secret 只显示一次、主机输出不可信警示、删除 / 吊销 / 取消 job 二次确认。
- 键盘可达：所有可点元素是 `button` / `a` / `input`；图标按钮有 `aria-label`；侧面板和命令面板支持 Esc 关闭并归还焦点。
- 浅色、暗色、窄屏（390px）三种情况各自检查一遍。
- 不引入外部 CDN 资源。

## 8. 待确认

1. 主机页的自然语言输入：保留中文关键词规则映射，还是只支持选择器语法？（原型只做了关键词规则，没有调用模型。）
2. B4 中参数是否可以在控制台展示，展示前用哪套脱敏规则。
3. 概览"一句话总结"的措辞是否需要英文版对应句式（i18n 插值）。
4. 服务账号卡片的"正在调用"状态是否值得实时推送，还是轮询即可。

## 9. 给 Claude Code 的起始提示

> 阅读 `docs/console-redesign/README.md` 和 `docs/console-redesign/prototypes/` 下的原型文件。按第 6 节第 1 步实现设计基础：更新 `web/src/index.css` 的浅色 / 暗色变量（第 3.1 节）、自托管 Geist / Geist Mono、在 `web/src/components/console/` 下实现第 3.4 节的组件、按第 3.5 节改造侧栏和顶栏、加入 ⌘K 命令面板。不要改业务逻辑和 API。完成后运行 `make test lint`，修复失败，并说明哪些现有测试因文案或结构变化做了调整。
