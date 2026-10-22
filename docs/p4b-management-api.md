# P4B 管理接口

HostService、JoinTokenService、CatalogService、SystemService 挂载在网关原有 HTTPS Connect 路由。认证、控制台 Origin/CSRF 校验、ABAC 和 P7 审计复用 P5B。主机操作按数据库授权标签逐台判定；上报标签、capabilities 和目录加载报告仅用于查询。写入先记录授权审计，再提交事务，随后记录结果审计。结果审计不可用会返回 `AUDIT_RESULT_UNAVAILABLE`，调用者须查询状态后再决定是否重试。

迁移 `00004_management.sql` 增加授权 revision、注册时间、主机上报快照、CSV 预览及目录上传暂存。旧迁移保持不变。已有记录无法恢复的注册、token 创建/吊销和目录发布时间保留为空，表示未知；迁移后的新记录自动写入实际时间。`store.DeleteHostTx` 和 `store.PublishTx` 复用原删除通知、版本检查及全局 action 名检查，允许 API 将检查和业务写入放在同一事务。主机身份保留 tombstone，历史关联不删除。

`management.preview_ttl` 默认 10 分钟；`management.upload_ttl` 默认 1 小时。CSV 仅修改已有主机，格式和 set/remove 语义见 [协议](protocol.md)。预览绑定 CSV SHA-256、调用者、不可变主机 ID 和授权 revision。心跳、证书续期和连接替代不改变授权 revision。过期、主机重注册或授权标签变化时，提交须重新预览。有效期内成功预览的重试返回第一次结果，同时重新检查权限，不覆盖后续修改。过期暂存记录在下次创建时清理。

join token 次数和有效期由 P4 原子消费。API 的列表仅返回元数据；secret 仅创建时返回。单次/多次默认 TTL 分别使用 `gateway.single_join_ttl`、`gateway.multi_join_ttl`，默认均为 24 小时。吊销按 token ID 操作，不影响已经签发的主机证书。

G35：`management.ca_pin` 使用 `sha256:<64 个十六进制字符>`，摘要对象为网关 TLS CA 证书的 DER 字节。它与主机身份 CA 无关。未配置时，仅当 TLS 证书链包含可验证自签名根 CA 时自动计算。两者均不满足时，启动日志提示 `gateway TLS CA pin unavailable; CreateJoinToken disabled; configure management.ca_pin`，CreateJoinToken 返回 FAILED_PRECONDITION，不生成 token。部署方须确保网关 TLS 链包含所指定的 CA，并让 `management.upstream` 对应 TLS 证书名称；upstream 未配置时采用 identity.origin。示例见 [gateway.yaml](../examples/gateway.yaml)。

上传绑定发布者身份、长度和 SHA-256；分块顺序及相同内容重试按协议检查。发布前网关验证 DSSE 签名、schema、有效期和 action 大小。新目录版本必须递增，当前目录的 action 名跨目录唯一。原子发布与上传结果一起提交，提交后 NOTIFY 通知各实例主机。成功 upload_id 重试返回首次发布元数据，未完成的字节不成为可见目录。

capabilities 来源于已校验的 AgentHello。目录分布来源于最后一次完整 CatalogLoadReport；部分报告不可见，离线后保留报告，失败加载计为未加载。为保持连接行为，完整报告的数据库快照写入失败不新增断线条件；此时查询只能显示最后成功保存的报告。两者均受 P4 消息上限约束，不参与授权或替代实际执行能力检查。主机在线状态基于当前连接和实例 heartbeat；实例失联阈值为心跳超时与两倍持久化刷新间隔的较大者，默认刷新间隔为 5 分钟。

G33：SystemService 按调用者权限计算主机、目录和服务账号 token 计数。P6 job 统计及对象存储尚未接入，依赖健康明确标记 UNAVAILABLE，整体状态为 DEGRADED。`running_jobs`、`failed_jobs_last_24_hours` 的默认数值不代表已测得零值，消费者必须结合 `job_statistics` 健康项判断。该限制待 P6 接入后补齐。新增稳定操作名 `view_system`，默认 admin 规则包含此权限。已有策略版本保持原数据，升级安装须通过策略试算和保存显式增加该权限。

CLI 输出默认表格，`--json` 使用 ProtoJSON。主机和 join token 命令默认采用 `allowops login` 保存的凭据；服务账号也可通过 `--token-env` 指定进程环境变量。发布命令要求显式提供服务账号 token 的环境变量，不接受 token 命令行明文。

```sh
allowops jointoken create --uses 500 --ttl 24h
allowops hosts list --selector env=test,reported.os=linux
allowops hosts label host-a --set env=test --remove temporary
allowops hosts label --selector env=test --expected-count 2 --set owner=ops
allowops catalog publish -f catalog.dsse --gateway https://gateway.example.org --ca-file tls-ca.pem --token-env ALLOWOPS_PUBLISHER_TOKEN
allowops hosts delete host-a
```

标签和删除命令先查询当前 ID/revision，再由服务端事务确认。selector 标签命令必须给出精确 expected-count。读取和修改是独立权限，调用者须具备目标的 view_hosts 和 manage_hosts。G36 确认管理主机隐含查看主机，默认 operator 规则增加 view_hosts；已有策略版本通过试算和保存更新。其余默认角色的现有职责读取权限无已确认缺口。

空 cases 的默认策略试算保留每个主体的 12 项全局控制台检查。view_hosts、manage_hosts 各按现有主机展开；view_catalog 按当前有效目录 action 展开；view_jobs、view_output 各按 action 与 (空主机 + 现有主机) 组合展开，空主机对应没有任务的 job；execute_action 按 action 与主机组合展开。设主体数为 S、有效 action 数为 A、主机数为 H，当前总求值数为 `S × (12 + 2H + 3A + 3AH)`。每增加一项输入都先检查同一 `MaxTestEvaluations`，不预先构造笛卡尔积、不抽样；超限时 TestPolicy 和 SavePolicy 复核均返回 RESOURCE_EXHAUSTED。展开增加覆盖数量，已有部署可能更早到达上限。默认试算按当前有效目录中的 action 展开；已移出当前目录或 risk 已变化的历史 job，其 action_definition 不在默认试算内。显式 cases 的语义见下文 view_* 用例的说明。

默认试算的主机只来自 `certificate_status='active'` 的主机。已删除主机上的历史 job 仍可通过 view_jobs、view_output 按已删除主机的授权标签求值，这些输入不在默认试算内，规则的 host_labels 只匹配已删除主机时，查看权限的变化不计入 changed_count。不展开的原因：已删除主机只增不减，展开会使求值数随删除次数无上限增长并终将超出 `MaxTestEvaluations`，且需要为每个已删除主机扫描 tasks 表判断是否被引用。显式 cases 也只从 active 主机中选择目标。

view_catalog、view_jobs、view_output 与 execute_action 一样，对带 action 的请求应用规则的 actions/risks 筛选（actions 与 risks 取并集，actions 含 `*` 匹配所有 action，两者均为空不筛选）。真实请求总是传入 action：目录读取按目录中的 action 名和 risk 求值，job 查看和输出读取使用 job 的 action_definition；没有任务的 job 以 (action, 空主机) 求值。不带 action 的全局检查（控制台入口判断、目录分发、没有可见 action 时的 ListActions 兜底判断）对 allow 规则不应用 actions/risks 筛选。对 deny 规则，用 actions 或 risks 限定范围的规则不匹配无 action 的全局查看检查，避免一条限定范围的 deny 规则拒绝整个列表；actions 含 `*` 的 deny 规则匹配全局检查，等同全拒绝；没有 actions 和 risks 的 deny 规则同样匹配全局检查。其他操作仍忽略 actions/risks。显式 cases 中的 view_* 用例带 action 时使用该 action 求值，action 不在当前有效目录中返回 invalid_argument；不带 action 时按全局检查求值。execute_action 用例始终要求 action。host_labels 按现有规则生效。

本地测试使用固定镜像 digest 的 PostgreSQL testcontainers，不读取外部数据库地址。`TestP4BCLISmokeAndDeletion` 构建实际 CLI，使用 examples/catalog 与 publisher 服务账号发布，验证跨实例删除、旧证书拒绝、完整报告持久化和 P7 哈希链。
