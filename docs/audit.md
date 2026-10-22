# P7 审计存储与运维接口

数据库迁移由维护账号执行 `allowops-gateway migrate`。00002 接在 P4 的 00001 后面。迁移账号需要创建表、函数和角色的权限。迁移创建 `allowops_audit_writer`（NOLOGIN）。部署时由数据库管理员把该角色授予网关的实际登录角色：

```sql
GRANT allowops_audit_writer TO your_gateway_login;
```

实际网关账号不能是超级用户、审计表所有者或继承维护角色。该角色对审计父表及所有通过维护函数创建的分区只有 INSERT、SELECT；对导出游标允许 SELECT、INSERT、UPDATE；对保留边界只允许 SELECT。游标与边界不是审计事件表。PUBLIC 不能调用分区维护函数。历史 00001 不授予既有网关表的权限，既有表的授权仍由 P4 部署负责。撤销审计迁移时保留 NOLOGIN 角色，因为其他数据库可能使用它。

`audit.Append` 是网关业务写入接口。`Payload` 只接收审计元数据，不接收参数或输出内容。调用方必须把原因及资源限制为可审计的业务字段，不能传秘密或原始请求。Append 显式使用读已提交（Read Committed）事务，取得锁 418007，再读取链尾、分配 seq、写入规范字节和摘要。链尾查询使用锁等待之后的新快照；不能继承 Repeatable Read 默认值，否则等待前的快照可能看不到前一个写入者的提交。分区删除也显式选择 Read Committed。seq 不使用 PostgreSQL sequence，所以事务回滚不留空洞。所有实例必须通过 Append 写入；拥有 INSERT 的恶意网关仍可插入伪造事件，哈希链检查会报告结构或摘要错误。数据库管理员重写整链只有与外部可信锚比较才能发现。

每个启动的网关运行检查点计时器。首次调用立即写检查点，之后每五分钟调用。锁内的时间检查防止多实例重复写入。同一事务的检查点记录前一条 seq/hash。停机期间不生成事件。事件时间为网关的 UTC 微秒时间，时钟回退时取已有链尾时间，保持时间与 seq 单调对应。实例时间需要同步。

`audit.Access` 是 P5 的认证和基于属性的访问控制（ABAC）接口。每次 RPC 都调用它，操作为 `view_audit`。空实现拒绝访问。游标绑定认证主体、过滤器、排序、冻结的最大 seq，使用 HMAC-SHA256 签名。P5 应向每个 API 实例提供同一个持久 `Config.CursorKey`。缺省密钥仅在本进程有效；重启或切换实例后旧 API 游标返回 INVALID_ARGUMENT。API 读权限不由游标替代。新增 server 路由只挂载三个 AuditService 方法，其余协议和 handler 保持已有分派。

默认载荷、分页、导出、校验限额见 protocol.md；`audit.Config` 可配置这些限额。导出冻结的是 seq 上界，并非 MVCC 快照跨请求保存。期间删除历史分区会使后续导出报告区间不可用。按时间导出会包含时间范围内的连续 seq 区间及仍可读取的前一条边界记录。过滤的 ListAuditEvents 不声明哈希链连续。

## 指定实例导出（A18）

`audit.Exporter` 将指定实例的持久目录（`Storage`）和游标身份（`Cursor`）集中在一处。`ExportStorage.Commit` 是可替换的目标写入接口。`FileStorage` 写权限 0600 的临时文件，在大小上限前轮转，完整文件 fsync 后原子发布为 `.jsonl`，再同步目录。成功返回后才能推进 PostgreSQL 游标。大小上限不能小于单条 JSON 行；超限返回错误，不丢事件。临时文件以点开头，日志采集器只读取 `.jsonl`。

只有配置 `audit.export.enabled=true` 的实例运行 Exporter，默认 false。部署时只为指定的一个网关实例开启该开关。Exporter.Run 用独占物理连接持有会话级 advisory lock 418009，覆盖整个运行期间及空闲轮询。多个实例误开启时只有持有实例锁的一个导出，其他实例记录 WARN 告警并等待；每次持续冲突只告警一次。每批次仍以 advisory lock 418008 保护文件写入和游标更新，保留维护可在批次间取得该锁。结束时使用独立的清理超时等待 PostgreSQL 解锁响应，再关闭对应物理连接。仅关闭本地连接不能保证服务器已处理 Terminate，立即续传可能遇到旧会话仍持有锁。物理连接始终关闭，避免取消或解锁失败后锁留在连接池内。文件成功发布后、游标更新前崩溃会重复写文件。接收端以 seq 去重，并核对同一 seq 的 hash；同 seq 不同 hash 应告警。游标只能证明本地持久写入，不能证明日志采集器已经送达外部系统。本地文件保留和采集重试由运维负责。

网关可配置：

```yaml
audit:
  export:
    enabled: true
  export_directory: /var/lib/allowops/audit
  cursor_name: chosen-export-stream
  max_file_bytes: 16777216
```

导出目录必须使用持久卷。开启导出时必须同时提供 export_directory 和 cursor_name；仅提供目录和游标名仍默认关闭导出。其他网关实例保持 enabled=false，它们继续追加审计和运行检查点计时器。指定实例故障或停止期间导出暂停，数据库游标保留。恢复该实例时重新挂载原持久卷并使用原 cursor_name，导出从保存的游标续传。切换指定实例前先停止原导出实例，并把原持久卷和游标名一起交给新实例。advisory lock 用于防止误配置，不作为其他实例自动接管导出的部署方式。

## 分区维护与 A19

迁移创建当月及未来两个月的 UTC 分区。维护账号每月执行下列函数，覆盖未来三个月；重复调用无副作用：

```sql
SELECT audit_create_partitions(now(), 3);
```

该函数必须由维护账号执行，网关账号不能创建分区。缺少当前分区时 Append 返回写入错误。维护账号通过 `audit.Store.Prune(ctx, RetentionOptions{})` 删除结束时间不晚于当前 UTC 月起点减 12 个月的分区。部分月份保留，所以实际最早数据可超过一年不足一个月。删除和追加、导出互斥，边界更新与 DROP TABLE 在同一事务中。已登记导出游标若还未越过待删除记录，删除失败。保留区间必须至少留下边界之后的一条记录。

删除前把最后被删除记录的 seq/hash 存入 `audit_boundary`，作为保留边界检查点。校验从下一 seq 开始；其 prev_hash 必须与边界一致。删除的历史区间报告无法验证。该数据库边界只证明内部一致性。`RetentionOptions.RequireExternalCheckpoint=true` 时必须同时传入从可信外部系统取得的 `ExternalCheckpoint`，seq/hash 必须等于删除边界。缺少或不匹配时回滚。A19 已确定该开关默认关闭（false）。默认保存数据库边界锚后即可删除；只有需要外部确认的部署才设置 true。未提供外部可信锚的校验结果返回 externally_anchored=false，表示只证明数据库内部一致性。

`externally_anchored=true` 仅表示本次校验匹配调用者提供的外部锚。系统不能判断锚来源是否可信，调用者应从独立系统获取，不能用同一次数据库查询结果充当外部信任依据。

## CLI 与本地验证

凭证只经环境变量 `ALLOWOPS_DATABASE_URL` 读取，不提供 DSN 命令参数。命令不会自动迁移。

```sh
allowops audit export --from 2026-10-01T00:00:00Z --to 2026-11-01T00:00:00Z --output audit.jsonl
allowops audit verify --from-seq 1 --to-seq 100
allowops audit verify --file audit.jsonl --from-seq 1 --to-seq 100 --expected-final-hash <64位十六进制SHA256>
```

export 不指定 output 时输出 JSON Lines 到 stdout，显式文件先完整写入再原子替换。CLI 导出是一次性时间范围查询，不推进后台导出游标。verify 输出 JSON 判定；链断裂时 exit 1，并报告首个错误 seq。默认只验证内部一致性；加入可信 expected-preceding-hash 或 expected-final-hash 后才校验外部锚。单次最多 10000 条，长区间由调用者分段并传递前一段的末尾 hash。

所有容器测试使用 internal/testpg 的本机 Docker Unix socket、回环地址和固定 PostgreSQL digest。使用 `ALLOWOPS_REQUIRE_DOCKER=1` 防止缺少 Docker 时跳过测试。`cmd/allowops/TestAuditCommands` 构建并执行实际 bin/allowops，对新建 PostgreSQL 容器做导出、数据库校验、文件外部锚校验和篡改定位冒烟。
