# 策略 {#policies}

网关内嵌 Open Policy Agent（OPA），并使用固定的 Rego 程序。运维人员提供结构化的规则数据，不提供任意 Rego 代码。拒绝优先于允许。没有规则匹配或评估出错时，结果为拒绝。执行动作还要求每台目标主机至少有一个由网关管理的授权标签。

规则使用以下条件：经过认证的 role/team/owner 属性、操作、动作名称或风险、主机授权标签，以及可选的时间窗口和来源网络。上报标签永远不作为策略属性。同一条件内的列表按 OR 匹配。主体、主机、时间和网络等不同条件按 AND 组合。`actions` 和 `risks` 是二选一的关系：同时提供时，满足其中任意一个即可匹配。如果要限定为一个确切的动作列表，不要在同一条规则中再添加范围更大的 `risks: [read]` 允许条件。

## 默认设置 {#defaults}

| 角色 | 初始权限 |
|---|---|
| `admin` | 管理和读取权限，以及在带标签主机上执行所有动作的权限，包括危险动作。 |
| `operator` | 主机管理和读取、join token、job 元数据和系统状态。 |
| `auditor` | 审计、job 元数据和输出。 |
| `viewer` | 主机、目录和 job 的元数据。 |
| `publisher` | 发布目录。 |

只有 admin 默认拥有执行权限。其他角色需要明确的动作规则。配置项 `bootstrap_admins` 保留修改策略的权限，作为恢复手段。它不是不受限制的执行身份。

## 规则结构 {#rule-shape}

策略 YAML 包含一个 `rules` 列表。规则使用 `name`、`effect: allow|deny`、必填的 `roles` 和 `operations`，以及可选的 `teams`、`owners`、`actions`、`risks`、`host_labels`、`hours` 和 `source_cidrs`。`roles: ['*']` 匹配任意角色。动作的通配写法只能是确切名称或 `'*'`，不是通用的 glob 模式。

```yaml
rules:
  - name: readers-on-test
    effect: allow
    roles: [ops-reader]
    operations: [execute_action]
    risks: [read]
    host_labels:
      env: test
      team: ops
```

仅有这段片段不能替代一套安装所需的管理规则。[示例策略](https://github.com/liubing0806/allowops/blob/main/examples/policy/read-only.yaml)包含管理员恢复权限和一条单独的输出规则。`hours` 使用 `from`、`to`、`timezone`。它表示同一天内的左闭右开区间，要求 `0 <= from < to <= 24`。跨夜的时间窗口需要使用两条规则。请显式提供 IANA 时区。来源网络规则使用 CIDR 表示法。请自行选择网络，不要把部署环境的地址复制到公开的策略仓库中。

操作名称包括 `execute_action`、`modify_policy`、`manage_service_accounts`、`manage_hosts`、`create_join_token`、`manage_user_roles`、`publish_catalog`、`view_hosts`、`view_catalog`、`view_jobs`、`view_output`、`view_audit` 和 `view_system`。

## 评审和应用 {#review-and-apply}

```sh
allowops policy get > rules.yaml
# Edit rules.yaml and retain the required management rules.
allowops policy test -f rules.yaml
allowops policy apply -f rules.yaml --reason 'restrict reader access to test hosts'
```

`apply` 替换整个策略，而不只是替换文件中的规则。它读取当前版本，模拟候选策略，显示变更，并在保存时进行乐观并发检查。请先评审单独执行的 `test` 结果。`apply` 不会提示交互式确认。快照、版本或权限发生变化时，需要重新模拟。如果策略导致没有任何主体能够修改策略，该策略会被拒绝。控制台中的历史回滚同样会先模拟，然后创建一个新版本。回滚不会降低策略版本号。

读取 job 汇总和读取其输出是两项独立的权限。服务账号只能读取或取消自己的 job。用户取消 job 时，会重新检查其对每台原始目标主机的执行权限。选择器计数是一项安全检查，不授予权限。请求格式见 [MCP](mcp.md)。
