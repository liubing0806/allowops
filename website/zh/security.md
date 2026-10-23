# 安全 {#security}

allowops 把执行范围限制在签名动作和带类型的输入内。签名目录是一个权限边界：在主机上信任目录的密钥之前，须评审命令、脚本字节、允许的根路径、URL 前缀、运行身份和输出。CI 发布流水线须按照具备 root 能力的运维人员同等级别保护。

使用最小权限的服务账号和网关管理的授权标签。默认管理员可以在带标签的主机上执行所有签名动作，包括危险动作。没有标签的主机拒绝执行。读身份和写身份须分开，并评审范围宽泛的动作规则或风险规则。

## 部署边界 {#deployment-boundaries}

经过四层负载均衡时须保留 TLS/ALPN。主机注册时固定网关 TLS CA，双向 TLS 使用独立的主机 CA。使用安全的 OIDC/LDAP 配置和经过验证的证书。私钥和 token 须通过凭据管理器存储，不能放在目录或公开文档中。

agent 以专用的低权限用户运行，不加入额外的组。root 辅助程序只接受其固定的 stdin 协议。不要放宽 sudoers 配置，也不要添加交互式 shell 动作。解释器例外和签名脚本须评审实际程序以及所有由调用方控制的输入。

## 防护范围的限制 {#limits-of-protection}

被攻破的网关可以在各主机上调用所有已签名的动作并读取输出。被攻破的签名密钥可以授权任意命令，包括 root 操作。主机本地没有风险上限来进一步限制被攻破的网关。主机 root 被攻破后，该主机的身份和输出不再可信。

脱敏在输出离开主机前进行，但可能遗漏密钥，也可能删除无害内容。返回给模型的输出对模型提供方可见。`output_trust: untrusted` 和纯文本渲染不能消除提示注入。不要把主机输出当作指令。断开连接或取消动作不能撤销其已产生的副作用。

恶意的数据库或对象存储管理员，以及在安装前已被攻破的主机，不在防护范围内。审计哈希链需要独立的检查点，才能检测数据库管理员对其进行的完整重写。

[仓库安全策略](https://github.com/liubing0806/allowops/blob/main/SECURITY.md)
列出了全部威胁 T1–T15 及其控制措施。这些控制措施是一个模型，不代表每个部署都经过了独立验证。[运维](operations.md)介绍备份、升级和轮换。

## 漏洞报告 {#vulnerability-reports}

使用仓库 GitHub 的 **Security → Advisories → Report a vulnerability** 私密报告途径。如果该途径不可用，在 issue 中请求私密联系方式，不要公开漏洞细节。见[GitHub 私密报告说明](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately)。报告中须提供版本或 commit、影响，以及使用合成数据的复现步骤。
