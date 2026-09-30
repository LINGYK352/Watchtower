---
type: 域渗透
aliases: 域渗透, ad security, active directory, 活动目录, 域控, domain admin, 内网域, LDAP 攻击
stage: post_exploitation
entry_points: [域账户, LDAP, 目录权限, 域信任]
cwe_ids: [CWE-284, CWE-269, CWE-522]
owasp_id: PTES-Post-Exploitation
severity_base: critical
chains_with: [internal_pivot, kerberos, windows_postexploit]
tech_stack: [internal]
---

# 域渗透（Active Directory）

> 思路参考，非清单。前提：授权红队场景、已在内网拿到立足点（转 `read_vuln_playbook internal_pivot` 拿 foothold）。核心目标：从一个域用户/主机，摸清域结构、找提权路径、最终拿域控。瞭望塔里经 foothold_exec / probe / agent 在内网侧执行。

## 先判这是不是域环境
拿到的主机加了域（`whoami /fqdn`、`nltest /dsgetdc`）、能连到 LDAP(389/636)/Kerberos(88)/SMB(445)、机器名带域后缀。有域用户凭证或机器账号。

## 瞭望塔工具怎么打（独有价值）
- **域信息评估**：先检查已授权采集数据的来源、范围与时间，再分析用户/组/ACL/信任关系。当前 `agent_deploy_tool` 没有 BloodHound 采集器注册项，缺少采集前置条件时报告依赖缺口。
- **攻击路径分析**：BloodHound 数据找最短提权路径——ACL 滥用（GenericAll/WriteDacl）、DCSync 权限、无约束委派、影子管理员。
- **Kerberos 攻击**：Kerberoasting / AS-REP Roasting 取可破解票据（转 `read_vuln_playbook kerberos`）。
- **横向移动**：拿到凭证/hash 后 PtH/PtT 横向（`internal_recon` 找目标、`agent_exec` 执行），逐跳向域控。
- **拿域控**：DCSync 导 krbtgt/域管 hash、或直接登域控。这是域渗透终点。
- **内网发现**：`internal_recon`/`internal_portscan` 摸内网存活与服务面。


## 验证与反证
目录图与 ACL 配置描述潜在路径，不证明每条边均可利用；采集范围、时间、继承权限和信任方向影响结论。BloodHound 采集器不在当前 agent_deploy_tool 注册表中，不能宣称一键部署已支持。

## 修复与复测
修正高风险组成员、对象 ACL、委派和信任配置；复测实际权限边界与正常域业务，按变更清单恢复测试对象并保留域审计记录。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
