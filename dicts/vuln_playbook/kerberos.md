---
type: Kerberos 攻击
aliases: Kerberos 攻击, kerberos, kerberoasting, AS-REP Roasting, 黄金票据, 白银票据, golden ticket, 票据攻击
stage: post_exploitation
entry_points: [Kerberos, SPN, 域认证, 票据]
cwe_ids: [CWE-287, CWE-522, CWE-294]
owasp_id: PTES-Post-Exploitation
severity_base: critical
chains_with: [ad_security, internal_pivot, windows_postexploit]
tech_stack: [internal]
---

# Kerberos 攻击

> 思路参考，非清单。前提：授权红队、内网已有域用户立足点（转 `internal_pivot`/`ad_security`）。Kerberos 是域认证核心，攻击它能离线破服务账号口令、伪造票据横向到任意主机。经 foothold_exec/agent_exec 在内网侧执行。

## 先判这是不是 Kerberos 面
域环境（88 端口 KDC 可达）、有域用户凭证或能匿名查目录。SPN（服务主体名）、预认证配置、krbtgt 是关键要素。

## 瞭望塔工具怎么打（独有价值）
- **Kerberoasting**：`foothold_exec`/`agent_exec` 用 Rubeus/impacket GetUserSPNs 请求有 SPN 的服务账号 TGS 票据（任意域用户即可请求）→ 导出票据 → `run_script` 沙盒离线 hashcat 爆破（服务账号口令弱则破出明文）。破出的常是高权服务账号。
- **AS-REP Roasting**：找未开启预认证的用户（`DONT_REQUIRE_PREAUTH`），无需凭证即可请求其 AS-REP → 离线爆破。ldapsearch/Rubeus 枚举这类账号。
- **票据伪造（拿到 krbtgt 后）**：Golden Ticket（krbtgt hash 伪造任意用户 TGT，域内通行）、Silver Ticket（服务账号 hash 伪造特定服务 TGS）。前提是已通过 DCSync 等拿到 krbtgt/服务 hash（转 `ad_security`）。
- **委派滥用**：无约束/约束/基于资源的委派配置错误可提权，BloodHound 标出后针对性打。
- **票据使用**：破出/伪造的票据经 PtT 横向，`internal_recon` 找目标、`agent_exec` 执行。


## 验证与反证
区分认证配置风险、取得票据和实际越权访问；票据可请求本身可能是正常协议行为。记录主体、SPN、时效、域与业务预期，不因无法访问某服务就推断密钥或票据一定无效。

## 修复与复测
加强服务账号管理、最小权限和认证配置，按事件范围轮换相关凭据；复测正常认证与已撤销权限，保留认证日志用于关联分析。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
