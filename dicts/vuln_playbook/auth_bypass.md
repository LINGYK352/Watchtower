---
type: 认证绕过
aliases: 认证绕过, auth bypass, 登录绕过, 会话, session, 密码重置绕过, 验证码绕过, 弱口令, 暴力破解, brute force, 用户枚举
stage: validation
entry_points: [登录, 注册, 密码重置, MFA, 验证码]
cwe_ids: [CWE-287, CWE-306, CWE-384]
owasp_id: A07:2021
severity_base: high
chains_with: [idor, unauthorized, jwt]
tech_stack: [web]
---

# 认证与会话

> 思路参考,非清单。JWT alg:none/弱密钥、会话固定、参数篡改等技法你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。分析主线:身份怎么被验证/绑定/传递/刷新/注销/恢复——找可跳过/伪造/重放/复用/篡改/降级的状态边界。

## 先判这是不是认证面
有登录/注册/找回/MFA/第三方登录/会话刷新/角色切换。重点对比这些流程**前后**的身份/会话/令牌状态差异。

## 瞭望塔工具怎么打(独有价值)
- **拿会话+JWT 结构**:`browser_login` 的实际返回包括 cookies 与 apis；不保证 localStorage 或 jwt_analysis 字段。仅对真实取得的会话材料分析身份与角色，缺少字段不能推断漏洞。
- **收验证码**:`tempmail_create`/`tempmail_check` 收注册/密码重置的邮箱验证码,支撑"任意用户注册/重置"验证。
- **换身份重放**:http_request 带不同 cookie/token 重放对比。
- **锁定与验证码边界**：围绕测试账户、约定阈值与服务端状态验证保护是否生效；受限或阻塞时记录原因，不用换出口或脚本绕过现有工具门控。
- **串联**:拿到的凭证/token `write_exploit_clue` 回写(带 verify_url 自动验真+TTL,供跨站维持认证态)。


## 验证与反证
以两个自有账户与独立匿名会话建立身份基线。登录页跳转、出现 cookie 或页面 200 不证明身份改变；读取服务端当前用户标识核对实际身份。注销、刷新、找回与 MFA 各有独立状态，不能互相代替验证。

## 修复与复测
服务端统一验证会话与恢复流程，绑定账户、用途和有效期；复测正常登录、注销后旧会话、已使用找回令牌及跨账户恢复均符合预期。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
