---
type: 开放重定向
aliases: 开放重定向, open redirect, url 跳转, 任意跳转, 钓鱼跳转, redirect
stage: validation
entry_points: [跳转, 返回地址, 登录回调, redirect]
cwe_ids: [CWE-601]
owasp_id: A01:2021
severity_base: low
chains_with: [ssrf, host_header, auth_bypass]
tech_stack: [web]
---

# 开放重定向

> 思路参考，非清单。核心：跳转目标由用户可控参数决定且未校验白名单——单独危害不高，但配合 OAuth/SSO 可偷授权码/token，是钓鱼与账号接管的跳板。

## 先判这是不是重定向面
带跳转语义的参数：`?url=`、`?redirect=`、`?next=`、`?returnUrl=`、`?target=`、`?goto=`、`?callback=`。登录后跳回、退出跳转、OAuth 的 `redirect_uri` 是重灾区。

## 瞭望塔工具怎么打（独有价值）
- **跳转探测**：`http_request`（禁用自动跟随重定向）把跳转参数改成 `https://evil.example.com`，看响应是否 302 到外部域，或页面 JS `location=` 跳外部。
- **绕白名单变体**：目标若校验白名单，`run_script` 批量试绕过变体——`//evil.com`（协议相对）、`https:evil.com`、`https://正常域@evil.com`（userinfo 混淆）、`https://正常域.evil.com`（后缀）、`/\evil.com`、URL 编码/双编码。用 `http_request` 逐个验哪个真跳出去。
- **OAuth 授权码窃取（高危链）**：若 OAuth 的 `redirect_uri` 可控，构造跳到攻击者域——授权码/token 会带在跳转里泄露，等于账号接管。这是开放重定向真正值钱的利用，需证明 code/token 确实外带。
- **配合 SSRF**：服务端跟随重定向的场景转 `ssrf`。


## 验证与反证
仅参数含 URL 不证明跳转。记录实际 Location、浏览器最终目标及是否发生敏感令牌传递；站内相对跳转与第三方跳转分开，登录回调要验证精确绑定。

## 修复与复测
使用服务端允许的目的地或不可伪造的目的地标识；复测正常业务跳转及非允许目的地拒绝，不把任意域名子串作为信任判断。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
