---
type: Host 头注入
aliases: Host 头注入, host header injection, host 头攻击, 密码重置投毒, host poisoning
stage: validation
entry_points: [Host, 转发头, 重置邮件, 绝对链接]
cwe_ids: [CWE-644, CWE-20]
owasp_id: A03:2021
severity_base: medium
chains_with: [cache_poison, ssrf, open_redirect]
tech_stack: [web]
---

# Host 头注入

> 思路参考，非清单。核心：后端用请求里的 `Host`（或 `X-Forwarded-Host`）拼 URL/发邮件/做路由，攻击者改 Host 让服务生成指向自己的链接——最典型是密码重置链接投毒。

## 先判这是不是 Host 头面
有「发链接给用户」的功能：密码重置邮件、邮箱验证、邀请链接。以及用 Host 做缓存键、做后端路由的场景。信号：改 Host 后响应里出现了你改的域名。

## 瞭望塔工具怎么打（独有价值）
- **Host 篡改探测**：`http_request` 把 `Host` 改成 `evil.example.com`，或保留原 Host 但加 `X-Forwarded-Host: evil.example.com` / `X-Host` / 双 Host 头，看响应体、Location、后续邮件里的链接是否用了被篡改的域名。
- **密码重置投毒**：对「忘记密码」接口，`http_request` 带篡改的 Host 发起重置——若重置邮件里的链接域名变成攻击者域名，用户点击就会把重置 token 泄露给攻击者（等于账号接管）。真实验证需能收到邮件内容或有回显。
- **配合缓存投毒**：Host/X-Forwarded-Host 若进了缓存响应，转 `read_vuln_playbook cache_poison`。
- **SSRF 联动**：Host 被用于后端再请求时可能触发 SSRF，转 `ssrf`。


## 验证与反证
响应反射 Host 不等于业务影响；核对重置邮件、绝对链接、缓存或路由是否实际采纳了不可信值。代理到应用的可信头边界需明确，只在自有账户与隔离缓存键上观察结果。

## 修复与复测
限制允许的主机并使用固定可信外部基址，网关统一覆盖转发头；复测正常多域部署、拒绝未知主机与重置链接生成。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
