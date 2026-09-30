---
type: Web 缓存投毒
aliases: Web 缓存投毒, cache poisoning, 缓存投毒, 缓存欺骗, cache deception, unkeyed header
stage: validation
entry_points: [缓存, CDN, 代理, 缓存键]
cwe_ids: [CWE-444, CWE-525]
owasp_id: A05:2021
severity_base: high
chains_with: [host_header, xss, request_smuggling, open_redirect]
tech_stack: [web]
---

# Web 缓存投毒

> 思路参考，非清单。核心：CDN/反代按「缓存键」（通常只有 URL+部分头）缓存响应，但响应内容却受**未进缓存键的输入**（unkeyed header/参数）影响——攻击者用这些输入污染一次，之后所有拿缓存的用户都吃到被投毒的响应。

## 先判这是不是缓存面
有 CDN/反代前置、静态或半静态响应。信号：响应带 `X-Cache: HIT/MISS`、`Age`、`CF-Cache-Status`、`Cache-Control: public`。投毒点是那些**影响响应但不进缓存键**的输入。

## 瞭望塔工具怎么打（独有价值）
- **找 unkeyed 输入**：`http_request` 加各种头（`X-Forwarded-Host`、`X-Forwarded-Scheme`、`X-Host`、`X-Forwarded-For`、自定义头）看响应是否变化（如页面里链接域名变了）**但 `X-Cache` 仍可 HIT**——说明该头影响响应却没进缓存键，是投毒点。
- **确认缓存生效**：先带恶意头请求（MISS，写入缓存），紧接**不带**恶意头再请求同 URL——若第二次（HIT）也返回了被污染的内容，证明投毒进了共享缓存、会影响其他用户。用 `http_request` 两连发对比 `X-Cache` 与内容。
- **cache key 精准控制**：`run_script` 批量试不同头/参数组合，找稳定「污染进缓存 + 命中」的组合；注意用无害标记（如插入一个唯一字符串）验证机制，别真挂恶意 payload 到生产缓存（探测/保守模式只定性，走闸刀）。
- **联动**：投毒载荷常来自 Host 头（`read_vuln_playbook host_header`）或走私（`request_smuggling`）；投毒内容是脚本则转 `xss`。


## 验证与反证
使用隔离测试路径和两组独立会话区分源站响应、缓存响应及浏览器本地缓存。只影响自己的回显不算共享缓存污染；记录缓存键相关头、命中标记、TTL 和第二会话实际收到的内容。

## 修复与复测
统一可信头处理和缓存键，敏感响应禁用共享缓存；修复后验证正常缓存仍工作、异常变体不影响另一会话，并清理测试缓存条目。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
