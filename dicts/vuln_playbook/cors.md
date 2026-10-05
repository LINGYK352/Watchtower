---
type: CORS 配置错误
aliases: CORS, cors, 跨域配置错误, 跨域, origin 反射, cross origin
stage: validation
entry_points: [跨域, Origin, 预检, 浏览器读取]
cwe_ids: [CWE-942, CWE-346]
owasp_id: A05:2021
severity_base: medium
chains_with: [xss, auth_bypass, idor]
tech_stack: [web]
---

# CORS 配置错误

> 思路参考，非清单。核心：后端把 `Access-Control-Allow-Origin` 设得太松（反射任意 Origin 或允许 null），且 `Allow-Credentials: true`——攻击者站点就能带受害者 Cookie 跨域读取其数据。

## 先判这是不是 CORS 面
带认证的接口（返回用户数据、走 Cookie/Token）。看响应有没有 `Access-Control-Allow-Origin`。危险组合是 `Allow-Origin: <反射我传的 Origin>` + `Allow-Credentials: true`。

## 瞭望塔工具怎么打（独有价值）
- **Origin 反射探测**：`http_request` 请求时带 `Origin: https://evil.example.com`（一个明显不该被信任的域），看响应 `Access-Control-Allow-Origin` 是否原样回显了它 + 是否同时 `Access-Control-Allow-Credentials: true`。回显任意 Origin + 带凭证 = 高危。
- **常见绕过变体**：试 `Origin: null`（部分配置白名单含 null）；试 `Origin: https://正常域.evil.com`（子域后缀匹配漏洞）、`https://evil正常域`（前缀匹配漏洞）——用 `http_request` 逐个发，看哪个被 ACAO 回显。
- **可利用性验证**：`run_script`/`browser_*` 写一个 PoC 页面（fetch 目标接口 `credentials:'include'`），证明跨域能读到受害者数据。保守/探测模式下到「确认 ACAO 反射 + credentials」即可定性，不必真钓。
- **区分真伪**：`Allow-Origin: *` 但**不带** credentials 时读不到私有数据，危害低；要 `*` + credentials（浏览器其实禁止这组合）或反射 Origin + credentials 才真高危。


## 验证与反证
区分响应声明与浏览器实际可读性。以自有第二来源和测试账户验证脚本是否能读敏感响应，同时记录 Origin、凭据策略与实际浏览器结果；仅反射 Origin 或返回通配符不足以确认敏感数据泄露。

## 修复与复测
按精确可信来源配置 CORS，避免动态反射任意来源；复测可信页面正常调用，不可信来源无法读取受保护内容，并覆盖预检与实际请求。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
