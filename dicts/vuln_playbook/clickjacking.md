---
type: 点击劫持与嵌入边界评估
aliases: 点击劫持, clickjacking, UI redressing, iframe
stage: validation
entry_points: [iframe, 页面嵌入, 敏感按钮, frame-ancestors]
cwe_ids: [CWE-1021]
severity_base: low
chains_with: [csrf, business_logic]
tech_stack: [web]
---

# 点击劫持与页面嵌入边界

## 适用条件
敏感业务页面可能被第三方来源嵌入。缺少 X-Frame-Options 不直接等于漏洞，CSP frame-ancestors、浏览器行为、会话状态及业务流程都会影响结论。

## 最小验证
用隔离的测试来源和自有账户观察浏览器是否真正加载受保护页面，以及页面能否维持认证状态。测试只选择可恢复的自有对象操作，记录页面实际可交互性和业务状态，不用真实用户或真实支付作证。

## 验证与反证
登录页或静态页可嵌入不代表敏感操作可被诱导；浏览器拒绝嵌入、Cookie 未携带、二次确认有效时应分别记录。通用 HTTP 工具返回页面不等于真实浏览器嵌入成功。

## 修复与复测
为页面设置符合业务预期的 frame-ancestors，并对关键操作保留必要的确认与会话保护。复测非受信来源被拒、合法嵌入可用，风险按实际可诱导操作评估，避免仅缺头就报高危。
