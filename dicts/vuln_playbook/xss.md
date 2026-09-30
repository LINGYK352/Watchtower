---
type: XSS
aliases: 跨站脚本, cross site scripting, xss, 存储型XSS, 反射型XSS, DOM XSS
stage: validation
entry_points: [富文本, 评论, 页面渲染, DOM]
cwe_ids: [CWE-79]
owasp_id: A03:2021
severity_base: medium
chains_with: [cors, auth_bypass]
tech_stack: [web]
---

# XSS

> 思路参考,非清单。分上下文的 payload/绕 WAF 变体/绕 CSP 等技法你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是 XSS 面 + 三型
- 反射型:输入即时回显在响应(搜索/报错/参数回显)。
- 存储型(危害最高):输入存库后在别处渲染(评论/昵称/工单/日志后台)——**跨端渲染点最值钱(打管理员)**。
- DOM 型:前端 JS 把 source(location/hash/postMessage)写进危险 sink(innerHTML/eval)。
先探转义:输入 `<test"'>` 看响应原样还是变 `&lt;`。

## 瞭望塔工具怎么打(独有价值)
- **真渲染验执行(关键)**:`browser_navigate`/`browser_login` 真浏览器渲染看 payload **真弹窗/真触发 JS**——反射/DOM 型必须真渲染,不能只看响应里有 payload 字符串。
- **存储型跨端**:A 提交 payload,切管理员 cookie `browser_navigate` 看后台是否执行。
- **找 DOM 数据流**:`fetch_sourcemap`/`browser_resources` 看前端 source→sink 路径。


## 验证与反证
输入回显、包含脚本片段或一次弹窗截图需与执行来源核对，不能把测试控制台执行算成目标执行。区分反射、存储、DOM 路径及真实受影响的用户上下文。

## 修复与复测
按输出上下文编码，采用可靠 HTML 净化并减少危险 DOM 接口；复测不同渲染位置、正常富文本和历史存储内容，删除测试内容。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
