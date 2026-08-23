---
type: XSS
aliases: 跨站脚本, cross site scripting, xss, 存储型XSS, 反射型XSS, DOM XSS
---

# XSS

> 思路参考,非清单。分上下文的 payload/绕 WAF 变体/绕 CSP 等技法你已具备且可 web_search 补,这里只补【哨兵工具编排 + 验证判据】。

## 先判这是不是 XSS 面 + 三型
- 反射型:输入即时回显在响应(搜索/报错/参数回显)。
- 存储型(危害最高):输入存库后在别处渲染(评论/昵称/工单/日志后台)——**跨端渲染点最值钱(打管理员)**。
- DOM 型:前端 JS 把 source(location/hash/postMessage)写进危险 sink(innerHTML/eval)。
先探转义:输入 `<test"'>` 看响应原样还是变 `&lt;`。

## 哨兵工具怎么打(独有价值)
- **真渲染验执行(关键)**:`browser_navigate`/`browser_login` 真浏览器渲染看 payload **真弹窗/真触发 JS**——反射/DOM 型必须真渲染,不能只看响应里有 payload 字符串。
- **存储型跨端**:A 提交 payload,切管理员 cookie `browser_navigate` 看后台是否执行。
- **找 DOM 数据流**:`fetch_sourcemap`/`collect_js` 看前端 source→sink 路径。

## 什么算 confirmed(服务证据强制)
payload **真执行了**(浏览器真弹窗/真触发 JS),或响应里 payload **未被转义**且上下文可执行(被转义成 `&lt;script&gt;` 就是没洞)。仅"响应里有我的输入但被 HTML 编码了"=没洞,别报。

## 定级要点
存储型打管理员/可盗 cookie 接管=高;反射型需诱导=中;配合 CSRF 可组账户接管链。
