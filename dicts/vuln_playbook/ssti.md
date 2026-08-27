---
type: 模板注入
aliases: SSTI, server side template injection, 模板注入, SpEL, OGNL, EL注入, el_injection
---

# 模板注入 SSTI

> 思路参考,非清单。polyglot 探针/分引擎 RCE 链/沙箱逃逸细节你已具备且可 web_search 补(尤其 Jinja2 MRO 子类索引因版本而异需动态定位),这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是 SSTI 面
用户输入被回显且可能进模板渲染:搜索回显、报错消息、邮件/PDF 模板、用户名昵称渲染。先探针判引擎:`{{7*7}}`→49=Jinja2/Twig;`${7*7}`→49=FreeMarker/Velocity/Java EL;`#{7*7}`=ERB/Thymeleaf。

## 瞭望塔工具怎么打(独有价值)
- **先确认引擎**:`record_stack` 证据化指纹+版本(引擎决定 payload)。
- **盲 SSTI 靠带外**:`oob_generate` 拿域名→模板表达式执行 nslookup→`oob_check` 收解析。
- **查框架 SSTI**:`query_vuln_intel`(struts2 的 S2-xxx、Spring SpEL 等);有 exec_ref 直接 `run_nuclei`。
- **复杂 payload**:`run_script` 沙盒生成沙箱逃逸链。RCE 后 `record_chain_step`。

## 什么算 confirmed(服务证据强制)
数学表达式真被求值(`{{7*7}}`→`49` 而非原样返回),或命令真回显/带外真收到解析。原样返回 `{{7*7}}`=没洞。

## 定级要点
能 RCE=critical;仅表达式求值无法升级到命令=中/高(看能读什么)。
