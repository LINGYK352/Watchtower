---
type: 模板注入
aliases: SSTI, server side template injection, 模板注入, SpEL, OGNL, EL注入, el_injection
stage: validation
entry_points: [模板, 服务端渲染, 邮件模板, 表达式]
cwe_ids: [CWE-1336, CWE-94]
owasp_id: A03:2021
severity_base: critical
chains_with: [rce]
tech_stack: [web]
---

# 模板注入 SSTI

> 思路参考,非清单。polyglot 探针/分引擎 RCE 链/沙箱逃逸细节你已具备且可 web_search 补(尤其 Jinja2 MRO 子类索引因版本而异需动态定位),这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是 SSTI 面
用户输入被回显且可能进模板渲染:搜索回显、报错消息、邮件/PDF 模板、用户名昵称渲染。先探针判引擎:`{{7*7}}`→49=Jinja2/Twig;`${7*7}`→49=FreeMarker/Velocity/Java EL;`#{7*7}`=ERB/Thymeleaf。

## 瞭望塔工具怎么打(独有价值)
- **先确认引擎**:`record_stack` 证据化指纹+版本(引擎决定 payload)。
- **盲 SSTI 靠带外**:`oob_generate` 拿域名→模板表达式执行 nslookup→`oob_check` 收解析。
- **查框架 SSTI**:`query_vuln_intel`(struts2 的 S2-xxx、Spring SpEL 等);exec_ref 仅作为线索；AI 会话禁用主动扫描工具，不应自动调用或绕过门控。
- **复杂 payload**:`run_script` 沙盒生成沙箱逃逸链。RCE 后 `record_chain_step`。


## 验证与反证
仅表达式文本回显不算模板执行；结果也可能由前端计算。使用无副作用的测试值及负向对照，核对服务端渲染阶段与模板上下文；表达式求值不自动推断可执行系统命令。

## 修复与复测
固定模板结构，把用户内容作为数据传入并缩减模板可见对象；复测正常模板功能、输入原样显示与服务端上下文隔离。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
