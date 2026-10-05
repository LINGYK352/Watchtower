---
type: 命令注入
aliases: 命令执行, RCE, remote code execution, command injection, 代码执行, 远程代码执行
stage: validation
entry_points: [命令参数, 文件转换, 任务执行, 代码解释]
cwe_ids: [CWE-77, CWE-78, CWE-94]
owasp_id: A03:2021
severity_base: critical
chains_with: [file_upload, ssti, internal_pivot]
tech_stack: [web]
---

# 命令注入 / RCE

> 思路参考,非清单。分隔符/绕空格/绕关键字等注入技法你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是命令执行面
参数进系统命令/危险函数:ping/nslookup 类、导出转换(ffmpeg/imagemagick)、备份压缩、任务调度、`filename/cmd/ip/host/domain` 参数。Java 序列化特征(`ac ed 00 05`/base64 `rO0AB`/`application/x-java-serialized-object`/Shiro `rememberMe`)、表达式注入(SpEL/OGNL/EL)也常升级 RCE。

## 瞭望塔工具怎么打(独有价值)
- **带外线索**：`oob_generate` 获取 domain/cookie，再以 `oob_check(domain,cookie)` 查询。记录本次标记与时间，区分解析、请求和执行三种事实，不能仅凭 hit=true 确认该类漏洞。
- **查组件 RCE**:`query_vuln_intel(组件)`(struts2/fastjson/log4j/shiro/weblogic 等,记忆库有 Copy Fail 提权可接);exec_ref 仅作为线索；AI 会话禁用主动扫描工具，不应自动调用或绕过门控。
- **反序列化 payload**:检测到 Java 序列化,`run_script` 沙盒生成 ysoserial payload 打带外验证。
- **串联**:getshell 后 `record_chain_step` 串成完整链。


## 验证与反证
带外 DNS 只证明发生了解析，不能区分命令执行、SSRF、解析器取资源或扫描器自测；需要当前请求唯一标记、时间关联和目标侧独立证据。错误堆栈、版本命中、响应反射均不足以确认执行。

## 修复与复测
消除不可信输入与命令/代码执行拼接，使用参数化接口并收紧运行身份；复测原触发路径、正常转换任务与异常输入，清点并恢复本次测试变更。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
