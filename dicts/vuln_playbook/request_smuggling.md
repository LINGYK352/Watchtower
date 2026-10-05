---
type: HTTP 请求走私
aliases: HTTP 请求走私, request smuggling, 请求走私, CL.TE, TE.CL, desync, http desync
stage: validation
entry_points: [反向代理, 连接复用, 消息边界, HTTP解析]
cwe_ids: [CWE-444]
owasp_id: A06:2021
severity_base: high
chains_with: [cache_poison, host_header, auth_bypass]
tech_stack: [web]
---

# HTTP 请求走私

> 思路参考，非清单。核心：前端代理与后端服务器对同一请求的「边界在哪」理解不一致（Content-Length vs Transfer-Encoding），攻击者构造让一个请求的尾巴被后端当成下一个请求——可劫持他人请求、投毒缓存、绕前端鉴权。

## 先判这是不是走私面
架构上有「前端代理/CDN/LB + 后端服务器」两层（几乎所有生产站）。走私是**协议层**问题，不看业务功能，看两层对 CL/TE 头的处理差异。有 CDN/nginx/HAProxy 前置 + 后端 app 的最典型。

## 瞭望塔工具怎么打（独有价值）
- **解析差异线索**：只在隔离测试链路比较前后端解析结果；延迟可能来自连接复用、排队或超时，时序探测也可能影响共享连接，不能称为无副作用。
- **TE 变体**：`Transfer-Encoding: chunked` 的混淆写法（`Transfer-Encoding : chunked` 带空格、`Transfer-Encoding: xchunked`、双 TE 头、`\x0b` 前缀）——`run_script` 里用原始 socket 发（`http_request` 可能规范化头，走私常需裸 socket 精确控制字节）。
- **验证走私成立**：构造走私前缀，紧接一个正常请求，看后端是否把走私部分拼进了下一个请求（响应错位/前缀污染下一响应）。**注意**：真正的 smuggling 会影响其他用户请求，探测/保守模式下**只做时序探测定性，不做会污染他人流量的实打利用**（避免对生产其他用户造成影响，走闸刀约束）。
- **DIY 工具**：`run_script` 沙盒跑 smuggler 类脚本或自写 socket 探测。


## 验证与反证
仅耗时变化不能证明前后端解析差异，连接排队和超时也会造成相同现象。时序探测同样可能影响共享连接，只在隔离测试服务验证解析边界，不声称天然无副作用。

## 修复与复测
统一代理与后端消息边界解析，拒绝歧义报文并更新组件；复测合法连接复用、异常报文拒绝与后续正常请求互不影响。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
