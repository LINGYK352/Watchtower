---
type: XXE
aliases: XML外部实体, xml external entity, xxe, XML注入
stage: validation
entry_points: [XML, SOAP, SAML, 文档解析]
cwe_ids: [CWE-611]
owasp_id: A05:2021
severity_base: high
chains_with: [ssrf, path_traversal]
tech_stack: [web]
---

# XXE

> 思路参考,非清单。外部实体 payload/参数实体外带/编码绕过等技法你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是 XXE 面
接受 XML 的接口(Content-Type text/xml、application/xml)、SOAP、SAML、RSS、SVG 上传、Office 文档(docx/xlsx 本质 xml zip)、`.xml` 导入、支付回调。JSON 接口试改 Content-Type 为 xml(有的框架双解析)。

## 瞭望塔工具怎么打(独有价值)
- **带外线索**：`oob_generate` 获取 domain/cookie，再以 `oob_check(domain,cookie)` 查询。记录本次标记与时间，区分解析、请求和执行三种事实，不能仅凭 hit=true 确认该类漏洞。
- **外部资源前置条件**：DNS 回连服务不提供 DTD 托管保证；`run_script` 运行在平台，不能假设临时服务具备目标可达的网络入口。条件不足时标记该验证未覆盖。
- **查组件 XXE**:`query_vuln_intel`;exec_ref 仅作为线索；AI 会话禁用主动扫描工具，不应自动调用或绕过门控。
- **升级+串联**:XXE→SSRF 探内网/打云元数据 `record_chain_step`;读到的敏感内容 `write_exploit_clue`。


## 验证与反证
XML 被接受或出现 DNS 查询仅是线索；核对解析路径与外部实体开关，关联唯一标记和服务端日志，排除代理扫描与浏览器加载。DNS 带外服务不等于可托管 DTD 的 HTTP 服务。

## 修复与复测
禁用外部实体/外部 DTD，限制解析器资源访问；复测正常 XML/SOAP 文档、外部引用拒绝和导入失败分支，不读取真实敏感文件作示例。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
