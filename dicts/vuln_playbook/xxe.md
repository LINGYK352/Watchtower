---
type: XXE
aliases: XML外部实体, xml external entity, xxe, XML注入
---

# XXE

> 思路参考,非清单。外部实体 payload/参数实体外带/编码绕过等技法你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是 XXE 面
接受 XML 的接口(Content-Type text/xml、application/xml)、SOAP、SAML、RSS、SVG 上传、Office 文档(docx/xlsx 本质 xml zip)、`.xml` 导入、支付回调。JSON 接口试改 Content-Type 为 xml(有的框架双解析)。

## 瞭望塔工具怎么打(独有价值)
- **盲 XXE 靠带外(主力)**:`oob_generate` 拿域名→外部实体指向 `http://xxx.dnslog/evil.dtd`→`oob_check` 收到解析=XXE 确认。数据外带用参数实体嵌套(evil.dtd 把文件内容拼进请求带出)。
- **托管 evil.dtd**:`run_script` 沙盒起 http 托管,或直接用带外通道。
- **查组件 XXE**:`query_vuln_intel`;有 exec_ref 直接 `run_nuclei`。
- **升级+串联**:XXE→SSRF 探内网/打云元数据 `record_chain_step`;读到的敏感内容 `write_exploit_clue`。

## 什么算 confirmed(服务证据强制)
响应有目标文件真实内容,或带外收到目标解析(命中唯一标识+时间吻合)。仅接口接收 xml 不算。

## 定级要点
读敏感文件/SSRF 内网=高;读到凭证=critical。
