---
type: SSRF
aliases: 服务端请求伪造, server side request forgery, ssrf
stage: validation
entry_points: [远程导入, 回调, URL预览, 服务端请求]
cwe_ids: [CWE-918]
owasp_id: A10:2021
severity_base: high
chains_with: [cloud_assessment, internal_pivot, path_traversal]
tech_stack: [web,cloud]
---

# SSRF

> 思路参考,非清单。IP 变形/协议利用/绕过白名单等通用技法你已具备,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是 SSRF 面
参数会让服务端发请求:`url/uri/img/source/target/callback/webhook/proxy/redirect` 等;隐蔽的有远程头像抓取、URL 导入、PDF/Office 生成、XML 解析(见 XXE)、SSO redirect_uri、翻译/预览/短链。从已观察请求或源码核对 url/file 类参数；`fuzz_params` 已全局禁用。

## 瞭望塔工具怎么打(独有价值)
- **带外线索**：`oob_generate` 获取 domain/cookie，再以 `oob_check(domain,cookie)` 查询。记录本次标记与时间，区分解析、请求和执行三种事实，不能仅凭 hit=true 确认该类漏洞。
- **有回显探内网**:http_request 让 `url` 指 `127.0.0.1:各端口`,看开/闭端口响应差异=能探内网。
- **拿到 SSRF 后优先打云元数据**(高分):`http://169.254.169.254/latest/meta-data/`(AWS)、`/computeMetadata/v1/`(GCP,需 header)、阿里云/腾讯云对应端点——常直接吐临时 AK/SK。
- **串联**:探到的内网 IP/服务 `write_exploit_clue` 回写;SSRF→内网→RCE `record_chain_step`。


## 验证与反证
关联 DNS 记录不单独证明目标服务端完成 HTTP 请求，也不证明可访问内网；排除浏览器预取、安全扫描和自测。平台自己的 http_request 直连元数据不能充当目标侧 SSRF 证据。

## 修复与复测
限制协议/目的地址/重定向与服务端出站网络，逐次解析后校验目的地；复测合法回调可用、受限目标被拒及跳转后的目的地仍受检查。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
