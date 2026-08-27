---
type: SSRF
aliases: 服务端请求伪造, server side request forgery, ssrf
---

# SSRF

> 思路参考,非清单。IP 变形/协议利用/绕过白名单等通用技法你已具备,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是 SSRF 面
参数会让服务端发请求:`url/uri/img/source/target/callback/webhook/proxy/redirect` 等;隐蔽的有远程头像抓取、URL 导入、PDF/Office 生成、XML 解析(见 XXE)、SSO redirect_uri、翻译/预览/短链。`fuzz_params` 试隐藏的 url/file 类参数。

## 瞭望塔工具怎么打(独有价值)
- **无回显靠带外(主力)**:`oob_generate` 拿域名→`url=http://xxx.dnslog`→`oob_check` 收到 DNS 解析=SSRF 确认。**关键**:区分"无回显有洞"和"目标出网被防火墙挡"——后者带外收不到不代表没 SSRF,换内网端口探测(开/闭端口响应差异)或时序再判。
- **有回显探内网**:http_request 让 `url` 指 `127.0.0.1:各端口`,看开/闭端口响应差异=能探内网。
- **拿到 SSRF 后优先打云元数据**(高分):`http://169.254.169.254/latest/meta-data/`(AWS)、`/computeMetadata/v1/`(GCP,需 header)、阿里云/腾讯云对应端点——常直接吐临时 AK/SK。
- **串联**:探到的内网 IP/服务 `write_exploit_clue` 回写;SSRF→内网→RCE `record_chain_step`。

## 什么算 confirmed(服务证据强制)
带外收到目标发起的解析/回连(命中本次 payload 唯一标识+时间吻合),或响应带回了内网服务真实内容,或读到云元数据真实凭证。光参数名像 url 不算。

## 定级要点
能探/打内网=高;读到云凭证/内网敏感数据=critical(`C:H`);仅能发对外请求无内网影响=中。
