---
type: 侦察方法论
aliases: 侦察方法论, recon, reconnaissance, 信息收集, 资产测绘, 攻击面, 子域名收集, 前期侦察
stage: recon
entry_points: [资产, 域名, 端口, 指纹, 证书]
cwe_ids: [CWE-200]
owasp_id: PTES-Intelligence-Gathering
severity_base: info
chains_with: [subdomain_takeover, ssrf, cloud_assessment]
tech_stack: [web, cloud, internal]
---

# 侦察方法论

> 思路参考，非清单。瞭望塔的资产测绘/侦察由**内核侦察引擎**（子域名/端口/指纹/探活/证书/JS 接口/ICP 归属）自动完成，本方法论不教通用 recon，而是告诉 AI 渗透会话：**侦察结果已在平台里，怎么调出来用、怎么从中定攻击面**，避免会话内重复扫。

## 侦察在平台里怎么拿（别在会话里重扫）
- **拿本会话/单位的侦察上下文**：`get_recon_context` 取该目标已归集的资产（域名/IP/站点/服务/端口/指纹）——这是内核侦察引擎跑完落库的结果，会话开局就该先读它，而不是自己 nmap/子域名爆破。
- **匹配已有资产**：`match_asset` 按线索匹配平台已测绘的资产条目。
- **组件打法**：`match_playbook`/`read_system_playbook` 按目标指纹查该组件的历史有效打法（第二维知识）。
- **接口/JS 深挖**：站点已抓的 JS 和同源接口用 `browser_resources`/`browser_discover`（持久浏览器），比盲扫路径高效——高价值接口往往藏在 JS 里。
- **DNS/存活补查**：`dns_query(domain)`、`icmp_ping`（ICMP/TCP 存活）按需补，别全量重扫。DNS 工具当前不接受记录类型参数，缺少的记录应标注未覆盖。

## 从侦察结果定攻击面（本方法论的核心价值）
- 指纹识别出组件 → `query_vuln_intel(组件)` 查已知漏洞，把版本和适用条件作为待核实线索。`run_nuclei`/`run_npoc` 在 AI 会话全局禁用，不调它们，也不以脚本绕过；根据当前暴露工具制定最小验证并保留对照证据。
- 子域名/CNAME 指向失效云资源 → 转 `read_vuln_playbook subdomain_takeover`。
- 发现云资产（S3/OSS/元数据面）→ 转 `cloud_assessment`。
- JS 里挖到的接口 → 按接口语义定漏洞类型（越权/注入/SSRF…）逐个测。
- 内网入口 → 拿到立足点后转 `internal_pivot`。

## 什么算有效侦察产出（对渗透而言）
不是"收集了多少资产"，而是"从资产里定出了几个可测的攻击面并进入了验证"。堆一堆子域名却不落到具体接口/组件/漏洞面 = 无效侦察。定级：侦察本身 info；据此打出漏洞按对应漏洞类型定。

## 验证与反证
核对资产归属、观察时间、端口/协议与服务身份；CDN、共享 IP、登录跳转和默认证书可能误导组件归属。历史漏洞与跨单位打法只能生成假设，不能直接作为本目标证据。

## 修复与复测
输出按资产去重的入口、已确认身份、待核实组件与缺口；复测新增证据能对应当前目标，不重复启动全量扫描，准备阶段转 pre_engagement。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
