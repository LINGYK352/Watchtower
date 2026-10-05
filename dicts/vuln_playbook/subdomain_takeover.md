---
type: 悬空 DNS 与子域名接管风险核验
aliases: subdomain takeover, 悬空DNS, 子域名接管
stage: recon
entry_points: [CNAME, 悬空DNS, 云资源绑定, 失效解析]
cwe_ids: [CWE-200]
severity_base: info
chains_with: [recon_methodology, cloud_assessment]
tech_stack: [web, cloud]
---

# 悬空 DNS 与子域名接管风险核验

## 输入与最小核验
从 `get_recon_context` 读取授权域名的已有记录，用 `dns_query(domain)` 核对当前解析。平台工具目前只接受 domain，不支持指定任意记录类型；所需记录未返回时应标注未覆盖，不编造参数。

对已经确认归属的站点，用 `http_request` 记录服务响应、时间、重定向与错误特征；第三方页面或历史指纹只能作为线索。结合资产管理员提供的资源绑定状态，排查域名仍解析但资源已删除、迁移遗漏或绑定异常的情况。

## 证据与边界
NXDOMAIN、404、供应商错误页都不足以单独确认可接管；供应商可能保留原租户绑定或要求域名验证。未验证所有权控制失效时保持待核实，不以创建/认领第三方资源作为自动验证步骤。

## 修复与复测
由资产管理员删除失效解析或恢复受控资源绑定，核查 DNS 缓存与传播后再次读取解析及正常业务响应。记录影响域名、旧目标、处置人和复测时间，避免把暂时故障当作接管漏洞。
