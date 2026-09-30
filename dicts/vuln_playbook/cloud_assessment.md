---
type: 云配置评估
aliases: 云配置评估, cloud assessment, 云安全基线, 配置审计, 云错误配置, 公开桶, 元数据泄露
stage: validation
entry_points: [云资源, 存储桶, 公开对象, 元数据]
cwe_ids: [CWE-16, CWE-732, CWE-1188]
owasp_id: A05:2021
severity_base: high
chains_with: [ssrf, aws_postexploit, azure_postexploit, gcp_postexploit]
tech_stack: [cloud]
---

# 云配置评估（只读基线）

> 思路参考，非清单。区别于 *_postexploit（拿凭证后主动利用），本方法论是**只读**地查云资源有没有暴露/错配——公开桶、开放的元数据、宽松的安全组、泄露的凭证入口。授权评估阶段的资产面梳理。

## 先判这是不是云评估面
目标资产是云上服务：`*.s3.amazonaws.com`、`*.blob.core.windows.net`、`*.storage.googleapis.com`、CloudFront/云 LB、`*.compute.amazonaws.com`。或从指纹/证书/IP 段判断部署在公有云。

## 瞭望塔工具怎么打（独有价值）
- **公开存储桶**：使用已知授权资源 URL 做只读核验，分别记录对象列表与测试对象可读性；结合资源预期公开策略判断风险。本只读流程不做上传写入。
- **元数据暴露线索**：先证实请求发生在目标服务端，再核对返回内容归属与敏感程度。平台直连元数据地址不证明目标存在 SSRF。
- **凭证泄露扫描**：`browser_resources` 抓前端 JS、`run_script` 扫下载的文件找硬编码的 AK/SK/service account key/连接串——云凭证泄露是进云的最短路径。
- **悬空解析**：转 `read_vuln_playbook(subdomain_takeover)`；资源失效是待核实线索，不代表可被其他租户接管。
- **暴露的管理面**：云控制台、K8s API（转 `k8s`）、容器 registry 未授权。


## 验证与反证
公开对象可能是刻意发布，需结合业务预期与数据分类；桶能列目录、能读对象、能写对象是三个不同权限。仅只读核验，不把上传写入夹在只读基线中；元数据可达性须证明发生在目标侧。

## 修复与复测
按业务收紧公共访问、资源策略和出站边界；复测受限对象匿名不可读且正常用户可用。凭据暴露应轮换并核对旧凭据失效，报告仅保留脱敏标识。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
