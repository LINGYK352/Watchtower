---
type: 信息暴露与敏感数据边界
aliases: information disclosure, 信息泄露, 敏感信息, SourceMap, 备份泄露, 调试信息, 凭据泄露
stage: validation
entry_points: [JS, SourceMap, 调试信息, 备份, 敏感文件, 泄露]
cwe_ids: [CWE-200, CWE-209, CWE-540]
severity_base: medium
chains_with: [auth_bypass, cloud_assessment]
tech_stack: [web, cloud]
---

# 信息暴露与敏感数据边界

## 入口与优先级
从已观察的页面、脚本、错误响应、下载接口和资源引用发现候选；区分正常公开内容、内部实现信息、个人数据和认证材料。文件存在、SourceMap 可下载或变量名包含 secret 都不自动构成高危。

## 平台验证流程
用 `browser_resources` 获取真实资源引用，`fetch_sourcemap` 查看已有映射；大文件使用 `fetch_large_file`，只有完整下载后才能做完整内容结论。`run_script` 仅分析平台工作区中的文件，不代表读到了目标系统文件。

优先查少量代表性内容及来源归属，保留必要脱敏样本、长度、摘要和请求证据。候选凭据可能是示例、过期或公开客户端标识；其真实性、有效性和可访问权限是三项不同结论。

## 验证与反证
排除 SPA 兜底页、登录重定向、截断文件、压缩/编码错误与示例配置。展示敏感内容需证明访问者本不应获得，不能把搜索引擎摘要或历史仓库记录当成本次目标实时泄露。

## 修复与复测
移除不必要的公开文件，限制敏感接口权限，脱敏错误和日志；泄露的有效认证材料由所有者轮换并确认旧材料失效。复测匿名不可获取受保护内容、授权下载正常及缓存已按策略更新。
