---
type: 前渗透准备与证据规划
aliases: 前渗透, 前渗透准备, pre engagement, assessment planning
stage: recon
entry_points: [测试范围, 账户角色, 评估准备, 覆盖矩阵]
cwe_ids: []
severity_base: info
chains_with: [recon_methodology, post_assessment]
tech_stack: [web, cloud, internal]
---

# 前渗透准备与证据规划

## 输入与边界
沿用任务已经确认的授权范围，不重复索取授权。记录本次目标的规范 URL、资产标识、账户角色、测试窗口、禁止变更项与停止条件。由线索发现的第三方域名、云资源或相邻网段不自动成为本次目标。

## 在平台中的执行顺序
1. `get_recon_context(asset_key)` 读取现有侦察档案，`match_asset(site)` 查已有资产；区分当前事实、历史记录和未经确认的推断。历史时间、站点重定向、IP 归属或组件版本变化要单独标注。
2. 根据已经看到的接口、组件和角色，使用 `list_vuln_playbooks(query, stage)` 检索，再用 `read_vuln_playbook(vuln_type)` 精确取需要的条目。索引和方法论不作漏洞结论，不把全库加入开局上下文。
3. 整理验证矩阵：目标/入口、前置账户、待验证假设、预期正常行为、最小测试、正反对照、停止条件、证据位置。未满足前置条件记录为“未测试”，不得记作安全或漏洞已确认。
4. 仅使用当前会话提供的工具。方法论返回的 `tool_status` 说明执行器及门控状态，`runtime_readiness=not_checked` 不代表探针、浏览器或带外服务已经联通。

## 可交付证据
每个观察记录目标、时间、会话、身份角色、脱敏请求/响应、完整性及工具日志标识。跨角色比较使用自有测试对象和最少数据。错误页、超时、拦截页和截断响应不足以证明漏洞存在或不存在。

## 退出与交接
以已覆盖/未覆盖/阻塞原因和剩余假设交接。存在目标状态变化时重新建立基线；有副作用的验证需事先定义恢复操作与验证点，完成后转 `post_assessment`。

参考：[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final)，本条为结合平台接口编写的评估流程。
