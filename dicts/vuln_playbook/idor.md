---
type: 越权访问
aliases: 越权, IDOR, BOLA, BFLA, 水平越权, 垂直越权, broken access control, 访问控制缺陷
stage: validation
entry_points: [对象ID, 订单, 附件, 导出, 租户]
cwe_ids: [CWE-639, CWE-284, CWE-863]
owasp_id: A01:2021
severity_base: high
chains_with: [auth_bypass, jwt, unauthorized]
tech_stack: [web]
---

# 越权访问 / IDOR / BOLA

> 这不是清单，是思路参考。目标的实际反应永远优先——按你在本目标看到的真实行为调整，别照搬。通用越权技法你已具备,这里只补【怎么用瞭望塔的手打 + 什么算真验证到】。

## 先判这是不是越权攻击面
带对象归属的接口才有越权:URL/body 里有 id/uid/oid/fileId/UUID、导出下载、批量 `ids=`、嵌套资源 `/orgs/1/users/2`、"我的xxx"类。没有归属概念的公开接口不算。

## 瞭望塔工具怎么打(独有价值)
- **两套身份是前提**:`browser_login` 各拿 A/B 一套 cookie;`read_exploit_clues` 看单位池有没有别站现成的凭证/工号可直接用。
- **挖隐藏的高权接口**:`browser_resources`(apis 字段)+`fetch_sourcemap` 还原前端角色判断逻辑和没暴露的 `/api/admin/*`——前端鉴权=假鉴权,拿这些接口直接换低权/匿名身份打。
- **抓登录后真实接口**:`browser_navigate` 带 B 的 cookie 访问 A 的资源页,抓渲染时真发起的 XHR(很多接口不访问页面拿不到)。
- **试隐藏归属参数**:从已观察请求或源码核对 id/uid/deptId；`fuzz_params` 已全局禁用，不自动猜测批量参数。
- **串联回写**:拿到的工号段/id 规律 `write_exploit_clue` 回写供同单位其他站用;打通一条链 `record_chain_step`。


## 验证与反证
用同租户两个自有账户及跨租户测试账户建立对象所有权矩阵；分别检查读、写、列表、导出和关联资源。只改 ID 后状态码相同不算越权，要核对对象归属与实际内容/状态变化。

## 修复与复测
将主体、租户、对象和操作联合做服务端授权，避免仅前端隐藏；复测本人对象可用、他人对象不可用、列表与导出无旁路。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
