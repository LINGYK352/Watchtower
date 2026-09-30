---
type: 未授权访问
aliases: 未授权, unauthorized, 接口未授权, 匿名访问, 认证缺失
stage: validation
entry_points: [匿名访问, 管理接口, 导出, API权限]
cwe_ids: [CWE-306, CWE-862]
owasp_id: A01:2021
severity_base: high
chains_with: [idor, auth_bypass]
tech_stack: [web]
---

# 未授权访问

> 思路参考,非清单。这类洞技法简单,价值全在【发现哪些接口漏了鉴权】——瞭望塔工具正是干这个的。

## 先判这是不是未授权面
接口/功能该鉴权却没做,匿名或低权直接访问到。最容易漏鉴权的:
- **约定式路由接口**(字面量抠不到、浏览器真发起过的 `/api/xxx/GetList` 类)。
- 管理/调试端点(`/actuator/*`、`/druid/`、`/swagger-ui`、`/console`、`/metrics`、`.git/`、备份文件)。
- 导出/下载/统计接口(常只校验登录不校验权限)。

## 瞭望塔工具怎么打(独有价值,这类洞的主力链)
- **挖接口全集**:`browser_resources`(apis 字段拿浏览器真发起的接口)+`fetch_sourcemap` 还原源码拿接口全集和鉴权逻辑+已观察请求中的参数（`fuzz_params` 已全局禁用）。约定式路由接口后端最常漏鉴权。
- **逐个去 cookie 打**:对每个接口先**去掉 cookie 直接 GET**,200 且吐敏感数据=未授权确认;前端限制的功能直接调背后 API 绕前端。
- **拿大文件提数据**:actuator/heapdump 用 `fetch_large_file` 下载沙盒 grep 提取内存里的凭证/token/连接串。
- **组件检查边界**：`run_npoc` 在 AI 会话全局禁用；组件名称不是漏洞证据。已确认接口清单可经 `write_exploit_clue` 回写，须检查工具是否实际成功。


## 验证与反证
匿名请求必须去除全部身份材料，而非只去 cookie；还需检查 Authorization、API key、代理注入头和浏览器缓存。正常公开内容、静态壳页或登录页 200 均不是未授权敏感访问。

## 修复与复测
统一服务端鉴权和缺省拒绝策略；复测匿名、低权和合法账户的真实内容，覆盖详情、导出、批量与错误分支。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
