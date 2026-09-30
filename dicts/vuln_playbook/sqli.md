---
type: SQL注入
aliases: SQLi, sql injection, sql, SQL注入
stage: validation
entry_points: [查询, 搜索, 排序, 筛选, 报表, SQL]
cwe_ids: [CWE-89]
owasp_id: A03:2021
severity_base: critical
chains_with: [auth_bypass, rce]
tech_stack: [web]
---

# SQL 注入

> 思路参考,非清单。分 DBMS 的取数函数/绕 WAF 变体你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是注入面
有查询/搜索/排序/筛选/报表/id 参数的接口。数字型 `and 1=1` vs `and 1=2` 看差异,字符型 `'`/`"`/`')` 看报错。二阶注入(注册/改资料存进去、别处查询触发)容易漏——存的地方无回显别放过。

## 瞭望塔工具怎么打(独有价值)
- **时序线索**：先明确可复用的时间观测来源与正常基线；当前 `http_request` 不提供 elapsed 字段，没有可信时间证据时不得推断延时注入。
- **带外线索**：`oob_generate` 返回 domain 与 cookie，`oob_check(domain,cookie)` 查询关联解析。出现记录只说明该域名被解析，不能据此推断数据库执行或数据外带。
- **查已知注入**:`query_vuln_intel(组件)` 查该组件注入 CVE(国产系统用英文别名 seeyon/weaver/yonyou 再查一遍);exec_ref 仅作为线索；AI 会话禁用主动扫描工具，按当前可用工具和证据条件安排验证。
- **验证受阻**：记录前置条件、响应完整性与未排除因素；不使用 `run_script` 绕过已禁用的主动扫描工具。


## 验证与反证
数据库错误只支持线索，需正负对照证明输入改变查询语义；页面差异要排除随机内容、缓存和身份变化。单次延时不确认盲注；当前 http_request 不提供专用 elapsed 字段，不得臆造耗时证据。

## 修复与复测
值参数使用绑定查询，动态排序/表名使用允许列表；复测合法查询、空值/边界类型、异常输入和不同角色数据隔离。SQL 与 NoSQL 分别评估，不套用同一判据。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
