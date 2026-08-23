---
type: SQL注入
aliases: SQLi, sql injection, sql, NoSQL注入, nosqli, 注入
---

# SQL 注入

> 思路参考,非清单。分 DBMS 的取数函数/绕 WAF 变体你已具备且可 web_search 补,这里只补【哨兵工具编排 + 验证判据】。

## 先判这是不是注入面
有查询/搜索/排序/筛选/报表/id 参数的接口。数字型 `and 1=1` vs `and 1=2` 看差异,字符型 `'`/`"`/`')` 看报错。二阶注入(注册/改资料存进去、别处查询触发)容易漏——存的地方无回显别放过。

## 哨兵工具怎么打(独有价值)
- **时序盲注靠 http_request 的耗时**:`sleep(5)`/`pg_sleep(5)`/`waitfor delay` 后对比 http_request 返回的响应耗时与基线。
- **无回显/盲注靠带外**:`oob_generate` 拿域名→构造让 DB 主动解析的 payload(MySQL `load_file`/Oracle `utl_inaddr`)→`oob_check` 看收到解析=注入确认且已外带数据(高分)。
- **查已知注入**:`query_vuln_intel(组件)` 查该组件注入 CVE(国产系统用英文别名 seeyon/weaver/yonyou 再查一遍);有 exec_ref 直接 `run_nuclei`/`run_npoc` 精准验证。
- **复杂盲注**:`run_script` 沙盒跑 sqlmap 或自写逐位爆破脚本。

## 什么算 confirmed(服务证据强制)
响应有 SQL 报错特征(`SQL syntax`/`ORA-`/`Unclosed quotation`),或布尔真假两次响应稳定差异,或时序注入耗时稳定拉长,或 OOB 收到带数据的解析。光一个 `'` 打出 500 不够(可能普通异常)——要能证明注入语义被执行。

## 定级要点
能取数(库名/表/凭证)=`C:H`;能写/删加 `I:H`;能 RCE(xp_cmdshell/into outfile)转命令执行报。
