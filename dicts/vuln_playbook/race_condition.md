---
type: 竞态条件
aliases: 竞态条件, race condition, TOCTOU, 并发漏洞, 条件竞争, 超发, 重复提交
stage: validation
entry_points: [并发, 订单, 优惠券, 一次性操作, 回调]
cwe_ids: [CWE-362, CWE-367]
owasp_id: WSTG-BUSL-04
severity_base: high
chains_with: [business_logic, rate_limit_bypass]
tech_stack: [web]
---

# 竞态条件 / TOCTOU

> 思路参考，非清单。核心：「检查」和「使用」之间有时间窗，同一时刻并发多个请求让校验失效——典型是余额/库存/优惠券只校验一次却被用多次。

## 先判这是不是竞态面
涉及「先查后改」的有状态操作：提现/转账（查余额→扣款）、兑换（查次数→发放）、投票/点赞（查是否投过→计数）、库存下单、优惠券核销、一次性 token 使用。单请求看着有校验，但校验与落库非原子就有窗口。

## 瞭望塔工具怎么打（独有价值）
- **并发同发探测**：`run_script` 里用脚本对同一操作**并发**发 N 个相同请求（Python `threading`/`asyncio` 或 `curl` 后台并发），关键是让它们几乎同时到达、抢在第一个落库前。对比「预期只成功 1 次」vs「实际成功 M 次」。
- **单包多请求（HTTP/2）**：目标支持 HTTP/2 时，`run_script` 用单 TCP 连接一次性推多个请求（last-byte-sync），把时间窗压到最小，比多连接更易命中。
- **状态核对**：竞态后用 `http_request` 查最终状态（余额/次数/库存），证明「校验被绕过的次数 > 1」。
- **结合限速绕过**：若有频控挡并发，先看 `read_vuln_playbook rate_limit_bypass`。


## 验证与反证
先验证串行重复操作应产生什么结果，再在约定低并发测试窗口核对最终持久化不变量。重复的成功响应可能只是幂等返回，不能直接计为多次收益。记录请求关联号与最终账本/状态。

## 修复与复测
把检查与写入放进原子事务，使用唯一约束及业务幂等；复测重复提交、并发、超时重试和回调乱序，保证只产生一次有效变更。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
