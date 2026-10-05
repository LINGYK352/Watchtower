---
type: 原型链污染
aliases: 原型链污染, prototype pollution, proto 注入, __proto__, 原型污染
stage: validation
entry_points: [对象合并, 原型, JSON, 嵌套属性]
cwe_ids: [CWE-1321, CWE-915]
owasp_id: A08:2021
severity_base: high
chains_with: [rce, xss, ssti]
tech_stack: [web]
---

# 原型链污染

> 思路参考，非清单。核心：Node.js/JS 后端把用户 JSON 递归合并进对象时，`__proto__`/`constructor.prototype` 键污染 Object 原型，全局生效——可致属性注入、绕过校验、DoS，配合特定 gadget 甚至 RCE/SSTI。

## 先判这是不是原型污染面
后端是 Node.js/JS（响应头 `X-Powered-By: Express`、JS 报错栈、`.json` 深合并配置）。接收 JSON 且做对象合并/克隆/set-by-path 的接口：批量更新、配置保存、嵌套表单。

## 瞭望塔工具怎么打（独有价值）
- **污染探测**：`http_request` 在 JSON body 注入 `{"__proto__":{"pollutedKey":"pwned"}}` 或 `{"constructor":{"prototype":{"pollutedKey":"pwned"}}}`，然后看后续无关请求/响应里是否莫名出现了 `pollutedKey`（原型被污染后所有对象都继承了它）。有的目标会在响应里回显、有的靠副作用。
- **状态反射验证**：污染一个会影响服务行为的键（如 `{"__proto__":{"status":500}}` 或已知框架 gadget），`http_request` 再发正常请求看行为是否被全局改变——这比找回显更可靠。
- **升级利用**：`run_script` 结合已知 gadget 链尝试升级——Node 环境下污染 `NODE_OPTIONS`/子进程参数可能 RCE；模板引擎场景可能转 SSTI（`read_vuln_playbook ssti`）；前端 DOM 原型污染可转 XSS（`xss`）。
- **查组件 gadget**：`query_vuln_intel(组件/库名)` 查该 JS 库的原型污染 CVE 与已知利用链。


## 验证与反证
输入包含特殊属性、页面报错或单对象属性变化不等于共享原型污染。用隔离测试对象观察与输入对象无关的新对象是否受影响；客户端与服务端影响分开，不把污染等同于 RCE。

## 修复与复测
拒绝危险键、限制深层合并及属性遍历，更新存在缺陷的依赖；复测合法嵌套数据、新对象属性和进程内残留状态。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
