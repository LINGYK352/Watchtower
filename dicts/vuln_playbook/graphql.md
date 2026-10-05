---
type: GraphQL 攻击
aliases: GraphQL, graphql, gql, 图查询, introspection, 内省查询
stage: validation
entry_points: [GraphQL, resolver, schema, 字段权限]
cwe_ids: [CWE-639, CWE-200, CWE-770]
owasp_id: A01:2021
severity_base: high
chains_with: [idor, auth_bypass, unauthorized, sqli]
tech_stack: [web]
---

# GraphQL 攻击

> 思路参考，非清单。GraphQL 的攻击面核心：一个端点暴露全部数据模型（introspection）+ 客户端自由拼查询，越权和资源耗尽比 REST 更隐蔽。

## 先判这是不是 GraphQL 面
路径含 `/graphql`、`/api/graphql`、`/query`、`/gql`；请求体是 `{"query":"..."}`；响应 `{"data":..,"errors":..}` 结构。前端 JS 里出现 `__typename`、`query {`、`mutation {` 也是信号（可用 `browser_resources` 挖）。

## 瞭望塔工具怎么打（独有价值）
- **introspection 拉全 schema**：`http_request` POST introspection 查询（`{__schema{types{name fields{name}}}}`）——若返回完整类型/字段，等于拿到整个数据模型和所有可调 query/mutation，据此定向找越权点。生产环境本该关闭 introspection，开着即信息泄露。
- **越权数据访问**：从 schema 找按 id 取对象的 query（`user(id:)`/`order(id:)`），`http_request` 换他人 id 拉数据——GraphQL 常缺对象级授权（等价 IDOR）。
- **批量/嵌套放大**：用 alias 批量（`a:user(id:1) b:user(id:2)...`）或深层嵌套查询做资源耗尽 DoS 探测；用 `run_script` 生成大批 alias 查询压测（保守/探测模式下只做轻量验证，别真打垮）。
- **mutation 越权操作**：schema 里的 `mutation` 是写操作（改密/转账/改角色），逐个试是否缺鉴权——写操作走闸刀校验。
- **注入下探**：GraphQL 参数最终进后端查询，`'`/`sleep()` 试 SQLi（转 `read_vuln_playbook sqli`）。


## 验证与反证
内省可用并不等于越权。建立角色、对象和字段三级矩阵，用自有对象比较不同身份的 resolver 结果；错误信息、字段 null 和真正返回受保护字段分开记录。

## 修复与复测
在每个 resolver 校验对象与字段权限，合理限制查询复杂度；复测查询/变更/关联字段和错误分支，不以关闭内省替代权限修复。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
