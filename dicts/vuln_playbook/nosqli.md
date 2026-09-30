---
type: NoSQL 注入
aliases: NoSQL注入, nosqli, nosql injection, MongoDB注入
stage: validation
entry_points: [NoSQL, MongoDB, 查询对象, JSON筛选]
cwe_ids: [CWE-943]
severity_base: high
chains_with: [auth_bypass, idor]
tech_stack: [web]
---

# NoSQL 查询边界评估

## 适用条件
已通过源码、组件信息或当前错误信息确认存在非 SQL 查询构造。JSON 接口或 MongoDB 指纹本身不构成注入证据；本方法论独立于 SQL，不复用 SQL 报错或延时函数判据。

## 最小验证流程
用测试账户和自有数据建立正常查询基线，记录字段类型、可用查询功能及权限预期。通过 `http_request` 对照接口接受的字符串、数字、数组和对象类型，检查服务端是否把本应为值的数据解释成查询结构；每次只改变一个条件。字段不存在、格式错误及空输入分别作为负向对照。

## 验证与反证
确认结果需要证明查询语义或访问边界被改变，并排除接口设计本来允许的高级筛选、默认查询、缓存及分页差异。错误信息、匹配数量变化或 HTTP 200 单独不足以确认；不通过批量导出真实数据来证明影响。

## 修复与复测
限制输入类型与允许的查询结构，在服务端构建固定查询并独立校验对象权限，避免直接将请求对象透传数据库。复测正常筛选、类型边界、空值、嵌套对象和跨账户数据隔离。

## 定级与交接
只按已证明的数据或身份影响定级，使用 `query_finding_template` 查询平台口径；未确定后端类型则保持线索，完成后转 `post_assessment`。
