---
type: LDAP 与 XPath 查询注入评估
aliases: LDAP注入, XPath注入, ldap injection, xpath injection
stage: validation
entry_points: [目录查询, LDAP, XPath, XML查询, 用户搜索]
cwe_ids: [CWE-90, CWE-643]
severity_base: high
chains_with: [auth_bypass, information_disclosure]
tech_stack: [web, internal]
---

# LDAP 与 XPath 查询边界

## 入口识别
从已知目录服务、用户搜索、XML 查询或源码确认查询语言，区分 LDAP 过滤器与 XPath 表达式。登录页或 XML 输入本身不足以证明使用相应后端。

## 假设与最小验证
以测试目录/文档中的自有对象建立查询基线，记录正常匹配、无匹配及类型错误时的结果。围绕“用户值是否改变查询结构”形成单一假设，采用无敏感数据的正负对照；条件允许时将结果与服务端查询日志或代码构造路径对应。

## 验证与反证
特殊字符导致错误、不同匹配数量或响应耗时变化只说明输入影响处理。应排除正常模糊查询、默认过滤、编码转换、缓存和权限变化；必须证明越过了预期查询/访问边界，不能根据 SQL 注入判据直接归类。

## 修复与复测
使用适配查询语言的安全构造方式和严格类型校验，LDAP 过滤器与 DN 场景分别采用正确转义；避免把用户数据拼接成表达式。复测正常搜索、特殊字符、空值、无匹配及跨账户隔离。
