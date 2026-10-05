---
type: 跨站请求伪造
aliases: csrf, cross site request forgery, 跨站请求伪造, 跨站操作
stage: validation
entry_points: [跨站请求, Cookie认证, 状态变更, 表单]
cwe_ids: [CWE-352]
severity_base: medium
chains_with: [session_management, cors, business_logic]
tech_stack: [web]
---

# 跨站请求伪造评估

## 适用条件与假设
存在浏览器自动附带认证材料的状态变更接口。先确认身份如何传递、接口是否真的修改状态，以及应用对跨站操作的预期；没有 CSRF 参数并不直接构成漏洞。

## 最小验证流程
使用测试账户和可恢复的自有对象建立正常操作基线；在隔离的第二来源测试浏览器实际请求是否携带认证信息，以及服务端是否接受。记录方法、来源、Cookie 策略和实际状态变化。手工 `http_request` 能发出请求不证明浏览器能跨站发起相同请求。

## 验证与反证
CORS 响应可读性与 CSRF 的状态变更不同。请求被发送但鉴权失败、浏览器没有携带 Cookie、服务端 token/Origin 校验生效或只产生无状态回显时，不确认 CSRF。最终状态读取需来自独立正常会话。

## 修复与复测
采用与会话绑定的防伪机制，核对来源，合理配置 Cookie 并避免 GET 修改状态。复测正常表单/接口、跨站拒绝、失效令牌、登录状态变化，恢复测试对象。
