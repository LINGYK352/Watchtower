---
type: TLS 与敏感数据传输评估
aliases: TLS, HTTPS, 传输安全, 证书校验, HSTS, mixed content
stage: validation
entry_points: [HTTPS, TLS证书, HTTP跳转, 混合内容, 敏感传输]
cwe_ids: [CWE-319, CWE-295, CWE-326]
severity_base: medium
chains_with: [session_management, information_disclosure]
tech_stack: [web]
---

# TLS 与敏感数据传输

## 观察边界
记录访问路径是直连、代理还是 TLS 终止网关，确认实际被评估的主机名、端口和证书主体。扫描端时间错误或代理换证不能直接归责目标。

## 最小验证路径
核对浏览器的证书验证、HTTPS 跳转、敏感请求目的地与混合内容；协议和密码套件结论需要相应握手证据。平台通用 `http_request` 可能关闭证书校验，成功返回不代表证书有效，不能用其响应推断 TLS 合规。

## 验证与反证
缺少 HSTS、支持 HTTP、证书临近到期和实际明文传输是不同事实。只在测试账户和无真实敏感内容的请求上核对传输路径；仅凭缺头或版本推断不报告明文凭据泄露。

## 修复与复测
修正证书链、主机名和有效期，按部署需求配置传输策略、重定向及安全 Cookie。复测正常客户端兼容性、各入口和跳转后的请求；缺少协议测量工具时明确未覆盖，不伪造套件清单。
