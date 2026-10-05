---
type: JWT 攻击
aliases: JWT, jwt, json web token, token 伪造, alg none, 令牌伪造, jwt 越权
stage: validation
entry_points: [JWT, Bearer, 签名, 令牌]
cwe_ids: [CWE-347, CWE-345, CWE-287]
owasp_id: A07:2021
severity_base: high
chains_with: [idor, auth_bypass, unauthorized]
tech_stack: [web]
---

# JWT 令牌攻击

> 思路参考，非清单。JWT 的价值在「拿到一个合法 token 后能不能伪造成别人/更高权限」——伪造成功往往直接账号接管或垂直越权。

## 先判这是不是 JWT 攻击面
响应头/Cookie/localStorage 里出现 `eyJ` 开头的三段式串（`header.payload.signature`）即是 JWT。base64 解 header 看 `alg`（HS256/384/512 对称，RS/ES/PS 非对称），解 payload 看有没有 `role`/`uid`/`isAdmin`/`exp` 这类可篡改的越权字段。有认证态的接口都值得看 token 怎么签的。

## 瞭望塔工具怎么打（独有价值）
- **弱密钥爆破（HS 系）**：直接用 `jwt_crack` 工具——传完整 token，本地字典爆 HS256/384/512 签名密钥（内置约 12 万弱密钥字典，离线纯计算零流量）。命中弱密钥即可用它重签任意 payload 伪造越权。
- **alg:none 绕过**：`run_script` 里把 header 的 `alg` 改成 `none`/`None`/`nОne`（大小写/同形字变体）、去掉 signature 段，重新 base64 组装，用 `http_request` 带上试——后端若信任 alg=none 则无需签名即接受伪造 token。
- **key confusion（RS→HS）**：拿到服务公钥（`/jwks.json`、证书、`/.well-known/`）后，`run_script` 用公钥当 HS256 的密钥重签 token——后端若用同一验签函数、未固定算法，会把公钥当对称密钥验过。
- **claim 篡改验证**：伪造后用 `http_request` 打需鉴权的接口（换成他人 uid/提权 role），对比响应确认越权生效。
- **查已知实现缺陷**：`query_vuln_intel(组件)` 查该框架/中间件的 JWT CVE。


## 验证与反证
可解码 JWT 不等于签名可伪造；发现弱密钥或修改声明也不代表服务端接受。用测试账户对照合法、失效及篡改令牌的认证结果，记录服务端真实主体而非只看返回码。

## 修复与复测
固定算法和密钥来源，验证签名、颁发者、受众与时效，落实密钥轮换；复测合法令牌、过期令牌、错误受众和注销后的状态。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
