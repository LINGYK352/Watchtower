---
type: WebSocket 攻击
aliases: WebSocket, websocket, ws, wss, CSWSH, 跨站 WebSocket 劫持, 实时通信漏洞
stage: validation
entry_points: [WebSocket, 消息订阅, 实时通知, 双向连接]
cwe_ids: [CWE-346, CWE-352, CWE-306]
owasp_id: A01:2021
severity_base: high
chains_with: [cors, auth_bypass, idor, xss]
tech_stack: [web]
---

# WebSocket 攻击

> 思路参考，非清单。核心：WebSocket 握手不受同源策略约束、常缺 Origin 校验和消息级鉴权——CSWSH（跨站 WebSocket 劫持）能借受害者 Cookie 建连，消息通道又常是越权/注入的隐蔽入口。

## 先判这是不是 WebSocket 面
`ws://`/`wss://` 连接；前端 JS 里 `new WebSocket(...)`（`browser_resources` 可挖）；聊天、通知、行情、协同编辑、实时面板功能。握手是带 `Upgrade: websocket` 的 HTTP 请求。

## 瞭望塔工具怎么打（独有价值）
- **握手 Origin 校验探测**：`http_request` 发握手请求（带 `Upgrade: websocket`+`Sec-WebSocket-Key`），改 `Origin` 为外部域看是否仍 101 切换成功——成功且握手只靠 Cookie 鉴权 = CSWSH 风险（攻击者页面可借受害者身份建连）。
- **消息级越权/注入**：`run_script` 用脚本建 ws 连接（Python `websocket-client`），发消息试——换他人 id 收不该收的数据（越权，转 `idor`）、发 `'`/`<script>`/模板 payload 试注入（消息内容常直接进 DB 或回显给其他在线用户 → 存储 XSS）。
- **鉴权缺失**：很多 ws 只在 HTTP 握手鉴权、连上后消息不再校验——`run_script` 连上后直接发敏感操作消息，看是否无需二次鉴权就执行。
- **CSWSH 验证**：`browser_*`/`run_script` 模拟攻击者页面跨域建连，证明能借受害者会话读数据/发消息。


## 验证与反证
握手 101 只说明建立连接，不代表能读/写受保护消息；对照身份、订阅对象、消息授权和令牌失效后的连接状态。平台通用 HTTP 工具不提供完整双向帧会话，缺失能力应标注未覆盖。

## 修复与复测
校验连接来源及消息级对象权限，令牌失效时按设计断开或重新认证；复测合法订阅、跨账户订阅、重连及消息重放。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
