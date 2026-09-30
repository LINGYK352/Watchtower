---
type: 内网横向
aliases: 内网渗透, internal pivot, 横向移动, lateral movement, 内网立足, 后渗透, pivot
stage: post_exploitation
entry_points: [立足点, 内网服务, 路由, 网络分段]
cwe_ids: [CWE-284]
owasp_id: PTES-Post-Exploitation
severity_base: critical
chains_with: [rce, ad_security, kerberos, windows_postexploit, linux_postexploit]
tech_stack: [internal]
---
# 内网立足 / 后渗透方法论（internal pivot）

> 面向瞭望塔「内网立足」工具链（foothold_register / foothold_exec / internal_recon / internal_portscan /
> harvest_creds）。**前提**：你已通过 Web 层漏洞（RCE/命令注入/webshell 上传/反序列化等）**合法拿到命令
> 执行落点**。这些工具不替你打点、不植入常驻后门——它们把你已控的 Web 点当跳板，帮你看清内网、执行命令、
> 探端口、收凭据。**仅红队/授权模式可用；只在客户明确授权的内网范围内使用。**

## 何时进入内网立足

- 已拿到稳定的命令执行（`id` 能回显、能读文件）。
- 目标是内网纵深（域内横向、内部系统、数据库），而非仅当前 Web 应用。
- 边界 Web 已挖透，价值在内网。

## 标准流程

### 1. 登记落点（foothold_register）
把已控命令执行点固化下来，后续工具复用。关键是找准**命令注入位**与**回显提取**：
- `url` 里放 `{cmd}` 占位（如 `http://t/shell.php?c={cmd}`），`inject=url`。
- 若命令走 POST body：`inject=body`，body 含 `{cmd}`。
- 若走 header：`inject=header` + `header_name`。
- **回显包裹**：webshell 常把输出夹在标记间（如 `echo START;{cmd};echo END`），给 `marker` 让工具精确提取，避免被页面 HTML 噪音淹没。
- 必须 `authorized=true` 自证——这是授权范围内合法取得的落点（会进拦截日志留痕）。

### 2. 信息收集（internal_recon）
一把梭收集内网拓扑线索：`hostname/id`、`/etc/hosts`、网卡（`ip a`）、路由（`ip route`）、ARP 邻居、监听端口。
重点看：
- **当前身份**：是不是 root/高权限？在容器里还是物理机？
- **内网网段**：网卡 IP + 路由揭示的内网段（10./172.16-31./192.168.）——工具会自动粗提。
- **本机监听**：可能有只绑 127.0.0.1 的内部服务（数据库/管理端口），从落点本地可直连。

### 3. 判定范围，再动手（合规）
`internal_recon` 探到的内网段**不代表授权你打整个内网**。先判断哪些在授权 scope 内，越界目标要经闸刀/人工确认。红队交付按客户授权范围走。

### 4. 内网端口探测（internal_portscan）
对判定为目标的内网 IP 扫端口。用落点主机自带 `bash /dev/tcp`（不上传扫描器二进制，轻、隐蔽、不落地）。
常见高价值端口：22(SSH)/445(SMB)/1433(MSSQL)/3306(MySQL)/6379(Redis 常未授权)/3389(RDP)/8080-8443(内部 Web)/9200(ES)。

### 5. 凭据收集（harvest_creds）
只读搜集落点主机上的凭据线索：`~/.bash_history`、环境变量、常见配置文件（.env / config.php / wp-config.php /
application.yml / db.conf）、SSH 私钥路径。命中疑似凭据（密码/token/私钥/连接串）自动写入共享情报池，
供本会话或**同单位其他会话**横向复用（A 点拿到的库密码 → B 点登录）。

### 6. 横向思路（用上面的工具组合，不做常驻）
- 拿到内网库口令 → 用 `foothold_exec` 经落点连内网库（`mysql -h 内网IP -u.. -p..` 回显）。
- 内网 Redis 未授权（6379 开放）→ 经落点 `redis-cli -h 内网IP` 尝试。
- 内网 Web 管理页 → 经落点 `curl 内网IP:端口` 看响应，判断能否顺着打。
- 找到新的可执行点 → 可再 `foothold_register` 登记为新落点，层层深入。

## 边界与铁律

- **只读优先**：先 recon/harvest（只读）摸清，再动写操作。
- **不常驻、不落地二进制**：所有能力都是经落点转发一条命令的无状态请求；不传扫描器、不装 beacon、不留后门。这是设计选择（合 3.6G 小机器 + 合规 + 隐蔽）。
- **破坏命令仍受闸刀**：rm -rf / 提权 / 清库等在非红队模式会被拦；红队模式放行但记录。
- **授权范围**：内网段不自动越界，客户授权外的目标不碰。
- **凭据是线索不是结论**：harvest 到的凭据需实际验证（登录成功）才算有效，写情报池标"待验证"。

## 验证与反证
已有执行点、路由可见、端口开放、认证成功和目标权限是不同层次，不应直接连成已确认路径。每一跳记录主机/主体/范围/时间与实际回执；发现新网段不自动扩展范围。

## 修复与复测
结合已证明路径收紧服务暴露、网络分段和身份权限；复测原路径受阻且正常管理功能可用，完成落点、测试凭据和临时文件的清理交接。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
