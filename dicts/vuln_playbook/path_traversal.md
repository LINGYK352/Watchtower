---
type: 路径遍历
aliases: 目录遍历, path traversal, directory traversal, LFI, RFI, 文件包含, 任意文件读取, 任意文件下载, 文件读取, 文件下载
---

# 路径遍历 / 文件读取下载 / 文件包含

> 思路参考,非清单。`../` 编码绕过/LFI→RCE(日志/session/wrapper)等技法你已具备且可 web_search 补,这里只补【哨兵工具编排 + 验证判据 + 读什么最值钱】。

## 先判这是不是文件读取面
`file/path/filename/filepath/dir/download/read/template/page/include/doc` 参数;下载/预览/导出/模板加载/头像读取功能。`fetch_sourcemap`/`collect_js` 挖前端的文件读取接口。

## 读什么最值钱(比 /etc/passwd 有用)
优先读应用配置拿凭证:`WEB-INF/web.xml`、`application.yml`、`.env`、`config.php`、`database.yml`——直接给数据库连接串/密钥。其次读源码(反编译看逻辑)、备份、数据库文件。

## 哨兵工具怎么打(独有价值)
- **下大文件提数据**:读到的源码/备份/db 用 `fetch_large_file` 下载沙盒 grep 敏感数据。
- **读到源码接代码审计**:`record_stack` 精确指纹→`get_code_audit` 看源码层已知洞。
- **查组件已知任意文件读**:`query_vuln_intel`(FE/致远/泛微/金蝶多有,记忆库有对应 POC)。
- **串联**:读到的凭证/连接串 `write_exploit_clue` 回写。

## 什么算 confirmed(服务证据强制)
响应有目标文件真实内容(passwd 的 `root:x:0:0`、配置的真实连接串/密钥、源码真实内容)。仅路径参数存在、报错但没读到内容→降线索。

## 定级要点
读到凭证/密钥/源码=`C:H` 高;LFI→RCE=critical;仅读公开静态文件=低。
