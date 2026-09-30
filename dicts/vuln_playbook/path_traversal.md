---
type: 路径遍历
aliases: 目录遍历, path traversal, directory traversal, LFI, RFI, 文件包含, 任意文件读取, 任意文件下载, 文件读取, 文件下载
stage: validation
entry_points: [下载, 文件预览, 导出, 文件路径]
cwe_ids: [CWE-22, CWE-98]
owasp_id: A01:2021
severity_base: high
chains_with: [file_upload, rce, ssrf]
tech_stack: [web]
---

# 路径遍历 / 文件读取下载 / 文件包含

> 思路参考,非清单。`../` 编码绕过/LFI→RCE(日志/session/wrapper)等技法你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据 + 读什么最值钱】。

## 先判这是不是文件读取面
`file/path/filename/filepath/dir/download/read/template/page/include/doc` 参数;下载/预览/导出/模板加载/头像读取功能。`fetch_sourcemap`/`browser_resources` 挖前端的文件读取接口。

## 读什么最值钱(比 /etc/passwd 有用)
优先读应用配置拿凭证:`WEB-INF/web.xml`、`application.yml`、`.env`、`config.php`、`database.yml`——直接给数据库连接串/密钥。其次读源码(反编译看逻辑)、备份、数据库文件。

## 瞭望塔工具怎么打(独有价值)
- **下大文件提数据**:读到的源码/备份/db 用 `fetch_large_file` 下载沙盒 grep 敏感数据。
- **读到源码接代码审计**:`record_stack` 精确指纹→`get_code_audit` 看源码层已知洞。
- **查组件已知任意文件读**:`query_vuln_intel`(FE/致远/泛微/金蝶多有,记忆库有对应 POC)。
- **串联**:读到的凭证/连接串 `write_exploit_clue` 回写。


## 验证与反证
需要已知的自有测试文件与预期允许根目录作为对照。文件路径回显、404 或通用错误不是越界读取证据；比对文件唯一标记及真实解析路径，区分网关规范化与应用处理。

## 修复与复测
在规范化后校验真实路径属于允许根目录，使用对象标识代替任意路径；复测合法文件、越界路径、符号链接及平台路径分隔差异。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
