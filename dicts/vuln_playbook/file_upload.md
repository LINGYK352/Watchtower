---
type: 文件上传
aliases: 任意文件上传, file upload, 上传漏洞, webshell, 上传
stage: validation
entry_points: [上传, 附件, 头像, 文件导入]
cwe_ids: [CWE-434]
owasp_id: A04:2021
severity_base: critical
chains_with: [rce, path_traversal]
tech_stack: [web]
---

# 文件上传

> 思路参考,非清单。扩展名/Content-Type/文件头/解析漏洞等绕过链你已具备且可 web_search 补,这里只补【瞭望塔工具编排 + 验证判据】。

## 先判这是不是上传面
头像、附件、导入、富文本图片、证件照、编辑器(kindeditor/ueditor/百度)、头图更换。`browser_resources`/`browser_navigate` 抓上传接口(常 /upload /file /attach)。

## 瞭望塔工具怎么打(独有价值)
- **生成畸形文件**:`run_script` 沙盒造图片马/多后缀/畸形文件。
- **验隐藏参数**:从已观察请求或源码核对上传参数，`fuzz_params` 已全局禁用(有的靠 type 参数决定存哪/是否二次渲染)。
- **查组件已知上传洞**:`query_vuln_intel(组件)`(编辑器/OA/中间件常有);exec_ref 仅作为线索；AI 会话禁用主动扫描工具，不应自动调用或绕过门控。
- **串联**:传上去的 webshell 路径 `write_exploit_clue` 回写;getshell `record_chain_step`。

## 关键:上传成功 ≠ 有洞
必须证明**能访问 + 能解析**:上传后拿路径→`http_request` 访问→看脚本**真被执行**(phpinfo/命令回显/唯一标记),不是原样返回源码或 403。传不了脚本时,传能解析的其他类型证明缺陷(svg 带 XSS、xml 带 XXE)。


## 验证与反证
上传成功、文件可访问和服务端执行分别取证；用无执行能力的唯一标记文件核对真实存储和下载路径。文件名/扩展名变化或图片预览异常不证明代码执行；任何写入都记录文件归属与删除回执。

## 修复与复测
扩展名、媒体类型、文件内容及存储隔离联合校验，禁止上传目录执行；复测正常文件可用、异常文件被拒或安全下载，测试文件全部清理。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
