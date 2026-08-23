---
type: 文件上传
aliases: 任意文件上传, file upload, 上传漏洞, webshell, 上传
---

# 文件上传

> 思路参考,非清单。扩展名/Content-Type/文件头/解析漏洞等绕过链你已具备且可 web_search 补,这里只补【哨兵工具编排 + 验证判据】。

## 先判这是不是上传面
头像、附件、导入、富文本图片、证件照、编辑器(kindeditor/ueditor/百度)、头图更换。`collect_js`/`browser_navigate` 抓上传接口(常 /upload /file /attach)。

## 哨兵工具怎么打(独有价值)
- **生成畸形文件**:`run_script` 沙盒造图片马/多后缀/畸形文件。
- **验隐藏参数**:`fuzz_params` 试上传接口的隐藏参数(有的靠 type 参数决定存哪/是否二次渲染)。
- **查组件已知上传洞**:`query_vuln_intel(组件)`(编辑器/OA/中间件常有);有 exec_ref 直接 `run_nuclei`/`run_npoc`。
- **串联**:传上去的 webshell 路径 `write_exploit_clue` 回写;getshell `record_chain_step`。

## 关键:上传成功 ≠ 有洞
必须证明**能访问 + 能解析**:上传后拿路径→`http_request` 访问→看脚本**真被执行**(phpinfo/命令回显/唯一标记),不是原样返回源码或 403。传不了脚本时,传能解析的其他类型证明缺陷(svg 带 XSS、xml 带 XXE)。

## 什么算 confirmed(服务证据强制)
上传的脚本被访问时**真执行了**(命令回显/phpinfo/唯一标记回显)=RCE 级 critical;仅能传任意类型但传不了可执行、也证明不了其他危害→降线索。

## 定级要点
getshell/RCE=critical;能覆盖他人文件/写敏感位置=高;仅无限制上传无法利用=中/低。
