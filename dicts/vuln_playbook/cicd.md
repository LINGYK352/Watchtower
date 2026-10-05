---
type: CI/CD 攻击
aliases: CI/CD 攻击, cicd, ci/cd, 流水线攻击, github actions, gitlab ci, jenkins, 供应链, pipeline injection, 密钥泄露 ci
stage: validation
entry_points: [流水线, 仓库, 构建, 发布, 工件]
cwe_ids: [CWE-1104, CWE-522, CWE-94]
owasp_id: A08:2021
severity_base: critical
chains_with: [cloud_assessment, aws_postexploit, rce]
tech_stack: [cloud]
---

# CI/CD 流水线攻击

> 思路参考，非清单。合「只读评估」与「攻击」：先查流水线配置暴露面（可注入的 workflow、泄露的 secret），再验证能否在流水线里执行代码窃取密钥/污染产物（供应链）。授权范围内。经 http_request / run_script / agent 执行。

## 先判这是不是 CI/CD 面
仓库里有 `.github/workflows/*.yml`、`.gitlab-ci.yml`、`Jenkinsfile`、`.drone.yml`；暴露的 Jenkins(8080)、GitLab、构建产物仓库、artifact registry。有仓库写权限或能提 PR。

## 瞭望塔工具怎么打（独有价值）
- **流水线配置审计（只读）**：`run_script`/`browser_resources` 拉 workflow 文件——找危险触发（`pull_request_target` + 检出 PR 代码 + 用 secret = 经典 GitHub Actions 提权点）、未固定版本的第三方 action（供应链）、`${{ github.event.* }}` 直接进 shell（脚本注入）。
- **脚本注入（pipeline injection）**：workflow 把不可信输入（PR 标题/分支名/issue 评论）拼进 `run:` 命令时，构造恶意输入在 runner 上执行代码——`http_request` 提带 payload 的 PR/issue，观察 runner 是否执行（授权仓库上验证）。
- **Secret 窃取**：拿到流水线执行后，`run_script` 在 runner 上 dump 环境变量/`$GITHUB_TOKEN`/云凭证（`printenv`、读 `/proc/self/environ`）——CI 里常挂着高权部署凭证。偷到即转对应 `*_postexploit`。
- **产物/供应链污染**（授权演练）：验证能否篡改构建产物、往制品库推恶意包——须明确授权、可回滚。
- **Jenkins 未授权**：`http_request` 打 Jenkins 未授权 script console（`/script`）直接 Groovy RCE（转 `rce`）。


## 验证与反证
核对代码来源、触发事件、执行身份和密钥暴露边界；流水线配置出现敏感权限不等于已被滥用。用测试仓库/分支与无敏感内容的标记确认执行边界，区分受信分支与外部贡献。

## 修复与复测
限制令牌和执行器权限，隔离不可信构建与发布凭据；复测外部贡献不能读取受保护资源，正常发布仍通过，并移除测试工件与分支。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
