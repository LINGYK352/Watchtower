---
type: eBPF 后渗透
aliases: eBPF 后渗透, ebpf, ebpf rootkit, 内核层, bpf 提权, 内核监控, 凭证嗅探
stage: post_exploitation
entry_points: [BPF, 内核观测, 程序加载, 检测覆盖]
cwe_ids: [CWE-250, CWE-269, CWE-522]
owasp_id: PTES-Post-Exploitation
severity_base: high
chains_with: [linux_postexploit, internal_pivot]
tech_stack: [internal]
---

# eBPF 权限与检测评估

## 适用条件
授权 Linux 评估中，已有明确主机身份与只读检查条件。核对内核观测能力的授权和审计边界，不能把已有 root 权限重新报告为提权漏洞。

## 最小评估路径
盘点已加载程序、挂载点、加载者、用途和变更来源，与平台/运维提供的受信清单对照。仅采集程序元数据，不采集真实用户口令或会话内容。在隔离测试环境使用已批准的无敏感采集测试程序，核对加载/卸载是否有审计与告警；生产侧只核对现有记录。

## 验证与反证
缺少告警需排除采集器离线、日志延迟、规则未覆盖及权限不足。未知程序、具备加载权限或一次无告警均不能单独证明隐蔽持久化成功。

## 修复与复测
收紧 BPF 加载权限与能力授予，维护受信程序清单和审计关联。复测合法观测组件工作、测试加载产生预期审计、卸载后无测试残留；保留日志。

## 定级与阶段交接
以具体权限配置和检测缺口的实际影响定级，完成后转 `post_assessment`；本条不提供隐藏进程、窃取凭据或植入持久化程序的步骤。
