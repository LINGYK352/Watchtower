---
type: Kubernetes 攻击
aliases: Kubernetes 攻击, k8s, kubernetes, 容器编排, kubelet, apiserver, pod 逃逸, rbac 提权, k8s 后渗透
stage: validation
entry_points: [Kubernetes, Pod, namespace, ServiceAccount, kubelet]
cwe_ids: [CWE-284, CWE-269, CWE-16]
owasp_id: A05:2021
severity_base: critical
chains_with: [cloud_assessment, linux_postexploit, internal_pivot]
tech_stack: [cloud, internal]
---

# Kubernetes 攻击

> 思路参考，非清单。合「只读评估」与「后渗透」两段：先只读查暴露面（未授权 API/kubelet），拿到 token/pod 内执行后再摸 RBAC 提权与 pod 逃逸。授权范围内。经 http_request / run_script / agent_exec 执行。

## 先判这是不是 K8s 面
暴露的端口：apiserver(6443/8443)、kubelet(10250/10255)、etcd(2379)、dashboard、NodePort 服务。或已在一个 pod 内（`/var/run/secrets/kubernetes.io/serviceaccount/` 存在、环境变量 `KUBERNETES_SERVICE_HOST`）。

## 瞭望塔工具怎么打（独有价值）
- **只读暴露面**：区分 API 发现、资源读取和执行操作；匿名 `/api` 响应不证明可以读取 pod/secret，按 namespace 与对象权限分别核对。
- **ServiceAccount 权限核对**：使用客户提供的测试身份和明确集群上下文核对权限，区分平台执行环境与目标 pod；`run_script` 读取的是平台侧文件，不能当作目标 pod token。
- **RBAC 提权**：SA 权限过大时提权原语——`create pods`（起特权 pod 挂载宿主机盘/hostPID）、`create clusterrolebindings`（给自己绑 cluster-admin）、`get secrets`（拉全集群密钥）、exec 进其他 pod。`run_script` 逐个验证。
- **Pod 逃逸到 Node**：特权容器/挂载 docker.sock/hostPath/危险 capability → 逃到宿主机（转 `linux_postexploit`）。
- **横向**：拿到 node/更高 SA 后打其他 namespace、连云元数据（转 `cloud_assessment`）。


## 验证与反证
匿名读取 /api 的发现信息不等于能读取业务资源。明确集群、namespace、ServiceAccount 与具体 verb/resource；容器内本地文件不能证明是宿主文件，策略允许结果也不等于实际资源操作成功。

## 修复与复测
收紧 RBAC 与资源暴露、隔离工作负载和宿主边界；复测正常服务账户所需操作、越界 namespace 拒绝与节点隔离，删除测试资源。

## 定级与阶段交接
以 `query_finding_template` 的当前定级口径及已验证影响为准；`severity_base` 与 `chains_with` 不是漏洞成立、提权成功或自动升级的证据。证据不足记线索，未覆盖写明原因；完成后转 `post_assessment` 核对残留、修复及复测。
