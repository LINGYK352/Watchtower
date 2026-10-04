# AI console and findings / AI控制台与漏洞闭环

Takeover confirmation is saved per session. An empty-target whiteboard waits for an explicit instruction. UI replies are saved separately from compacted model context, using stable message identities; repeated instructions remain separate turns. Reconnects restore a canonical session snapshot.

The system setting supplies an unknown-model context fallback. Native mode resolves explicit provider metadata, model suffixes and known model limits; a protocol name does not imply a model window. The API window remains finite.

Findings are recorded as leads immediately. Actual tool evidence is assessed by vulnerability type. Where needed, the system attempts one safe, scoped read verification through the existing mode, proxy and cancellation controls. It does not automatically replay arbitrary model-provided scripts or write requests. Insufficient evidence remains a lead; failed verification is explicit. Endpoint plus normalized vulnerability type is unique across sessions; evidence and provenance are merged, and historical duplicate aliases remain auditable.

Script syntax is checked before execution. Nonzero exit codes and timeouts remain failures; cancellation and timeouts clean up only the tool's owned process tree. The UI shows tool name, elapsed time and timeout, rather than implying execution has succeeded merely because text was returned.

接管确认以会话持久状态为准；空目标白板待命。每次指令和答复独立保存，显示记录不随模型上下文压缩删除。多进程以数据库状态和唯一身份保持一致，不靠前端或单个worker缓存兜底。

漏洞线索立即入库，只有真实证据成立才确认；同接口同类漏洞唯一，同接口不同类型仍分开。报告预览过滤脚本、事件属性和外部资源，Word精确打印布局以下载文档为准。

Code and built frontend assets use the existing Web hot-update channel. No user configuration migration or new image dependency is required. The existing169 updater may automatically restart application services when applying backend code; this release does not claim container-free runtime reload.
