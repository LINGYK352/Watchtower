# Update delivery / 热更新契约

## Guardian transition171

171 replaces the old single-hop/latest fallback and transient continuation intent with a fixed target, durable cursor, a cross-process OS file lock, and per-hop readiness checks. Missing intermediate releases must stop rather than silently jumping to the latest. Only a historical installation below171 may bootstrap directly to the guardian.

Upgrade and rollback both follow adjacent releases. Same-version repair remains available. Rollback below171 is currently rejected before mutation: it would remove the new updater, and an independent persistent legacy guardian is not yet implemented. This is an explicit temporary boundary, not support for the entire historical rollback range.

The first installation of171 uses the existing delivery protocol. The old installed updater may restart application services. There are no new image dependencies. Later Web source changes use Gunicorn reload; the chain checks worker boot identities, database connectivity and frontend digest before advancing. State and progress are read from disk across workers, rather than trusting process-local flags. Interrupted commits are restored before application code imports.

## Prebuilt packages from172

The build machine prepares every adjacent forward AND reverse transition ahead of upload. Each hop has one common ZIP and one platform ZIP, signed plans, complete owned inventory, changes/removals and migration metadata. Normal packages contain the version's changed content, not the whole system. Shared members must have reviewed cross-platform compatibility and must not be duplicated in exclusive ZIPs. The distribution server validates, stores and serves prepared artifacts; it must not compare user files or build ZIPs on request.

Names: `Watchtower-common-vX.Y.Z-from-vA.B.C.zip`, `Watchtower-web-vX.Y.Z-update-from-vA.B.C.zip`, `Watchtower-win-vX.Y.Z-update-from-vA.B.C.zip`. Reverse transitions use the same target/from convention.172→171 also needs a prepared reverse package, not the legacy per-file route.

Requests report client OS, architecture, ABI and current version. Legacy requests without OS route only to Web; unknown/conflicting platforms are rejected. Windows and Web have separate product sources, build/update/extension channels, synchronized version numbers and shared registration/activation accounts. This171 release publicly ships Web only.

Both packages must be downloaded, verified and staged before any live file changes. Retain `.part` downloads for Range resumption. Reject signature/hash mismatches, path traversal, duplicate members, links, reserved names, excessive expansion and unsupported ABI. Never replace credentials, activation, user configuration, tasks or evidence. Remove only owned obsolete content; preserve user-modified files. A missing baseline produces a repair explanation, not a hidden fallback to per-file delivery.

## Progress and continuation

Show current version, fixed final target, current hop/total hops, phase, bytes and errors. Persist completed hops and cache state. Navigation, reload and connection resets must restore progress. Failure pauses the chain with a visible reason and resume action. Completion means the target application actually started, not merely that files were written.

## 中文要点与边界

旧单跳与短期认领会丢失续更信息，跨版本差异包也无法正确还原，因此改为相邻正向/逆向变更包、固定目标及持久事务。171为存量用户入口，172才正式切换公共＋专属ZIP。原来全历史版本回退能力目前被守门员安全边界限制：早于171的回退操作明确拒绝，独立守护方案列入下一阶段。

真实测试覆盖两端逐级升级/回退、三Web worker就绪、真实HTTP断流与续传、坏签名/摘要、归属删除和提交恢复。Windows只在Win11实测；Linux专属工具适配、Win10及Windows公开分发尚未完成。源码附件不包含外部工具和完整离线运行环境。
