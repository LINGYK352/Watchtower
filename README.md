# Watchtower Windows ·175

> **v1.21.175 Web + Windows 正式版** · 开发始于 **2026年6月3日** · 原创代码 **GPL-3.0-only**。

## 选择你的工作方式

| 产品 | 适合的工作 | 安装与升级 |
| --- | --- | --- |
| Web | 长任务、稳定服务器运行、集中部署和跨平台远程访问 | Linux x64 / Docker；旧部署使用175新基板保数据修复安装 |
| Windows | 及时开始、本机工作、原生窗口和桌面入口 | 完整安装EXE供新用户；存量172约82 MiB逐级热更新175 |

175修复旧镜像控制代码与新Docker宿主不兼容引发的启动/更新故障。更新采用签名公共＋平台ZIP、固定目标、事务恢复和真实后台就绪确认；断流、提交中断和重启后可继续。Windows守护独立于业务源码，覆盖完整GUI/helper/DLL。双端175以下禁止回退，后续继续逐级更新。

Web旧用户结束运行任务并备份后，重新获取官网install.sh，选择**修复安装（2）**；保留账号、配置、数据库、任务、证据、浏览器和扩展数据。Windows不受此次Docker故障影响，存量用户使用热更新，无需下载完整EXE或重装。Win11已实测；Win10尚未实机验证，Linux专属工具边界保留，未消耗模型API。

[官网与安装](https://watchtowers.info/) · [175下载与日志](https://github.com/LINGYK352/Watchtower/releases/tag/v1.21.175) · [Windows源码](https://github.com/LINGYK352/Watchtower/tree/windows/v1.21.175) · [双端升级契约](docs/update-delivery.md)

