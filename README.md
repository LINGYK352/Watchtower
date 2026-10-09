# 瞭望塔 Watchtower

> **v1.21.176 · Web + Windows** · 开发始于 **2026年6月3日** · 原创代码 **GPL-3.0-only**。

[English](README.en.md) · [官网与安装](https://watchtowers.info/) · [176下载与日志](https://github.com/LINGYK352/Watchtower/releases/tag/v1.21.176)

| 产品 | 适合的工作 | 安装与更新 |
| --- | --- | --- |
| Web | 长任务、稳定服务器运行、集中部署和跨平台远程访问 | Linux x64 / Docker；175镜像基板安装，激活后逐级热更新176 |
| Windows | 及时开始、本机工作、原生窗口和桌面入口 | 新用户使用176完整EXE，可浏览选择安装目录；存量175用户热更新176，无需重装 |

176修复Windows页面文字选择、Ctrl+C、右键复制与缩放，增加安装器目录浏览；AI控制台支持文件上传、真实进度、取消和失败重试；通告区分系统/安装版本/平台，并按优先级依次弹窗；资源按实际数据盘余量与内存预算计算并发；改善不同DPI和窗口宽度下的界面比例。

控制台单文件最大16MiB，上传完成后发送指令；上传文件不会自行执行或调用模型。Windows已在本机Win11验证，Win10尚缺实机验收。Linux专属工具有平台边界，不能宣称全部原生等价；未验收Android原型不在此版。

更新使用构建端预制的签名公共/平台ZIP，升级与回退都逐级；配置、账号、任务、证据、浏览器资料和扩展属于用户数据。双端回退下限175，Web175基板不因普通代码更新而重复重建。

[Windows源码](https://github.com/LINGYK352/Watchtower/tree/windows/v1.21.176) · [交付契约](docs/update-delivery.md) · [许可](LICENSE) · [安全说明](SECURITY.md)
