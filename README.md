# Watchtower Windows ·172

> `main` 展示 **v1.21.172 Web正式源码**；[Windows独立源码](https://github.com/LINGYK352/Watchtower/tree/codex/windows)与[双端下载](https://github.com/LINGYK352/Watchtower/releases/tag/v1.21.172)同步172。官网：[watchtowers.info](https://watchtowers.info/)。开发始于 **2026年6月3日**，原创代码 **GPL-3.0-only**。

## 选择你的工作方式

| 产品 | 适合的工作 | 安装与更新 |
| --- | --- | --- |
| Web | 服务器持续运行、长任务、集中部署；通过浏览器跨平台和远程访问 | Linux x64 / Docker，一条安装命令；171守门员后逐级热更新 |
| Windows | 及时开始、本机工作、原生窗口和桌面入口 | 完整安装EXE，自带必要基础组件；独立本地运行与Windows热更新通道 |

172将每级变动离线压缩成公共＋平台ZIP，预制逆向包，校验齐全才提交。配置、任务和浏览器数据保留；更新进度与失败原因可见，断流可继续。Web独立守护使历史回退和冷启动后仍可逐级续更。两端源码、构建与扩展独立，版本同步、注册激活账户共用。

Windows内置代理、Chromium与持久浏览器、HTTPx、Nuclei、DNSX、原创TCP/HTTP/TLS服务识别、NPoC及其依赖，不要求用户手工部署Python/Docker/WSL。缺少WebView2时安装器从微软官方源自动准备并验签。Win11实测，Win10尚未实机验证；Linux专属能力以[平台说明](docs/platforms.md)为准。Windows首次正式发布是172，无虚构的旧Windows下载。

验证：双端各37个菜单、语言切换和资产操作；真实Windows热更新/回退；Web六级历史回退、170冷重建再六级续更、三worker就绪；代理真实流量、打包浏览器与持久Cookie、原生工具、扩展隔离、断流/篡改/事务/并发检查。未调用付费模型。见[更新机制](docs/update-delivery.md)和[更新日志](CHANGELOG.md)。镜像基板仍为165，与源码版本分别维护。


Source branch: `codex/windows`; exact source tag: `windows/v1.21.172`. Build: `windows_native/build.py`; complete installer builder: `release_tools/build_complete_setup.py`. Keep app/runtime separate from user state.
