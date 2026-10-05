# Watchtower Windows ·172

> `main` contains **v1.21.172 Web source**. [Independent Windows source](https://github.com/LINGYK352/Watchtower/tree/codex/windows) and [both downloads](https://github.com/LINGYK352/Watchtower/releases/tag/v1.21.172) share release172. Website: [watchtowers.info](https://watchtowers.info/). Development began **June 3, 2026**. Original code: **GPL-3.0-only**.

## Choose your workspace

| Product | Designed for | Installation and updates |
| --- | --- | --- |
| Web | Long tasks, stable server execution, centralized deployment and remote browser access across platforms | Linux x64 / Docker; one-command setup and sequential updates after the171 guardian |
| Windows | Immediate local work, a native window and desktop access | One complete setup EXE with necessary components; independent local services and Windows updates |

172 introduces offline-prepared common and platform change ZIPs, including adjacent inverse packages. Verify both before committing; preserve configuration, tasks and browser data, show durable progress and failures, and resume interrupted downloads. An independent Web guardian preserves sequential updates after historical rollback and cold recreation. Sources, builds and extension channels are independent; version numbers and registration/activation accounts are shared.

Windows bundles Python, MongoDB, the proxy, Chromium and persistent browser, HTTPx, Nuclei, DNSX, native TCP/HTTP/TLS identification and NPoC. No manual Python/Docker/WSL deployment. Missing WebView2 is prepared automatically from Microsoft and publisher-verified. Windows11 was tested; Windows10 was not tested on a real machine. See [platform boundaries](docs/platforms.md).172 is the first public Windows release.

Validation covers37 menus per product, language switching and asset actions, actual Windows updates/rollback, a six-hop Web rollback to170 and six-hop return after cold recreation, three-worker readiness, actual proxy traffic, bundled/persistent browsers, native tools, extension isolation, interrupted transfers, tamper rejection, transaction recovery and process concurrency. No paid model calls. See [delivery](docs/update-delivery.md) and [English changelog](CHANGELOG.en.md). The image base remains165 and is tracked separately.


Source branch: `codex/windows`; exact source tag: `windows/v1.21.172`. Build: `windows_native/build.py`; complete installer builder: `release_tools/build_complete_setup.py`. Keep app/runtime separate from user state.
