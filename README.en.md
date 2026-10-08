# Watchtower Windows ·175

> **v1.21.175 Web + Windows** · Development began **June 3, 2026** · Original code **GPL-3.0-only**.

## Choose your workspace

| Product | Designed for | Installation and upgrades |
| --- | --- | --- |
| Web | Long tasks, stable server operation, centralized deployment and cross-platform remote access | Linux x64 / Docker; existing deployments repair-install the175 image base while retaining data |
| Windows | Immediate local work, a native window and desktop access | A complete setup EXE for new users; official172 installations sequentially hotupdate to175 (about82 MiB) |

175 fixes restart/update failures caused by incompatible Docker control code in the old image. Signed common/platform ZIPs, fixed targets, transaction recovery and actual background initialization confirm completion. Interrupted downloads, committing and process restarts resume. The Windows guardian is independent of business source and covers GUI/helper/support DLLs. Rollback below175 is disabled; subsequent updates remain adjacent chains.

Existing Web users should finish running tasks, back up and download the official install.sh again, selecting **Repair (2)**. Preserve accounts, configuration, database volumes, tasks, evidence, browsers and extensions. Windows is not affected by this Docker fault; existing users hotupdate without a complete installer download or reinstall. Windows11 tested; Windows10 has not been physically tested. Linux-specific tool boundaries remain documented; no paid model calls were part of validation.

[Website and installation](https://watchtowers.info/) · [Release175 and downloads](https://github.com/LINGYK352/Watchtower/releases/tag/v1.21.175) · [Windows source](https://github.com/LINGYK352/Watchtower/tree/windows/v1.21.175) · [Delivery contract](docs/update-delivery.md)

