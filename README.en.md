<div align="center">

<img src="frontend/public/logo.png" width="112" height="112" alt="Watchtower logo" />

# Watchtower

**From attack surface to evidence.**

A self-hosted platform for AI penetration testing and asset intelligence in authorized security assessments.

**Development started: June 3, 2026.**

**[中文](README.md) · [English](README.en.md)**

[![License: GPL v3](https://img.shields.io/badge/License-GPL_v3-19b6cf.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8%20runtime-3776AB?logo=python&logoColor=white)](requirements.txt)
[![Vue](https://img.shields.io/badge/Vue-3-42b883?logo=vuedotjs&logoColor=white)](frontend/package.json)
[![Deployment](https://img.shields.io/badge/Deploy-Linux%20x86__64-101622?logo=docker&logoColor=white)](docs/installation.md)

[Website](https://watchtowers.info/) · [Installation (Chinese)](docs/installation.md) · [Development (Chinese)](docs/development.md) · [Architecture (Chinese)](docs/architecture.md) · [Releases](https://github.com/LINGYK352/Watchtower/releases) · [Issues](https://github.com/LINGYK352/Watchtower/issues)

</div>

![Watchtower assessment workflow](docs/assets/workflow.svg)

## Overview

Watchtower connects asset reconnaissance, AI tool use, human intervention, and evidence organization in one workspace. Create tasks from target assets, follow session execution, manage vulnerability leads and verification records, and prepare reports.

The project is maintained by an individual developer and is available free of charge under **GPL-3.0-only**. You can deploy it yourself; model calls and external data sources may require your own accounts or incur separate costs.

> `main` contains official stable source, currently **v1.21.167**. The website source snapshot is also `167`; the prebuilt image base may be older and is currently `165`. Source and image versions are distinct. Test iterations are not pushed directly to the main branch. See [version.txt](version.txt) for the source version and the [website](https://watchtowers.info/) for installation packages and subsequent official releases.

## v1.21.167 highlights

- Fixes tool-message pairing after DeepSeek DSML text calls. Existing affected history is repaired on the next resume request while retaining text, reasoning and saved results.
- Missing results are marked explicitly; orphan or duplicate results remain historical observations. Historical tools are never re-executed by the repair.
- Durable parameter references reduce queue and prefetch duplication for large tasks. Monitoring avoids overlapping polls and resource admission re-samples after conflicts.
- Hot updates download changed content; older versions without a historical manifest perform an initial full verification. This release covers the Linux Web edition only; Windows remains a local test build.

## v1.21.166 highlights

- Extension manifests include source and licensing information, with ZIP/tar.gz support and separate local-install and cloud-review flows.
- Updated brand icons and streamed reasoning/reply previews for automatically dispatched sessions.
- Fixes for manual sessions entering automatic recovery and repeated assessments of the same target being blocked.
- Policy presets in the AI console, improved layout for long target names, and recovery of tool calls emitted as plain text by models.
- Updated registration, privacy, and activation-related text.

See the [full changelog — Chinese](CHANGELOG.md) and [version downloads](https://github.com/LINGYK352/Watchtower/releases).

## Capabilities

| Area | What you can do |
| --- | --- |
| **Assets and attack surface** | Manage domains, IP addresses, websites, services, and fingerprints; organize reconnaissance results by task or asset group |
| **AI penetration testing sessions** | Configure model providers, invoke tools using asset context, and inspect execution traces and session states |
| **Human collaboration** | Intervene, take over, and continue sessions through the AI console while retaining associated records |
| **Findings and reports** | Distinguish unverified leads from results with associated verification evidence; organize reproduction details and reports |
| **Connected intelligence** | Query component vulnerabilities, methodologies, and historical clues; connect assets, systems, and attack-chain information |
| **Tools and extensions** | Manage tool settings and extension packages; integrate independent tools and platform capabilities through adapters |
| **Operations** | Configure proxy egress, scheduled tasks, and resource concurrency; review access, execution, and system logs |

Web and API assessments are the primary use cases. App, mini-app, and probe modules require their respective environments, external components, and explicit authorization. Available capabilities depend on the deployed version and configuration.

## Quick deployment

Prebuilt installation packages target **Linux x86_64** and run the platform and supporting services with Docker Compose.

```bash
# Download the official installer and review its contents before running it.
curl -fL https://watchtowers.info/dist/install.sh -o install.sh
sudo bash install.sh
```

Choose the installation mode from the interactive menu. Back up your configuration and database before working on an existing deployment. **Fresh installation and uninstall modes delete existing data; do not use them as routine updates.**

Follow the terminal output to access the platform, typically at `http://<server-address>:5555`. Change the default credentials after your first login, then configure model providers and required data sources. Confirm target authorization, network egress, and data-handling boundaries before conducting assessments.

**[Full deployment guide — Chinese →](docs/installation.md)**

## Assessment workflow

1. **Define the target:** establish the assets, accounts, time window, and permitted operations.
2. **Build context:** create a reconnaissance task or enter assets, then associate website, service, and component information.
3. **Start a session:** select the model and task settings, observe AI tool use, and intervene when needed.
4. **Review evidence:** inspect actual requests, responses, and reproduction conditions; distinguish leads, verification status, and severity.
5. **Organize results:** consolidate findings, handling status, and reports to support remediation and retesting.

The illustration above is a conceptual workflow. It contains no real customer data and does not represent performance measurements. AI output and automated classifications still require review against actual evidence.

## Architecture and stack

| Layer | Technologies and responsibilities |
| --- | --- |
| Frontend | Vue 3, TypeScript, Vite, Ant Design Vue |
| API | Python, Flask, Flask-RESTX, Gunicorn |
| Task execution | Celery, RabbitMQ, a separate scheduler |
| Data | MongoDB and instance persistence directories |
| Deployment | Docker Compose, Nginx, the Mihomo proxy service |
| Tool integration | Independent-process adapters, browser tools, and an extension runtime |

```text
Watchtower/
├── sentinel_platform/    Backend, APIs, business modules, and tests
│   ├── core/             Configuration, data access, and shared foundations
│   ├── contracts/        Service contracts, registry, and collection definitions
│   ├── router/           HTTP APIs, authentication, and response envelopes
│   └── modules/          Assets, tasks, AI sessions, intelligence, and system management
├── frontend/             Frontend source and public brand assets
├── docker/               Installer, image build, and deployment configuration
├── config/               Configuration samples without operational credentials
├── dicts/                Runtime dictionaries and templates
├── docs/                 Public project documentation
└── .github/              Issue and pull request templates
```

The repository excludes developer runtime secrets, real configuration files, databases, session data, internal operations material, and complete external binary and offline dependency packages. **Cloning the source does not provide a complete distribution that can immediately be built offline.** See the [development guide (Chinese)](docs/development.md).

## Documentation

The guides linked below are currently written in Chinese. This page provides the English project overview.

| Goal | Start here |
| --- | --- |
| Install and use the platform | [Deployment and updates](docs/installation.md) |
| Download versioned source and read release notes | [Releases](https://github.com/LINGYK352/Watchtower/releases) |
| Understand modules and call paths | [Architecture](docs/architecture.md) |
| Develop locally and validate changes | [Development guide](docs/development.md) |
| Contribute code or propose a feature | [Contributing](CONTRIBUTING.md) |
| Report a platform security issue | [Security policy](SECURITY.md) |
| Understand licensing and external-component boundaries | [GPL-3.0](LICENSE) · [Third-party notices](THIRD_PARTY_NOTICES.md) |
| Review previous changes | [Changelog](CHANGELOG.md) |

## Contributions and feedback

Use [Issues](https://github.com/LINGYK352/Watchtower/issues) for reproducible bugs and feature suggestions, and pull requests to contribute improvements. Read the [contribution guide (Chinese)](CONTRIBUTING.md) before submitting.

For platform vulnerabilities, credential exposure, or issues involving real target data, use the private reporting channel in [SECURITY.md (Chinese)](SECURITY.md). Do not post sensitive details in a public issue.

## License and use boundaries

Original project code is provided under the [GNU General Public License v3.0 only](LICENSE), identified as `GPL-3.0-only`. Third-party code, tools, data, and assets retain their own notices and licenses; the project license does not relicense them. The software is provided under the applicable license terms, subject to liabilities that cannot be excluded by law.

Conduct assessments only where you have the legal right to do so or have valid authorization. Downloading, registering, activating, or selecting a runtime mode does not grant permission to test third-party systems. Models and external services may receive data sent to them; review their terms, confidentiality requirements, and data-processing arrangements.

---

<div align="center">

Maintained by **LINGYK** · [watchtowers.info](https://watchtowers.info/) · [Contact the developer](mailto:lingyangkang352@163.com)

</div>
