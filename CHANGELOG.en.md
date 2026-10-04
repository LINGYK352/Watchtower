# Changelog

[中文完整历史](CHANGELOG.md) · [Releases](https://github.com/LINGYK352/Watchtower/releases)

## v1.21.170 · 2026-10-04

Session takeover is persistent and idempotent. Empty-target whiteboards stay on standby, and session data is isolated during navigation. Each instruction and reply has its own durable display identity; context compaction no longer discards display history. Reasoning-only responses receive one bounded correction and then an explicit failure state.

Context fallback follows the system setting, while native mode uses known model limits or explicit metadata. Findings are captured promptly and checked against actual evidence. Endpoint plus vulnerability type forms a database-unique identity, retaining provenance and historical aliases. A successful HTTP status alone does not confirm a vulnerability.

Scripts receive syntax checks, real exit-code reporting, elapsed-time status, and owned-process-tree cleanup. The console adds loading animation and a mode label, restores the prior sidebar state on exit, and highlights selected AI policy controls. Status icons follow the dark theme. Generated task, session and finding reports support sanitized previews. Developer WeChat contact details were removed.

Validation: 249 relevant regressions and VM tests with owned mock providers/targets and actual browser clicks. Website delivery from169 downloads96 changed files and removes77 obsolete frontend assets; unchanged tools and dependencies are excluded. Unknown baselines require full verification. Existing configuration, accounts and evidence are preserved. Missing historical content cannot be recreated. Windows is not distributed in this release.

## Earlier releases

The complete dated release history is preserved in the [Chinese changelog](CHANGELOG.md). Versioned assets and bilingual release notes are available in [GitHub Releases](https://github.com/LINGYK352/Watchtower/releases).
