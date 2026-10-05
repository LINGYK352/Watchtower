# Windows source and build

Use Windows x64, Python3.11 and Node.js. Original code is GPL-3.0-only; preserve third-party licenses. Source is independently maintained in `codex/windows`; `windows/v1.21.172` identifies the exact release.

1. Create a virtual environment and install `requirements-native-build.txt`. The Python backend may need additional packages for enabled integrations; the default installer excludes ML frameworks and Linux-only executables.
2. In `frontend`, run `npm ci` then `npm run build`. Output is `docker/frontend`.
3. Run `python windows_native/build.py --stage-only`. It builds the native service, GUI and setup stub into `validation/native-dist`, using `release_tools/workspace_paths.py` for exported source paths.
4. Prepare a program directory containing `WatchtowerNative.exe`, `app` (owned source, built frontend, dictionaries and example configuration) and `runtime` (service, embedded Python, MongoDB, tools and browsers). Do not include `state`, accounts, activation keys, caches or logs. Paths must match `windows_native/paths.py`. The default deployment profile is local/native and contains no operator credentials.
5. Obtain runtime components from their official upstream projects at the exact versions in the install manifest/component metadata: Python3.11.9 embedded; Playwright1.63.0 Chromium revision1243; MongoDB Community; Mihomo1.19.32; ProjectDiscovery HTTPx/Nuclei/DNSX/Naabu/Katana/Subfinder. Keep upstream licenses. NPoC source and its Python3.11 compatibility edit are in `third_party/npoc`. Nmap/Npcap are excluded.
6. Build the single EXE using `python release_tools/build_complete_setup.py --program <program> --stub validation/native-dist/WatchtowerSetup.exe --output <setup.exe> --sign-key <your-private-key> --stable`. Sign with your own key and update the public trust anchor when making an independent distribution; the official private signing key is never published.

The installer embeds an Ed25519 signed inventory and compressed payload. It prepares Microsoft WebView2 if missing, verifies Microsoft publisher signatures and creates a desktop shortcut. User data stays in the installation's `state` directory, separate from update ownership.

Bundled component versions, source locations and notices accompany the program in `runtime/licenses`. Unmodified external programs retain their own licenses; modified NPoC source is provided here. Windows10 compatibility has not been verified on a physical Windows10 machine. Linux-specific driver, raw-packet, NSE and shell tools require appropriate external platform support; do not label them as tested native equivalents.
