# Language packs

`zh-CN.json` and `en-US.json` contain interface messages, grouped by feature. Runtime code uses stable message keys and Vue I18n interpolation; business data, tool output, evidence and model responses are not translated.

Add a locale JSON file and register its display name/component-library locale in `../i18n/index.ts`, then build the shared frontend. Web and Windows use the same frontend sources with their own versioned builds. Keep keys aligned with the Chinese base pack; missing keys use the base pack. User choice is stored in localStorage and synchronized across tabs. The header and login form provide a one-click Chinese/English toggle without remounting the route.

Existing named parameters are interpolated. Literal JSON, e-mail addresses and code remain literal; they are not interpreted as linked-message syntax. Table/option labels are reactive getters, and built-in manuals/agreement presentation are reactive. Translation does not change the Chinese agreement version or create an acceptance record.

Never use DOM text rewriting or alter original user/target content to produce a translated interface. Translate full sentences with named parameters where word order differs.
