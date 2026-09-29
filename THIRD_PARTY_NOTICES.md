# Third-party notices

Vigil at Home is licensed under the Apache License 2.0 (see [LICENSE](LICENSE) and [NOTICE](NOTICE)). It includes, adapts or works with the software below.

## Code adapted into this repository

### T3 Code

Parts of the Usage chart and its number formatting (`apps/desktop/src/renderer/src/views/UsageChart.tsx`, `apps/desktop/src/renderer/src/views/usage-format.ts`) are adapted from [T3 Code](https://github.com/pingdotgg/t3code) (`apps/web/src/components/usage`).

```
MIT License

Copyright (c) 2026 T3 Tools Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

### Santa

`packages/sensors/src/logParser.test.ts` uses sample log lines from Santa's serializer tests. Santa is [North Pole Security's Santa](https://github.com/northpolesec/santa), licensed under the Apache License 2.0 (the same text as [LICENSE](LICENSE)).

## Shipped inside the app

The DMG bundles these, each under its own license:

| Component                                                                                             | License                                                                                                                                            |
| ----------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Electron](https://github.com/electron/electron) and Chromium                                         | MIT for Electron; Chromium's component licenses are listed in `LICENSES.chromium.html` in each Electron release                                    |
| [Node.js](https://github.com/nodejs/node) runtime for the Vigil helper                                | MIT, plus the third-party licenses in Node's own `LICENSE`                                                                                         |
| [Plus Jakarta Sans](https://github.com/tokotype/PlusJakartaSans), via `@fontsource/plus-jakarta-sans` | SIL Open Font License 1.1, Copyright 2020 The Plus Jakarta Sans Project Authors                                                                    |
| [Roboto Mono](https://github.com/googlefonts/robotomono), via `@fontsource/roboto-mono`               | SIL Open Font License 1.1, Copyright 2015 The Roboto Mono Project Authors                                                                          |
| [Claude Agent SDK](https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk)                      | Proprietary: © Anthropic PBC, use subject to Anthropic's legal agreements (https://code.claude.com/docs/en/legal-and-compliance). Not open source. |
| Other npm dependencies (React, lucide-react, zod, the Anthropic and MCP SDKs and their dependencies)  | MIT, ISC, BSD-2-Clause, BSD-3-Clause or Unlicense; run `pnpm licenses list --prod` for the full list                                               |

## Installed separately, not shipped

Vigil talks to these but does not bundle them. You install them yourself, under their own terms.

| Component                                           | License or terms                                         |
| --------------------------------------------------- | -------------------------------------------------------- |
| [Santa](https://github.com/northpolesec/santa)      | Apache License 2.0                                       |
| [osquery](https://github.com/osquery/osquery)       | Apache License 2.0 or GPL-2.0                            |
| [Ollama](https://github.com/ollama/ollama)          | MIT                                                      |
| Qwen 2.5 models (0.5B, 1.5B), pulled through Ollama | Apache License 2.0                                       |
| Claude Code, OpenAI Codex CLI                       | Their vendors' terms; Vigil uses your own signed-in copy |
| Jev (TypeSafe), OpenRouter                          | Hosted APIs under their providers' terms                 |
