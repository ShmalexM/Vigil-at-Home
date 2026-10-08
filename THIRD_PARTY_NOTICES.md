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

### Beautiful UI

The chat's thinking trace, word-by-word answers and one-at-a-time tool approvals (`apps/desktop/src/renderer/src/components/Thinking.tsx`, `StreamingText.tsx`, `ApprovalStack.tsx`, `apps/desktop/src/renderer/src/agent-ui.ts` and `styles/agent-ui.css`) are adapted from [Beautiful UI](https://github.com/slev12397/beautiful-ui) (`components/primitives/ThinkingState.tsx`, `StreamingText.tsx`, `ApprovalCard.tsx`) and restyled on Vigil's own tokens. No Beautiful UI npm dependencies are used.

```
MIT License

Copyright (c) 2026 Shane Levine

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

The DMG, the .deb and the AppImage bundle these, each under its own license:

| Component                                                                                                   | License                                                                                                                                                                                      |
| ----------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Electron](https://github.com/electron/electron) and Chromium                                               | MIT for Electron; Chromium's component licenses are in `LICENSES.chromium.html`, shipped next to the app's `LICENSE`                                                                         |
| [Node.js](https://github.com/nodejs/node) runtime for the Vigil helper                                      | MIT, plus the third-party licenses in Node's own `LICENSE`, shipped as `helper/NODE-LICENSE`                                                                                                 |
| [Plus Jakarta Sans](https://github.com/tokotype/PlusJakartaSans), via `@fontsource/plus-jakarta-sans`       | SIL Open Font License 1.1, Copyright 2020 The Plus Jakarta Sans Project Authors                                                                                                              |
| [Roboto Mono](https://github.com/googlefonts/robotomono), via `@fontsource/roboto-mono`                     | SIL Open Font License 1.1, Copyright 2015 The Roboto Mono Project Authors                                                                                                                    |
| [Claude Agent SDK](https://www.npmjs.com/package/@anthropic-ai/claude-agent-sdk)                            | Proprietary: © Anthropic PBC, use subject to Anthropic's legal agreements (https://code.claude.com/docs/en/legal-and-compliance). Not open source and not covered by Vigil's Apache License. |
| Other npm packages bundled into the app (React, lucide-react, zod, the MCP SDK, ajv and their dependencies) | MIT, ISC or BSD-3-Clause; each one's name, version and full license text is in the app's `licenses` folder (`Contents/Resources/licenses` on a Mac, `resources/licenses` on Linux)           |

## Installed separately, not shipped

Vigil talks to these but does not bundle them. You install them yourself, under their own terms.

| Component                                                                              | License or terms                                                                        |
| -------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| [Santa](https://github.com/northpolesec/santa)                                         | Apache License 2.0                                                                      |
| [osquery](https://github.com/osquery/osquery)                                          | Apache License 2.0 or GPL-2.0                                                           |
| [fapolicyd](https://github.com/linux-application-whitelisting/fapolicyd) (Linux)       | GPL-3.0                                                                                 |
| [Ollama](https://github.com/ollama/ollama)                                             | MIT                                                                                     |
| Qwen 2.5 models (0.5B, 1.5B), pulled through Ollama                                    | Apache License 2.0                                                                      |
| Other local models Vigil can use if you already have them (Llama 3.2, Gemma 3, Qwen 3) | Their own licenses: Llama 3.2 Community License, Gemma Terms of Use, Apache License 2.0 |
| Claude Code, OpenAI Codex CLI                                                          | Their vendors' terms; Vigil uses your own signed-in copy                                |
| Jev (TypeSafe), OpenRouter                                                             | Hosted APIs under their providers' terms                                                |

## Threat data

Vigil downloads these lists at run time; they are not stored in this repository or shipped in the app. abuse.ch makes its platforms free for not-for-profit use; commercial use may need a paid Spamhaus subscription.

| Source                                                                                                                                                               | License                                                                                          |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| [abuse.ch](https://abuse.ch) feeds: [Feodo Tracker](https://feodotracker.abuse.ch/), [URLhaus](https://urlhaus.abuse.ch/), [MalwareBazaar](https://bazaar.abuse.ch/) | Feodo Tracker blocklist: CC0. All three: [abuse.ch terms of use](https://abuse.ch/terms-of-use/) |

## Fonts

Plus Jakarta Sans (Copyright 2020 The Plus Jakarta Sans Project Authors, https://github.com/tokotype/PlusJakartaSans) and Roboto Mono (Copyright 2015 The Roboto Mono Project Authors, https://github.com/googlefonts/robotomono) are licensed under the SIL Open Font License, Version 1.1:

```
-----------------------------------------------------------
SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007
-----------------------------------------------------------

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide
development of collaborative font projects, to support the font creation
efforts of academic and linguistic communities, and to provide a free and
open framework in which fonts may be shared and improved in partnership
with others.

The OFL allows the licensed fonts to be used, studied, modified and
redistributed freely as long as they are not sold by themselves. The
fonts, including any derivative works, can be bundled, embedded,
redistributed and/or sold with any software provided that any reserved
names are not used by derivative works. The fonts and derivatives,
however, cannot be released under any other type of license. The
requirement for fonts to remain under this license does not apply
to any document created using the fonts or their derivatives.

DEFINITIONS
"Font Software" refers to the set of files released by the Copyright
Holder(s) under this license and clearly marked as such. This may
include source files, build scripts and documentation.

"Reserved Font Name" refers to any names specified as such after the
copyright statement(s).

"Original Version" refers to the collection of Font Software components as
distributed by the Copyright Holder(s).

"Modified Version" refers to any derivative made by adding to, deleting,
or substituting -- in part or in whole -- any of the components of the
Original Version, by changing formats or by porting the Font Software to a
new environment.

"Author" refers to any designer, engineer, programmer, technical
writer or other person who contributed to the Font Software.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining
a copy of the Font Software, to use, study, copy, merge, embed, modify,
redistribute, and sell modified and unmodified copies of the Font
Software, subject to the following conditions:

1) Neither the Font Software nor any of its individual components,
in Original or Modified Versions, may be sold by itself.

2) Original or Modified Versions of the Font Software may be bundled,
redistributed and/or sold with any software, provided that each copy
contains the above copyright notice and this license. These can be
included either as stand-alone text files, human-readable headers or
in the appropriate machine-readable metadata fields within text or
binary files as long as those fields can be easily viewed by the user.

3) No Modified Version of the Font Software may use the Reserved Font
Name(s) unless explicit written permission is granted by the corresponding
Copyright Holder. This restriction only applies to the primary font name as
presented to the users.

4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font
Software shall not be used to promote, endorse or advertise any
Modified Version, except to acknowledge the contribution(s) of the
Copyright Holder(s) and the Author(s) or with their explicit written
permission.

5) The Font Software, modified or unmodified, in part or in whole,
must be distributed entirely under this license, and must not be
distributed under any other license. The requirement for fonts to
remain under this license does not apply to any document created
using the Font Software.

TERMINATION
This license becomes null and void if any of the above conditions are
not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT
OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT. IN NO EVENT SHALL THE
COPYRIGHT HOLDER BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
INCLUDING ANY GENERAL, SPECIAL, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL
DAMAGES, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF THE USE OR INABILITY TO USE THE FONT SOFTWARE OR FROM
OTHER DEALINGS IN THE FONT SOFTWARE.
```

## Original artwork

The Scout logo, the menu-bar and tray icons, and the pack's dog drawings (`apps/desktop/resources`, `apps/desktop/src/renderer/src/components/Dog.tsx`) were made for this project and are licensed under Apache-2.0 with the rest of the code.
