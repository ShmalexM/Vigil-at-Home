# @vigil/ai

Connects Vigil to the AI the user already has: their own signed-in Claude Code, their own Codex (ChatGPT plan), or a local model through Ollama. The model is never in the blocking path. It explains what Vigil's rules already decided, and it runs out-of-band analysis whose output is a proposal a person approves.

```mermaid
flowchart LR
  caller[Popup or rule analysis] --> runner[Runner<br/>redact, prompt, quota, validate]
  runner --> claude[Claude Agent SDK<br/>user's own claude binary]
  runner --> codex[codex app-server<br/>Vigil's own CODEX_HOME]
  runner --> ollama[Ollama on 127.0.0.1]
  claude -. in-process .-> tools[Vigil read-only tools]
  codex -. dynamic tools .-> tools
  ollama -. Vigil's own loop .-> tools
```

## Using it

```ts
import { createVigilAi, defaultAiSettings } from '@vigil/ai';
import { z } from 'zod';

const ai = createVigilAi({ settings: defaultAiSettings(appSupportDir), log, pins });

const result = await ai.run({
  purpose: 'analyze', // or 'explain'
  urgency: 'background', // or 'now'
  instructions: 'Propose detection rules for ...',
  data: telemetrySummary, // redacted and size-capped before it leaves the Mac
  output: z.object({ rules: z.array(RuleProposal) }),
  deadlineMs: 120_000,
});
if (result.ok) result.value; // validated against the schema
```

`result.reason` on failure is one of `quota`, `timeout`, `invalid_output`, `no_provider`, `error`. Every prompt is recorded through `log` so the user can see what was sent.

## What the agent can and can't do

| Provider | Built-in tools                                                                                                    | Outside config                                                | Network and files                                   |
| -------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- | --------------------------------------------------- |
| Claude   | `tools: []`, every other request refused by `canUseTool`                                                          | `settingSources: []`, `strictMcpConfig`, no plugins or skills | Empty temp `cwd`, allowlisted env, no session saved |
| Codex    | `shell_tool`, `unified_exec`, `code_mode_host`, web search, apps, plugins, hooks and more off; approvals declined | Vigil's own `CODEX_HOME`                                      | Read-only sandbox without network, ephemeral thread |
| Ollama   | None. Vigil runs the tool loop                                                                                    | None                                                          | Talks only to `127.0.0.1`                           |

Vigil's tools run inside Vigil's process (the Claude SDK's in-process MCP server, Codex's dynamic tools), so there is no port for another program to reach. The user's login stays with the vendor's CLI; this package never reads a credential file or Keychain item.

Binaries are found by absolute path (including the usual Homebrew and `~/.local/bin` locations that a Finder-launched app misses). The first one seen is recorded. A signed binary may update as long as its Apple Team ID stays the same; an unsigned one must keep the same hash. A change stops runs until the user accepts it.

## Quota

Subscription windows come from the vendors' own signals (Claude's `rate_limit_event`, Codex's `account/rateLimits/updated`). Background work stops once Vigil has used its share of a window (10% by default) or the window is 90% full. Work marked `now` runs until the vendor refuses, and then falls through to the next provider, usually Ollama.

## Tests

`pnpm test` checks the settings, and launches the real Claude and Codex binaries far enough to confirm their tool lists and sandbox without calling a model.

The live escape tests use your subscription. They give the agent evidence and a tool result that tell it to read a secret file, write a file and call a local web server, then check that none of it happened:

```sh
VIGIL_LIVE_PROVIDERS=claude,codex,ollama pnpm --filter @vigil/ai test:live
```

Codex needs Vigil's Codex home signed in first: `CODEX_HOME=<dir> codex login`, then set `VIGIL_CODEX_HOME=<dir>`.

## Claude subscription mode

On by default, and a setting. Anthropic's terms allow a user to sign in to the unmodified Claude Code with their own plan, but also say apps built on the Agent SDK should use API keys. `CLAUDE_SUBSCRIPTION_NOTE` is the text setup shows. Switch `claude.mode` to `apiKey` to use a key from the Keychain instead. `pausedByVigil` lets an app update switch a provider off if terms change.
