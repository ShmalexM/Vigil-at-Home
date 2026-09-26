# Vigil at Home

Your own security operations center, running on your Mac.

Vigil at Home watches what runs on your laptop, blocks malicious activity as it happens, and pops up to tell you when it does. It uses the AI subscription you already have (Claude, ChatGPT/Codex or GitHub Copilot) to explain what it found and help you decide, but it never waits on the AI to block, and only you can allow or release something.

> Status: early development. Nothing here is ready to install yet.

## How it works

```
 program starts ──► Santa ─── known bad? ──► blocked before it runs
                      │
                      ▼
                   osquery ──► process / file / network / persistence events
                      │
                      ▼
          deterministic rules (milliseconds, offline, no AI)
             │            │                 │
          shadow        alert             block ──► privileged helper
       (logged only)      │                 │        suspends / firewalls / quarantines
                          ▼                 ▼
                  popup + menu-bar "Needs you" badge
                                  │
                                  ▼
                AI explains and recommends (your subscription)
                                  │
                                  ▼
                   you decide: keep blocked, allow, undo
```

- **Deterministic inline, AI after.** LLMs have a high false-positive rate, so they never decide what gets blocked. Rules do. The AI explains alerts and drafts new rules from traffic it has analysed; drafted rules start in shadow mode, where they only log matches, and you promote them once their track record looks right.
- **Only you release.** Rules can contain, never release. The AI can only propose actions, and never proposes allowing something.
- **Local.** Everything lives in a SQLite database on your Mac. No Docker, no server, no cloud account.

## Repository layout

| Path              | What                                                                    |
| ----------------- | ----------------------------------------------------------------------- |
| `apps/desktop`    | Electron menu-bar app: SQLite, scheduler, popup, UI                     |
| `packages/core`   | Shared types and schemas: events, alerts, rules, actions, action policy |
| `packages/<name>` | Sensors, helper, detection engine, AI bridge (one package each)         |
| `scripts`         | Repo checks                                                             |

## Develop

Needs Node 22.12+ and pnpm 10.

```bash
pnpm install
pnpm check   # naming check, lint, typecheck, tests
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for conventions.

## License

Apache-2.0. See [LICENSE](LICENSE).
