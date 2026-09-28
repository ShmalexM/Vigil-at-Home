# Vigil at Home

Your own security operations center, running on your Mac.

Vigil at Home watches what runs on your laptop, blocks malicious activity as it happens, and pops up to tell you when it does. It uses the AI subscription you already have (Claude, ChatGPT/Codex or GitHub Copilot) to explain what it found and help you decide, but it never waits on the AI to block, and only you can allow or release something.

> Status: early alpha. The app, popup and alert pipeline work, but the sensors, detection rules and AI connection are still being merged in. Until then the app has nothing real to watch, and blocks are simulated and labelled that way.

## Install

Download the latest DMG from [Releases](https://github.com/ShmalexM/Vigil-at-Home/releases): `-arm64.dmg` for Apple silicon (M1 and later), `-x64.dmg` for Intel Macs.

1. Open the DMG and drag **Vigil at Home** into **Applications**.
2. Open it. Releases aren't signed with an Apple Developer ID yet, so macOS refuses the first time. Choose **Done**.
3. Open **System Settings > Privacy & Security**, scroll to Security and choose **Open Anyway** next to Vigil at Home.
4. Vigil appears as a shield in the menu bar.

Steps 2 and 3 happen once. To skip them, build it yourself:

```bash
git clone https://github.com/ShmalexM/Vigil-at-Home.git && cd Vigil-at-Home
pnpm install
pnpm --filter @vigil/desktop dist   # DMGs land in apps/desktop/dist
```

A build made on your own Mac isn't quarantined, so it opens without the prompt. `pnpm --filter @vigil/desktop dev` runs it without packaging.

Maintainers: run the **Release** workflow by hand with a version (like `0.1.0-alpha.2`) to build both DMGs and create a draft release, then publish it.

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
