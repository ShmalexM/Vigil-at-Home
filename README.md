# Vigil at Home

Your own security operations center, running on your Mac.

Vigil at Home watches what runs on your laptop, blocks malicious activity as it happens, and pops up to tell you when it does. It uses AI you already have (an API key, your ChatGPT plan through Codex, a local model, or your Claude plan when you ask it about an alert) to explain what it found and help you decide, but it never waits on the AI to block, and only you can allow or release something.

> Status: early alpha. Sensors, detection rules, blocking (once the helper is installed), the popup and AI explanations work on a real Mac, but expect rough edges. Releases aren't signed yet.

## Install

Download the latest DMG from [Releases](https://github.com/ShmalexM/Vigil-at-Home/releases): `-arm64.dmg` for Apple silicon (M1 and later), `-x64.dmg` for Intel Macs.

1. Open the DMG and drag **Vigil at Home** into **Applications**.
2. Open it. Releases aren't signed with an Apple Developer ID yet, so macOS refuses the first time. Choose **Done**.
3. Open **System Settings > Privacy & Security**, scroll to Security and choose **Open Anyway** next to Vigil at Home.
4. Vigil appears as a shield in the menu bar.

Steps 2 and 3 happen once. To skip them, build it yourself (see below).

### The Vigil helper

Blocking needs a small helper that runs as root. Until it's installed, Vigil only simulates blocks and says so. On **Home > Protection**, choose **Install helper**. macOS asks for your password once. The same script also runs from Terminal:

```bash
sudo "/Applications/Vigil at Home.app/Contents/Resources/helper/install.sh"
```

It copies the helper and its own Node.js runtime into `/Library/PrivilegedHelperTools`, owned by root, and starts it with launchd. `uninstall.sh`, in the same folder, removes it. Uninstalling keeps `/Library/Application Support/Vigil`, so nothing Vigil quarantined is lost.

### Build from source

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
                AI explains and recommends (your AI)
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

## Contributing

Issues and pull requests are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md), and follow the [Code of Conduct](CODE_OF_CONDUCT.md). Report security problems privately, as [SECURITY.md](SECURITY.md) describes, not as issues.

## License

Apache-2.0. See [LICENSE](LICENSE). Third-party code and assets are credited in [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
