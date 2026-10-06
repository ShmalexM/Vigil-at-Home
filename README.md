<p align="center">
  <img src="apps/desktop/resources/icon.png" alt="Vigil at Home logo: Scout, a black and white husky, on a blue shield" width="128" height="128">
</p>

# Vigil at Home

Your own security operations center, running on your Mac or Linux PC.

Vigil at Home watches what runs on your computer, blocks malicious activity as it happens, and pops up to tell you when it does. It uses AI you already have (an API key, your ChatGPT plan through Codex, a local model, or your Claude plan when you ask it about an alert) to explain what it found and help you decide, but it never waits on the AI to block, and only you can allow or release something.

- **Blocks in real time.** Deterministic rules catch malware, persistence, credential theft and beacons in seconds, and keep blocking with the app closed.
- **Stays quiet.** Routine things go to History. You're interrupted only when something needs your decision.
- **Watches your AI agents.** Claude Code, Codex and other coding agents are tracked down to every command they start, and Claude Code can ask Vigil before a tool runs. See [docs/agents.md](docs/agents.md).
- **A pack of AI helpers.** Scout, your Lead dog, answers questions from Vigil's data and runs small jobs for you; the other dogs explain alerts, label events and review rules. No dog can block, allow or change a rule. See [docs/pack.md](docs/pack.md).
- **Local.** Everything lives in a SQLite database on your computer. No server, and no account to sign up for.

> Status: early alpha. Sensors, detection rules, blocking (once the helper is installed), the popup and AI explanations work on a real Mac, and on Ubuntu in CI, but expect rough edges. Releases aren't signed yet.

## Install on a Mac

Download the latest DMG from [Releases](https://github.com/ShmalexM/Vigil-at-Home/releases): `-arm64.dmg` for Apple silicon (M1 and later), `-x64.dmg` for Intel Macs.

1. Open the DMG and drag **Vigil at Home** into **Applications**.
2. Open it. Releases aren't signed with an Apple Developer ID yet, so macOS refuses the first time. Choose **Done**.
3. Open **System Settings > Privacy & Security**, scroll to Security and choose **Open Anyway** next to Vigil at Home.
4. Vigil appears in the menu bar as Scout, a dog's head.

Steps 2 and 3 happen once. To skip them, build it yourself (see below).

### The Vigil helper

Blocking needs a small helper that runs as root. Until it's installed, Vigil only simulates blocks and says so. On **Home > Protection**, choose **Install helper**. macOS asks for your password once. The same script also runs from Terminal:

```bash
sudo "/Applications/Vigil at Home.app/Contents/Resources/helper/install.sh"
```

It copies the helper and its own Node.js runtime into `/Library/PrivilegedHelperTools`, owned by root, and starts it with launchd. `uninstall.sh`, in the same folder, removes it. Uninstalling keeps `/Library/Application Support/Vigil`, so nothing Vigil quarantined is lost.

## Install on Linux

From [Releases](https://github.com/ShmalexM/Vigil-at-Home/releases):

- **Debian, Ubuntu and their relatives**: `sudo apt install ./Vigil-at-Home-<version>-amd64.deb`, then open Vigil at Home from your apps.
- **Other distributions**: download `Vigil-at-Home-<version>-x86_64.AppImage`, make it executable (`chmod +x`) and run it.

Setup in the app installs osquery, fapolicyd and the Vigil helper (a root systemd service), asking for your password through your desktop's own dialog. Programs your package manager installed stay trusted. On GNOME, Scout shows in the top bar once the AppIndicator extension is on (Ubuntu has it on already). Linux builds are for 64-bit Intel and AMD computers for now. They're tested on Ubuntu; a full Wayland desktop hasn't been tried yet.

## Build from source

```bash
git clone https://github.com/ShmalexM/Vigil-at-Home.git && cd Vigil-at-Home
pnpm install
pnpm --filter @vigil/desktop dist   # DMGs (or a .deb and AppImage on Linux) land in apps/desktop/dist
```

A build made on your own Mac isn't quarantined, so it opens without the prompt. `pnpm --filter @vigil/desktop dev` runs it without packaging.

Maintainers: run the **Release** workflow by hand with a version (like `0.1.0-alpha.3`) to build the DMGs, the .deb and the AppImage and create a draft release, then publish it.

## How it works

```
 program starts ──► Santa (Mac) or fapolicyd (Linux) ── known bad? ──► blocked before it runs
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
- **Local.** Everything lives in a SQLite database on your computer. No Docker, no server, no cloud account.

### How well it works

[`packages/bench`](packages/bench/README.md) measures detection on every change, against attacks written from public reports without looking at the rules. Today the rules catch 9 of 25 of those held-out attacks with no false blocks on their look-alikes, and the gaps (known-bad domains, sweeps of Documents) are listed openly. An end-to-end test on GitHub's macOS and Ubuntu runners launches harmless malware stand-ins and checks that Vigil catches and blocks them.

## Repository layout

| Path              | What                                                                    |
| ----------------- | ----------------------------------------------------------------------- |
| `apps/desktop`    | Electron menu-bar app: SQLite, scheduler, popup, UI                     |
| `packages/core`   | Shared types and schemas: events, alerts, rules, actions, action policy |
| `packages/<name>` | Sensors, helper, detection engine, AI bridge, agent hook, benchmarks    |
| `docs`            | AI agents, the pack, performance budget                                 |
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

## Thanks

Vigil at Home stands on [Santa](https://github.com/northpolesec/santa), [osquery](https://github.com/osquery/osquery) and [fapolicyd](https://github.com/linux-application-whitelisting/fapolicyd) for watching and blocking, and on [abuse.ch](https://abuse.ch)'s free threat feeds. Parts of the UI are adapted from [T3 Code](https://github.com/pingdotgg/t3code) and [Beautiful UI](https://github.com/slev12397/beautiful-ui).

## License

Apache-2.0. See [LICENSE](LICENSE). Third-party code and assets are credited in [NOTICE](NOTICE) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
