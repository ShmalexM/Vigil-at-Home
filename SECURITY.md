# Security policy

Vigil at Home runs a root helper and can block programs on your Mac, so we take reports about it seriously.

## Reporting a vulnerability

Please don't open a public issue. Report it privately through GitHub instead: open the repository's **Security** tab and choose **Report a vulnerability**. Only the maintainers can see the report.

Useful things to include:

- what an attacker could do, and what access they need first (a local user, a malicious file, a network position)
- the Vigil version or commit, and your macOS version and chip
- steps or a proof of concept

We aim to reply within a week, and we'll tell you when a fix is released. Once it is, we're happy to credit you unless you'd rather stay anonymous.

## Supported versions

Vigil at Home is in alpha. Only the latest release and `main` get security fixes.

## In scope

- the privileged helper (`packages/helper`, installed under `/Library/PrivilegedHelperTools`), its socket and its command list
- ways to get a block lifted, an allow rule added or a detection rule changed without the user's approval
- ways for event data, alert text or AI output to reach anything other than Vigil's read-only tools
- the Santa sync server, the osquery configuration and the app's IPC
- the agent socket (`run/agent.sock` in the app's data folder) that Claude Code's pre-flight hook asks. Only your account can reach it, and it is read-only: it answers deny, ask or nothing, never allow, and changes no rule, setting or block. Anything that makes it do more, or makes the hook (`vigil-hook.mjs`) read files or send what a tool would write, is in scope. See [docs/agents.md](docs/agents.md)
- leaks of API keys that Vigil stores in the Keychain

Bugs in Santa, osquery, Electron, Claude Code, Codex or Ollama belong with those projects. Tell us too if Vigil makes one of them worse.
