# AI agents on your Mac

AI coding agents (Claude Code, Codex, Copilot CLI, Gemini CLI, cursor-agent,
the Claude and Codex apps, and the MCP servers they start) run commands on
your Mac as you. Vigil watches them in two ways:

- **Agent watch.** Vigil follows the process tree of every agent it knows and
  tags what each one starts, down to the shells and tools its shells run.
  Agent rules look at what actually ran.
- **Pre-flight** (Claude Code, opt-in). Claude Code asks Vigil before a tool
  runs, and Vigil answers from its rules: deny, ask you, or no opinion.

Both are rules, not AI. Vigil's AI helpers (the explainer, labeller and rule
reviewer) can explain an alert afterwards; they never decide what runs.

## Threat model

Here the agent is the attacker, or rather whatever steers it: a prompt
injection in a web page, README or issue, a malicious MCP server or package,
or a confused model. Assume it can:

- run any command you can, read any file you can and reach the network;
- read Vigil's rules (they are open source) and word its commands around them;
- edit its own configuration, hooks included.

So:

- **Pre-flight is a speed bump.** It stops the obvious steps before they run
  and puts the doubtful ones in front of you. An agent that removes the hook,
  splits a step over several commands or hides a command inside a script can
  get past it, and it covers only Claude Code.
- **Agent watch is the backstop.** Santa reports every program that starts,
  whatever started it, so agent watch doesn't depend on the agent's
  cooperation. It sees a step once it has started, and its responses pause
  that child process, never the agent itself.
- **Vigil never answers allow.** In Claude Code, `allow` from a hook skips
  your own permission prompt. Vigil answers deny, ask or nothing; with
  nothing, Claude Code's own permissions apply as if Vigil weren't there.
- **Failing means asking.** When Vigil can't answer, the hook asks you. It
  never fails into a deny you can't see the reason for, or into an allow.

## Agent watch

Vigil knows the common agents by name, path and command line, and shows them
on the **Agents** page. Defaults:

- **CLI agents and agent apps:** watched.
- **IDEs (Cursor, VS Code):** not watched, because you type your own commands
  in their built-in terminals. An IDE started by a watched agent stays tagged.
- **Runtimes (Ollama):** listed only, never tagged.

You can turn watch on or off per agent, edit a built-in agent (your copy wins
until you reset it), or add your own from recently seen programs or by path,
name, team ID, signing ID or arguments, after a preview of the last 14 days.
Vigil may also suggest an agent it doesn't know: a program, other than a
terminal, shell or build tool, that starts 20 or more shell commands within
10 minutes. A suggestion tags nothing until you accept it, and you get at most
one a day.

Everything an agent starts carries its agent, session and depth (0 for the
agent itself, 1 for its shell, and so on). The agent rules, tagged
`agent-watch` on the Rules page, cover reading cloud and SSH credentials,
uploading them or pasting to paste sites, persistence, tampering with Vigil
or Santa, editing agent hook configuration, reading keychain secrets and
detaching from the agent's process tree. None of them block; the ones that
pause a process pause only the agent's child.

## Pre-flight for Claude Code

### Set it up

1. On **Agents › Tool policy**, turn pre-flight **On**.
2. Copy the snippet Vigil shows and paste it into the `hooks` section of your
   Claude Code settings: `~/.claude/settings.json` for every project, or a
   project's `.claude/settings.json`. If you already have hooks, add the
   `PreToolUse` and `SessionStart` entries next to yours.
3. Restart your Claude Code sessions. Vigil shows **Connected** once a session
   starts or a tool request arrives.

Vigil doesn't change the file for you: it never reads or writes Claude Code's
settings, because they can hold API keys. The snippet looks like this:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|WebFetch|mcp__.*",
        "hooks": [
          {
            "type": "command",
            "command": "\"/Applications/Vigil at Home.app/Contents/Resources/helper/node\" \"/Applications/Vigil at Home.app/Contents/Resources/helper/vigil-hook.mjs\" preflight --socket \"/Users/you/Library/Application Support/Vigil at Home/run/agent.sock\" --on-unavailable ask",
            "timeout": 5
          }
        ]
      }
    ],
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "\"/Applications/Vigil at Home.app/Contents/Resources/helper/node\" \"/Applications/Vigil at Home.app/Contents/Resources/helper/vigil-hook.mjs\" hello --socket \"/Users/you/Library/Application Support/Vigil at Home/run/agent.sock\"",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

The hook is `vigil-hook.mjs`, run by the Node.js that ships inside Vigil, as
you. It doesn't need the root helper. The SessionStart hook only says hello,
so Vigil can show the hook is connected; it prints nothing, because Claude
Code would add its output to the conversation.

The **If Vigil can't answer** setting on the same tab chooses between asking
you (the default) and letting Claude Code decide. The choice is part of the snippet, so
copy it again after changing it. Remove the snippet when you turn pre-flight
off or uninstall Vigil; until then every checked step asks.

### What the hook sends

| Claude Code's input               | Sent to Vigil                                                          |
| --------------------------------- | ---------------------------------------------------------------------- |
| the tool's name                   | as is (`Bash`, `Write`, `mcp__<server>__<tool>`, …)                    |
| `command`                         | the first 4 KB, plus the full size in bytes                            |
| `file_path`, `notebook_path`      | made absolute against the session's folder, with `..` and `~` resolved |
| `url`                             | the first 2 KB                                                         |
| `content`, `new_string` and edits | **only** the size and SHA-256, never the text                          |
| `session_id`, `cwd`               | as is                                                                  |
| (the hook's parent process)       | its process ID, to tie the request to the agent's process tree         |

Everything else in the input, including the path to the conversation's
transcript, is dropped unread.

### How Vigil answers

Pre-flight rules are ordinary Vigil rules on the `agent.tool_request` event.
A rule's mode decides the answer:

| Rule mode on the Tool policy tab | Claude Code                                         |
| -------------------------------- | --------------------------------------------------- |
| Deny (block)                     | doesn't run the tool and tells Claude why           |
| Ask (alert)                      | asks you, showing the rule and its reason           |
| Record (shadow)                  | goes ahead as usual; Vigil records the match        |
| no rule matches                  | goes ahead as usual (Claude Code's own permissions) |

Out of the box, only two rules deny: sending secrets off the Mac and tampering
with Vigil or Santa. The others ask. Write your own on the Tool policy tab,
starting from a template, and replay them against the requests Vigil has
already seen before you turn them on. Turning a rule to Deny takes a
press-and-hold.

Vigil keeps every request as an event (Activity › Agent requests). A deny
also raises a quiet alert, at most once per rule and session every
10 minutes, and five or more stopped requests in one session within
10 minutes raise a "probing" alert. An ask raises nothing: Claude Code is
already asking you.

### When Vigil can't answer

| Situation                                                   | The hook prints                                                                    |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Vigil isn't running, or pre-flight is off                   | ask ("Vigil couldn't check this step"), or nothing with **Let Claude Code decide** |
| No connection within 250 ms, or no answer within 1.5 s      | the same                                                                           |
| An answer that isn't deny, ask or nothing                   | the same                                                                           |
| Input over 256 KB, or input Vigil can't read                | the same                                                                           |
| Vigil busy (over 30 requests a second, after a burst of 60) | ask                                                                                |
| A command over 4 KB                                         | ask (the `preflight-long-command` rule), since Vigil checks only the first 4 KB    |

The hook always exits 0 and never prints allow. If the hook can't start at
all (Vigil moved or uninstalled, so the path in the snippet is gone), Claude
Code reports a hook error and carries on with its own permissions.

### The socket

The hook talks to Vigil over a Unix socket at
`~/Library/Application Support/Vigil at Home/run/agent.sock`, or
`$TMPDIR/vigil-<your uid>/agent.sock` when that path is too long for a
socket. The socket is mode 0600 inside a 0700 folder, so other accounts on
the Mac can't reach it.

Anything running as you can, the agent included, so the socket only answers
questions. It replies deny, ask or nothing to a tool request and "ok" to a
hello, and nothing it is sent changes a rule, a setting or an agent, runs an
action or lifts a block. It is limited to 30 requests a second (with a burst
of 60), 16 connections and 64 KB per request. An agent that uses it to test
which commands get stopped leaves a trail of stored requests and trips the
probing alert.

## What Vigil never reads

- Claude Code's settings (`~/.claude/settings.json` and project settings),
  which can hold API keys.
- Agents' sign-ins and tokens: `~/.claude/.credentials.json`,
  `~/.codex/auth.json`, keychain items and the like.
- Conversations: the transcript path in the hook's input is dropped unread.
- What a tool would write: only its size and SHA-256 reach Vigil.

Tests scan the agent code in the app and the hook package for these names.
To follow agents, Vigil reads only what Santa reports and the process list
(`ps`), whose command lines it keeps in memory.

## Cost

Pre-flight adds about 60–150 ms to each tool call it checks, almost all of it
Node.js starting up; Vigil's own answer takes under 5 ms. Between tool calls
nothing runs. Following agents' process trees takes about 2 MB of memory. See
[performance.md](performance.md).

## Limits

- Pre-flight works with Claude Code only. Cursor and Codex hooks may follow.
- The agent catalogue matches by program name, path and arguments. Team IDs
  are added once they have been checked on a real Mac with `codesign -dv`.
- Agents in a virtual machine, a container or on another computer are out of
  Vigil's sight.
