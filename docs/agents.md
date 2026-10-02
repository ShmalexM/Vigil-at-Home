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

Separately, and also opt-in, your own agents can read what Vigil saw through
[Vigil's tools](#vigils-tools-for-your-own-agents), a read-only MCP server.

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
  cooperation. It sees a step once it has started, and it alerts rather than
  stops: for the riskiest steps the alert offers to pause that child process
  (never the agent itself), and nothing is paused until you approve it or set
  the rule to Block. A short-lived step, such as a `curl` upload, may have
  finished by then, so agent watch mostly shows you what happened.
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
- **Runtimes (Ollama):** listed only. A runtime never starts a session of its
  own; one started by a watched agent stays tagged, like an IDE.

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
detaching from the agent's process tree. None of them block or pause anything
on their own. Four of them (uploading credentials, paste-site uploads,
tampering and keychain secrets) offer to pause the agent's child process,
never the agent, and it is paused only when you approve.

## Pre-flight for Claude Code

### Set it up

1. On **Agents › Tool policy**, turn pre-flight **On**.
2. Copy the snippet Vigil shows and add it to your Claude Code settings:
   `~/.claude/settings.json` for every project, or a project's
   `.claude/settings.local.json` (the per-user file that stays out of git: the
   snippet holds paths on this Mac, including your home folder name). If the
   file already has settings, add the `hooks` section to them. If you already
   have hooks, add the `PreToolUse` and `SessionStart` entries next to yours.
3. Restart your Claude Code sessions. Vigil shows **Connected** once a session
   starts or a tool request arrives.

Vigil doesn't change the file for you: it never reads or writes Claude Code's
settings, because they can hold API keys. The snippet looks like this:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|MultiEdit|NotebookEdit|Read|Grep|WebFetch|mcp__.*",
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

| Claude Code's input                         | Sent to Vigil                                                                          |
| ------------------------------------------- | -------------------------------------------------------------------------------------- |
| the tool's name                             | as is (`Bash`, `Write`, `mcp__<server>__<tool>`, …)                                    |
| `command`                                   | the first 4 KB, plus the full size in bytes                                            |
| `file_path`, `notebook_path`, Grep's `path` | made absolute against the session's folder, with `..`, `~` and symbolic links resolved |
| `url`                                       | the first 2 KB                                                                         |
| `content`, `new_string` and edits           | **only** the size and SHA-256, never the text                                          |
| `session_id`, `cwd`                         | as is                                                                                  |
| (the hook's parent process)                 | its process ID, to tie the request to the agent's process tree                         |

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

Vigil keeps requests as events (Activity › Agent requests): up to 600 an hour
from one session and 3,000 an hour in all. Stopped requests have room of
their own, 300 an hour, so a flood of other requests can't push them out.
A deny also raises a quiet alert, at most once per rule and session every
10 minutes, and five or more stopped requests in one session within
10 minutes, or ten across sessions, raise a "probing" alert. Alerts don't
depend on what was stored. For these alerts, requests Vigil can't tie to an
agent's process tree count as one session, whatever session ID the hook
sends. An ask raises nothing: Claude Code is already asking you.

### When Vigil can't answer

| Situation                                                   | The hook prints                                                                    |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------- |
| Vigil isn't running, or pre-flight is off                   | ask ("Vigil couldn't check this step"), or nothing with **Let Claude Code decide** |
| No connection within 250 ms, or no answer within 1.5 s      | the same                                                                           |
| An answer that isn't deny, ask or nothing                   | the same                                                                           |
| Vigil busy (over 30 requests a second, after a burst of 60) | ask                                                                                |
| Input over 256 KB, or input the hook can't read             | ask ("Vigil couldn't read this step, so it asks first"), whatever the setting      |
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
questions. It replies deny, ask or nothing to a tool request, "ok" to a
hello and, when [Vigil's tools](#vigils-tools-for-your-own-agents) are on,
read-only data to a tools call. Nothing it is sent changes a rule, your
settings or an agent, runs an action or lifts a block (Vigil only notes when
it last heard from the hook and counts tool calls). It is limited to 30
requests a second (with a burst of 60), 16 connections and 64 KB per
request, and it closes a connection that doesn't read its replies or keeps
sending while Vigil is busy. An agent that uses it to test which commands get
stopped leaves a trail of stored requests and trips the probing alert.

Vigil checks that the socket is still its own. If another program removes or
replaces it, Vigil takes it back; if one is already listening there when
Vigil starts, Vigil doesn't answer in its place and shows the error. Either
way it raises the "Another program took over Vigil's agent socket" alert, at
most once an hour. A program running as you can still race Vigil for the
socket, and while it holds it, it answers the hook; the alert tells you it
happened.

The socket is open while pre-flight or Vigil's tools are on. With only the
tools on, a pre-flight request gets what the hook would print if Vigil
weren't running (ask, or nothing with **Let Claude Code decide**), and
nothing is checked or stored.

## Vigil's tools for your own agents

Advanced and off by default. Add Vigil as an MCP server to your own Claude
Code, Cursor or Codex, and the agent can look up Vigil's alerts, what Vigil
saw in the last 7 days and the agent sessions on this Mac: "what was that
alert about?", or "did anything I just ran trip a rule?". Your agent asks
with its own model and account. Vigil runs no model for this, and its AI
settings, API keys and Claude plan play no part.

### Set it up

1. On **Agents › Tool policy**, turn **Vigil tools for your agents** on.
2. Add the server entry Vigil shows to your agent. Vigil doesn't write these
   files for you:
   - **Claude Code:** run the `claude mcp add-json vigil '…'` command in
     Terminal (add `--scope user` after `add-json` to have it in every
     project), or put the `.mcp.json` form in a project.
   - **Cursor:** the same `mcpServers` entry, in `~/.cursor/mcp.json` or a
     project's `.cursor/mcp.json`.
   - **Codex:** the `[mcp_servers.vigil]` table, in `~/.codex/config.toml`.
3. Start a new session of the agent.

The `.mcp.json` form looks like this:

```json
{
  "mcpServers": {
    "vigil": {
      "type": "stdio",
      "command": "/Applications/Vigil at Home.app/Contents/Resources/helper/node",
      "args": [
        "/Applications/Vigil at Home.app/Contents/Resources/helper/vigil-hook.mjs",
        "mcp",
        "--socket",
        "/Users/you/Library/Application Support/Vigil at Home/run/agent.sock"
      ]
    }
  }
}
```

The server is the same `vigil-hook.mjs`, started with `mcp`: a small MCP
server on the agent's stdin and stdout (JSON-RPC, one message a line) that
passes each `tools/list` and `tools/call` on to Vigil over the agent socket.
It reads no files and has no tools of its own.

### The tools

| Tool                | Arguments                        | Returns                                                                               |
| ------------------- | -------------------------------- | ------------------------------------------------------------------------------------- |
| `vigil_status`      |                                  | protection level and reasons, sensors, rules by mode, pre-flight on and connected     |
| `list_alerts`       | `since`, `status`, `limit`       | alerts, newest first: title, rule name, severity, time, status and explanation if any |
| `get_alert`         | `id`                             | one alert, its explanation and the events behind it                                   |
| `search_events`     | `kind`, `text`, `since`, `limit` | events from the last 7 days at most, newest first, with the rules they matched        |
| `list_agents`       |                                  | the agents on this Mac, today's numbers and their latest sessions                     |
| `get_agent_session` | `id`                             | one agent session: its process tree and latest events                                 |

`since` is an ISO time or a span such as `30m`, `24h` or `7d`. `kind` is an
event kind (`process.exec`, `file`, `agent.tool_request`, …) or a group
(`programs`, `network`, `files`, `startup`, `system`, `agents`). A text
search looks through the newest 10,000 events of the window and says so
when there were more.

Every result is cut to 50 rows and 64 KB and goes through the same redaction
as the data Vigil's own AI gets: user names in `/Users/…` paths, private
keys, AWS keys, GitHub, Slack and API tokens, JWTs, passwords and tokens in
`key=value` form, and email addresses are replaced. Long text, such as a command line, is cut to
1,000 characters.

### What they can't do

- **Change anything.** No tool changes a rule, a mode, an exception, a
  setting or an agent, runs or undoes an action, lifts a block or answers a
  proposal.
- **Show how a rule works.** Alerts and events name the rule that matched,
  never its condition, exclusions or response, so an agent can't use Vigil
  to learn how to word its commands around the rules.
- **Try a command.** There is no dry-run pre-flight check. An agent that
  wants to know whether a step would be stopped has to send it as a real
  pre-flight request, which is stored and counts towards the probing alert.
- **Read secrets or settings.** No API key, setting or AI prompt is reachable.

While the tools are off, every call is refused before anything is read. They
share the socket's limits and add their own: at most 120 calls a minute on
one connection, and about 50 ms of Vigil's time a second across all
connections, so a busy agent hears "Vigil is busy" rather than slowing
pre-flight or the app. Vigil counts the calls and shows the last one on the
Tool policy tab.

Turn them on only if you want your agents to see this. An agent that has been
steered by a prompt injection can read it too, including whether Vigil has
noticed it; that's why the tools are off by default, read-only and redacted.

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
- Pre-flight checks a file path as the hook found it just before the step:
  symbolic links are followed, `/private/var`, `/private/tmp` and
  `/private/etc` count as `/var`, `/tmp` and `/etc`, and a path through the
  `/System/Volumes/Data` firmlink counts as the same path without it. A link
  changed between the check and the step can still point somewhere else;
  agent watch sees what then runs.
- The agent catalogue matches by program name, path and arguments. Team IDs
  are added once they have been checked on a real Mac with `codesign -dv`.
- Agents in a virtual machine, a container or on another computer are out of
  Vigil's sight.
