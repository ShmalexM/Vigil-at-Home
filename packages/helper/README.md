# @vigil/helper

The root daemon that takes action on the Mac. It accepts only the response actions in
`@vigil/core` (plus four read-only queries and the blocking rules it runs itself),
validated strictly, and it never runs a shell or a program it was handed.

```
Vigil app (runs as you) ──NDJSON over /var/run/vigil-helper.sock (0600, yours)──► helper (root)
                                                                                    │
  containment, runs at once          release, needs your admin password             │
  process.suspend / kill             process.resume                                 ├─ signals
  network.block                      network.unblock                                ├─ pf anchor com.apple/vigil
  file.quarantine                    file.restore                                   ├─ Quarantine/ (root, 0700)
  persistence.disable                persistence.enable                             ├─ launchctl + Quarantine/
  santa.rule.set (block)             santa.rule.set (allow), santa.rule.remove      └─ RuleStore ─► Santa sync
```

## Why releasing needs the password

Malware running as you can send the app's requests too. So every release (core's
`isRelease`) needs proof that the person at the keyboard typed the macOS admin password:

1. The helper answers `needsApproval` with a one-time nonce tied to that exact command.
2. The app runs `osascript` "do shell script … with administrator privileges". macOS
   shows its own password dialog, and only the right password runs
   `vigil-helper approve <nonce>` as root.
3. That writes a root-owned file. The helper checks the file is root-owned, not
   writable by others, less than 2 minutes old and bound to the same command. Then it
   deletes the file and acts.

A process running as you cannot create a root-owned file. Releases also only reverse
what the helper itself did: resume needs a pause in the journal, unblock needs a block.

## Starting osquery

Installing osquery (`brew install --cask osquery` or its pkg) puts `osqueryd` on disk but
starts nothing. When `osqueryd` is present, the helper writes Vigil's
`/var/osquery/osquery.conf` and `osquery.flags`, installs osquery's launchd job
(`io.osquery.agent`: background priority, restarted if it exits) and loads it. It checks
again every 5 minutes, and restarts osquery if the config has drifted. A config, flags
or job that was there before Vigil is kept as `*.before-vigil`.
`vigil-helper osquery-remove` (run by the uninstaller) stops Vigil's job and puts those
back; `vigil-helper osquery-setup` does the setup by hand.

## Blocking rules in the helper

The app hands the helper its block-mode rules with `detection.sync`, and the helper runs
them on every sensor event before passing the event on. A block no longer waits on two
trips over the socket and the app's event loop, and it still happens while the app is
closed, or at boot before anyone logs in (the rules are kept in `helper-rules.json`).

```
Santa / osquery ─► SensorHub ─► FastPath (same engine as the app) ─► Executor: kill, block…
                                    │                                   │ journaled, undo works
                                    └────────── event + what ran ───────┴─► app: alert, popup
```

- Only rules the helper can run alone are sent (`fastPathRules` in `@vigil/detection`):
  block mode, no "first seen" baseline, no field only the app fills in
  (`APP_ONLY_FIELD_PREFIXES`: an agent's tag, `process.agent`, and the fields of an
  agent's tool request), and no rule on tool requests (`agent.tool_request`), which
  only the app receives. Those stay in the app, which runs every rule either way.
  `process.ancestors` is filled in by the SensorHub here, so rules on it can run.
- The user's exceptions and Vigil's own paths come along, so "this is fine" and the
  safety floor apply here too. A rule with an exception on an app-only field stays in
  the app, since the helper couldn't honour it. The app re-sends whenever rules, modes or exceptions change.
- Indicator lists the rules use are named by digest; the helper asks for the ones it
  lacks, which arrive in parts (`detection.list.set`) and only apply once complete and
  matching.
- The app records what the helper ran as the alert's actions instead of running them a
  second time. Only containment runs here; releases still need the password.
- The same rules feed Santa's pre-launch (CEL) rules, so the ones Santa can express stop
  the program before it runs at all.
- Anything running as the user can reach the socket, so a sync can't weaken these rules
  on its own say-so. One that turns a rule off or changes what it blocks, adds an
  exception or adds one of Vigil's own paths gets a needs-approval answer and only applies
  after the admin password, the same flow releases use. Wording changes (name, reasons,
  severity) and new rules need none. If the user cancels, the app undoes the change on its
  side too (`Detector.setMode`, `learn` and `approveProposal` resolve to `declined`), and
  it doesn't ask again on its own for a set the user declined. Releasing an alert with
  "remember" holds the exception's sync (`HelperClient.hold`) so the release's dialog
  approves both: one password, `vigil-helper approve <nonce> <nonce>`.
- Indicator lists change daily as feeds age entries out, so they need no password; instead
  an entry a list drops keeps blocking for a week (`RETIRE_MS`), and a list may drop at
  most `RETIRED_MAX` entries in that time. A list's old contents stay in force until the
  new ones have fully arrived.
- `helper-rules.json` is root-owned in a root-owned folder, and `helper.status` reports its
  revision (`helperRules.rev`), which goes up with every change.
- The app pinned at install is spared (`appPin.ts`): `install.sh` runs `vigil-helper
pin-app` as root, which records the cdhash and sha256 of the app's main executable on
  macOS, or the AppImage's device, inode and sha256 on Linux. The pin is signed with a
  root-only key and kept in a root-only folder (`pin/`, 0700), held in memory and flagged
  immutable (`pinStore.ts`); `app-pin.json` beside it is a readable copy for the app. Before
  pausing or stopping a process, the helper checks the target against the pin (codesign on
  the pid on macOS, with the process identified again afterwards so a reused pid counts for
  nothing; the AppImage's mount on Linux), and it refuses a hash block naming the pinned
  hashes. No pin, or one for another app, spares nothing. Only an app outside the
  installer's folder is pinned: one in `/Applications/Vigil at Home.app` or
  `/opt/Vigil at Home` is protected by path already, has no pin, runs no extra codesign
  and asks for nothing when updated in place. An app outside it is re-pinned by the next
  self grant the password approves that covers it, or else by the helper update the app
  offers when its pin is stale.

Anything running as the user can reach the socket and send fewer rules. That only moves
those blocks back to the app's engine, as before, so this needs no password.

## Sensor health

`helper.status` includes `sensors`: whether Santa and osquery are installed, when each
last delivered an event, and when Santa last finished a sync with the helper
(milliseconds since epoch, or `null` since the helper started). The app decides what
counts as stale. osquery only logs changes, so on a quiet Mac it can go minutes without
an event while working fine; Santa logs every program launch.

## Safety rails

- **Reused process ids.** Process actions must carry the executable path or start time.
  The helper reads the real path from the kernel's text mapping (`lsof -d txt`), which
  argv tricks cannot fake. It refuses when the pid now belongs to something else, and
  resume re-checks the start time.
- **Protected processes.** Anything under `/System`, `/usr/libexec`, `/usr/sbin` or
  `/sbin`, plus Santa and Vigil, is never paused or killed.
- **Protected paths.** macOS system folders, top-level folders, home folders, and the
  files of Vigil, Santa and osquery (helper, launch items, units, socket, data) are never
  quarantined, nor is a folder that holds one. Paths are checked by name first and then by
  identity (device and inode), so another spelling of a protected path, or a hard link to a
  protected file, is refused too. Files with more than one hard link are refused.
  Symlinked parent folders are resolved and checked again. Restore never overwrites
  something new, and makes a missing folder again with the mode it had.
- **No root writes through your folders.** Quarantine and restore copy an item between
  its folder and the helper's own in two small processes (`commands/fsChild.ts`): the
  side in your folders runs as you (the folder's owner), with your groups, so a folder
  swapped for a link mid-move leads only where you could already go. Root acts directly
  only where every folder on the path is root's alone: root-owned, not writable by
  group or others, and with no ACL letting anyone else write (read with `ls -le` on
  macOS; on Linux a POSIX ACL's mask shows in the group bits). Files are created with
  `O_EXCL|O_NOFOLLOW`, the original is removed only after the copy is complete, and a
  failed copy removes only what it created. A root-owned item in a folder others can
  write to (like a package-installed app in `/Applications`) is refused. An item goes
  back into a folder that is root's alone as root, with each entry's owner given last;
  anywhere else, anything a user owns is restored as that user, keeping each entry's
  group when it is one of theirs, and when they can't write where it goes back, the
  restore is refused. Startup items are read the same way before they are turned off.
- **Bounded moves.** A move (or read) still running after two minutes is stopped: its
  reading process is killed, and its writing process removes what it made and is killed
  too. An item may hold at most 200,000 entries and 8 GiB, and at most four moves run at
  once. The helper's own rules never wait on a move: each event's pauses, kills and blocks
  are done first, and its moves go on beside the next events. Events still reach the
  app in the order they happened, each once its moves end, or after 15 seconds, when the
  app shows the item was not moved in time.
- **Startup items.** Launch items and units of Vigil and its sensors are refused by name
  (as written and where they really are), by label, by the names systemd knows them by,
  and by the program they run. One is turned off only in the startup folder as written. The only
  links followed are ones only root could have made, above the user's home (or anywhere
  in a path with no home), like `/home -> var/home` on ostree systems or
  `/var -> private/var` on macOS: root's, in a folder that is root's alone, and leading
  to one too. Any other link on the way, such as a startup folder a dotfile manager
  links in, is refused with its own code, and the app says so in one line. An
  item in a user's folder must be that user's, and that user must be the one asking
  (the console user, who owns the socket): Vigil is a single-user personal tool.
- **App grants.** The app named in a self grant is hashed off the event loop (up to
  1 GiB), one grant at a time; a newer grant replaces one still waiting for the
  password. At most 64 approvals wait at once, and a nonce offered with a command it
  was not issued for is left as it is.
- **One pin writer.** `pin-app` refuses to run while the daemon answers on its socket,
  and the daemon re-reads the signed pin before repairing it, adopting a newer one. The
  highest generation signed is kept in a signed counter (`pin/app-pin.gen`), so an
  older pin put back while the helper was stopped is refused at start, and pins are
  checked only with the key loaded at start. `vigil-helper pin-remove`, which the
  uninstallers run once the helper has stopped, clears the immutable flag and removes
  the pin folder. Like `pin-app` it is a root command line only (not a socket command),
  and it refuses while the daemon answers.
- **Network blocks.** Loopback, link-local and multicast addresses are refused, and so
  are ranges wider than /8 (IPv4) or /24 (IPv6). Single ports are not supported yet.
  pf forgets its tables at reboot, so the helper re-applies active blocks from its
  journal at startup.
- **Journal.** Every action is recorded in a root-only journal (`helper-journal.json`),
  which `helper.journal` returns.

## Checked on a real Mac

`src/helper.mac.test.ts` runs every action against a real macOS 15 system as root
(`VIGIL_MAC_INTEGRATION=1 pnpm --filter @vigil/helper test:mac`, on GitHub's hosted Macs):

- The stock `/etc/pf.conf` evaluates `com.apple/*`, so a block in `com.apple/vigil`
  really stops traffic to that address, unblocking brings it back, and blocks are
  re-applied after pf forgets them.
- Pause, resume and kill hit the right process, and a pid that now runs a different
  program, or a system process, is refused.
- Quarantine and restore keep the file's permissions.
- A launch daemon (`system`) and a launch agent in the logged-in user's `gui/<uid>`
  session are unloaded, moved aside and restored.

## Still open

- Packaging: the helper has to run as a single root-owned executable in
  `/Library/PrivilegedHelperTools` (bundled Node or Electron's node, registered with
  `SMAppService`). The app shell decides this; `launchd/com.vigilathome.helper.plist` is
  the job definition.
