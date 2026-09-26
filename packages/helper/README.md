# @vigil/helper

The root daemon that takes action on the Mac. It accepts only the response actions in
`@vigil/core` (plus four read-only queries), validated strictly, and it never runs a
shell or a program it was handed.

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

## Safety rails

- **Reused process ids.** Process actions must carry the executable path or start time.
  The helper reads the real path from the kernel's text mapping (`lsof -d txt`), which
  argv tricks cannot fake. It refuses when the pid now belongs to something else, and
  resume re-checks the start time.
- **Protected processes.** Anything under `/System`, `/usr/libexec`, `/usr/sbin` or
  `/sbin`, plus Santa and Vigil, is never paused or killed.
- **Protected paths.** macOS system folders, top-level folders, home folders and Vigil's
  own files are never quarantined. Symlinked parent folders are resolved and checked
  again. Restore never overwrites something new.
- **Network blocks.** Loopback, link-local and multicast addresses are refused, and so
  are ranges wider than /8 (IPv4) or /24 (IPv6). Single ports are not supported yet.
  pf forgets its tables at reboot, so the helper re-applies active blocks from its
  journal at startup.
- **Journal.** Every action is recorded in a root-only journal (`helper-journal.json`),
  which `helper.journal` returns.

## Not yet verified on a real Mac

- pf evaluating the `com.apple/vigil` anchor from the stock `/etc/pf.conf`.
- `launchctl bootout` / `bootstrap` for agents in the logged-in user's `gui/<uid>` domain.
- Packaging: the helper has to run as a single root-owned executable in
  `/Library/PrivilegedHelperTools` (bundled Node or Electron's node, registered with
  `SMAppService`). The app shell decides this; `launchd/com.vigilathome.helper.plist` is
  the job definition.
