# @vigil/sensors

What Vigil sees on a Mac, turned into `@vigil/core` `SensorEvent`s.

```
Santa (Endpoint Security)
  ├─ /var/db/santa/santa.log ──► santaLogLineToEvent ──┐   every launch, block, watched-file
  │                                                     │   access, launch item, XProtect/TCC/
  │                                                     │   Gatekeeper alert, in real time
  └─ sync HTTPS (preflight, eventupload, ruledownload,  │
     postflight) ◄──► SantaSyncServer ─── blocks ───────┤
                         ▲                              ├─► SensorHub ─► sink (the helper
                         └── RuleStore (Vigil's rules)  │                 streams them to the app)
osquery ── osqueryd.results.log ──► osqueryLineToEvents ┘   outbound connections, listening
                                                            ports, browser extensions, launchd
                                                            and cron changes, every 30–300 s
osqueryd -S ◄── SensorHub: suspicious programs' sockets every 2 s for a minute
```

## Santa as the blocker

Santa (github.com/northpolesec/santa) is what actually stops a program from starting,
and what stops programs other than the listed ones from opening protected files. Vigil
is its sync server on the same Mac:

- **Local sync server.** Santa only accepts plain `http` for `localhost`, `127.0.0.1` or
  `::1` (`SNTConfigurator.mm`, `syncBaseURL`). Vigil still uses HTTPS: anything running
  as the user could grab the port first and serve "allow" rules. A private CA
  (`tls.ts`) is pinned through Santa's `ServerAuthRootsFile`, and its key is readable
  only by root. The folder and `ca.pem` stay world-readable, because `santasyncservice`
  runs as `nobody` and fails every sync with a TLS error if it can't read the CA
  (found on a real Mac with Santa 2026.8). If something else holds the port, syncs fail and Santa keeps its
  current rules.
- **Monitor mode.** The profile sets `ClientMode` 1: Santa enforces only explicit block
  rules, so a personal Mac keeps working. Lockdown would block every program not
  already allowed.
- **Incremental rules.** `RuleStore` keeps a revision per change and tombstones for
  removals. Each sync sends only what changed since Santa last confirmed a sync. It
  sends a clean sync the first time, when Santa asks, or when Santa's rule count no
  longer matches Vigil's.
- **Pre-launch rules (CEL).** Santa 2025.8 and later can decide a launch by running a
  small expression over the program's arguments. Vigil's block-mode rules that kill a
  program on launch and only test its name and arguments (today: the fake password
  dialog) are turned into such rules by `@vigil/detection/preexec` and installed by the
  helper (`packages/helper/src/preexec.ts`), so Santa stops the program before it runs.
  Only Apple's own programs are targeted, because a CEL rule's "otherwise" answer is
  allow. Vigil's engine keeps running the same rules as a backstop.
- **File protection.** `fileAccessPolicy()` watches browser cookies and saved logins
  (Chrome, Brave, Edge, Arc, Firefox, Safari), crypto wallets (Exodus, Electrum, Atomic),
  SSH private keys, the user's keychains, and writes to the privacy (TCC) database.
  Each item reports only programs it doesn't allow, and the allowlists are narrow: the
  browser's own team ID, only OpenSSH for SSH keys, only Apple's binaries for keychains
  and TCC.db. A process-centric item also reports Apple's script tools (curl, osascript,
  python3, sqlite3, shells, cp, ditto…) opening keychains or Safari cookies, which the
  Apple-only allowlists would let through. It starts **audit-only**, so a wrong rule
  never breaks an app; Arc and the wallets stay audit-only even with blocking on until
  their team IDs are confirmed. `watchDocuments` adds Documents and Desktop (off by
  default: every document a third-party app opens would be a log line).
- **No FileChangesRegex.** Santa logs file writes only through the watch items above.
  A change regex would log Apple's own writes too, from processes Vigil often can't vouch
  for (they started before it), which reads as tampering.

## What each event says about the program

Rules treat unsigned and ad hoc programs as untrusted, so every event needs a
`process.signing`:

- **Santa launches** carry the leaf certificate's name (`cert_cn`): "Software Signing" is
  Apple, "Apple Mac OS Application Signing" the App Store, "Developer ID Application" an
  identified developer. No certificate means unsigned or ad hoc (Santa's log doesn't say
  which). `quarantine_url` becomes `process.quarantine.originUrl`.
- **osquery listeners** join osquery's `signature` table without hashing the program, so
  it reads the signature only.
- **Everything else** (Santa file-access lines, osquery connections) names just a pid and
  a path. `SensorHub` fills in the signature from the program's launch through
  `ProcessEnricher`: by pid while the path still matches, otherwise by path. A program
  that started before Vigil stays without one.

## Installing Santa without MDM

1. Install Santa's signed package (or `brew install santa`).
2. In System Settings, approve its system extension and give it Full Disk Access.
3. Double-click the profile from `santaProfile()` (the helper serves it as
   `santa.profile`) and approve it under General > Device Management. Santa reads
   settings only from a profile (`CFPreferencesAppValueIsForced`). The profile points
   at files Vigil manages, so certificate rotation and policy changes never need a
   reinstall.

## Not yet verified on a real Mac

- That a profile the user installs by hand counts as "forced" for Santa. Expected, since
  that is how custom settings payloads work, but not yet tested.
- Santa accepting the pinned private CA through `ServerAuthRootsFile` for `127.0.0.1`.

## osquery setup

`osqueryConfig()` goes in `/var/osquery/osquery.conf` and `osqueryFlags()` in
`/var/osquery/osquery.flags`. osquery ignores startup-only settings (logger plugin,
watchdog limits, extensions) when they are in the config file, so those live in the
flag file that osquery's launchd job reads.

osquery's watchdog kills its worker when it goes over the CPU or memory limit, and by
default osquery then switches off whichever query was running for 24 hours. Every
Vigil query sets `denylist: false`, so a kill on a busy Mac costs one run, not a day
of connections. A `vigil_health` query every 5 minutes reads `osquery_schedule` and
logs every row each run: it keeps `lastEventAt` fresh while nothing changes, and `SensorHub` reports any query
osquery has still switched off through `onError`.

Installing osquery starts nothing. The helper (`packages/helper/src/osquery.ts`) writes
both files, installs `/Library/LaunchDaemons/io.osquery.agent.plist` and loads it, and
checks again every 5 minutes, so osquery installed after the helper is picked up too.

`src/osquery.mac.test.ts` runs every scheduled query against the real tables on
macOS 15 with osquery 5.23, and runs osqueryd with the generated files to check that
its results log parses into listen and connection events
(`VIGIL_MAC_INTEGRATION=1 pnpm --filter @vigil/sensors test:mac`, as root).
