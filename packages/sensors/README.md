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
  only by root. `santasyncservice` runs as `nobody` and fails every sync with a TLS
  error if it can't read the CA (found on a real Mac with Santa 2026.8), so the CA and
  the client identity sit in a folder `nobody` can read (below). If something else
  holds the port, syncs fail and Santa keeps its current rules.
- **Client certificate (mutual TLS).** The same CA signs a client certificate for
  Santa. The profile sets `ClientAuthCertificateFile` (a PKCS#12 file Santa opens
  itself, no keychain import) and `ClientAuthCertificatePassword`. The helper's sync
  server requires a client certificate from that CA and pins its SHA-256, so another
  local program can't pull the rules or confirm a sync in Santa's place. The key is
  root-only (`client.key`); the PKCS#12 copy is owned by root with group `nobody`, mode
  0440, in a root:`nobody` 0750 folder, because `santasyncservice` reads it after
  dropping to `nobody` (assumed to take `nobody`'s primary group, gid -2, as Santa's
  `DropRootPrivileges` does). `nobody` can read it but not replace, truncate or chmod it.
  The password is not a secret (it is in the profile); the file's owner and mode protect
  it. Code running as `nobody` could still copy the identity; moving it into the
  keychain is left for later. A profile installed
  before this certificate existed has no client keys: the helper serves a client
  without a certificate until Santa first presents the pinned one, then requires it
  for good (`SyncClientAuth` in the helper). A new install requires it from the start.
  Until the user reinstalls the profile, `helper.status` reports
  `clientCertRequired: false`; `clientCertSeenAt` is when Santa last presented the
  pinned certificate.
- **One identity store.** The CA, server and client certificates, the PKCS#12 file, its
  password, the pin, the previous pin, revoked pins and the required flag are written
  together into a new `versions/<id>/` folder, and a `current` link is switched to it
  in one rename (`ca.pem` and `client.p12`, the paths the profile names, are links into
  `current`). First start, renewal, recovery and the required flag all go through one
  lock in the helper (`SyncIdentityStore`), so a crash or two changes at once never
  leave a mix. A first start that never wrote its `installed` marker starts over in the
  strict state. If the required flag can't be saved, it stays in force and
  `helper.status` reports `identityProblem` until a retry saves it.
- **Renewal and recovery.** The client certificate lasts 397 days and is renewed 30 days
  before it expires, under the same file and password. `santasyncservice` builds a new
  `MOLAuthenticatingURLSession` for every sync, which opens `ClientAuthCertificateFile`
  again with `SecPKCS12Import`, so the renewed certificate is presented on the next
  sync without a new profile. The replaced certificate's pin is still taken for 30 days
  for a sync already under way. Every hour the helper reads `client.p12` back with
  openssl and issues a new one if it doesn't hold the pinned certificate. When Santa
  can't sync anyway, the helper's `santa.client.reissue` command (Home's Repair button,
  or `sudo vigil-helper santa-reissue`) issues a new identity, revokes the old pins and
  drops the requirement, serving a client without a certificate until Santa presents
  the new one. That loosens the port, so it needs the admin password whenever the
  certificate is required when the new identity takes over.
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
- Santa presenting the client certificate from `ClientAuthCertificateFile` as `nobody`
  and completing a sync against the helper's mutual-TLS server. The macOS CI checks the
  file's owner and that Apple's Security framework opens it (`tls.mac.test.ts`), but no
  runner has Santa installed.

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
