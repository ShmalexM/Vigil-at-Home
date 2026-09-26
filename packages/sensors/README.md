# @vigil/sensors

What Vigil sees on a Mac, turned into `@vigil/core` `SensorEvent`s.

```
Santa (Endpoint Security)
  ├─ /var/db/santa/santa.log ──► santaLogLineToEvent ──┐   every launch, block, file write,
  │                                                     │   launch item, XProtect/TCC/Gatekeeper
  │                                                     │   alert, in real time
  └─ sync HTTPS (preflight, eventupload, ruledownload,  │
     postflight) ◄──► SantaSyncServer ─── blocks ───────┤
                         ▲                              ├─► SensorHub ─► sink (the helper
                         └── RuleStore (Vigil's rules)  │                 streams them to the app)
osquery ── osqueryd.results.log ──► osqueryLineToEvents ┘   outbound connections, listening
                                                            ports, browser extensions, launchd
                                                            and cron changes, every 10–300 s
```

## Santa as the blocker

Santa (github.com/northpolesec/santa) is what actually stops a program from starting,
and what stops programs other than the listed ones from opening protected files. Vigil
is its sync server on the same Mac:

- **Local sync server.** Santa only accepts plain `http` for `localhost`, `127.0.0.1` or
  `::1` (`SNTConfigurator.mm`, `syncBaseURL`). Vigil still uses HTTPS: anything running
  as the user could grab the port first and serve "allow" rules. A private CA
  (`tls.ts`) is pinned through Santa's `ServerAuthRootsFile`, and its key is readable
  only by root. If something else holds the port, syncs fail and Santa keeps its
  current rules.
- **Monitor mode.** The profile sets `ClientMode` 1: Santa enforces only explicit block
  rules, so a personal Mac keeps working. Lockdown would block every program not
  already allowed.
- **Incremental rules.** `RuleStore` keeps a revision per change and tombstones for
  removals. Each sync sends only what changed since Santa last confirmed a sync. It
  sends a clean sync the first time, when Santa asks, or when Santa's rule count no
  longer matches Vigil's.
- **File protection.** `fileAccessPolicy()` watches Chrome and Firefox cookies and saved
  logins, SSH private keys and the user's keychains. Only the owning vendor, or Apple's
  own binaries, may open them. It starts **audit-only**, so a wrong rule never breaks
  an app. Blocking is a later switch.

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
- The exact osquery `process_open_sockets`, `listening_ports` and `chrome_extensions`
  columns on current macOS.
