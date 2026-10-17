# Running the tests safely on a Mac you use

Vigil's helper runs as root and can block addresses with pf, add Santa rules,
turn off startup items, and pause or stop processes. A test that reaches the
real helper, or runs the helper's code against the real system, can leave any
of these in force after it ends. It can also put test alerts in the app's real
database. This page covers how the test harness prevents that, and how to run
each kind of test on a development Mac.

## What is safe by default

| What                                           | Runs against                                                   | On your Mac        |
| ---------------------------------------------- | -------------------------------------------------------------- | ------------------ |
| `pnpm test` (all `*.test.ts`)                  | Fakes (`packages/helper/src/testing`)                          | Safe               |
| `node e2e/popup.e2e.mjs`, `e2e/agents.e2e.mjs` | An isolated helper and a throwaway profile                     | Safe               |
| `node perf/measure.mjs`                        | No helper (actions are only simulated) and a throwaway profile | Safe               |
| `node e2e/flow.e2e.mjs`                        | The installed helper, for real                                 | Refuses to start   |
| `*.mac.test.ts`, `*.integration.test.ts`       | The real system, as root                                       | Refuses to enforce |

**The isolated helper** (`packages/helper/src/testing/isolatedHelper.ts`) is
the real helper daemon with its own socket, state folder and approvals folder
in a new temporary folder. A fake system (`testing/fakeSystem.ts`) stands in
for pf, Santa, launchd and signals. The e2e harness
(`apps/desktop/e2e/harness.mjs`) starts one for each run and points the app at
it. The app gets a throwaway profile, so the real `vigil.db` is never opened.

**The app** (development builds only) reads three variables. A packaged app
ignores all three.

- `VIGIL_HELPER_SOCKET`: the helper socket to connect to.
- `VIGIL_USER_DATA`: the profile folder to use.
- `VIGIL_E2E=1`: with no `VIGIL_HELPER_SOCKET`, the app connects to no helper
  at all, unless the run opted in (see below).

## The guard

Helper code refuses to enforce on the real machine when the process running
it is in a test context. A test context is any of these:

- Vitest
- `NODE_ENV=test`
- `VIGIL_E2E` is set
- `VIGIL_TEST_RUN_ID` is set

The guard has three layers (`packages/helper/src/testGuard.ts` and
`client.ts`):

- The client refuses to connect to the installed helper's socket
  (`/var/run/vigil-helper.sock` or `/run/vigil-helper.sock`). The helper runs
  in its own process and can't tell a test's request from the app's, so a test
  that calls `HelperClient.connect()` with the default socket gets a `refused`
  error before anything is sent.

- The real system (`realSystem()` in `system.ts`) refuses these operations:
  - pf blocks, rule loads and turning pf on
  - `launchctl bootout`, `unload` and `disable`
  - `santactl rule`
  - nftables adds, `systemctl stop` and `disable`, and fapolicyd rule loads
  - `SIGSTOP` and `SIGKILL`
- The executor refuses `network.block`, `process.suspend`, `process.kill`,
  `persistence.disable`, `file.quarantine` and Santa block rules when the
  system under it is the real one.

Reads and undos still run. The installed helper and the app run without any
of these variables, so the guard never applies to them. Only code that runs in
the test's own process is covered. A test that starts some other program to
talk to the helper is not covered.

### Opting in: `VIGIL_ALLOW_REAL_ENFORCEMENT=1`

Set `VIGIL_ALLOW_REAL_ENFORCEMENT=1` (exactly `1`) only on a machine you can
throw away, such as a GitHub-hosted runner or a VM. CI sets it for the
`flow` job (`bench.yml`), the helper's Mac checks (`macos.yml`) and the Linux
integration tests (`ci.yml`).

## Opted-in runs clean up after themselves

`flow.e2e.mjs` needs the installed helper, real osquery, real pf and real
processes. So it runs only when the run opts in. When it does:

1. **It tags every action with a test-run id.** The harness makes an id
   (`e2e-<date>-<random>`, or `VIGIL_TEST_RUN_ID` if you set one). The app,
   started by the harness with `VIGIL_E2E`, sends it with every helper request.
   A process without `VIGIL_E2E` never sends a tag, whatever
   `VIGIL_TEST_RUN_ID` says. The helper records it on each journal
   entry (`testRun`). Blocks the helper's own rules make while the app is
   closed carry the id too, as long as the helper has not restarted since the
   run gave it those rules.
2. **It tears down at the end.** The teardown
   (`packages/helper/src/testing/teardown.ts`) does three things:
   - It reads the helper journal and undoes every entry with the run's id that
     is still active: unblocks, resumes, re-enables startup items, restores
     quarantined files and takes back Santa rules.
   - It never undoes the user's own enforcement:
     - A Santa rule the run set over an existing rule is replaced by that
       earlier rule, not removed.
     - A Santa rule someone else set on the same program after the run is
       left as it is.
     - If the user blocks an address the run had already blocked, the block
       becomes theirs and the teardown leaves it.
   - If the helper still runs the blocking rules the run gave it, the teardown
     removes them. The helper keeps the run's id for those rules in its state
     folder, so a restart doesn't lose it. If the helper can't report the id,
     the teardown fails.
   - It reads the journal again.
3. **If anything stays in force, the run fails.** The output names each
   leftover and prints `TEARDOWN FAILED`.

The teardown approves its undos with `sudo -n vigil-helper approve`. That
works on CI runners, which have passwordless sudo. Without passwordless sudo
the undos are refused, and the run fails rather than leaving blocks behind
silently.

What the teardown does not undo:

- The app's self grant, which names the test's Electron binary as Vigil's own.
- Sensor events from the run that the helper keeps for replay. An app that
  connects soon after the run can still receive them and raise alerts.

These are further reasons to run the flow check only on a machine you can
throw away.

## On a development Mac

- Run `pnpm test`, `node e2e/popup.e2e.mjs` and `node e2e/agents.e2e.mjs` as
  they are. They never reach the installed helper or your profile.
- Don't run `flow.e2e.mjs` against the helper you use. Run it in a macOS VM
  or let CI run it (`bench.yml`, `workflow_dispatch`). If you must run it
  locally, install the helper in a VM, set `VIGIL_ALLOW_REAL_ENFORCEMENT=1`,
  and check its output for `TEARDOWN FAILED`.
- Run `*.mac.test.ts` and `*.integration.test.ts` as root only with the
  opt-in, on a machine you can throw away.
- Leftovers from older runs have recognisable names. Remove them by hand, or
  from Vigil's alerts and the helper journal:
  - Blocks on `1.1.1.1`
  - `~/Library/LaunchAgents/com.apple.vigil-e2e-lookalike.plist`
  - Processes and files under `/private/tmp/vigil-e2e`
