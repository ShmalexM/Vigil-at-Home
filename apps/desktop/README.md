# Vigil at Home desktop app

The Electron menu-bar app. Its main process owns the SQLite database, the
scheduler, the alert pipeline and the windows; the renderer is React.

```
apps/desktop/src
├── main/            Electron main process
│   ├── db/          SQLite (node:sqlite) schema and typed store
│   ├── alerts.ts    detections → alerts, inline containment, user decisions
│   ├── scheduler.ts urgent and routine lanes for background work
│   ├── status.ts    Good / Fair / Poor
│   ├── service.ts   VigilCore: everything above, without Electron
│   ├── windows.ts   menu-bar item, popover, main window, detection popup
│   └── ipc.ts       validated IPC handlers
├── preload/         contextBridge API (sandboxed)
├── shared/          IPC contract shared by main and renderer
└── renderer/        React UI
```

## Run it

```bash
pnpm install
pnpm --filter @vigil/desktop dev                 # empty database
VIGIL_DEMO=1 pnpm --filter @vigil/desktop dev    # sample rules and one blocked detection
```

Until the privileged helper is installed, every block runs through
`DryRunExecutor`: it is logged, shown as "Simulated", and nothing on the Mac
changes. Settings → Send a test alert shows the popup without any action.

## First-run setup

`main/onboarding` and `renderer/src/views/onboarding` are the setup wizard that
opens on first launch (and from Settings › Run setup again). The user picks where
the AI runs (on the Mac, cloud, or both); protection is the same in every mode.
Each step shows the Terminal commands to paste, and Vigil checks the result
itself with read-only probes (`checks.ts`); it never runs an install. API keys
for cloud AI are encrypted with Electron's `safeStorage` in `api-keys.json`, and
only `KeyStore.get()` in the main process can read them back.

`VIGIL_DEMO=1` also fakes a Mac halfway through setup, so the wizard can be seen on
Linux. When the helper ships, pass `plan: () => ({ helperInstallCommand, santaProfilePath })`
to `OnboardingService` and those two steps turn on.

## Plugging in the other packages

- **Detection engine**: for a rule in alert or block mode call
  `core.alerts.raise({ rule, events, actions })` with the response already
  resolved; for shadow mode call `core.alerts.recordShadowMatch(rule, events)`.
- **Sensors and helper**: implement `ActionExecutor` and report health with
  `core.sensors.report({ id, name, state })`.
- **Sensor events**: after detection has seen an event, hand it to
  `core.events.add(event)`, which stores it in batches. Optional work checks
  `power.isBusy()` first. Both follow the budget in
  [docs/performance.md](../../docs/performance.md).
- **AI bridge**: read with `core.alertDetail(id)`, write with
  `core.alerts.recordAssessment(id, assessment)` and
  `core.alerts.propose('ai', action, alertId, rationale)`. Queue AI work with
  `core.scheduler.enqueue(name, fn, 'urgent')`.
- **Usage page** (`main/usage.ts`): hand every prompt log entry to
  `core.usage.record(entry)` as well (a `PromptLogEntry` fits; add `model` when
  known), and set `core.usage.setLimitsSource(async () => { const s = await
ai.spending([]); return { plans: s.plans, backgroundSharePercent:
s.limits.backgroundSharePercent, caps } })`, where `caps` holds any monthly
  caps on the Jev and cloud API keys. `VIGIL_DEMO=1` seeds 90 days of runs.

## Package it

```bash
pnpm --filter @vigil/desktop dist   # on a Mac: dmg and zip in apps/desktop/dist
```

Releases come from `.github/workflows/release.yml` (push a `v*` tag, or run it
by hand). Until Apple signing secrets are added they are ad hoc signed, so macOS
asks the user to approve the app once under System Settings › Privacy &
Security › Open Anyway. The workflow signs and notarizes automatically once the
secrets exist; nothing else changes.
