# @vigil/bench

How well Vigil at Home works, measured the same way on every run.

```
simulated attacks ──┬─► agent tracker ─► rules (full telemetry) ──────────────► caught?
train: 48 scenarios └─► Santa/osquery log lines ─► Vigil's parsers ─► tracker ─► rules ─► caught?
held-out: 25 + 14 look-alikes, same two paths ─► the score that counts

4 weeks of normal use ─► tracker ─► rules ─► false alerts, popups and blocks per day,
(everyday, developer)                         µs per event, bytes stored per event

agent tool calls (Claude Code's pre-flight hook) ─► rules ─► deny / ask / nothing?
(attacks, look-alikes, known gaps)

events the rules let through ─► local model or Jev ─► flagged? (vs. ground truth)
```

- `src/attacks.ts`: harmless stand-ins for real macOS threats (AMOS, ClickFix,
  Adload...), as the telemetry they produce. `canonical` ones must be caught;
  `evasive` ones measure gaps. The AI-agent scenarios (`agentTree`) are an
  agent's process tree doing what injected text told it to; each scenario
  gets a fresh process tracker, as the app tags events before rules run.
- `src/heldout.ts`: the held-out set. Attacks written from public reports
  without looking at the rules, plus legitimate look-alikes (Docker's helper,
  `gh` reading its keychain token, Dropbox syncing Documents). No rule or AI
  prompt is tuned on it: tuning loops only see train results and use held-out
  scores to keep or drop a change (`scoreCandidatesHeldout`). A train score far
  above the held-out score means the rules fit the test, not the threats. When
  a held-out case becomes a rule's target, move it to `attacks.ts` and write a
  new one.
- `src/sensors.ts`: renders each activity as the Santa or osquery log line it
  would produce with Vigil's shipped configuration and runs Vigil's own parser
  on it, so the benchmark shows what the rules actually get to see.
- `src/workday.ts`: a seeded normal-use workload, including legitimate
  activity that looks like an attack (install one-liners, `xattr -cr`, test
  binaries in /tmp). The developer also runs Claude Code sessions (commands,
  edits and the pre-flight requests its hook sends). The daily rates are
  estimates and are listed in the file. `storedBytesPerEvent` is what the
  event log keeps per event, with and without agent ancestry.
- `src/preflight.ts`: tool calls as Claude Code's hook sends them, answered
  the way the app answers (`engine.check`): attacks must be denied or asked
  about, look-alikes never denied, and only credential theft and switching
  off protections denied. Known gaps are listed and reported, not guarded.
- `src/labels.ts`: the test sets for the event labeller (train, and a held-out
  set from `heldout.ts`). `bench:labels` also runs every prompt in
  `prompts/labeller/*.txt` (or `VIGIL_LABEL_PROMPTS`) next to the shipped one.
- `src/review.ts`: an eval for the AI rule review. Two weeks of a developer's
  Mac with the attacks the rules miss hidden in it, one real review, and a
  grade for the rules it queues (share of hidden attacks caught, false alerts
  a day on a workload it never saw). `bench:review` runs it a few times per
  split and reports a 95% interval; keep a prompt or model change only if the
  held-out score rises beyond it. It costs what a review costs, per run.

Run:

```
pnpm --filter @vigil/bench bench                    # detection and pre-flight, ~90 s
VIGIL_BENCH_LABELLER=ollama VIGIL_OLLAMA_MODEL=qwen2.5:0.5b pnpm --filter @vigil/bench bench:labels
ANTHROPIC_API_KEY=... VIGIL_BENCH_LABELLER=claude VIGIL_CLAUDE_MODEL=claude-haiku-4-5-20251001 pnpm --filter @vigil/bench bench:labels
ANTHROPIC_API_KEY=... VIGIL_BENCH_REVIEW=1 VIGIL_REVIEW_RUNS=3 [VIGIL_REVIEW_PROMPT=file] [VIGIL_REVIEW_MODEL=id] pnpm --filter @vigil/bench bench:review
```

Results land in `bench-results/`. The Benchmarks workflow also runs the full
response path on a hosted Mac (`apps/desktop/e2e/flow.e2e.mjs`). Nothing here
runs malware: every attack is data, and the end-to-end test uses copies of
`sleep` and `node` as the "malware".
