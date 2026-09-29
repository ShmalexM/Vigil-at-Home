# @vigil/bench

How well Vigil at Home works, measured the same way on every run.

```
simulated attacks ──┬─► rules (full telemetry) ─────────────────► caught?
train: 42 scenarios └─► Santa/osquery log lines ─► Vigil's parsers ─► rules ─► caught?
held-out: 25 + 14 look-alikes, same two paths ─► the score that counts

4 weeks of normal use ─► rules ─► false alerts, popups and blocks per day, µs per event
(everyday, developer)

events the rules let through ─► local model or Jev ─► flagged? (vs. ground truth)
```

- `src/attacks.ts`: harmless stand-ins for real macOS threats (AMOS, ClickFix,
  Adload...), as the telemetry they produce. `canonical` ones must be caught;
  `evasive` ones measure gaps.
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
  binaries in /tmp). The daily rates are estimates and are listed in the file.
- `src/labels.ts`: the test sets for the event labeller (train, and a held-out
  set from `heldout.ts`). `bench:labels` also runs every prompt in
  `prompts/labeller/*.txt` (or `VIGIL_LABEL_PROMPTS`) next to the shipped one.

Run:

```
pnpm --filter @vigil/bench bench                    # detection, ~40 s
VIGIL_BENCH_LABELLER=ollama VIGIL_OLLAMA_MODEL=qwen2.5:0.5b pnpm --filter @vigil/bench bench:labels
VIGIL_BENCH_LABELLER=claude VIGIL_CLAUDE_MODEL=claude-haiku-4-5-20251001 pnpm --filter @vigil/bench bench:labels
```

Results land in `bench-results/`. The Benchmarks workflow also runs the full
response path on a hosted Mac (`apps/desktop/e2e/flow.e2e.mjs`). Nothing here
runs malware: every attack is data, and the end-to-end test uses copies of
`sleep` and `node` as the "malware".
