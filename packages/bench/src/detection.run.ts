import { describe, expect, it } from 'vitest';
import {
  runAttacks,
  runHeldout,
  runWorkload,
  scoreRules,
  summarize,
  summarizeHeldout,
} from './detection.js';
import { labelSet } from './labels.js';
import { writeResult } from './report.js';

// The full detection benchmark: every simulated attack with ideal telemetry
// and through Vigil's sensor parsers, then four weeks of normal use (one
// learning week, three measured) for two kinds of user. Events go through
// Vigil's process tracker first, as in the app, so agent rules see which AI
// agent a process runs under. Results go to bench-results/detection.json.

// Held-out ratchet: the score on attacks the rules were never written for may
// not drop below the best seen so far. Raise these when it improves; never
// lower them to get a change through. Only counts are checked, so nothing
// about the held-out cases leaks into what rule authors or reviewers see.
const HELDOUT_FLOOR = { caughtIdeal: 9, caughtSensors: 9 } as const; // of 25, 2026-10-02

describe('detection benchmark', () => {
  it('runs', () => {
    const attacks = runAttacks();
    const enforced = runAttacks({ enforceFileAccess: true }).filter(
      (r) => r.telemetry === 'sensors',
    );
    const days = 28;
    const workload = [
      ...(['everyday', 'developer'] as const).flatMap((p) =>
        (['ideal', 'sensors'] as const).map((t) => runWorkload(p, t, { days })),
      ),
      {
        ...runWorkload('developer', 'sensors', { days, sensorOpts: { enforceFileAccess: true } }),
        variant: 'file-access-enforced',
      },
    ];
    const summary = summarize(attacks);
    const heldout = runHeldout();
    const heldoutSummary = summarizeHeldout(heldout);
    writeResult('detection', {
      at: new Date().toISOString(),
      platform: `${process.platform}-${process.arch}`,
      node: process.version,
      summary,
      heldoutSummary,
      heldout,
      rules: scoreRules(attacks, workload),
      attacks,
      sensorsWithFileAccessEnforced: enforced.map((r) => ({
        id: r.id,
        caught: r.caught,
        caughtBy: r.caughtBy,
      })),
      labelCoverage: labelSet().coverage,
      workload,
    });
    // Regression guard: every canonical attack is caught when the telemetry is there.
    expect(summary.canonical.caughtIdeal).toBe(summary.canonical.total);
    expect(heldoutSummary.caughtIdeal).toBeGreaterThanOrEqual(HELDOUT_FLOOR.caughtIdeal);
    expect(heldoutSummary.caughtSensors).toBeGreaterThanOrEqual(HELDOUT_FLOOR.caughtSensors);
    expect(summary.agents.caughtIdeal).toBe(summary.agents.total);
    for (const w of workload) {
      // Agent rules stay out of a developer's way (alerts, and steps the agent
      // stops to ask about), and following agents costs little storage.
      expect(w.agentRules.alerts + w.agentRules.asks, w.profile).toBeLessThanOrEqual(0.5);
      expect(w.storedBytesPerEvent.delta, w.profile).toBeLessThanOrEqual(40);
    }
  });
});
