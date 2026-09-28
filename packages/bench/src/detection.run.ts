import { describe, expect, it } from 'vitest';
import { runAttacks, runWorkload, summarize } from './detection.js';
import { labelSet } from './labels.js';
import { writeResult } from './report.js';

// The full detection benchmark: every simulated attack with ideal telemetry
// and through Vigil's sensor parsers, then four weeks of normal use (one
// learning week, three measured) for two kinds of user. Results go to
// bench-results/detection.json.
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
    writeResult('detection', {
      at: new Date().toISOString(),
      platform: `${process.platform}-${process.arch}`,
      node: process.version,
      summary,
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
  });
});
