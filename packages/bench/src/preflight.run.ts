import { describe, expect, it } from 'vitest';
import { runPreflight, summarizePreflight } from './preflight.js';
import { writeResult } from './report.js';

// The pre-flight benchmark: every tool call in src/preflight.ts answered the
// way the app answers Claude Code's hook. Results go to bench-results/preflight.json.
describe('pre-flight benchmark', () => {
  it('runs', () => {
    const run = runPreflight();
    const summary = summarizePreflight(run);
    writeResult('preflight', {
      at: new Date().toISOString(),
      platform: `${process.platform}-${process.arch}`,
      node: process.version,
      summary,
      results: run.results,
    });
    // Regression guards: no look-alike is refused, every attack is at least
    // asked about, and only the steps meant to be refused are.
    expect(summary.lookalikes.denied).toBe(0);
    expect(summary.attacks.missed).toBe(0);
    expect(summary.deniesExact).toBe(true);
  });
});
