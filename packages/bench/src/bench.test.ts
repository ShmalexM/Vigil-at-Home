import { SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { ATTACKS } from './attacks.js';
import { runAttacks, runWorkload, START } from './detection.js';
import { santaWatchItems, throughSensors } from './sensors.js';

// Quick checks on the benchmark itself, so it can't rot between bench runs.
// The full benchmark is src/detection.run.ts (pnpm --filter @vigil/bench bench).
describe('benchmark corpus', () => {
  it('only contains valid sensor events', () => {
    for (const s of ATTACKS)
      for (const e of s.events(START)) expect(() => SensorEvent.parse(e), s.id).not.toThrow();
  });

  it('reads the watch items from the Santa policy Vigil ships', () => {
    expect(santaWatchItems().map((w) => w.name)).toContain('ChromeCookies');
  });

  it('renders events through the real sensor parsers', () => {
    const exec = ATTACKS.find((s) => s.id === 'clickfix-curl-pipe')!.events(START)[0]!;
    const [seen] = throughSensors(exec);
    expect(seen?.kind).toBe('process.exec');
    // The pipe survives Santa's <pipe> escaping.
    expect(seen && 'process' in seen && seen.process?.args?.join(' ')).toContain('| bash');
  });

  it('catches every canonical attack when the telemetry has what the rules need', () => {
    const missed = runAttacks()
      .filter((r) => r.telemetry === 'ideal' && r.variant === 'canonical' && !r.caught)
      .map((r) => r.id);
    expect(missed).toEqual([]);
  });

  it('never blocks anything in a normal everyday week', () => {
    const w = runWorkload('everyday', 'sensors', { days: 8 });
    expect(w.perDay.blocks).toBe(0);
  });
});
