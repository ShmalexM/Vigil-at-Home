import { SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { ATTACKS } from './attacks.js';
import { HELDOUT_ATTACKS, HELDOUT_LOOKALIKES } from './heldout.js';
import { runAttacks, runWorkload, START } from './detection.js';
import { santaWatchItems, throughSensors } from './sensors.js';

// Quick checks on the benchmark itself, so it can't rot between bench runs.
// The full benchmark is src/detection.run.ts (pnpm --filter @vigil/bench bench).
describe('benchmark corpus', () => {
  it('only contains valid sensor events', () => {
    for (const s of ATTACKS)
      for (const e of s.events(START)) expect(() => SensorEvent.parse(e), s.id).not.toThrow();
  });

  it('keeps the held-out set valid and apart from the train set', () => {
    const train = new Set(ATTACKS.map((s) => s.id));
    for (const s of HELDOUT_ATTACKS) {
      expect(train.has(s.id), s.id).toBe(false);
      expect(s.variant, s.id).toBe('heldout');
      for (const e of s.events(START)) expect(() => SensorEvent.parse(e), s.id).not.toThrow();
    }
    for (const l of HELDOUT_LOOKALIKES)
      for (const e of l.events(START)) expect(() => SensorEvent.parse(e), l.id).not.toThrow();
    expect(ATTACKS.some((s) => s.variant === 'heldout')).toBe(false);
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

describe('rule scoring', () => {
  it('credits a candidate rule with the attacks only it catches', async () => {
    const { scoreCandidates } = await import('./detection.js');
    const [score] = scoreCandidates(
      [
        {
          id: 'candidate-pipe-full-path',
          version: 1,
          origin: 'user',
          name: 'Downloaded script piped to a shell by full path',
          description: 'curl or wget piped into /bin/sh, /bin/bash or /bin/zsh.',
          mode: 'shadow',
          severity: 'medium',
          fidelity: 'medium',
          eventKinds: ['process.exec'],
          condition: {
            field: 'process.commandLine',
            op: 'regex',
            value: ['(curl|wget)\\s[^|]*\\|\\s*(sudo\\s+)?/bin/(ba|z|da)?sh\\b'],
          },
          response: [],
          exclusions: [],
          reasons: ['A command downloaded code and ran it with a shell.'],
          tags: [],
          createdAt: START,
          updatedAt: START,
        },
      ],
      { days: 8, telemetry: ['sensors'] },
    );
    expect(score?.newlyCaught).toContain('curl-pipe-full-path (sensors)');
    expect(score?.falsePerDay.developer.alerts).toBe(0);
  }, 30_000);
});
