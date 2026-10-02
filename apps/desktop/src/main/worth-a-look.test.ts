import type { SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import type { EventLabel } from '../shared/ipc.js';
import { WORTH_A_LOOK_PER_DAY, WorthALook } from './worth-a-look.js';

const DAY = 24 * 60 * 60 * 1000;

function setup() {
  let now = 1_800_000_000_000;
  const raised: { title?: string | undefined; subject?: unknown; actions: unknown[] }[] = [];
  const w = new WorthALook(
    { raise: async (d) => (raised.push(d), { id: `a${raised.length}` }) as never },
    () => now,
  );
  return { w, raised, later: (ms: number) => (now += ms) };
}

const label = (score: number, l: EventLabel['label'] = 'suspicious'): EventLabel => ({
  label: l,
  score,
  reason: 'Looks like a stealer',
  by: 'jev',
  at: 0,
});

let n = 0;
const exec = (path: string): SensorEvent => ({
  id: `e${++n}`,
  ts: 0,
  source: 'santa',
  kind: 'process.exec',
  process: { pid: n, path, signing: 'unsigned' },
});

describe('worth a look', () => {
  it('only raises for suspicious labels the classifier is sure of, with no actions', async () => {
    const { w, raised } = setup();
    expect(await w.consider(exec('/tmp/a'), label(0.9, 'unusual'))).toBeUndefined();
    expect(await w.consider(exec('/tmp/a'), label(0.3))).toBeUndefined();
    expect(await w.consider(exec('/tmp/a'), label(0.6))).toBeDefined();
    expect(raised).toEqual([
      expect.objectContaining({
        title: 'Worth a look: a',
        actions: [],
        subject: { kind: 'process', label: 'a', path: '/tmp/a' },
      }),
    ]);
  });

  it('raises once a day for the same thing, and only a few a day in all', async () => {
    const { w, raised, later } = setup();
    await w.consider(exec('/tmp/a'), label(0.9));
    await w.consider(exec('/tmp/a'), label(0.9));
    expect(raised).toHaveLength(1);
    for (let i = 0; i < 10; i++) await w.consider(exec(`/tmp/x${i}`), label(0.9));
    expect(raised).toHaveLength(WORTH_A_LOOK_PER_DAY);
    later(DAY + 1);
    await w.consider(exec('/tmp/a'), label(0.9));
    expect(raised).toHaveLength(WORTH_A_LOOK_PER_DAY + 1);
  });

  it('names what to look at for connections, files and startup items', async () => {
    const { w, raised } = setup();
    await w.consider(
      {
        id: 'n1',
        ts: 0,
        source: 'osquery',
        kind: 'network.connection',
        direction: 'outbound',
        protocol: 'tcp',
        remoteAddress: '203.0.113.9',
        remotePort: 443,
        process: { pid: 1, path: '/tmp/beacon' },
      },
      label(0.9),
    );
    await w.consider(
      {
        id: 'p1',
        ts: 0,
        source: 'osquery',
        kind: 'persistence',
        change: 'added',
        mechanism: 'launch_agent',
        path: '/Users/a/Library/LaunchAgents/x.plist',
        label: 'com.example.x',
      },
      label(0.9),
    );
    expect(raised.map((r) => r.subject)).toEqual([
      { kind: 'network', label: 'beacon → 203.0.113.9' },
      {
        kind: 'persistence',
        label: 'com.example.x',
        path: '/Users/a/Library/LaunchAgents/x.plist',
      },
    ]);
  });
});
