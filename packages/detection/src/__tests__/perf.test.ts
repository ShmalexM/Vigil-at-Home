import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { memoryStores } from '../state/stores.js';
import type { DetectionEvent } from '../types.js';
import { chrome, proc, T0 } from './fixtures.js';

describe('inline cost', () => {
  it('evaluates the full pack well under a millisecond per event', () => {
    const stores = memoryStores();
    stores.lists.replace(
      'known_bad_sha256',
      Array.from({ length: 100_000 }, (_, i) => i.toString(16).padStart(64, '0')),
      { source: 't', updatedAt: 0 },
    );
    const engine = new DetectionEngine(macosCoreRules, stores, { recordHistory: false });
    const events: DetectionEvent[] = [];
    for (let i = 0; i < 100_000; i++) {
      const p =
        i % 3 === 0
          ? chrome
          : proc({
              path: `/Users/a/code/bin/t${i % 500}`,
              args: ['t', '--x', String(i)],
              signing: 'adhoc',
              sha256: (i % 700).toString(16).padStart(64, 'f'),
            });
      const base = { id: `p${i}`, ts: T0 + i * 10, source: 'test' as const, process: p };
      switch (i % 4) {
        case 0:
          events.push({ ...base, kind: 'process.exec' });
          break;
        case 1:
          events.push({
            ...base,
            kind: 'file',
            op: 'open',
            path: `/Users/a/Library/Application Support/App/file${i % 50}.db`,
          });
          break;
        case 2:
          events.push({
            ...base,
            kind: 'network.connection',
            direction: 'outbound',
            protocol: 'tcp',
            remoteAddress: `140.82.${i % 250}.${i % 200}`,
            remoteHost: `h${i % 900}.example.test`,
          });
          break;
        default:
          events.push({
            ...base,
            kind: 'file',
            op: 'write',
            path: `/Users/a/Documents/f${i % 50}.txt`,
          });
      }
    }
    const start = performance.now();
    for (const e of events) engine.evaluate(e);
    const perEventUs = ((performance.now() - start) * 1000) / events.length;
    console.log(`full pack: ${perEventUs.toFixed(1)} µs per event`);
    expect(perEventUs).toBeLessThan(200);
  });
});
