import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { Store } from './db/store.js';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { makeExec } from './testing.js';

describe('VigilCore database cap', () => {
  it('prunes to the cap as events arrive, without waiting for the hourly job', async () => {
    const store = new Store(new DatabaseSync(':memory:'));
    const cap = 1024 * 1024;
    const core = new VigilCore(store, new DryRunExecutor(), true, Date.now, cap);
    const event = (i: number) => ({
      ...makeExec(`/usr/bin/tool${i}`),
      process: { pid: i, path: `/usr/bin/tool${i}`, args: ['x'.repeat(200)] },
    });
    for (let i = 0; i < 9_999; i++) core.ingest(event(i));
    core.events.flush();
    expect(store.usedBytes()).toBeGreaterThan(cap);
    core.ingest(event(9_999));
    core.events.flush();
    await new Promise((r) => setImmediate(r));
    expect(store.usedBytes()).toBeLessThanOrEqual(cap);
    core.stop();
  });
});
