import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { Store } from './db/store.js';
import { DryRunExecutor } from './executor.js';
import { EVENT_STATS_TTL_MS, VigilCore } from './service.js';
import { makeExec } from './testing.js';

describe('Activity strip numbers', () => {
  it('are reused for a few seconds, then counted again', () => {
    let now = 10_000_000;
    const store = new Store(new DatabaseSync(':memory:'));
    const core = new VigilCore(store, new DryRunExecutor(), true, () => now);
    const at = (ts: number) => ({ ...makeExec(), ts });
    store.insertEvent(at(now - 1000), {
      checked: 2,
      matches: [{ ruleId: 'r1', ruleName: 'R', mode: 'alert' }],
    });
    const first = core.eventStats();
    expect(first).toMatchObject({ lastHour: 1, matchedLastHour: 1, programsLastHour: 1 });
    store.insertEvent(at(now), { checked: 2, matches: [] });
    now += EVENT_STATS_TTL_MS - 1;
    expect(core.eventStats().lastHour).toBe(1);
    now += 1;
    expect(core.eventStats()).toMatchObject({ lastHour: 2, matchedLastHour: 1 });
  });
});
