import { DatabaseSync } from 'node:sqlite';
import { TEXT_SEARCH_WINDOW_MS } from '../shared/ipc.js';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { Store } from './db/store.js';
import { makeExec, makeRule, memoryStore } from './testing.js';

describe('Store', () => {
  it('nests transactions as savepoints and rolls back only the inner one', () => {
    const store = memoryStore();
    const a = makeExec();
    const b = makeExec();
    store.tx(() => {
      store.insertEvent(a);
      expect(() =>
        store.tx(() => {
          store.insertEvent(b);
          throw new Error('inner');
        }),
      ).toThrow('inner');
      store.insertEvents([{ event: b }]);
    });
    expect(store.getEvents([a.id, b.id]).map((e) => e.id)).toEqual([a.id, b.id]);
  });

  it('recovers from a transaction left open outside tx', () => {
    const db = new DatabaseSync(':memory:');
    const store = new Store(db);
    const a = makeExec();
    db.exec('BEGIN');
    store.insertEvent(a);
    const b = makeExec();
    expect(() => store.insertEvents([{ event: b }])).not.toThrow();
    expect(db.isTransaction).toBe(false);
    expect(store.getEvents([a.id, b.id])).toHaveLength(2);
  });

  it('round-trips events, rules and settings', () => {
    const s = memoryStore();
    const e = makeExec();
    s.insertEvent(e);
    s.insertEvent(e); // idempotent
    expect(s.getEvent(e.id)).toEqual(e);
    expect(s.recentEvents({ kind: 'process.exec' })).toHaveLength(1);

    s.upsertRule(makeRule());
    s.upsertRule(makeRule({ version: 2, mode: 'shadow' }));
    expect(s.getRule('test.rule')?.version).toBe(2);
    expect(s.listRules('shadow')).toHaveLength(1);

    expect(s.getSetting('theme', z.enum(['dark', 'light']), 'dark')).toBe('dark');
    s.setSetting('theme', 'light');
    expect(s.getSetting('theme', z.enum(['dark', 'light']), 'dark')).toBe('light');
    s.setSetting('theme', 42);
    expect(s.getSetting('theme', z.enum(['dark', 'light']), 'dark')).toBe('dark');
  });

  it('is idempotent across reopen (migrations run once)', () => {
    const s = memoryStore();
    s.upsertRule(makeRule());
    expect(s.listRules()).toHaveLength(1);
  });

  it('prunes old events except ones an alert references', () => {
    const s = memoryStore();
    const keep = makeExec();
    const drop = makeExec();
    s.insertEvent(keep);
    s.insertEvent(drop);
    s.saveAlert({
      id: 'a1',
      createdAt: 1,
      updatedAt: 1,
      ruleId: 'r',
      ruleVersion: 1,
      title: 't',
      summary: 's',
      severity: 'low',
      fidelity: 'low',
      notify: 'silent',
      status: 'open',
      containment: 'none',
      eventIds: [keep.id],
      actionIds: [],
    });
    expect(s.pruneEvents(Number.MAX_SAFE_INTEGER)).toBe(1);
    expect(s.getEvent(keep.id)).toBeDefined();
    expect(s.getEvent(drop.id)).toBeUndefined();
  });

  it('counts rule matches since a time', () => {
    const s = memoryStore();
    for (const ts of [10, 20, 30]) {
      s.insertRuleMatch({
        id: `m${ts}`,
        ruleId: 'r',
        ruleVersion: 1,
        mode: 'shadow',
        ts,
        eventIds: ['e'],
      });
    }
    expect(s.ruleMatchCounts(15).get('r')).toBe(2);
  });

  it('keeps the database under a size cap by dropping the oldest events', () => {
    const s = memoryStore();
    const kept = makeExec();
    s.insertEvent(kept);
    s.saveAlert({
      id: 'a-cap',
      createdAt: 1,
      updatedAt: 1,
      ruleId: 'test.rule',
      ruleVersion: 1,
      title: 't',
      summary: 's',
      severity: 'high',
      fidelity: 'high',
      notify: 'popup',
      status: 'open',
      containment: 'none',
      eventIds: [kept.id],
      actionIds: [],
    });
    const many = Array.from({ length: 3000 }, (_, i) => ({
      ...makeExec(`/usr/bin/tool${i}`),
      process: { pid: i, path: `/usr/bin/tool${i}`, args: ['x'.repeat(200)] },
    }));
    expect(s.insertEvents(many.map((event) => ({ event })))).toBe(0);
    const full = s.usedBytes();
    const removed = s.pruneEventsToSize(full / 2);
    expect(removed).toBeGreaterThan(0);
    expect(s.usedBytes()).toBeLessThanOrEqual(full / 2);
    expect(s.getEvent(kept.id)).toBeDefined();
    // The newest events stay.
    expect(s.getEvent(many.at(-1)!.id)).toBeDefined();
  });

  it('lists the event feed with filters, paging and outcomes', () => {
    const s = memoryStore();
    const a = { ...makeExec('/Applications/Safari.app/Contents/MacOS/Safari'), ts: 1000 };
    const b = { ...makeExec('/tmp/100%_evil'), ts: 2000 };
    s.insertEvent(a, { checked: 3, matches: [] });
    s.insertEvent(b, {
      checked: 3,
      matches: [{ ruleId: 'r1', ruleName: 'Rule one', mode: 'alert' }],
    });
    s.insertEvent({
      id: 'net1',
      ts: 3000,
      source: 'osquery',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress: '1.2.3.4',
    });

    expect(s.listEventViews().map((v) => v.event.ts)).toEqual([3000, 2000, 1000]);
    expect(s.listEventViews({ group: 'network' })).toHaveLength(1);
    expect(s.listEventViews({ matchedOnly: true }).map((v) => v.event.id)).toEqual([b.id]);
    expect(s.listEventViews({ text: 'safari' }, 5000).map((v) => v.event.id)).toEqual([a.id]);
    // % and _ are literal, not wildcards.
    expect(s.listEventViews({ text: '100%_' }, 5000).map((v) => v.event.id)).toEqual([b.id]);
    expect(s.listEventViews({ text: '%' }, 5000).map((v) => v.event.id)).toEqual([b.id]);
    expect(s.listEventViews({ before: 2000, limit: 5 }).map((v) => v.event.id)).toEqual([a.id]);
    expect(s.listEventViews({ group: 'network' })[0]?.outcome).toBeNull();
    // A search looks back one day from where the page starts.
    const dayLater = 1000 + TEXT_SEARCH_WINDOW_MS + 1;
    expect(s.listEventViews({ text: 'safari' }, dayLater)).toEqual([]);
    expect(s.listEventViews({ text: 'safari', before: 1500 }, dayLater)).toHaveLength(1);

    const stats = s.eventStats(1500);
    expect(stats).toMatchObject({
      lastHour: 2,
      matchedLastHour: 1,
      programsLastHour: 1,
      newest: 3000,
    });
    expect(stats.byGroup).toMatchObject({ programs: 1, network: 1, files: 0 });
  });

  it('fills in the outcome of an event an alert already stored, keeping its raw record', () => {
    const s = memoryStore();
    const e = { ...makeExec(), raw: { line: 'santa' } };
    s.insertEvent(e);
    s.insertEvents([{ event: { ...e, raw: undefined }, outcome: { checked: 2, matches: [] } }]);
    expect(s.getEvent(e.id)).toMatchObject({ raw: { line: 'santa' } });
    expect(s.listEventViews()[0]?.outcome).toEqual({ checked: 2, matches: [] });
  });

  it('marks batched events that matched a rule, including ones an alert stored first', () => {
    const s = memoryStore();
    const hit = makeExec();
    const plain = makeExec();
    const matches = [{ ruleId: 'r', ruleName: 'R', mode: 'alert' as const }];
    s.insertEvent(hit);
    s.insertEvents([
      { event: hit, outcome: { checked: 1, matches } },
      { event: plain, outcome: { checked: 1, matches: [] } },
    ]);
    expect(s.listEventViews({ matchedOnly: true }).map((v) => v.event.id)).toEqual([hit.id]);
  });
});
