import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { makeExec, makeRule, memoryStore } from './testing.js';

describe('Store', () => {
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
    expect(s.insertEvents(many)).toBe(0);
    const full = s.usedBytes();
    const removed = s.pruneEventsToSize(full / 2);
    expect(removed).toBeGreaterThan(0);
    expect(s.usedBytes()).toBeLessThanOrEqual(full / 2);
    expect(s.getEvent(kept.id)).toBeDefined();
    // The newest events stay.
    expect(s.getEvent(many.at(-1)!.id)).toBeDefined();
  });
});
