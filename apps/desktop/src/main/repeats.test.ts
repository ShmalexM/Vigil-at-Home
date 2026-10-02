import type { Action, Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { AlertService, REPEAT_WINDOW_MS } from './alerts.js';
import { DryRunExecutor } from './executor.js';
import { makeExec, makeRule, memoryStore } from './testing.js';

const rule = makeRule({ mode: 'alert', severity: 'high', fidelity: 'high' });

function setup() {
  let now = 1_000_000;
  const store = memoryStore();
  const svc = new AlertService(store, new DryRunExecutor(), () => now);
  const popups: Alert[] = [];
  const raised: Alert[] = [];
  svc.on('popup', (a) => popups.push(a));
  svc.on('raised', (a) => raised.push(a));
  return { store, svc, popups, raised, tick: (ms: number) => (now += ms) };
}

describe('folding identical repeats', () => {
  it('folds an exact repeat into one row, keeps every event, and interrupts once', async () => {
    const { store, svc, popups, raised, tick } = setup();
    const first = await svc.raise({ rule, events: [makeExec()], actions: [] });
    tick(60_000);
    const again = await svc.raise({ rule, events: [makeExec()], actions: [] });
    expect(again.id).toBe(first.id);
    expect(again.repeats?.count).toBe(2);
    expect(again.eventIds).toHaveLength(2);
    expect(store.listAlerts({ status: 'open' })).toHaveLength(1);
    expect(store.ruleMatchCounts(0).get(rule.id)).toBe(2);
    expect(popups).toHaveLength(1);
    expect(raised).toHaveLength(1);
  });

  it('keeps rows apart when any evidence differs', async () => {
    const { store, svc } = setup();
    await svc.raise({ rule, events: [makeExec('/tmp/evil', 1)], actions: [] });
    await svc.raise({ rule, events: [makeExec('/tmp/evil', 2)], actions: [] }); // new process
    await svc.raise({ rule, events: [makeExec('/tmp/other', 1)], actions: [] }); // other program
    await svc.raise({
      rule: { ...rule, version: 2 },
      events: [makeExec('/tmp/evil', 1)],
      actions: [],
    });
    const withArgs = makeExec('/tmp/evil', 1);
    if (withArgs.kind === 'process.exec') withArgs.process.args = ['--quiet'];
    await svc.raise({ rule, events: [withArgs], actions: [] }); // other command
    expect(store.listAlerts({ status: 'open' })).toHaveLength(5);
  });

  it('starts a new row after the window', async () => {
    const { store, svc, tick } = setup();
    await svc.raise({ rule, events: [makeExec()], actions: [] });
    tick(REPEAT_WINDOW_MS + 1);
    await svc.raise({ rule, events: [makeExec()], actions: [] });
    expect(store.listAlerts({ status: 'open' })).toHaveLength(2);
  });

  it('never folds critical alerts, holds, suggestions, or anything decided', async () => {
    const { store, svc } = setup();
    const crit = { ...rule, severity: 'critical' as const };
    await svc.raise({ rule: crit, events: [makeExec()], actions: [] });
    await svc.raise({ rule: crit, events: [makeExec()], actions: [] });

    const suspend: Action = { kind: 'process.suspend', pid: 9 };
    const block = makeRule({ id: 'b', mode: 'block' });
    await svc.raise({ rule: block, events: [makeExec('/tmp/b', 9)], actions: [suspend] });
    await svc.raise({ rule: block, events: [makeExec('/tmp/b', 9)], actions: [suspend] });

    const suggest = makeRule({ id: 's', mode: 'alert' });
    await svc.raise({ rule: suggest, events: [makeExec('/tmp/s', 3)], actions: [suspend] });
    await svc.raise({ rule: suggest, events: [makeExec('/tmp/s', 3)], actions: [suspend] });

    const plain = makeRule({ id: 'p', mode: 'alert' });
    const decided = await svc.raise({ rule: plain, events: [makeExec('/tmp/p', 4)], actions: [] });
    await svc.decide(decided.id, { verdict: 'expected', release: false });
    await svc.raise({ rule: plain, events: [makeExec('/tmp/p', 4)], actions: [] });

    expect(store.listAlerts()).toHaveLength(8);
  });
});
