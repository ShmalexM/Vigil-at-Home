import { DatabaseSync } from 'node:sqlite';
import type { Action, Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { isNoticed, needsDecision } from '../shared/attention.js';
import { Store } from './db/store.js';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { makeExec, makeRule } from './testing.js';

const base: Alert = {
  id: 'a',
  createdAt: 1,
  updatedAt: 1,
  ruleId: 'r',
  ruleVersion: 1,
  title: 't',
  summary: 's',
  severity: 'medium',
  fidelity: 'medium',
  notify: 'badge',
  status: 'open',
  containment: 'none',
  eventIds: ['e'],
  actionIds: [],
};
const alert = (over: Partial<Alert> = {}): Alert => ({ ...base, ...over });

describe('needsDecision and isNoticed', () => {
  it('puts a medium alert with nothing held under Noticed', () => {
    expect(needsDecision(alert())).toBe(false);
    expect(isNoticed(alert())).toBe(true);
  });

  it('asks for a decision when something is held, serious, or popped up', () => {
    for (const over of [
      { containment: 'active' as const },
      { severity: 'high' as const },
      { severity: 'critical' as const },
      { notify: 'popup' as const },
    ]) {
      expect(needsDecision(alert(over))).toBe(true);
      expect(isNoticed(alert(over))).toBe(false);
    }
  });

  it('ignores decided and resolved alerts', () => {
    const decision = { at: 2, verdict: 'expected' as const, remember: false };
    expect(isNoticed(alert({ decision }))).toBe(false);
    expect(isNoticed(alert({ status: 'resolved' }))).toBe(false);
    expect(needsDecision(alert({ status: 'resolved', containment: 'active' }))).toBe(false);
  });
});

describe('VigilCore', () => {
  const suspend: Action = { kind: 'process.suspend', pid: 4242 };
  const at = new Date(2026, 9, 1, 15, 0).getTime();

  function setup() {
    const store = new Store(new DatabaseSync(':memory:'));
    const executor = new DryRunExecutor();
    const core = new VigilCore(store, executor, true, () => at);
    return { core, store, executor };
  }

  it('clears only Noticed alerts and never releases a block', async () => {
    const { core, executor } = setup();
    const noticed = await core.alerts.raise({
      rule: makeRule({
        id: 'quarantine-removed',
        mode: 'alert',
        severity: 'medium',
        fidelity: 'medium',
      }),
      events: [makeExec()],
      actions: [],
    });
    const blocked = await core.alerts.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [suspend],
    });
    expect(core.status()).toMatchObject({ needsYou: 1, noticed: 1 });

    expect(await core.clearNoticed([noticed.id, blocked.id, 'nope'])).toBe(1);
    expect(core.store.getAlert(noticed.id)).toMatchObject({
      status: 'resolved',
      decision: { verdict: 'expected', remember: false },
    });
    expect(core.store.getAlert(blocked.id)).toMatchObject({
      status: 'open',
      containment: 'active',
    });
    expect(executor.log).toEqual([suspend]);
    expect(core.status()).toMatchObject({ needsYou: 1, noticed: 0 });
  });

  it('reports what it checked and blocked today', async () => {
    const { core } = setup();
    const yesterday = new Date(2026, 8, 30, 23, 0).getTime();
    core.store.insertEvent({ ...makeExec(), ts: yesterday });
    core.store.insertEvent({ ...makeExec(), ts: at - 60_000 });
    expect(core.status().watch).toEqual({
      checkedToday: 1,
      lastEventAt: at - 60_000,
      blockedToday: 0,
    });
    await core.alerts.raise({
      rule: makeRule(),
      events: [{ ...makeExec(), ts: at }],
      actions: [suspend],
    });
    expect(core.status().watch).toMatchObject({ checkedToday: 2, blockedToday: 1 });
  });
});
