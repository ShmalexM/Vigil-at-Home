import { DatabaseSync } from 'node:sqlite';
import type { Action, Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { isNoticed, needsDecision } from '../shared/attention.js';
import { Store } from './db/store.js';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { alertCounts } from './status.js';
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

  it('counts every open alert in the status, not just the newest 200', () => {
    const { core, store } = setup();
    for (let i = 0; i < 250; i++) {
      store.saveAlert(alert({ id: `n${i}`, createdAt: i, updatedAt: i }));
      store.saveAlert(
        alert({ id: `h${i}`, createdAt: 1000 + i, updatedAt: 1000 + i, severity: 'high' }),
      );
    }
    expect(core.status()).toMatchObject({ needsYou: 250, noticed: 250 });
    store.saveAlert(alert({ id: 'n0', status: 'resolved' }));
    expect(core.status()).toMatchObject({ needsYou: 250, noticed: 249 });
  });

  it('clears every Noticed alert up to the moment the confirm opened', async () => {
    const { core, store } = setup();
    for (let i = 0; i < 230; i++) store.saveAlert(alert({ id: `n${i}`, createdAt: i }));
    store.saveAlert(alert({ id: 'later', createdAt: 500 }));
    store.saveAlert(alert({ id: 'serious', createdAt: 5, severity: 'high' }));
    expect(await core.clearNoticedUpTo(300)).toBe(230);
    expect(core.status()).toMatchObject({ noticed: 1, needsYou: 1 });
    expect(store.getAlert('later')?.decision).toBeUndefined();
    expect(store.getAlert('serious')?.decision).toBeUndefined();
  });

  it('leaves Noticed alerts with an action or AI suggestion out of the bulk clear', async () => {
    const { core, store } = setup();
    const ai = {
      provider: 'x',
      at: 1,
      verdict: 'unsure' as const,
      summary: '',
      proposalIds: ['p'],
    };
    store.saveAlert(alert({ id: 'plain', createdAt: 1 }));
    store.saveAlert(alert({ id: 'suggested', createdAt: 2, ai }));
    store.saveAlert(alert({ id: 'acted', createdAt: 3, actionIds: ['x'] }));
    // The confirm's count is exactly what will be cleared.
    expect(core.status()).toMatchObject({ noticed: 3, noticedClearable: 1 });
    expect(await core.clearNoticedUpTo(10)).toBe(1);
    expect(await core.clearNoticed(['suggested', 'acted'])).toBe(0);
    expect(store.getAlert('suggested')?.decision).toBeUndefined();
    expect(store.getAlert('acted')?.decision).toBeUndefined();
    expect(core.status()).toMatchObject({ noticed: 2, noticedClearable: 0 });
  });

  it("leaves a Noticed alert with a rule's pending suggestion out of the bulk clear", async () => {
    const { core, store } = setup();
    const rule = makeRule({
      id: 'download-pipe-to-shell',
      mode: 'alert',
      severity: 'medium',
      fidelity: 'medium',
    });
    // A suggested suspend and no AI assessment: only the proposals table knows.
    const suggested = await core.alerts.raise({ rule, events: [makeExec()], actions: [suspend] });
    expect(suggested.ai).toBeUndefined();
    store.saveAlert(alert({ id: 'plain', createdAt: 1 }));
    expect(core.status()).toMatchObject({ noticed: 2, noticedClearable: 1 });
    expect(await core.clearNoticedUpTo(at)).toBe(1);
    expect(await core.clearNoticed([suggested.id])).toBe(0);
    expect(store.getAlert(suggested.id)?.decision).toBeUndefined();
    expect(store.listProposals({ alertId: suggested.id }).map((p) => p.status)).toEqual([
      'pending',
    ]);
    // Once the suggestion is settled, it can go in bulk again.
    const [p] = store.listProposals({ alertId: suggested.id });
    store.saveProposal({ ...p!, status: 'rejected', decidedAt: at });
    expect(core.status()).toMatchObject({ noticed: 1, noticedClearable: 1 });
  });

  it('leaves an alert whose repeat arrived after the confirm opened', async () => {
    let now = at;
    const store = new Store(new DatabaseSync(':memory:'));
    const core = new VigilCore(store, new DryRunExecutor(), true, () => now);
    const rule = makeRule({ mode: 'alert', severity: 'medium', fidelity: 'medium' });
    const first = await core.alerts.raise({ rule, events: [makeExec()], actions: [] });
    const opened = now;
    now += 60_000;
    // The repeat folds into the alert raised before the confirm.
    const again = await core.alerts.raise({ rule, events: [makeExec()], actions: [] });
    expect(again.id).toBe(first.id);
    expect(again.createdAt).toBe(opened);
    expect(await core.clearNoticedUpTo(opened)).toBe(0);
    expect(store.getAlert(first.id)?.decision).toBeUndefined();
    expect(await core.clearNoticedUpTo(now)).toBe(1);
  });

  it('counts exactly as needsDecision and piles do', () => {
    const { store } = setup();
    const pile = (key: string) => ({ key, who: 'claude' });
    const decision = { at: 2, verdict: 'expected' as const, remember: false };
    const cases: Partial<Alert>[] = [
      {},
      { severity: 'high' },
      { severity: 'critical', decision },
      { notify: 'popup' },
      { containment: 'active' },
      { containment: 'active', pile: pile('a') },
      { severity: 'high', pile: pile('a') },
      { severity: 'high', pile: pile('a') },
      { severity: 'high', pile: pile('b') },
      { severity: 'high', pile: pile('a'), actionIds: ['x'] },
      {
        severity: 'high',
        pile: pile('c'),
        ai: { provider: 'x', at: 1, verdict: 'unsure', summary: '', proposalIds: ['p'] },
      },
      { pile: pile('d') },
      { actionIds: ['y'] },
      { ai: { provider: 'x', at: 1, verdict: 'unsure', summary: '', proposalIds: ['q'] } },
      { status: 'resolved', severity: 'high' },
      { decision },
    ];
    const all = cases.map((over, i) => alert({ id: `c${i}`, createdAt: i, ...over }));
    for (const a of all) store.saveAlert(a);
    const open = store.listAlerts({ status: 'open', limit: -1 });
    expect(store.openAlertCounts()).toEqual(alertCounts(open));
    // An alert saved in a transaction that rolls back isn't counted.
    expect(() =>
      store.tx(() => {
        store.saveAlert(alert({ id: 'gone', severity: 'critical' }));
        throw new Error('rolled back');
      }),
    ).toThrow();
    expect(store.openAlertCounts()).toEqual(alertCounts(open));
  });

  it('counts afresh when SQLite has already ended the transaction itself', () => {
    const db = new DatabaseSync(':memory:');
    const store = new Store(db);
    expect(store.openAlertCounts()).toMatchObject({ needsYou: 0 });
    // SQLITE_FULL and the like roll the whole transaction back before the error reaches tx.
    expect(() =>
      store.tx(() => {
        store.saveAlert(alert({ id: 'gone', severity: 'critical' }));
        db.exec('ROLLBACK');
        throw new Error('database or disk is full');
      }),
    ).toThrow('full');
    expect(store.getAlert('gone')).toBeUndefined();
    expect(store.openAlertCounts()).toMatchObject({ needsYou: 0 });
    // The same from a nested tx: the outer one finds no transaction left either.
    expect(() =>
      store.tx(() => {
        store.saveAlert(alert({ id: 'outer', severity: 'critical' }));
        store.tx(() => {
          store.saveAlert(alert({ id: 'inner', severity: 'critical' }));
          db.exec('ROLLBACK');
          throw new Error('database or disk is full');
        });
      }),
    ).toThrow('full');
    expect(store.listAlerts()).toEqual([]);
    expect(store.openAlertCounts()).toMatchObject({ needsYou: 0 });
  });

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

  it('counts noticed alerts on the badge only with Show me more', async () => {
    const { core } = setup();
    await core.alerts.raise({
      rule: makeRule({ mode: 'alert', severity: 'medium', fidelity: 'medium' }),
      events: [makeExec()],
      actions: [],
    });
    expect(core.status()).toMatchObject({ alertView: 'less', badge: 0 });
    core.setAlertView('more');
    expect(core.status()).toMatchObject({ alertView: 'more', badge: 1 });
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
