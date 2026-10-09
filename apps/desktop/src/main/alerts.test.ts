import type { Action, ActionResult, Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { AlertService, notifyLevel } from './alerts.js';
import { DryRunExecutor, type ActionExecutor } from './executor.js';
import { makeExec, makeRule, memoryStore } from './testing.js';

const suspend: Action = { kind: 'process.suspend', pid: 4242 };

function setup(executor: ActionExecutor = new DryRunExecutor()) {
  const store = memoryStore();
  const svc = new AlertService(store, executor);
  const popups: Alert[] = [];
  svc.on('popup', (a) => popups.push(a));
  return { store, svc, popups, executor };
}

describe('AlertService', () => {
  it('blocks inline, then pops up with containment active', async () => {
    const { svc, popups, store, executor } = setup();
    const alert = await svc.raise({ rule: makeRule(), events: [makeExec()], actions: [suspend] });
    expect((executor as DryRunExecutor).log).toEqual([suspend]);
    expect(alert.containment).toBe('active');
    expect(alert.actionIds).toHaveLength(1);
    // Recorded as simulated at the time, so the popup can say "would have" truthfully later.
    expect(store.getAction(alert.actionIds[0]!)?.result?.simulated).toBe(true);
    expect(popups.map((a) => a.id)).toEqual([alert.id]);
    expect(store.ruleMatchCounts(0).get('test.rule')).toBe(1);
  });

  it('in alert mode proposes the response instead of running it', async () => {
    const { svc, store, executor } = setup();
    const alert = await svc.raise({
      rule: makeRule({ mode: 'alert', fidelity: 'medium' }),
      events: [makeExec()],
      actions: [suspend],
    });
    expect((executor as DryRunExecutor).log).toEqual([]);
    expect(alert.containment).toBe('none');
    expect(alert.notify).toBe('badge');
    const [p] = store.listProposals({ alertId: alert.id });
    expect(p?.proposedBy).toBe('rule');
    await svc.approveProposal(p!.id);
    expect(store.getAlert(alert.id)?.containment).toBe('active');
  });

  it('refuses to raise from shadow rules and records shadow matches silently', async () => {
    const { svc, store, popups } = setup();
    const shadow = makeRule({ mode: 'shadow', origin: 'ai' });
    await expect(svc.raise({ rule: shadow, events: [makeExec()], actions: [] })).rejects.toThrow();
    svc.recordShadowMatch(shadow, [makeExec()]);
    expect(store.listAlerts()).toHaveLength(0);
    expect(store.ruleMatchCounts(0).get('test.rule')).toBe(1);
    expect(popups).toHaveLength(0);
  });

  it('denies a rule trying to release, and logs the denial', async () => {
    const { svc, executor } = setup();
    const alert = await svc.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [{ kind: 'process.resume', pid: 1 }],
    });
    expect((executor as DryRunExecutor).log).toEqual([]);
    expect(alert.containment).toBe('none');
  });

  it('releases only on the user decision, and undoes each containment', async () => {
    const { svc, store, executor } = setup();
    const alert = await svc.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [suspend, { kind: 'network.block', address: '203.0.113.9' }],
    });
    const decided = await svc.decide(alert.id, { verdict: 'benign', release: true });
    expect(decided.status).toBe('resolved');
    expect(decided.containment).toBe('released');
    expect((executor as DryRunExecutor).log.slice(2)).toEqual([
      { kind: 'process.resume', pid: 4242 },
      { kind: 'network.unblock', address: '203.0.113.9' },
    ]);
    const log = store.listActions({ alertId: alert.id });
    expect(log.filter((r) => r.actor === 'user')).toHaveLength(2);
  });

  it('keeps the alert open and blocked when a release fails', async () => {
    class FailsResume extends DryRunExecutor {
      override async execute(action: Action): Promise<ActionResult> {
        if (action.kind === 'process.resume')
          return { at: Date.now(), error: 'helper not running' };
        return super.execute(action);
      }
    }
    const { svc, store } = setup(new FailsResume());
    const alert = await svc.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [suspend, { kind: 'network.block', address: '203.0.113.9' }],
    });
    const out = await svc.decide(alert.id, { verdict: 'benign', release: true });
    expect(out.status).toBe('open');
    expect(out.decision).toBeUndefined();
    expect(out.containment).toBe('active');
    expect(store.getAlert(alert.id)?.decision).toBeUndefined();
    const undos = store.listActions({ alertId: alert.id }).filter((r) => r.undoes);
    expect(undos.map((r) => r.status).sort()).toEqual(['done', 'failed']);

    // Once the helper is back, the same choice goes through.
    const ok = setup();
    const again = await ok.svc.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [suspend],
    });
    expect((await ok.svc.decide(again.id, { verdict: 'benign', release: true })).status).toBe(
      'resolved',
    );
  });

  it('keeps the alert open when an undo throws', async () => {
    class Throws extends DryRunExecutor {
      override async execute(action: Action): Promise<ActionResult> {
        if (action.kind === 'process.resume') throw new Error('socket closed');
        return super.execute(action);
      }
    }
    const { svc } = setup(new Throws());
    const alert = await svc.raise({ rule: makeRule(), events: [makeExec()], actions: [suspend] });
    const out = await svc.decide(alert.id, { verdict: 'benign', release: true });
    expect(out.decision).toBeUndefined();
    expect(out.containment).toBe('active');
  });

  it('keeps containment when the user confirms malicious', async () => {
    const { svc } = setup();
    const alert = await svc.raise({ rule: makeRule(), events: [makeExec()], actions: [suspend] });
    const decided = await svc.decide(alert.id, { verdict: 'malicious', release: false });
    expect(decided.containment).toBe('active');
  });

  it('never lets the AI propose a release, and keeps its assessment advisory', async () => {
    const { svc } = setup();
    const alert = await svc.raise({ rule: makeRule(), events: [makeExec()], actions: [suspend] });
    expect(() =>
      svc.propose('ai', { kind: 'process.resume', pid: 4242 }, alert.id, 'looks fine'),
    ).toThrow('Only the user');
    const after = svc.recordAssessment(alert.id, {
      provider: 'claude',
      at: 5,
      verdict: 'likely_benign',
      summary: 'Probably a build tool',
      proposalIds: [],
    });
    expect(after.containment).toBe('active');
    expect(after.ai?.verdict).toBe('likely_benign');
  });

  it('marks failed executions without throwing', async () => {
    const failing: ActionExecutor = {
      execute: async (): Promise<ActionResult> => {
        throw new Error('helper not installed');
      },
    };
    const { svc, store } = setup(failing);
    const alert = await svc.raise({ rule: makeRule(), events: [makeExec()], actions: [suspend] });
    expect(alert.containment).toBe('none');
    expect(store.listActions({ alertId: alert.id })[0]).toMatchObject({
      status: 'failed',
      result: { error: 'helper not installed' },
    });
  });
});

describe('notifyLevel', () => {
  it('pops up for blocks and trustworthy serious rules only', () => {
    expect(notifyLevel(makeRule({ mode: 'block', fidelity: 'low', severity: 'low' }))).toBe(
      'popup',
    );
    expect(notifyLevel(makeRule({ mode: 'alert', fidelity: 'high', severity: 'high' }))).toBe(
      'popup',
    );
    expect(notifyLevel(makeRule({ mode: 'alert', fidelity: 'medium', severity: 'critical' }))).toBe(
      'badge',
    );
    expect(notifyLevel(makeRule({ mode: 'alert', fidelity: 'low', severity: 'low' }))).toBe(
      'silent',
    );
  });
});
