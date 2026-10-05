import type { Alert, SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { needsDecision } from '../shared/attention.js';
import { commonFolder, pileMates, pileUp } from '../shared/piles.js';
import { AlertService, REPEAT_WINDOW_MS } from './alerts.js';
import { DryRunExecutor } from './executor.js';
import { computeStatus } from './status.js';
import { makeExec, makeRule, memoryStore } from './testing.js';

const rule = makeRule({
  id: 'agent-secret-read',
  mode: 'alert',
  severity: 'high',
  fidelity: 'high',
});
let n = 0;

/** A file the Claude app (one run of it) opened. */
function opened(path: string, session = 'aaaaaaaaaaaaaaaa'): SensorEvent {
  n++;
  return {
    id: `pf-${n}`,
    ts: 1_000 + n,
    source: 'test',
    kind: 'file',
    op: 'open',
    path,
    process: {
      pid: 500,
      path: '/Applications/Claude.app/Contents/MacOS/Claude',
      signing: 'developer_id',
      agent: { id: 'claude-desktop', session, depth: 0 },
    },
  };
}

function setup() {
  let now = 1_000_000;
  const store = memoryStore();
  const svc = new AlertService(store, new DryRunExecutor(), () => now);
  const popups: Alert[] = [];
  svc.on('popup', (a) => popups.push(a));
  return { store, svc, popups, tick: (ms: number) => (now += ms) };
}

describe('piles', () => {
  it('piles one agent run’s alerts into one Needs-you row that interrupts once', async () => {
    const { store, svc, popups, tick } = setup();
    for (let i = 0; i < 5; i++) {
      await svc.raise({ rule, events: [opened(`/Users/a/Library/x/${i}.log`)], actions: [] });
      tick(1_000);
    }
    const open = store.listAlerts({ status: 'open' });
    expect(open).toHaveLength(5); // every alert is still its own record
    expect(open[0]!.pile).toMatchObject({ who: 'Claude app' });
    expect(popups).toHaveLength(1);
    const rows = pileUp(open.filter(needsDecision));
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({ kind: 'pile', who: 'Claude app' });
    expect(computeStatus(open, []).needsYou).toBe(1);
    expect(pileMates(open[2]!, open)).toHaveLength(5);
  });

  it('keeps other agent runs, other rules and decided alerts apart', async () => {
    const { store, svc } = setup();
    await svc.raise({ rule, events: [opened('/a')], actions: [] });
    await svc.raise({ rule, events: [opened('/b')], actions: [] });
    await svc.raise({ rule, events: [opened('/c', 'bbbbbbbbbbbbbbbb')], actions: [] });
    await svc.raise({ rule: { ...rule, id: 'other' }, events: [opened('/d')], actions: [] });
    const d = await svc.raise({ rule, events: [opened('/e')], actions: [] });
    await svc.decide(d.id, { verdict: 'expected', release: false });
    const open = store.listAlerts({ status: 'open' });
    const rows = pileUp(open.filter(needsDecision));
    expect(rows.map((r) => (r.kind === 'pile' ? r.alerts.length : 1)).sort()).toEqual([1, 1, 2]);
  });

  it('pops up again once a burst is over', async () => {
    const { svc, popups, tick } = setup();
    await svc.raise({ rule, events: [opened('/a')], actions: [] });
    tick(REPEAT_WINDOW_MS + 1);
    await svc.raise({ rule, events: [opened('/b')], actions: [] });
    expect(popups).toHaveLength(2);
  });

  it('never piles critical alerts or ones that act', async () => {
    const { store, svc } = setup();
    const crit = { ...rule, severity: 'critical' as const };
    await svc.raise({ rule: crit, events: [opened('/a')], actions: [] });
    await svc.raise({ rule: crit, events: [opened('/b')], actions: [] });
    const block = makeRule({ id: 'b', mode: 'block' });
    const suspend = { kind: 'process.suspend' as const, pid: 9 };
    await svc.raise({ rule: block, events: [makeExec('/tmp/b', 9)], actions: [suspend] });
    await svc.raise({ rule: block, events: [makeExec('/tmp/b', 10)], actions: [suspend] });
    const open = store.listAlerts({ status: 'open' });
    expect(open.every((a) => !a.pile)).toBe(true);
    expect(pileUp(open)).toHaveLength(4);
  });

  it('piles a program outside any agent by its path', async () => {
    const { store, svc } = setup();
    await svc.raise({ rule, events: [makeExec('/tmp/x', 1)], actions: [] });
    await svc.raise({ rule, events: [makeExec('/tmp/x', 2)], actions: [] });
    const open = store.listAlerts({ status: 'open' });
    expect(open[0]!.pile?.who).toBe('x');
    expect(pileUp(open)).toHaveLength(1);
  });
});

describe('commonFolder', () => {
  it('finds the folder the paths share', () => {
    expect(commonFolder(['/a/b/Cookies', '/a/b/Login Data', '/a/b/c/LOCK'])).toBe('/a/b/');
    expect(commonFolder(['/a/bc', '/a/bd'])).toBe('/a/');
  });
  it('is empty for one path or none shared', () => {
    expect(commonFolder(['/a/b'])).toBe('');
    expect(commonFolder(['a', 'b'])).toBe('');
  });
});
