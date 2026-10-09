import type { Action, ActionProposal, ActionRecord, Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import {
  activeContainment,
  containLabel,
  isSimulated,
  keepLabel,
  othersNeedingYou,
  provenance,
  releaseLabel,
  releaseStep,
  responseProvenance,
} from './decision';

let n = 0;
const rec = (action: Action, over: Partial<ActionRecord> = {}): ActionRecord => ({
  id: `a${++n}`,
  action,
  actor: 'rule',
  reason: 'r',
  requestedAt: 1,
  status: 'done',
  result: { at: 1 },
  ...over,
});
const prop = (action: Action): ActionProposal => ({
  id: `p${++n}`,
  action,
  proposedBy: 'rule',
  alertId: 'x',
  rationale: 'r',
  createdAt: 1,
  status: 'pending',
});
const suspend: Action = { kind: 'process.suspend', pid: 7, path: '/tmp/evil' };
const block: Action = { kind: 'network.block', address: '203.0.113.9' };

describe('decision wording', () => {
  it('names the effect of keeping and releasing', () => {
    const paused = [rec(suspend)];
    expect(keepLabel(paused)).toBe('Keep paused');
    expect(releaseLabel(paused)).toBe('Resume app');
    expect(releaseLabel([rec(block)])).toBe('Unblock connection');
    expect(releaseLabel([rec(block), rec(block)])).toBe('Unblock connections');
    expect(keepLabel([rec(suspend), rec(block)])).toBe('Keep blocked');
    expect(releaseLabel([rec(suspend), rec(block)])).toBe('Release both');
  });

  it('lists only containment still in force, the same set the main process undoes', () => {
    const quarantined = rec({ kind: 'file.quarantine', path: '/x/a.dmg' });
    const restorable = rec(
      { kind: 'file.quarantine', path: '/x/b.dmg' },
      { result: { at: 1, quarantineId: 'q1' } },
    );
    const list = [
      rec(suspend),
      rec(block, { status: 'undone' }),
      rec(block, { status: 'failed' }),
      rec({ kind: 'process.resume', pid: 7 }, { actor: 'user', undoes: 'z' }),
      quarantined,
      restorable,
    ];
    expect(activeContainment(list).map(releaseStep)).toEqual(['Resume evil', 'Restore b.dmg']);
  });

  it('names a suggested response', () => {
    expect(containLabel([prop(suspend)])).toBe('Pause app');
    expect(containLabel([prop(block)])).toBe('Block connection');
    expect(containLabel([prop(suspend), prop(block)])).toBe('Do all 2');
  });
});

describe('simulated containment', () => {
  const alert = (over: Partial<Alert> = {}): Alert =>
    ({
      id: 'x',
      createdAt: 1,
      updatedAt: 1,
      ruleId: 'r',
      ruleVersion: 1,
      title: 't',
      summary: '',
      severity: 'high',
      fidelity: 'high',
      notify: 'popup',
      status: 'open',
      containment: 'active',
      eventIds: ['e'],
      actionIds: [],
      ...over,
    }) as Alert;
  const suspend: Action = { kind: 'process.suspend', pid: 1 };

  it('follows the records, not whether the helper is connected now', () => {
    const real = rec(suspend, { result: { at: 1, simulated: false } });
    const dry = rec(suspend, { result: { at: 1, simulated: true } });
    expect(isSimulated(dry)).toBe(true);
    expect(responseProvenance([dry])).toBe('simulated');
    expect(responseProvenance([real])).toBe('real');
    expect(responseProvenance([real, dry])).toBe('mixed');
    expect(responseProvenance([])).toBeUndefined();
  });

  it('counts actions with no undo, like a kill', () => {
    const kill: Action = { kind: 'process.kill', pid: 1 };
    const dryKill = rec(kill, { result: { at: 1, simulated: true } });
    const realKill = rec(kill, { result: { at: 1, simulated: false } });
    expect(responseProvenance([dryKill])).toBe('simulated');
    expect(
      responseProvenance([realKill, rec(suspend, { result: { at: 1, simulated: true } })]),
    ).toBe('mixed');
    // Undoes and actions that didn't go through say nothing about the response.
    expect(responseProvenance([realKill, rec(suspend, { status: 'failed' })])).toBe('real');
  });

  it('never reads a row from an older build as real', () => {
    // Older builds saved simulations without the field; only a dry-run quarantine id tells.
    const old = rec(suspend, { result: { at: 1 } });
    const oldDryQuarantine = rec(
      { kind: 'file.quarantine', path: '/tmp/x' },
      { result: { at: 1, quarantineId: 'dry-1' } },
    );
    expect(provenance(old)).toBe('unknown');
    expect(provenance(oldDryQuarantine)).toBe('simulated');
    expect(responseProvenance([old])).toBe('unknown');
    expect(responseProvenance([old, rec(suspend, { result: { at: 1, simulated: false } })])).toBe(
      'unknown',
    );
  });

  it('counts the other decisions, keeping a pile this alert sits in', () => {
    const pile = { key: 'k', who: 'claude' };
    const a = alert({ id: 'a', containment: 'none', pile });
    const b = alert({ id: 'b', containment: 'none', pile });
    const c = alert({ id: 'c', containment: 'none' });
    // Rows: the a+b pile and c.
    expect(othersNeedingYou(a, 2, [a, b, c])).toBe(2);
    expect(othersNeedingYou(c, 2, [a, b, c])).toBe(1);
    expect(
      othersNeedingYou(alert({ severity: 'low', notify: 'badge', containment: 'none' }), 2, []),
    ).toBe(2);
  });
});
