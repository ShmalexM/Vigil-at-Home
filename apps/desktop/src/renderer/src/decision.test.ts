import type { Action, ActionProposal, ActionRecord } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { activeContainment, containLabel, keepLabel, releaseLabel, releaseStep } from './decision';

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
