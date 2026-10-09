import type { Action, ActionProposal, ActionRecord } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import {
  actionErrorText,
  activeContainment,
  containLabel,
  refusalNote,
  keepLabel,
  releaseLabel,
  releaseStep,
  sameAlert,
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

describe('a quarantine an installer’s ownership stopped', () => {
  const app = '/Applications/Tool.app/Contents/MacOS/Tool';
  const refused = (path: string) =>
    rec(
      { kind: 'file.quarantine', path },
      {
        status: 'failed',
        alertId: 'al1',
        result: { at: 1, error: 'Not done: x', errorCode: 'installer-owned' },
      },
    );
  const santaBlock = (over: Partial<ActionRecord> = {}) =>
    rec(
      { kind: 'santa.rule.set', ruleType: 'binary', identifier: 'a'.repeat(64), policy: 'block' },
      { alertId: 'al1', ...over },
    );

  it('says the app is blocked only when this alert blocked it', () => {
    const q = refused(app);
    expect(refusalNote(q, [q, santaBlock()])).toBe(
      'Vigil blocked this app from running but can’t move apps an installer put in Applications. Drag it to the Trash to remove it.',
    );
    // No block, a failed one, or one undone since: no claim.
    for (const others of [
      [],
      [santaBlock({ status: 'failed' })],
      [santaBlock({ status: 'undone' })],
    ])
      expect(refusalNote(q, [q, ...others])).toBe(
        'Vigil can’t move apps an installer put in Applications. Drag it to the Trash to remove it.',
      );
    expect(
      refusalNote(q, [
        q,
        santaBlock({
          action: {
            kind: 'santa.rule.set',
            ruleType: 'binary',
            identifier: 'b'.repeat(64),
            policy: 'allow',
          },
        }),
      ]),
    ).not.toMatch(/blocked/);
  });

  it('uses the generic line for something that is not an app', () => {
    const q = refused('/tmp/shared/helper.sh');
    expect(refusalNote(q, [q, santaBlock()])).toBe(
      'Vigil can’t move this item because it belongs to the system. Remove it yourself if you don’t need it.',
    );
  });

  it('leaves other failures as they were', () => {
    const plain = rec(
      { kind: 'file.quarantine', path: '/tmp/x' },
      { status: 'failed', result: { at: 1, error: 'boom' } },
    );
    expect(refusalNote(plain, [plain])).toBeUndefined();
    expect(actionErrorText(plain, [plain])).toBe('boom');
    const q = refused(app);
    const elsewhere = santaBlock({ alertId: 'other' });
    expect(sameAlert([q, elsewhere], q)).toEqual([q]);
    expect(actionErrorText(q, sameAlert([q, elsewhere], q))).not.toMatch(/blocked/);
  });
});

describe('a restore its owner can’t write back', () => {
  it('shows one calm line for it', () => {
    const r = rec(
      { kind: 'file.restore', quarantineId: 'q1' },
      { status: 'failed', result: { at: 1, error: 'x', errorCode: 'owner-cannot-write' } },
    );
    expect(actionErrorText(r, [r])).toBe(
      'Vigil can’t put this back because its owner can’t write to that folder.',
    );
  });
});

describe('a move the helper stopped waiting on', () => {
  it('shows one calm line for it', () => {
    const r = rec(
      { kind: 'file.quarantine', path: '/home/a/miner' },
      { status: 'failed', result: { at: 1, error: 'x', errorCode: 'move-stalled' } },
    );
    expect(actionErrorText(r, [r])).toBe(
      'Vigil couldn’t move this in time. Anything it stopped or blocked stays that way.',
    );
  });
});
