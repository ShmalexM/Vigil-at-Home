import type { ActionRecord, Alert } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { describeRecord, headline } from './format';

const alert = (containment: Alert['containment']) => ({ containment }) as Alert;

describe('headline', () => {
  it('never says blocked while blocks are only simulated', () => {
    expect(headline(alert('active'), 'real')).toBe('Vigil blocked something');
    expect(headline(alert('active'), 'simulated')).toBe('Vigil would have blocked this');
    expect(headline(alert('none'), 'simulated')).toBe('Vigil needs you');
  });

  it('says what really happened when only part was simulated', () => {
    expect(headline(alert('active'), 'mixed')).toBe(
      'Vigil blocked part of this; the rest was only simulated',
    );
  });

  it("doesn't claim a block it can't vouch for", () => {
    expect(headline(alert('active'), 'unknown')).toBe('Vigil acted on this');
    expect(headline(alert('active'), undefined)).toBe('Vigil acted on this');
  });
});

describe('describeRecord', () => {
  const rec = (over: Partial<ActionRecord>): ActionRecord => ({
    id: 'x',
    action: { kind: 'process.kill', pid: 7 },
    actor: 'rule',
    reason: '',
    requestedAt: 1,
    status: 'done',
    ...over,
  });

  it('marks History rows the way the popup does', () => {
    const what = describeRecord(rec({ result: { at: 1, simulated: false } }));
    expect(describeRecord(rec({ result: { at: 1, simulated: true } }))).toBe(`${what} (simulated)`);
    expect(describeRecord(rec({ result: { at: 1 } }))).toBe(`${what} (maybe simulated)`);
    expect(describeRecord(rec({ status: 'undone', result: { at: 1, simulated: true } }))).toBe(
      `${what} (undone, simulated)`,
    );
    expect(describeRecord(rec({ status: 'failed', result: { at: 1, error: 'x' } }))).toBe(
      `${what}: failed`,
    );
  });
});
