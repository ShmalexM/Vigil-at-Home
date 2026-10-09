import { describe, expect, it } from 'vitest';
import { costNote, estimateNote } from './usage-format';

const t = (over: Partial<Parameters<typeof costNote>[0]>) => ({
  costUsd: 0,
  billedUsd: 0,
  billedUnpricedRuns: 0,
  loginUsd: 0,
  ...over,
});

describe('costNote', () => {
  it('says a plan run used the plan, never that it was not charged', () => {
    expect(costNote(t({ costUsd: 2.17 }))).toBe('at API prices, on your plan');
    expect(costNote(t({ costUsd: 2.17, loginUsd: 2.08 }))).toBe(
      'at API prices, on your Claude login',
    );
    expect(costNote(t({ costUsd: 2.17, billedUsd: 0.09, loginUsd: 2.08 }))).toBe(
      '$0.09 billed to your keys, the rest at API prices, on your Claude login',
    );
  });

  it('never claims a run was not charged', () => {
    const notes = [
      costNote(t({ costUsd: 2.17 })),
      costNote(t({ costUsd: 2.17, billedUsd: 0.09 })),
      estimateNote(t({ costUsd: 1 })),
    ];
    for (const note of notes) expect(note).not.toMatch(/not charged|free/i);
  });

  it('never says nothing was billed when a billed run has no price', () => {
    expect(costNote(t({ billedUnpricedRuns: 3 }))).toBe('3 billed runs at a cost Vigil can’t see');
    expect(costNote(t({}))).toBe('nothing billed');
  });

  it('notes a provider whose whole cost is an estimate', () => {
    expect(estimateNote(t({ costUsd: 1 }))).toBe('at API prices, on your plan');
    expect(estimateNote(t({ costUsd: 1, loginUsd: 1 }))).toBe(
      'at API prices, on your Claude login',
    );
    expect(estimateNote(t({ costUsd: 1, billedUsd: 1 }))).toBeUndefined();
  });
});
