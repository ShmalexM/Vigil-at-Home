import { describe, expect, it } from 'vitest';
import type { InForceItem } from '../../../shared/in-force';
import { ageWords, groupItems, untilWords } from './in-force-format';

const DAY = 24 * 60 * 60 * 1000;
const NOW = 1_800_000_000_000;

const item = (key: string, kind: InForceItem['kind']): InForceItem => ({
  key,
  kind,
  title: key,
  release: 'release',
  flags: [],
});

describe('In force wording', () => {
  it('says how long something has been in force', () => {
    expect(ageWords(undefined, NOW)).toBeUndefined();
    expect(ageWords(NOW - 3_600_000, NOW)).toBe('since today');
    expect(ageWords(NOW - DAY, NOW)).toBe('for 1 day');
    expect(ageWords(NOW - 12 * DAY, NOW)).toBe('for 12 days');
  });

  it('says when a dropped block-list entry stops', () => {
    expect(untilWords(undefined, NOW)).toBeUndefined();
    expect(untilWords(NOW + 3_600_000, NOW)).toBe('stops within a day');
    expect(untilWords(NOW + 5.5 * DAY, NOW)).toBe('stops in 6 days');
  });

  it('groups items by kind in a fixed order, leaving out empty groups', () => {
    const groups = groupItems([
      item('a', 'network'),
      item('b', 'block-list'),
      item('c', 'network'),
    ]);
    expect(groups.map(([k, list]) => [k, list.map((i) => i.key)])).toEqual([
      ['block-list', ['b']],
      ['network', ['a', 'c']],
    ]);
  });
});
