import { describe, expect, it } from 'vitest';
import { checkedAt } from './updates-format';

describe('checkedAt', () => {
  const now = new Date(2026, 9, 8, 15, 0).getTime();
  it('gives only the time for today, and says the day otherwise', () => {
    expect(checkedAt(new Date(2026, 9, 8, 9, 5).getTime(), now)).not.toMatch(/yesterday| at /);
    expect(checkedAt(new Date(2026, 9, 7, 9, 5).getTime(), now)).toMatch(/^yesterday at /);
    expect(checkedAt(new Date(2026, 9, 2, 9, 5).getTime(), now)).toMatch(/^Oct 2 at /);
  });
});
