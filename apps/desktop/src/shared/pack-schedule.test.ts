import { describe, expect, it } from 'vitest';
import { jobDue, nextRunAt, nextRunWords, SCHEDULE_CHECK_MS } from './pack';

const MIN = 60_000;
const HOUR = 60 * MIN;
/** Local times, so the tests hold in any time zone. */
const at = (h: number, m = 0, day = 8) => new Date(2026, 9, day, h, m).getTime();

const dog = (schedule: 'manual' | 'hourly' | 'daily' | 'nightly', extra: object = {}) => ({
  role: 'pack' as const,
  enabled: true,
  schedule,
  createdAt: at(9),
  ...extra,
});
const report = (when: number, ok = true) => ({ at: when, ok, summary: '', findings: [] });

describe('when a scheduled job runs next', () => {
  it('follows the scheduler’s rule, in its five-minute steps', () => {
    const hourly = dog('hourly', { lastReport: report(at(14, 5)) });
    expect(nextRunAt(hourly, at(14, 30))).toBe(at(15, 5));
    expect(jobDue(hourly, at(15, 5), 15)).toBe(true);
    expect(jobDue(hourly, at(15, 4), 15)).toBe(false);

    const daily = dog('daily', { lastReport: report(at(14, 5)) });
    expect(nextRunAt(daily, at(14, 30))).toBe(at(14, 5, 9));

    // A nightly dog waits for 1 am; a failed run tries again an hour on, still at night.
    expect(nextRunAt(dog('nightly'), at(14))).toBe(at(1, 0, 9));
    const failed = dog('nightly', { lastReport: report(at(2), false) });
    expect(nextRunAt(failed, at(2, 30))).toBe(at(3));
    expect(nextRunAt(failed, at(14))).toBe(at(1, 0, 9));
  });

  it('is due now when it is overdue, and never for manual, napping or helper dogs', () => {
    const overdue = dog('hourly', { lastReport: report(at(8)) });
    expect(nextRunAt(overdue, at(14))).toBe(at(14));
    expect(nextRunAt(dog('manual'), at(14))).toBeUndefined();
    expect(nextRunAt(dog('hourly', { enabled: false }), at(14))).toBeUndefined();
    expect(nextRunAt(dog('hourly', { role: 'helper' }), at(14))).toBeUndefined();
  });

  it('says it in fixed words', () => {
    const time = (t: number) =>
      `${new Date(t).getHours()}:${String(new Date(t).getMinutes()).padStart(2, '0')}`;
    expect(nextRunWords(at(14, 40), at(14), false, time)).toBe('in 40 min');
    expect(nextRunWords(at(14) + SCHEDULE_CHECK_MS - 1, at(14), false, time)).toBe('any minute');
    expect(nextRunWords(at(16, 5), at(14), false, time)).toBe('today 16:05');
    expect(nextRunWords(at(9, 30, 9), at(14), false, time)).toBe('tomorrow 9:30');
    expect(nextRunWords(at(1, 0, 9), at(14), true, time)).toBe('tonight ~1–5 am');
    expect(nextRunWords(at(1, 0, 9) + 24 * HOUR, at(14), true, time)).toBe(
      'tomorrow night ~1–5 am',
    );
  });
});
