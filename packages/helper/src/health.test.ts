import { describe, expect, it } from 'vitest';
import {
  ErrorTally,
  helperBuild,
  OsqueryRestarts,
  parseLaunchdJob,
  restartGapMs,
  SANTA_GONE_MS,
  SANTA_LIVE_MS,
  santaReporting,
} from './health.js';

const MIN = 60_000;
const HOUR = 60 * MIN;

describe('santaReporting', () => {
  it('turns on with a recent event and stays on through quiet spells shorter than two hours', () => {
    const now = 10 * HOUR;
    expect(santaReporting(false, null, now)).toBe(false);
    expect(santaReporting(false, now - SANTA_LIVE_MS + 1, now)).toBe(true);
    // Quiet for 15 minutes: off if it wasn't on, kept on if it was. One
    // threshold flipped osquery's config, and restarted it, on every crossing.
    expect(santaReporting(false, now - 15 * MIN, now)).toBe(false);
    expect(santaReporting(true, now - 15 * MIN, now)).toBe(true);
    expect(santaReporting(true, now - SANTA_GONE_MS, now)).toBe(false);
  });
});

describe('osquery restart backoff', () => {
  it('waits longer between restarts the more there were in the last hour', () => {
    expect([0, 1, 2, 3, 4, 5, 9].map((n) => restartGapMs(n) / MIN)).toEqual([
      0, 5, 10, 20, 40, 60, 60,
    ]);
  });

  it('holds a restart back, keeps it pending, and makes it once the gap has passed', () => {
    let now = 100 * HOUR;
    const r = new OsqueryRestarts(() => now);
    expect(r.mayRestart()).toBe(true);
    r.after('restarted');
    now += MIN;
    expect(r.mayRestart()).toBe(false);
    r.after('deferred');
    expect(r.pending).toBe(true);
    expect(r.status()).toMatchObject({ lastHour: 1, restartDeferredUntil: 100 * HOUR + 5 * MIN });
    now = 100 * HOUR + 5 * MIN;
    expect(r.mayRestart()).toBe(true);
    r.after('restarted');
    expect(r.pending).toBe(false);
    expect(r.status()).toMatchObject({ lastHour: 2, lastDay: 2, restartDeferredUntil: null });
    // The counts age out.
    now += 25 * HOUR;
    expect(r.status()).toMatchObject({ lastHour: 0, lastDay: 0, lastAt: null });
  });

  it('counts launchd runs beyond its own restarts as osquery exiting by itself', () => {
    let now = 50 * HOUR;
    const r = new OsqueryRestarts(() => now);
    r.observe({ runs: 1, lastExit: null });
    r.after('restarted'); // the helper's own: runs goes to 2
    now += 5 * MIN;
    r.observe({ runs: 4, lastExit: 'signal 9' }); // and two more it didn't make
    expect(r.status()).toMatchObject({
      lastHour: 3,
      exitsLastDay: 2,
      lastExit: 'signal 9',
    });
    // A newly loaded job starts counting again.
    r.after('started');
    r.observe({ runs: 1, lastExit: null });
    expect(r.status().exitsLastDay).toBe(2);
  });

  it("reads launchd's run count and how the job last ended", () => {
    const out = [
      'system/io.osquery.agent = {',
      '\tactive count = 1',
      '\truns = 7',
      '\tlast exit code = 78: EX_CONFIG',
      '}',
    ].join('\n');
    expect(parseLaunchdJob(out)).toEqual({ runs: 7, lastExit: 'exit code 78: EX_CONFIG' });
    expect(parseLaunchdJob('\truns = 2\n\tlast terminating signal = Killed: 9\n')).toEqual({
      runs: 2,
      lastExit: 'signal Killed: 9',
    });
    expect(parseLaunchdJob('\truns = 1\n\tlast exit code = (never exited)\n')).toEqual({
      runs: 1,
      lastExit: null,
    });
    expect(parseLaunchdJob('')).toBeNull();
  });
});

describe('ErrorTally', () => {
  it('groups a repeated problem by its text without numbers and counts it by hour and day', () => {
    let now = 30 * HOUR;
    const t = new ErrorTally(() => now);
    for (let i = 0; i < 30; i++) {
      t.note(`santa postflight mismatch: sent ${i % 3}, received NaN, processed NaN`);
      t.note('osquery restarted');
      now += 10 * MIN;
    }
    t.note('could not re-apply network blocks: pfctl exited 1');
    expect(t.repeated()).toEqual([
      {
        message: 'santa postflight mismatch: sent #, received NaN, processed NaN',
        lastHour: 6,
        lastDay: 30,
        lastAt: 30 * HOUR + 29 * 10 * MIN,
      },
    ]);
    // A day later it is gone.
    now += 25 * HOUR;
    expect(t.repeated()).toEqual([]);
  });

  it('keeps a bounded number of kinds', () => {
    const t = new ErrorTally(() => 0);
    for (let i = 0; i < 200; i++) {
      const word =
        String.fromCharCode(97 + (i % 26)) + String.fromCharCode(97 + Math.floor(i / 26));
      t.note(`could not read ${word}`);
      t.note(`could not read ${word}`);
    }
    expect(t.repeated().length).toBeLessThanOrEqual(5);
  });
});

describe('helperBuild', () => {
  it('is null when the helper runs from source', () => {
    expect(helperBuild()).toBeNull();
  });
});
