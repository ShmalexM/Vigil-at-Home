import { describe, expect, it } from 'vitest';
import {
  ErrorTally,
  helperBuild,
  OsqueryRestarts,
  parseLaunchdJob,
  restartGapMs,
  SANTA_GONE_MS,
  SANTA_LIVE_MS,
  LaunchItemsMode,
  MAX_KINDS,
  MAX_TIMES,
  SLOW_HOLD_MS,
} from './health.js';

const MIN = 60_000;
const HOUR = 60 * MIN;

describe('LaunchItemsMode', () => {
  it('slows only on a recent Santa event and holds the fast query for two hours after', () => {
    let now = 10 * HOUR;
    const m = new LaunchItemsMode();
    expect(m.want(null, now)).toBe(false);
    expect(m.want(now - SANTA_LIVE_MS + 1, now)).toBe(true);
    // Quiet spells shorter than 15 minutes keep it.
    now += 14 * MIN;
    expect(m.want(now - 14 * MIN, now)).toBe(true);
    now += MIN;
    expect(m.want(now - SANTA_GONE_MS, now)).toBe(false);
    // Santa is back at once, but the slow query waits out the hold.
    expect(m.want(now, now)).toBe(false);
    now += SLOW_HOLD_MS - MIN;
    expect(m.want(now, now)).toBe(false);
    now += MIN;
    expect(m.want(now, now)).toBe(true);
  });

  it('brings the fast query back within 15 minutes when Santa is killed, past any backoff', () => {
    let now = 100 * HOUR;
    const mode = new LaunchItemsMode();
    const restarts = new OsqueryRestarts(() => now);
    // Santa reporting: osquery runs the slow query.
    expect(mode.want(now, now)).toBe(true);
    mode.applied('restarted', true, false);
    expect(mode.urgent()).toBe(false);
    // Plenty of restarts this hour: the backoff now holds the next one back.
    for (let i = 0; i < 5; i++) restarts.after('restarted');
    now += 5 * MIN;
    expect(restarts.mayRestart()).toBe(false);

    // An attacker kills Santa; its last event was just now.
    const killedAt = now;
    now += 10 * MIN;
    expect(mode.want(killedAt, now)).toBe(true); // 10 minutes is a quiet spell
    expect(restarts.mayRestart() || mode.urgent()).toBe(false);
    now += 5 * MIN;
    expect(mode.want(killedAt, now)).toBe(false);
    // The restart that applies the fast query skips the backoff.
    expect(restarts.mayRestart()).toBe(false);
    expect(mode.urgent()).toBe(true);
    mode.applied('restarted', false, false);
    expect(mode.urgent()).toBe(false);
  });

  it('keeps a held-back slow-down from counting as applied', () => {
    const mode = new LaunchItemsMode();
    mode.applied('unchanged', false, false);
    expect(mode.want(0, 1)).toBe(true);
    mode.applied('deferred', true, true);
    // Santa goes quiet before the slow query went in: no urgent restart needed.
    expect(mode.want(0, SANTA_GONE_MS)).toBe(false);
    expect(mode.urgent()).toBe(false);
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

  it('keeps at most MAX_KINDS kinds, dropping the rarest, and MAX_TIMES times per kind', () => {
    const t = new ErrorTally(() => 0);
    for (let i = 0; i < 3; i++) t.note('could not reach the frequent one');
    const word = (i: number) => String.fromCharCode(97 + (i % 26), 97 + Math.floor(i / 26));
    for (let i = 0; i < MAX_KINDS + 20; i++) t.note(`could not read ${word(i)}`);
    expect(t.kindCount).toBe(MAX_KINDS);
    expect(t.repeated(3).map((e) => e.message)).toEqual(['could not reach the frequent one']);

    const busy = new ErrorTally(() => 0);
    for (let i = 0; i < MAX_TIMES + 500; i++) busy.note('could not write the journal');
    expect(busy.repeated()[0]?.lastDay).toBe(MAX_TIMES);
  });

  it('frees kinds with nothing in the last day before dropping recent ones', () => {
    let now = 0;
    const t = new ErrorTally(() => now);
    const word = (i: number) => String.fromCharCode(97 + (i % 26), 97 + Math.floor(i / 26));
    // Old ones, seen many times a day ago.
    for (let i = 0; i < MAX_KINDS - 1; i++) for (let j = 0; j < 5; j++) t.note(`failed ${word(i)}`);
    now = 25 * HOUR;
    t.note('failed recent');
    t.note('failed recent');
    t.note('failed newer');
    t.note('failed newer');
    expect(
      t
        .repeated()
        .map((e) => e.message)
        .sort(),
    ).toEqual(['failed newer', 'failed recent']);
  });
});

describe('helperBuild', () => {
  it('is null when the helper runs from source', () => {
    expect(helperBuild()).toBeNull();
  });
});
