import { describe, expect, it } from 'vitest';
import {
  AwakeClock,
  checkHealth,
  feedHealth,
  helperSensorsFrom,
  QUIET_AFTER_MS,
  reportFeedHealth,
  reportHealth,
  type HealthProbe,
} from './sensor-health.js';
import { SensorRegistry } from './sensors.js';
import { computeStatus } from './status.js';

function probe(over: Partial<HealthProbe> & { installed?: string[]; procs?: string[] } = {}) {
  const installed = new Set(over.installed ?? []);
  const procs = new Set(over.procs ?? []);
  return {
    exists: (p: string) => installed.has(p),
    running: async (n: string) => procs.has(n),
    lastEventAt: () => null,
    helper: () => 'not_installed' as const,
    now: () => 1_000_000_000,
    ...over,
  } satisfies HealthProbe;
}

const byId = async (p: HealthProbe) =>
  Object.fromEntries((await checkHealth(p)).map((h) => [h.id, h]));

describe('checkHealth', () => {
  it('says the helper is down when it drops or fails during the check', async () => {
    let state: 'connected' | 'not_running' = 'connected';
    const dropped = await byId(
      probe({
        helper: () => state,
        helperSensors: async () => {
          state = 'not_running';
          return null;
        },
      }),
    );
    expect(dropped['helper']?.state).toBe('down');
    const failed = await byId(
      probe({
        helper: () => 'connected' as const,
        helperSensors: () => Promise.reject(new Error('socket closed')),
      }),
    );
    expect(failed['helper']?.state).toBe('down');
  });

  it('says the helper is down while it reconnects with no connection', async () => {
    const h = await byId(
      probe({
        helper: () => 'connected' as const,
        helperSensors: helperSensorsFrom(async () => null),
      }),
    );
    expect(h['helper']?.state).toBe('down');
    // An older helper that answers without sensors is still up.
    const old = await byId(
      probe({
        helper: () => 'connected' as const,
        helperSensors: helperSensorsFrom(async () => ({})),
      }),
    );
    expect(old['helper']?.state).toBe('ok');
  });

  it('lets only the latest check report when checks overlap', async () => {
    const registry = new SensorRegistry();
    let state: 'connected' | 'not_running' = 'connected';
    let answer!: () => void;
    const p = probe({
      helper: () => state,
      helperSensors: () =>
        new Promise((resolve) => {
          answer = () => resolve(null);
        }),
    });
    const older = reportHealth(registry, p);
    state = 'not_running';
    await reportHealth(registry, p);
    expect(registry.get('helper')?.state).toBe('down');
    state = 'connected'; // even if the older check's own read says connected
    answer();
    await older;
    expect(registry.get('helper')?.state).toBe('down');
  });

  it('reports nothing installed on a fresh Mac', async () => {
    const h = await byId(probe());
    expect(h['santa']?.state).toBe('not_installed');
    expect(h['osquery']?.state).toBe('not_installed');
    expect(h['helper']?.state).toBe('not_installed');
  });

  it('sees Santa once setup installs it, even before the helper', async () => {
    const h = await byId(
      probe({ installed: ['/Applications/Santa.app'], procs: ['com.northpolesec.santa.daemon'] }),
    );
    expect(h['santa']).toMatchObject({ state: 'degraded' });
    expect(h['santa']?.note).toMatch(/helper/);
  });

  it('says a sensor is down when installed but not running', async () => {
    const h = await byId(
      probe({ installed: ['/opt/osquery/lib/osquery.app'], helper: () => 'connected' as const }),
    );
    expect(h['osquery']?.state).toBe('down');
  });

  it('expects osquery to wait for the helper, which starts it', async () => {
    const h = await byId(probe({ installed: ['/opt/osquery/lib/osquery.app'] }));
    expect(h['osquery']).toMatchObject({
      state: 'degraded',
      note: 'Starts once the Vigil helper is installed',
    });
  });

  it('is healthy when events arrive, and flags a sensor gone quiet', async () => {
    const base = {
      installed: ['/usr/local/bin/osqueryd'],
      procs: ['osqueryd'],
      helper: () => 'connected' as const,
    };
    const fresh = await byId(probe({ ...base, lastEventAt: () => 1_000_000_000 - 60_000 }));
    expect(fresh['osquery']?.state).toBe('ok');
    expect(fresh['helper']?.state).toBe('ok');
    const quiet = await byId(
      probe({ ...base, lastEventAt: () => 1_000_000_000 - QUIET_AFTER_MS.osquery - 120_000 }),
    );
    expect(quiet['osquery']).toMatchObject({ state: 'degraded', note: 'No events for 32 minutes' });
    const starting = await byId(probe(base));
    expect(starting['osquery']).toMatchObject({ state: 'ok', note: 'Starting; no events yet' });
  });

  it('counts only awake running time towards quiet, but says how long it really was', async () => {
    const now = 1_000_000_000;
    const base = {
      installed: ['/usr/local/bin/osqueryd'],
      procs: ['osqueryd'],
      helper: () => 'connected' as const,
      // Last event before a night asleep.
      lastEventAt: () => now - 8 * 60 * 60_000,
    };
    const justWoke = await byId(probe({ ...base, awakeMs: () => 60_000 }));
    expect(justWoke['osquery']?.state).toBe('ok');
    const awakeAWhile = await byId(
      probe({ ...base, awakeMs: () => QUIET_AFTER_MS.osquery + 60_000 }),
    );
    expect(awakeAWhile['osquery']).toMatchObject({
      state: 'degraded',
      note: 'No events for 480 minutes',
    });
  });

  it("uses the helper's own report of installs and last events", async () => {
    const now = 1_000_000_000;
    const h = await byId(
      probe({
        procs: ['osqueryd'],
        helper: () => 'connected',
        helperSensors: async () => ({ osquery: { installed: true, lastEventAt: now - 1000 } }),
      }),
    );
    expect(h['osquery']?.state).toBe('ok');
    expect(h['santa']?.state).toBe('not_installed');
  });

  describe('on Linux', () => {
    const linux = (over: Parameters<typeof probe>[0] = {}) =>
      byId({ ...probe(over), platform: 'linux' });

    it('checks fapolicyd, osquery and the helper, not Santa', async () => {
      const h = await linux();
      expect(Object.keys(h)).toEqual(['fapolicyd', 'osquery', 'helper']);
      expect(h['fapolicyd']?.state).toBe('not_installed');
      expect(h['osquery']?.state).toBe('not_installed');
    });

    it('finds osquery where its Linux packages put it', async () => {
      const h = await linux({
        installed: ['/opt/osquery/bin/osqueryd'],
        procs: ['osqueryd'],
        helper: () => 'connected' as const,
        lastEventAt: () => 1_000_000_000 - 60_000,
      });
      expect(h['osquery']?.state).toBe('ok');
    });

    it('needs fapolicyd running and the helper connected to block', async () => {
      const installed = ['/usr/sbin/fapolicyd'];
      expect((await linux({ installed }))['fapolicyd']?.state).toBe('down');
      expect((await linux({ installed, procs: ['fapolicyd'] }))['fapolicyd']).toMatchObject({
        state: 'degraded',
        note: 'Running; Vigil needs its helper to add blocks',
      });
      const ok = await linux({
        installed,
        procs: ['fapolicyd'],
        helper: () => 'connected' as const,
      });
      expect(ok['fapolicyd']?.state).toBe('ok');
    });
  });
});

describe('AwakeClock', () => {
  it('adds up awake time across sleeps, so a sensor dead over many wakes still counts', () => {
    let t = 0;
    const min = 60_000;
    const clock = new AwakeClock(0, () => t);
    // Five cycles of 10 minutes awake, then an hour asleep.
    for (let i = 0; i < 5; i++) {
      t += 10 * min;
      clock.suspend();
      t += 60 * min;
      clock.resume();
    }
    expect(clock.awakeMs(0)).toBe(50 * min);
    // Asleep right now: the time so far doesn't count.
    clock.suspend();
    t += 30 * min;
    expect(clock.awakeMs(0)).toBe(50 * min);
    // Nothing from before Vigil started counts.
    expect(new AwakeClock(t, () => t + min).awakeMs(0)).toBe(min);
  });
});

describe('feedHealth', () => {
  it('adds one quiet line while a feed is held back, and takes it away after', () => {
    const registry = new SensorRegistry();
    let changes = 0;
    registry.on('changed', () => changes++);
    const before = computeStatus([], registry.list());

    reportFeedHealth(registry, [{ name: 'Feodo Tracker' }, { name: 'URLhaus' }]);
    expect(registry.get('threat-feeds')).toBeUndefined();
    expect(changes).toBe(0);

    reportFeedHealth(registry, [{ name: 'Feodo Tracker', heldBack: true }, { name: 'URLhaus' }]);
    const line = registry.get('threat-feeds');
    expect(line).toMatchObject({ state: 'ok' });
    expect(line?.note).toMatch(/^Stale: Feodo Tracker kept its last list/);
    // Neither the level nor the reasons change, so nothing badges or pops up.
    expect(computeStatus([], registry.list())).toEqual(before);

    // Reporting the same thing again is not a change.
    reportFeedHealth(registry, [{ name: 'Feodo Tracker', heldBack: true }]);
    expect(changes).toBe(1);

    reportFeedHealth(registry, [{ name: 'Feodo Tracker' }]);
    expect(registry.get('threat-feeds')).toBeUndefined();
    expect(changes).toBe(2);
  });

  it('names every held-back feed in the one line', () => {
    expect(
      feedHealth([
        { name: 'A', heldBack: true },
        { name: 'B', heldBack: true },
      ])?.note,
    ).toMatch(/^Stale: A, B kept their last list/);
  });
});
