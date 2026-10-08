import { describe, expect, it } from 'vitest';
import {
  checkHealth,
  QUIET_AFTER_MS,
  santaSyncProblem,
  type HealthProbe,
  type HelperSantaSync,
} from './sensor-health.js';

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

describe("Santa's syncs with the helper", () => {
  const NOW = 1_000_000_000;
  const MIN = 60_000;
  const required: HelperSantaSync = {
    lastSyncAt: NOW - 5 * MIN,
    syncError: null,
    clientCertRequired: true,
    clientCertIssued: true,
    clientCertSeenAt: NOW - 5 * MIN,
    clientCertExpiresAt: NOW + 300 * 86_400_000,
    lastRefusal: null,
    syncIntervalSeconds: 600,
  };

  it('is quiet while Santa syncs', () => {
    expect(santaSyncProblem(required, NOW)).toBeUndefined();
    // An older helper reports none of this.
    expect(santaSyncProblem({}, NOW)).toBeUndefined();
    expect(santaSyncProblem(undefined, NOW)).toBeUndefined();
  });

  it('says so when a Santa without its certificate is refused', () => {
    const refused = {
      ...required,
      lastRefusal: { at: NOW - MIN, reason: 'no_certificate' as const },
    };
    expect(santaSyncProblem(refused, NOW)).toMatch(/refused: it came without its certificate/);
    // A refusal before Santa's last good sync is over.
    expect(
      santaSyncProblem({ ...refused, clientCertSeenAt: NOW - 10_000, lastSyncAt: null }, NOW),
    ).toBeUndefined();
    expect(
      santaSyncProblem(
        { ...required, lastRefusal: { at: NOW - MIN, reason: 'handshake_failed' } },
        NOW,
      ),
    ).toMatch(/secure connection failed/);
  });

  it('flags Santa missing three syncs, counted from waking', () => {
    const stale = { ...required, lastSyncAt: null, clientCertSeenAt: NOW - 31 * MIN };
    expect(santaSyncProblem(stale, NOW)).toBe('Santa hasn’t synced with Vigil for 31 minutes');
    // The Mac just woke: Santa hasn't had the chance.
    expect(santaSyncProblem(stale, NOW, NOW - 2 * MIN)).toBeUndefined();
    // Never seen with the certificate (a new install before the profile): setup's to say.
    expect(santaSyncProblem({ ...stale, clientCertSeenAt: null }, NOW)).toBeUndefined();
  });

  it('flags a closed sync port and a certificate about to lapse', () => {
    expect(santaSyncProblem({ ...required, syncError: 'listen EADDRINUSE' }, NOW)).toMatch(
      /sync port isn’t open/,
    );
    expect(
      santaSyncProblem({ ...required, clientCertExpiresAt: NOW + 3 * 86_400_000 }, NOW),
    ).toMatch(/expires in 3 days/);
  });

  it('shows on the Santa layer as needing a repair, which lowers the level', async () => {
    const h = await byId(
      probe({
        installed: ['/Applications/Santa.app'],
        procs: ['com.northpolesec.santa.daemon'],
        helper: () => 'connected' as const,
        lastEventAt: () => NOW - MIN,
        helperSensors: async () => ({
          santa: {
            installed: true,
            lastEventAt: NOW - MIN,
            ...required,
            lastRefusal: { at: NOW - MIN, reason: 'no_certificate' },
          },
        }),
      }),
    );
    expect(h['santa']).toMatchObject({ state: 'degraded', repair: 'santa-sync' });
  });
});
