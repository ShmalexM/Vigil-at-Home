import { describe, expect, it } from 'vitest';
import { checkHealth, QUIET_AFTER_MS, type HealthProbe } from './sensor-health.js';

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
});
