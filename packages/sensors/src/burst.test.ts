import { describe, expect, it, vi } from 'vitest';
import type { SensorEvent } from '@vigil/core';
import { NetworkBurst, burstQuery, parseOsqueryJson, worthWatching } from './osquery/burst.js';
import { SensorHub } from './hub.js';

const exec = (pid: number, extra: Record<string, unknown> = {}): SensorEvent => ({
  id: `exec-${pid}`,
  ts: 1,
  source: 'santa',
  kind: 'process.exec',
  process: { pid, path: `/tmp/p${pid}`, ...extra },
});

const exit = (pid: number): SensorEvent => ({
  id: `exit-${pid}`,
  ts: 2,
  source: 'santa',
  kind: 'process.exit',
  process: { pid, path: `/tmp/p${pid}` },
});

const row = (pid: number, remote = '203.0.113.9', port = '443') => ({
  pid: String(pid),
  path: `/tmp/p${pid}`,
  uid: '501',
  remote_address: remote,
  remote_port: port,
  local_address: '192.168.1.2',
  local_port: '50000',
  protocol: '6',
});

describe('worthWatching', () => {
  it('picks untrusted and downloaded programs, not signed ones', () => {
    expect(worthWatching(exec(10, { signing: 'unsigned' }))).toBe(true);
    expect(worthWatching(exec(10, { signing: 'adhoc' }))).toBe(true);
    expect(worthWatching(exec(10, { signing: 'developer_id', quarantine: {} }))).toBe(true);
    expect(worthWatching(exec(10, { signing: 'apple' }))).toBe(false);
    expect(worthWatching(exec(10, { signing: 'developer_id' }))).toBe(false);
    expect(worthWatching(exit(10))).toBe(false);
  });
});

describe('burstQuery', () => {
  it('only asks about the watched pids', () => {
    expect(burstQuery([12, 34])).toContain('WHERE p.pid IN (12, 34)');
  });
});

describe('NetworkBurst', () => {
  function setup(opts: Partial<ConstructorParameters<typeof NetworkBurst>[0]> = {}) {
    let now = 1_000_000;
    const emitted: SensorEvent[] = [];
    const run = vi.fn(async (sql: string) => {
      const pids = [...sql.matchAll(/IN \(([\d, ]+)\)/g)][0]![1]!.split(', ').map(Number);
      return pids.map((p) => row(p));
    });
    const burst = new NetworkBurst({
      run,
      emit: (e) => emitted.push(e),
      now: () => now,
      intervalMs: 60_000_000, // ticks are driven by hand
      ...opts,
    });
    return { burst, emitted, run, advance: (ms: number) => (now += ms) };
  }

  it('reports a watched program connection once, and stops after it exits', async () => {
    const { burst, emitted, run } = setup();
    burst.observe(exec(500, { signing: 'unsigned' }));
    await burst.tick();
    await burst.tick();
    expect(emitted).toHaveLength(1);
    expect(emitted[0]).toMatchObject({
      kind: 'network.connection',
      remoteAddress: '203.0.113.9',
      remotePort: 443,
      process: { pid: 500 },
    });
    burst.observe(exit(500));
    await burst.tick();
    expect(run).toHaveBeenCalledTimes(2);
    burst.stop();
  });

  it('ignores trusted programs', async () => {
    const { burst, run } = setup();
    burst.observe(exec(501, { signing: 'apple' }));
    await burst.tick();
    expect(run).not.toHaveBeenCalled();
    burst.stop();
  });

  it('drops a watch after its minute is up', async () => {
    const { burst, run, advance } = setup();
    burst.watch(502);
    advance(61_000);
    await burst.tick();
    expect(run).not.toHaveBeenCalled();
    expect(burst.isWatching(502)).toBe(false);
    burst.stop();
  });

  it('keeps to its hourly budget', async () => {
    const { burst, run, advance } = setup({ queriesPerHour: 3 });
    burst.watch(503);
    for (let i = 0; i < 5; i++) await burst.tick();
    expect(run).toHaveBeenCalledTimes(3);
    advance(3600_000);
    burst.watch(503);
    await burst.tick();
    expect(run).toHaveBeenCalledTimes(4);
    burst.stop();
  });

  it('caps how many programs it watches at once', () => {
    const { burst } = setup({ maxWatched: 2 });
    expect(burst.watch(600)).toBe(true);
    expect(burst.watch(601)).toBe(true);
    expect(burst.watch(602)).toBe(false);
    expect(burst.watch(600)).toBe(true); // renewing an existing watch is fine
    burst.stop();
  });

  it('treats a failed osquery run as no rows', async () => {
    const { burst, emitted } = setup({
      run: async () => {
        throw new Error('boom');
      },
    });
    burst.watch(700);
    await burst.tick();
    expect(emitted).toHaveLength(0);
    burst.stop();
  });
});

describe('SensorHub with a closer look', () => {
  it('skips the snapshot row for a connection the closer look already reported', async () => {
    const out: SensorEvent[] = [];
    const hub = new SensorHub({
      santaLogPath: false,
      osqueryResultsPath: false,
      sink: (e) => out.push(e),
      osqueryRunner: async () => [row(800)],
    });
    hub.emit(exec(800, { signing: 'unsigned' }));
    // Drive the burst directly rather than waiting 2 s.
    await (hub as unknown as { burst: NetworkBurst }).burst.tick();
    hub.emit({
      id: 'osquery:snapshot-row',
      ts: 3,
      source: 'osquery',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress: '203.0.113.9',
      remotePort: 443,
      process: { pid: 800, path: '/tmp/p800' },
    });
    expect(out.map((e) => e.kind)).toEqual(['process.exec', 'network.connection']);
    expect(out[1]!.id.startsWith('osquery-burst:')).toBe(true);
    await hub.stop();
  });
});

describe('parseOsqueryJson', () => {
  it('reads osquery shell JSON and rejects anything else', () => {
    expect(parseOsqueryJson('[{"pid":"1"}]')).toEqual([{ pid: '1' }]);
    expect(parseOsqueryJson('not json')).toBeUndefined();
    expect(parseOsqueryJson('{"a":1}')).toBeUndefined();
  });
});
