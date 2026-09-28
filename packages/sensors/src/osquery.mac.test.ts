// Real-Mac checks for the osquery side: every scheduled query runs against the
// real tables, and osqueryd's own results log parses into Vigil events. Runs
// only on macOS with VIGIL_MAC_INTEGRATION=1, as root, with osquery installed
// (`pnpm --filter @vigil/sensors test:mac`).

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync, spawn, type ChildProcess } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { createServer, connect, type Server, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SensorEvent } from '@vigil/core';
import { osqueryConfig, osqueryFlags, QUERY_NAMES } from './osquery/config.js';
import { osqueryLineToEvents } from './osquery/resultParser.js';

const enabled = process.platform === 'darwin' && process.env.VIGIL_MAC_INTEGRATION === '1';
const bin = (name: string) =>
  [`/usr/local/bin/${name}`, `/opt/osquery/lib/osquery.app/Contents/MacOS/${name}`].find((p) =>
    existsSync(p),
  ) ?? name;

type Row = Record<string, string>;

function osqueryi(sql: string): Row[] {
  const out = execFileSync(bin('osqueryi'), ['--json', sql], { encoding: 'utf8' });
  return (JSON.parse(out) as Record<string, unknown>[]).map((r) =>
    Object.fromEntries(Object.entries(r).map(([k, v]) => [k, String(v)])),
  );
}

/** The line osqueryd would write for a newly seen row. */
function added(name: string, columns: Row): string {
  return JSON.stringify({
    name,
    hostIdentifier: 'test',
    unixTime: Math.floor(Date.now() / 1000),
    counter: 1,
    action: 'added',
    columns,
  });
}

const schedule = JSON.parse(osqueryConfig()).schedule as Record<string, { query: string }>;

describe.skipIf(!enabled)('osquery on a real Mac', () => {
  let listener: Server;
  let listenPort: number;
  let outbound: Socket;

  beforeAll(async () => {
    listener = createServer(() => {});
    await new Promise<void>((r) => listener.listen(0, '0.0.0.0', r));
    listenPort = (listener.address() as { port: number }).port;
    outbound = connect(443, '1.1.1.1');
    await new Promise<void>((resolve, reject) => {
      outbound.once('connect', resolve);
      outbound.once('error', reject);
    });
  });

  afterAll(() => {
    outbound?.destroy();
    listener?.close();
  });

  for (const [name, { query }] of Object.entries(schedule)) {
    it(`runs ${name} against the real tables`, () => {
      const rows = osqueryi(query);
      for (const row of rows.slice(0, 50)) {
        for (const ev of osqueryLineToEvents(added(name, row))) SensorEvent.parse(ev);
      }
    });
  }

  it('sees this process listening on the network', () => {
    const rows = osqueryi(schedule[QUERY_NAMES.listeningPorts]!.query).filter(
      (r) => r.pid === String(process.pid) && r.port === String(listenPort),
    );
    expect(rows.length).toBeGreaterThan(0);
    const [ev] = osqueryLineToEvents(added(QUERY_NAMES.listeningPorts, rows[0]!));
    expect(SensorEvent.parse(ev)).toMatchObject({
      kind: 'network.listen',
      protocol: 'tcp',
      localPort: listenPort,
      process: { pid: process.pid, path: realpathSync(process.execPath) },
    });
    // Node from nodejs.org and setup-node is Developer ID signed; Homebrew's is ad hoc.
    expect(['developer_id', 'adhoc']).toContain(
      ev?.kind === 'network.listen' ? ev.process?.signing : undefined,
    );
  });

  it('sees this process connected to 1.1.1.1', () => {
    const rows = osqueryi(schedule[QUERY_NAMES.networkConnections]!.query).filter(
      (r) => r.pid === String(process.pid) && r.remote_address === '1.1.1.1',
    );
    expect(rows.length).toBeGreaterThan(0);
    const [ev] = osqueryLineToEvents(added(QUERY_NAMES.networkConnections, rows[0]!));
    expect(SensorEvent.parse(ev)).toMatchObject({
      kind: 'network.connection',
      remoteAddress: '1.1.1.1',
      remotePort: 443,
      process: { pid: process.pid },
    });
  });

  describe('osqueryd with the generated config', () => {
    let dir: string;
    let daemon: ChildProcess | undefined;
    let daemonOutput = '';

    beforeAll(() => {
      dir = mkdtempSync(join(tmpdir(), 'vigil-osqueryd-'));
      const cfg = JSON.parse(
        osqueryConfig({ networkIntervalSeconds: 2, persistenceIntervalSeconds: 2 }),
      );
      cfg.options.logger_path = join(dir, 'log');
      mkdirSync(cfg.options.logger_path);
      writeFileSync(join(dir, 'osquery.conf'), JSON.stringify(cfg));
      writeFileSync(join(dir, 'osquery.flags'), osqueryFlags());
      daemon = spawn(
        bin('osqueryd'),
        [
          `--flagfile=${join(dir, 'osquery.flags')}`,
          `--config_path=${join(dir, 'osquery.conf')}`,
          `--database_path=${join(dir, 'db')}`,
          `--pidfile=${join(dir, 'osqueryd.pid')}`,
          `--logger_path=${join(dir, 'log')}`,
          `--extensions_socket=${join(dir, 'osquery.em')}`,
          '--disable_watchdog',
          '--force',
          '--verbose',
        ],
        { stdio: ['ignore', 'pipe', 'pipe'] },
      );
      const keep = (d: Buffer) => {
        daemonOutput = (daemonOutput + d.toString()).slice(-8000);
      };
      daemon.stdout?.on('data', keep);
      daemon.stderr?.on('data', keep);
    });

    afterAll(() => {
      daemon?.kill('SIGTERM');
      rmSync(dir, { recursive: true, force: true });
    });

    it('writes results that parse into listen and connection events', async () => {
      const log = () => join(dir, 'log', 'osqueryd.results.log');
      const kinds = new Set<string>();
      let seenListen = false;
      for (
        let i = 0;
        i < 60 && daemon?.exitCode === null && !(seenListen && kinds.has('network.connection'));
        i++
      ) {
        await new Promise((r) => setTimeout(r, 1000));
        if (!existsSync(log())) continue;
        for (const line of readFileSync(log(), 'utf8').split('\n').filter(Boolean)) {
          for (const ev of osqueryLineToEvents(line, { includeBaseline: true })) {
            const parsed = SensorEvent.parse(ev);
            kinds.add(parsed.kind);
            if (parsed.kind === 'network.listen' && parsed.localPort === listenPort)
              seenListen = true;
          }
        }
      }
      expect(
        existsSync(log()),
        `osqueryd wrote no results log (exit ${daemon?.exitCode}):\n${daemonOutput}`,
      ).toBe(true);
      expect(daemonOutput).not.toMatch(/CLI only flag/);
      expect(seenListen).toBe(true);
      expect([...kinds]).toContain('network.connection');
    }, 90_000);
  });
});
