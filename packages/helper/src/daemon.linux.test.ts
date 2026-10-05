import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { appendFileSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { ProcessRef } from '@vigil/core';
import { HelperClient } from './client.js';
import { linuxPaths, type HelperPaths } from './config.js';
import { runDaemon, type SensorHealth } from './daemon.js';
import type { ActionOutcome } from './executor.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

let root: string;
let paths: HelperPaths;
let stop: (() => Promise<void>) | undefined;
let client: HelperClient | undefined;
const sys = new FakeLinuxSystem();

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-daemon-linux-'));
  paths = {
    ...linuxPaths(join(root, 'support')),
    approvalsDir: join(root, 'approvals'),
    socket: join(root, 'helper.sock'),
    osqueryResults: join(root, 'osquery.log'),
  };
  writeFileSync(paths.osqueryResults as string, '');
  sys.console = undefined;
  stop = await runDaemon({
    paths,
    sys,
    log: () => {},
    approvalOwnerUid: process.getuid!(),
    sensorBinaries: { santa: false, osquery: join(root, 'no-osqueryd') },
    osquery: false,
    trust: (path) =>
      path === '/usr/bin/curl'
        ? { signing: 'package', signingId: 'pkg:curl' }
        : { signing: 'unsigned' },
  });
  client = await HelperClient.connect(paths.socket, async () => false);
});

afterAll(async () => {
  client?.close();
  await stop?.();
  rmSync(root, { recursive: true, force: true });
});

describe('daemon on Linux', () => {
  it('marks launches from osquery with whether a package installed them', async () => {
    const got: ProcessRef[] = [];
    client!.onEvent((e) => {
      if (e.kind === 'process.exec') got.push(e.process);
    });
    await client!.subscribe();
    const line = (pid: number, path: string) =>
      JSON.stringify({
        name: 'vigil_process_events',
        action: 'added',
        counter: 0,
        unixTime: 1790000000,
        columns: {
          pid: String(pid),
          parent: '1',
          uid: '1000',
          path,
          cmdline: path,
          time: '1790000000',
        },
      }) + '\n';
    appendFileSync(paths.osqueryResults as string, line(10, '/usr/bin/curl') + line(11, '/tmp/x'));
    for (let i = 0; i < 50 && got.length < 2; i++) await new Promise((r) => setTimeout(r, 100));
    expect(got).toMatchObject([
      { path: '/usr/bin/curl', signing: 'package', signingId: 'pkg:curl' },
      { path: '/tmp/x', signing: 'unsigned' },
    ]);
  });

  it('starts without Santa: no sync certificate or file-access policy', () => {
    expect(existsSync(join(paths.tlsDir, 'ca.pem'))).toBe(false);
    expect(existsSync(paths.fileAccessPolicy)).toBe(false);
  });

  it('reports Santa as absent and blocks through nftables', async () => {
    const out = await client!.call<ActionOutcome>({
      kind: 'network.block',
      address: '203.0.113.9',
    });
    expect(out.summary).toBe('blocked network traffic with 203.0.113.9');
    const status = await client!.call<{ sensors: SensorHealth; firewall: string[] }>({
      kind: 'helper.status',
    });
    expect(status.sensors.santa.installed).toBe(false);
    expect(status.firewall).toEqual(['203.0.113.9']);
    expect(sys.runs.some((r) => r.bin === 'pfctl' || r.bin === 'santactl')).toBe(false);
  });
});
