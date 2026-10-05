import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
  });
  client = await HelperClient.connect(paths.socket, async () => false);
});

afterAll(async () => {
  client?.close();
  await stop?.();
  rmSync(root, { recursive: true, force: true });
});

describe('daemon on Linux', () => {
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
