import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  appendFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { SensorEvent } from '@vigil/sensors';
import { HelperClient } from './client.js';
import { defaultPaths, type HelperPaths } from './config.js';
import { runDaemon, type SensorHealth } from './daemon.js';
import { FakeSystem } from './testing/fakeSystem.js';

let root: string;
let paths: HelperPaths;
let stop: (() => Promise<void>) | undefined;
let client: HelperClient | undefined;
const port = 47000 + Math.floor(Math.random() * 1000);

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-daemon-'));
  paths = {
    ...defaultPaths(join(root, 'support')),
    approvalsDir: join(root, 'approvals'),
    socket: join(root, 'helper.sock'),
    santaLog: join(root, 'santa.log'),
    osqueryResults: join(root, 'osquery.log'),
  };
  writeFileSync(paths.santaLog as string, '');
  writeFileSync(paths.osqueryResults as string, '');
  // As earlier versions left it; the daemon must open it up on start.
  mkdirSync(paths.supportDir, { mode: 0o700 });
  // Handing the socket to the console user needs root; CI runs as a normal
  // user, where the socket simply stays with the current user.
  const sys = new FakeSystem();
  sys.console = process.getuid!() === 0 ? 501 : undefined;
  stop = await runDaemon({
    paths,
    syncPort: port,
    sys,
    log: () => {},
    approvalOwnerUid: process.getuid!(),
    opensslBin: 'openssl',
    // Santa counts as installed; osquery doesn't.
    sensorBinaries: { santa: paths.santaLog as string, osquery: join(root, 'no-osqueryd') },
    osquery: false,
  });
  client = await HelperClient.connect(paths.socket, async () => false);
});

afterAll(async () => {
  client?.close();
  await stop?.();
  rmSync(root, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in tests
function santaPost(stage: string, body: unknown): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: `/${stage}/M1`,
        ca: readFileSync(join(paths.tlsDir, 'ca.pem')),
        headers: { 'content-type': 'application/json' },
      },
      (res) => {
        let d = '';
        res.on('data', (c) => (d += c));
        res.on('end', () => resolve(JSON.parse(d)));
      },
    );
    req.on('error', reject);
    req.end(JSON.stringify(body));
  });
}

describe('helper daemon', () => {
  it("lets Santa's sync service (running as nobody) reach the pinned CA", () => {
    expect(statSync(paths.supportDir).mode & 0o777).toBe(0o755);
    expect(statSync(paths.tlsDir).mode & 0o777).toBe(0o755);
    expect(statSync(join(paths.tlsDir, 'ca.pem')).mode & 0o777).toBe(0o644);
    expect(statSync(join(paths.tlsDir, 'ca.key')).mode & 0o777).toBe(0o600);
  });

  it('serves commands, Santa sync and live sensor events together', async () => {
    const status = await client!.call<{ activeActions: number; sensors: SensorHealth }>({
      kind: 'helper.status',
    });
    expect(status.activeActions).toBe(0);
    expect(status.sensors).toEqual({
      santa: { installed: true, lastEventAt: null, lastSyncAt: null },
      osquery: { installed: false, lastEventAt: null },
    });

    await client!.call({
      kind: 'santa.rule.set',
      ruleType: 'teamid',
      identifier: 'ABCDE12345',
      policy: 'block',
    });
    const pre = await santaPost('preflight', { machine_id: 'M1' });
    expect(pre.sync_type).toBe('CLEAN');
    const rules = await santaPost('ruledownload', { cursor: '' });
    expect(rules.rules).toEqual([
      { identifier: 'ABCDE12345', policy: 'BLOCKLIST', rule_type: 'TEAMID' },
    ]);

    const got: SensorEvent[] = [];
    client!.onEvent((e) => got.push(e));
    await client!.subscribe();
    appendFileSync(
      paths.santaLog as string,
      '[2026-09-26T21:00:00.000Z] I santad: action=EXEC|decision=DENY|reason=TEAMID|teamid=ABCDE12345|pid=9|ppid=1|uid=501|user=a|mode=M|path=/tmp/evil|args=/tmp/evil|machineid=M1\n',
    );
    await santaPost('eventupload', {
      events: [{ file_path: '/tmp', file_name: 'evil2', decision: 'BLOCK_TEAMID', pid: 10 }],
    });
    await new Promise((r) => setTimeout(r, 600));
    const blocks = got
      .filter((e) => e.kind === 'santa.decision')
      .map((e) => e.kind === 'santa.decision' && e.process.path);
    expect(blocks.sort()).toEqual(['/tmp/evil', '/tmp/evil2']);
    expect(readFileSync(paths.fileAccessPolicy, 'utf8')).toContain('SSHKeys');

    await santaPost('postflight', { rules_received: 1, rules_processed: 1 });
    const after = await client!.call<{ sensors: SensorHealth }>({ kind: 'helper.status' });
    expect(after.sensors.santa.lastEventAt).toBeGreaterThan(0);
    expect(after.sensors.santa.lastSyncAt).toBeGreaterThan(0);
    expect(after.sensors.osquery.lastEventAt).toBeNull();
  });
});
