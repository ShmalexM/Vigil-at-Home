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
import { connect, createServer, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DetectionEngine, macosCoreRules, memoryStores } from '@vigil/detection';
import { fastPathRules } from '@vigil/detection/fastpath';
import type { SensorEvent } from '@vigil/sensors';
import { fileAccessPolicy, syncTlsPaths } from '@vigil/sensors';
import { HelperClient } from './client.js';
import { defaultPaths, type HelperPaths } from './config.js';
import {
  createSyncHttpsServer,
  runDaemon,
  SYNC_SERVER_LIMITS,
  type SensorHealth,
} from './daemon.js';
import type { HelperRan } from './fastpath.js';
import { FakeSystem } from './testing/fakeSystem.js';

const BAD = 'b'.repeat(64);

let root: string;
let paths: HelperPaths;
let sys: FakeSystem;
let stop: (() => Promise<void>) | undefined;
let client: HelperClient | undefined;
const port = 47000 + Math.floor(Math.random() * 1000);

function testPaths(dir: string): HelperPaths {
  const p = {
    ...defaultPaths(join(dir, 'support')),
    approvalsDir: join(dir, 'approvals'),
    socket: join(dir, 'helper.sock'),
    santaLog: join(dir, 'santa.log'),
    osqueryResults: join(dir, 'osquery.log'),
  };
  writeFileSync(p.santaLog, '');
  writeFileSync(p.osqueryResults, '');
  return p;
}

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-daemon-'));
  paths = testPaths(root);
  // As earlier versions left it; the daemon must open it up on start.
  mkdirSync(paths.supportDir, { mode: 0o700 });
  // Blocking rules the app synced earlier: the core pack, with one known-bad hash.
  const set = fastPathRules(new DetectionEngine(macosCoreRules, memoryStores()).listRules());
  writeFileSync(
    paths.helperRules,
    JSON.stringify({
      rev: 1,
      rules: set.rules,
      exceptions: [],
      selfPaths: [],
      lists: Object.fromEntries(set.lists.map((l) => [l, l === 'known_bad_sha256' ? [BAD] : []])),
    }),
  );
  // An older policy with blocking turned on: newer watch items must reach it, blocking kept.
  writeFileSync(
    paths.fileAccessPolicy,
    '<plist><dict><key>Version</key><string>vigil-1</string><key>AuditOnly</key>\n<false/></dict></plist>',
  );
  // Handing the socket to the console user needs root; CI runs as a normal
  // user, where the socket simply stays with the current user.
  sys = new FakeSystem();
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

function santaPost(
  stage: string,
  body: unknown,
  at = { port, tlsDir: paths.tlsDir },
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in tests
): Promise<any> {
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: at.port,
        method: 'POST',
        path: `/${stage}/M1`,
        ca: readFileSync(join(at.tlsDir, 'ca.pem')),
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
      santa: { installed: true, lastEventAt: null, lastSyncAt: null, syncError: null },
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
    // Only Santa's own log counts; anyone can post to the sync port.
    expect(blocks).toEqual(['/tmp/evil']);
    expect(readFileSync(paths.fileAccessPolicy, 'utf8')).toBe(fileAccessPolicy({ enforce: true }));

    await santaPost('postflight', { rules_received: 1, rules_processed: 1 });
    const after = await client!.call<{ sensors: SensorHealth }>({ kind: 'helper.status' });
    expect(after.sensors.santa.lastEventAt).toBeGreaterThan(0);
    expect(after.sensors.santa.lastSyncAt).toBeGreaterThan(0);
    expect(after.sensors.osquery.lastEventAt).toBeNull();
  });

  it('never acts on events posted to the sync port', async () => {
    const seen: [SensorEvent, HelperRan[]][] = [];
    client!.onEvent((e, ran) => seen.push([e, ran]));
    await client!.subscribe();
    sys.processes.set(4242, { path: '/tmp/posted', started: 'T' });
    sys.processes.set(4343, { path: '/tmp/logged', started: 'T' });
    sys.signals.length = 0;
    await santaPost('eventupload', {
      events: [
        {
          file_path: '/tmp',
          file_name: 'posted',
          file_sha256: BAD,
          decision: 'ALLOW_UNKNOWN',
          pid: 4242,
        },
      ],
    });
    appendFileSync(
      paths.santaLog as string,
      `[2026-09-26T21:00:01.000Z] I santad: action=EXEC|decision=ALLOW|reason=UNKNOWN|sha256=${BAD}|pid=4343|ppid=1|uid=501|user=a|mode=M|path=/tmp/logged|args=/tmp/logged|machineid=M1\n`,
    );
    for (let i = 0; i < 50 && !sys.signals.length; i++)
      await new Promise((r) => setTimeout(r, 100));
    await new Promise((r) => setTimeout(r, 300));
    expect(sys.signals).toEqual([{ pid: 4343, signal: 'SIGKILL' }]);
    expect(seen.map(([e]) => e.kind === 'process.exec' && e.process.path)).not.toContain(
      '/tmp/posted',
    );
  });
});

describe('helper daemon with the sync port taken', () => {
  it('keeps serving its socket and takes the port once it frees', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-daemon-busy-'));
    const busyPort = port + 1000;
    const blocker = createServer();
    await new Promise<void>((r) => blocker.listen(busyPort, '127.0.0.1', () => r()));
    const busyPaths = testPaths(dir);
    let stopBusy: (() => Promise<void>) | undefined;
    let busyClient: HelperClient | undefined;
    // As above: only root can hand the socket to another user.
    const busySys = new FakeSystem();
    busySys.console = process.getuid!() === 0 ? 501 : undefined;
    try {
      stopBusy = await runDaemon({
        paths: busyPaths,
        syncPort: busyPort,
        sys: busySys,
        log: () => {},
        approvalOwnerUid: process.getuid!(),
        opensslBin: 'openssl',
        sensorBinaries: { santa: busyPaths.santaLog as string, osquery: join(dir, 'no-osqueryd') },
        osquery: false,
        syncRetryMs: 100,
      });
      busyClient = await HelperClient.connect(busyPaths.socket, async () => false);
      const status = () => busyClient!.call<{ sensors: SensorHealth }>({ kind: 'helper.status' });
      expect((await status()).sensors.santa.syncError).toMatch(/EADDRINUSE/);

      await new Promise<void>((r) => blocker.close(() => r()));
      for (let i = 0; i < 50 && (await status()).sensors.santa.syncError; i++)
        await new Promise((r) => setTimeout(r, 100));
      expect((await status()).sensors.santa.syncError).toBeNull();
      expect(
        (await santaPost('preflight', {}, { port: busyPort, tlsDir: busyPaths.tlsDir })).sync_type,
      ).toBe('CLEAN');
    } finally {
      busyClient?.close();
      blocker.close();
      await stopBusy?.();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the Santa sync port', () => {
  const tlsFiles = () => {
    const t = syncTlsPaths(paths.tlsDir);
    return { key: readFileSync(t.serverKey), cert: readFileSync(t.serverCert) };
  };
  const freePort = port + 2000;
  const closed = (s: Socket) => new Promise<void>((r) => s.once('close', () => r()));
  const open = async (p: number) => {
    const s = connect(p, '127.0.0.1');
    s.on('error', () => {});
    await new Promise<void>((r) => s.once('connect', () => r()));
    return s;
  };

  it('cuts off slow clients and keeps few connections', () => {
    const server = createSyncHttpsServer(tlsFiles(), () => {});
    expect(server.maxConnections).toBe(16);
    expect(server.headersTimeout).toBe(15_000);
    expect(server.requestTimeout).toBe(30_000);
    expect(server.keepAliveTimeout).toBe(5_000);
    expect(SYNC_SERVER_LIMITS.handshakeTimeoutMs).toBe(10_000);
  });

  it('drops a connection that never finishes the TLS handshake, and ones over the limit', async () => {
    const server = createSyncHttpsServer(tlsFiles(), () => {}, {
      ...SYNC_SERVER_LIMITS,
      maxConnections: 2,
      handshakeTimeoutMs: 200,
    });
    await new Promise<void>((r) => server.listen(freePort, '127.0.0.1', () => r()));
    try {
      const [a, b] = [await open(freePort), await open(freePort)];
      const third = await open(freePort);
      // Over the limit: closed at once, long before the handshake timeout.
      const t0 = Date.now();
      await closed(third);
      expect(Date.now() - t0).toBeLessThan(150);
      // Never sent a ClientHello: closed after the handshake timeout.
      await Promise.all([closed(a), closed(b)]);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
