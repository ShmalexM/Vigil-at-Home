import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  appendFileSync,
  existsSync,
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
import {
  certFingerprint,
  fileAccessPolicy,
  IdentityApprovalNeeded,
  type IdentityStep,
  issueClientCertificate,
  RuleStore,
  SyncIdentityStore,
  syncTlsPaths,
} from '@vigil/sensors';
import { HelperClient } from './client.js';
import { defaultPaths, type HelperPaths } from './config.js';
import {
  CLIENT_SEEN_FILE,
  createSyncHttpsServer,
  listenUnlessStopped,
  runDaemon,
  SYNC_SERVER_LIMITS,
  SyncClientAuth,
  type SensorHealth,
  type SyncClientPin,
} from './daemon.js';
import { Approvals } from './approval.js';
import { Executor } from './executor.js';
import { Journal } from './journal.js';
import { needsApproval } from './protocol.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';
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

/** The client identity in a sync folder, as Santa presents it. */
function clientIdentity(tlsDir: string): { key: Buffer; cert: Buffer } {
  const t = syncTlsPaths(tlsDir);
  return { key: readFileSync(t.clientKey), cert: readFileSync(t.clientCert) };
}

/** Another client identity from the same CA, not the one the helper pinned. */
function sameCaIdentity(tlsDir: string): Promise<{ key: Buffer; cert: Buffer }> {
  const t = syncTlsPaths(tlsDir);
  return issueClientCertificate({ key: readFileSync(t.caKey), cert: readFileSync(t.caCert) });
}

/** Whether the identity in use says the certificate is required, as written on disk. */
function requiredOnDisk(tlsDir: string): boolean {
  return (JSON.parse(readFileSync(syncTlsPaths(tlsDir).state, 'utf8')) as { required: boolean })
    .required;
}

/** santa-sync/ as a helper from before the client certificate left it: CA and server only. */
async function preClientCertLayout(tlsDir: string): Promise<void> {
  const src = mkdtempSync(join(tmpdir(), 'vigil-old-layout-'));
  try {
    const store = new SyncIdentityStore(join(src, 'santa-sync'), { opensslBin: 'openssl' });
    await store.start();
    mkdirSync(tlsDir, { recursive: true });
    for (const f of ['ca.key', 'ca.pem', 'server.key', 'server.pem'])
      writeFileSync(join(tlsDir, f), readFileSync(join(store.paths.current, f)), { mode: 0o600 });
  } finally {
    rmSync(src, { recursive: true, force: true });
  }
}

function santaPost(
  stage: string,
  body: unknown,
  at: { port: number; tlsDir: string; client?: { key: Buffer; cert: Buffer } | false } = {
    port,
    tlsDir: paths.tlsDir,
  },
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in tests
): Promise<any> {
  // Santa's own certificate unless the test says otherwise.
  const client = at.client === undefined ? clientIdentity(at.tlsDir) : at.client;
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port: at.port,
        method: 'POST',
        path: `/${stage}/M1`,
        ca: readFileSync(join(at.tlsDir, 'ca.pem')),
        ...(client ? client : {}),
        agent: false,
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
    const t = syncTlsPaths(paths.tlsDir);
    expect(statSync(paths.supportDir).mode & 0o777).toBe(0o755);
    expect(statSync(paths.tlsDir).mode & 0o777).toBe(0o755);
    expect(statSync(join(paths.tlsDir, 'ca.pem')).mode & 0o777).toBe(0o644);
    expect(statSync(t.caKey).mode & 0o777).toBe(0o600);
    expect(statSync(t.clientKey).mode & 0o777).toBe(0o600);
    expect(statSync(t.clientP12Password).mode & 0o777).toBe(0o600);
    // Readable by its group (nobody on a Mac), writable by no one but root.
    expect(statSync(join(paths.tlsDir, 'client.p12')).mode & 0o777).toBe(0o440);
    expect(statSync(t.current).mode & 0o777).toBe(0o750);
  });

  it('serves a profile that has Santa present its client certificate', async () => {
    const r = await client!.call<{ mobileconfig: string }>({ kind: 'santa.profile' });
    const password = readFileSync(syncTlsPaths(paths.tlsDir).clientP12Password, 'utf8').trim();
    expect(r.mobileconfig).toMatch(
      /<key>ClientAuthCertificateFile<\/key>\s*<string>[^<]*\/client\.p12<\/string>/,
    );
    expect(r.mobileconfig).toMatch(
      new RegExp(`<key>ClientAuthCertificatePassword</key>\\s*<string>${password}</string>`),
    );
  });

  it('takes only the pinned client certificate on a new install', async () => {
    const status = await client!.call<{ sensors: SensorHealth }>({ kind: 'helper.status' });
    expect(status.sensors.santa.clientCertRequired).toBe(true);
    // Never presented yet: nothing to vouch for the profile.
    expect(status.sensors.santa.clientCertSeenAt).toBeNull();
    expect(status.sensors.santa.lastRefusal).toBeNull();
    await expect(
      santaPost('preflight', {}, { port, tlsDir: paths.tlsDir, client: false }),
    ).rejects.toThrow();
    // A refusal shows in helper.status, so the app can say Santa can't sync.
    const refused = await client!.call<{ sensors: SensorHealth }>({ kind: 'helper.status' });
    expect(refused.sensors.santa.lastRefusal).toMatchObject({ reason: 'no_certificate' });
    const other = await sameCaIdentity(paths.tlsDir);
    await expect(
      santaPost('preflight', {}, { port, tlsDir: paths.tlsDir, client: other }),
    ).rejects.toThrow();
    const before = Date.now();
    expect((await santaPost('preflight', {})).sync_type).toBeDefined();
    const seen = await client!.call<{ sensors: SensorHealth }>({ kind: 'helper.status' });
    expect(seen.sensors.santa.clientCertSeenAt).toBeGreaterThanOrEqual(before);
    expect(readFileSync(join(paths.tlsDir, CLIENT_SEEN_FILE), 'utf8')).toMatch(/^\d{4}-/);
  });

  it('serves commands, Santa sync and live sensor events together', async () => {
    const status = await client!.call<{ activeActions: number; sensors: SensorHealth }>({
      kind: 'helper.status',
    });
    expect(status.activeActions).toBe(0);
    expect(status.sensors).toEqual({
      santa: {
        installed: true,
        lastEventAt: null,
        lastSyncAt: null,
        syncError: null,
        clientCertRequired: true,
        clientCertIssued: true,
        clientCertValid: true,
        identityProblem: null,
        installedAt: expect.any(Number),
        // The test above presented Santa's certificate, and others before it.
        clientCertSeenAt: expect.any(Number),
        clientCertExpiresAt: expect.any(Number),
        lastRefusal: { at: expect.any(Number), reason: 'wrong_certificate' },
        syncIntervalSeconds: 600,
      },
      osquery: { installed: false, lastEventAt: null },
    });
    // 397 days, renewed 30 days before.
    expect(status.sensors.santa.clientCertExpiresAt! - Date.now()).toBeGreaterThan(
      390 * 86_400_000,
    );

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
    return {
      key: readFileSync(t.serverKey),
      cert: readFileSync(t.serverCert),
      ca: readFileSync(t.caCert),
    };
  };
  const pinned = (required = true): SyncClientPin & { seen: number; refusals: string[] } => {
    const fingerprint = certFingerprint(readFileSync(syncTlsPaths(paths.tlsDir).clientCert));
    return {
      required,
      seen: 0,
      refusals: [],
      accepts: (fp) => fp === fingerprint,
      pinnedSeen(fp) {
        expect(fp).toBe(fingerprint);
        this.seen++;
      },
      refused(reason) {
        this.refusals.push(reason);
      },
    };
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
    const server = createSyncHttpsServer(tlsFiles(), () => {}, pinned());
    expect(server.maxConnections).toBe(16);
    expect(server.headersTimeout).toBe(15_000);
    expect(server.requestTimeout).toBe(30_000);
    expect(server.keepAliveTimeout).toBe(5_000);
    expect(SYNC_SERVER_LIMITS.handshakeTimeoutMs).toBe(10_000);
  });

  it('drops a connection that never finishes the TLS handshake, and ones over the limit', async () => {
    const server = createSyncHttpsServer(tlsFiles(), () => {}, pinned(), {
      ...SYNC_SERVER_LIMITS,
      maxConnections: 2,
      handshakeTimeoutMs: 200,
    });
    await listenUnlessStopped(server, freePort, () => false);
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

  /** POSTs a preflight with node's TLS client; 'refused' when the connection is dropped. */
  const tryPreflight = (
    p: number,
    id?: { key: Buffer; cert: Buffer },
  ): Promise<number | 'refused'> =>
    new Promise((resolve) => {
      const req = request(
        {
          host: '127.0.0.1',
          port: p,
          method: 'POST',
          path: '/preflight/M1',
          ca: readFileSync(syncTlsPaths(paths.tlsDir).caCert),
          agent: false,
          ...(id ?? {}),
        },
        (res) => {
          res.resume();
          res.on('end', () => resolve(res.statusCode ?? 0));
        },
      );
      req.on('error', () => resolve('refused'));
      req.end('{}');
    });

  const serve = async (pin: SyncClientPin) => {
    const routed: string[] = [];
    const server = createSyncHttpsServer(
      tlsFiles(),
      (req, res) => {
        routed.push(req.url ?? '');
        res.end('{}');
      },
      pin,
    );
    await listenUnlessStopped(server, freePort, () => false);
    return {
      routed,
      close: () => new Promise<void>((r) => server.close(() => r())),
    };
  };

  it('requires the pinned client certificate before routing anything', async () => {
    const pin = pinned();
    const s = await serve(pin);
    try {
      // No certificate: refused in the handshake.
      expect(await tryPreflight(freePort)).toBe('refused');
      // Signed by Vigil's CA, but not the certificate the helper made for Santa.
      expect(await tryPreflight(freePort, await sameCaIdentity(paths.tlsDir))).toBe('refused');
      // From another CA altogether.
      expect(await tryPreflight(freePort, await issueClientCertificate(null))).toBe('refused');
      expect(s.routed).toEqual([]);
      // Santa's own certificate.
      expect(await tryPreflight(freePort, clientIdentity(paths.tlsDir))).toBe(200);
      expect(s.routed).toEqual(['/preflight/M1']);
      expect(pin.seen).toBeGreaterThan(0);
      expect(pin.refusals).toEqual(['no_certificate', 'wrong_certificate', 'wrong_certificate']);
    } finally {
      await s.close();
    }
  });

  it('serves a client without a certificate only until Santa presents its own', async () => {
    let required = false;
    const fingerprint = certFingerprint(readFileSync(syncTlsPaths(paths.tlsDir).clientCert));
    const pin: SyncClientPin = {
      accepts: (fp) => fp === fingerprint,
      get required() {
        return required;
      },
      pinnedSeen() {
        required = true;
      },
    };
    const s = await serve(pin);
    try {
      expect(await tryPreflight(freePort)).toBe(200);
      // A wrong certificate is refused even then.
      expect(await tryPreflight(freePort, await sameCaIdentity(paths.tlsDir))).toBe('refused');
      expect(await tryPreflight(freePort, clientIdentity(paths.tlsDir))).toBe(200);
      expect(required).toBe(true);
      expect(await tryPreflight(freePort)).toBe('refused');
      expect(s.routed).toEqual(['/preflight/M1', '/preflight/M1']);
    } finally {
      await s.close();
    }
  });

  it('does not stay bound when the helper stops during listen', async () => {
    const server = createSyncHttpsServer(tlsFiles(), () => {}, pinned());
    let stopped = false;
    const listening = listenUnlessStopped(server, freePort, () => stopped);
    stopped = true;
    await listening;
    expect(server.listening).toBe(false);
    // The port is free again.
    const probe = createServer();
    await new Promise<void>((r) => probe.listen(freePort, '127.0.0.1', () => r()));
    await new Promise<void>((r) => probe.close(() => r()));
  });
});

describe('helper upgrade with a Santa profile from before the client certificate', () => {
  it('keeps Santa syncing, then requires the certificate once Santa presents it', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-daemon-upgrade-'));
    const upPort = port + 3000;
    const upPaths = testPaths(dir);
    // An earlier helper made the CA and server certificate, flat in the
    // folder; the client identity is new in this version.
    const t = syncTlsPaths(upPaths.tlsDir);
    await preClientCertLayout(upPaths.tlsDir);
    const start = async () => {
      const s = new FakeSystem();
      s.console = process.getuid!() === 0 ? 501 : undefined;
      const stopIt = await runDaemon({
        paths: upPaths,
        syncPort: upPort,
        sys: s,
        log: () => {},
        approvalOwnerUid: process.getuid!(),
        opensslBin: 'openssl',
        sensorBinaries: { santa: upPaths.santaLog as string, osquery: join(dir, 'no-osqueryd') },
        osquery: false,
      });
      const c = await HelperClient.connect(upPaths.socket, async () => false);
      return { stop: stopIt, c };
    };
    const at = (client?: { key: Buffer; cert: Buffer } | false) => ({
      port: upPort,
      tlsDir: upPaths.tlsDir,
      client: client ?? false,
    });
    let run = await start();
    try {
      const required = async () =>
        (await run.c.call<{ sensors: SensorHealth }>({ kind: 'helper.status' })).sensors.santa
          .clientCertRequired;
      expect(existsSync(t.clientP12)).toBe(true);
      expect(await required()).toBe(false);
      // Santa with the old profile: no certificate, still syncs.
      expect((await santaPost('preflight', {}, at())).sync_type).toBe('CLEAN');
      // Any other certificate is refused.
      await expect(
        santaPost('preflight', {}, at(await sameCaIdentity(upPaths.tlsDir))),
      ).rejects.toThrow();
      expect(requiredOnDisk(upPaths.tlsDir)).toBe(false);
      // The new profile is installed and Santa presents its certificate.
      expect((await santaPost('preflight', {}, at(clientIdentity(upPaths.tlsDir)))).sync_type).toBe(
        'CLEAN',
      );
      expect(await required()).toBe(true);
      for (let i = 0; i < 50 && !requiredOnDisk(upPaths.tlsDir); i++)
        await new Promise((r) => setTimeout(r, 20));
      expect(requiredOnDisk(upPaths.tlsDir)).toBe(true);
      await expect(santaPost('preflight', {}, at())).rejects.toThrow();

      // And it stays required after a restart.
      run.c.close();
      await run.stop();
      run = await start();
      expect(await required()).toBe(true);
      await expect(santaPost('preflight', {}, at())).rejects.toThrow();
      expect((await santaPost('preflight', {}, at(clientIdentity(upPaths.tlsDir)))).sync_type).toBe(
        'CLEAN',
      );
    } finally {
      run.c.close();
      await run.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("Santa's client certificate pin", () => {
  const setup = async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-pin-'));
    const store = new SyncIdentityStore(join(dir, 'santa-sync'), { opensslBin: 'openssl' });
    await store.start();
    let now = Date.now();
    const logs: string[] = [];
    const make = () =>
      new SyncClientAuth({
        store,
        seen: join(store.paths.dir, CLIENT_SEEN_FILE),
        log: (m) => logs.push(m),
        now: () => now,
      });
    return {
      dir,
      store,
      logs,
      make,
      now: () => now,
      advance: (ms: number) => (now += ms),
    };
  };

  it('takes the replaced certificate until its overlap ends, and starts over on recovery', async () => {
    const t = await setup();
    try {
      await t.store.reissue({ approved: true });
      const auth = t.make();
      expect(auth.required).toBe(false);
      expect(auth.seenAt).toBeNull();
      const first = t.store.current!.pin;

      // Renewal: the new certificate and, for a while, the old one.
      await t.store.renew(t.now() + 380 * 86_400_000);
      const second = t.store.current!.pin;
      expect(auth.accepts(second)).toBe(true);
      expect(auth.accepts(first)).toBe(true);
      expect(auth.accepts(BAD)).toBe(false);

      // Santa presenting the old one still counts as the new profile being in place.
      auth.pinnedSeen(first);
      expect(auth.required).toBe(true);
      expect(auth.seenAt).toBe(t.now());
      await t.store.idle();
      // Kept across a restart.
      expect(t.make().seenAt).toBe(t.now());
      expect(requiredOnDisk(t.store.paths.dir)).toBe(true);

      // The renewal ran as if 380 days on; its overlap ends 30 days after that.
      t.advance(411 * 86_400_000);
      expect(auth.accepts(first)).toBe(false);
      expect(auth.accepts(second)).toBe(true);

      auth.refused('no_certificate');
      expect(auth.lastRefusal).toEqual({ at: t.now(), reason: 'no_certificate' });

      // Recovery: needs approval while required; then the seen time goes and nothing old is taken.
      await expect(auth.reissue(false)).rejects.toBeInstanceOf(IdentityApprovalNeeded);
      await auth.reissue(true);
      expect(auth.required).toBe(false);
      expect(auth.seenAt).toBeNull();
      expect(auth.lastRefusal).toBeNull();
      expect(requiredOnDisk(t.store.paths.dir)).toBe(false);
      expect(existsSync(join(t.store.paths.dir, CLIENT_SEEN_FILE))).toBe(false);
      expect(auth.accepts(second)).toBe(false);
      expect(auth.accepts(t.store.current!.pin)).toBe(true);
    } finally {
      rmSync(t.dir, { recursive: true, force: true });
    }
  });
});

describe('recovering a Santa that cannot sync', () => {
  it('needs the admin password to drop the requirement, then serves Santa again', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-daemon-reissue-'));
    const rePort = port + 4000;
    const rePaths = testPaths(dir);
    const s = new FakeSystem();
    s.console = process.getuid!() === 0 ? 501 : undefined;
    const stopIt = await runDaemon({
      paths: rePaths,
      syncPort: rePort,
      sys: s,
      log: () => {},
      approvalOwnerUid: process.getuid!(),
      opensslBin: 'openssl',
      sensorBinaries: { santa: rePaths.santaLog as string, osquery: join(dir, 'no-osqueryd') },
      osquery: false,
    });
    const prompts: string[] = [];
    let approve = false;
    const c = await HelperClient.connect(rePaths.socket, async (nonce, prompt, also = []) => {
      prompts.push(prompt);
      if (approve)
        for (const n of [nonce, ...also]) Approvals.writeApproval(rePaths.approvalsDir, n);
      return approve;
    });
    const at = (client: { key: Buffer; cert: Buffer } | false) => ({
      port: rePort,
      tlsDir: rePaths.tlsDir,
      client,
    });
    const santa = async () =>
      (await c.call<{ sensors: SensorHealth }>({ kind: 'helper.status' })).sensors.santa;
    try {
      const old = clientIdentity(rePaths.tlsDir);
      expect((await santaPost('preflight', {}, at(old))).sync_type).toBe('CLEAN');
      expect((await santa()).clientCertRequired).toBe(true);

      // Cancelled password: nothing changes.
      await expect(c.call({ kind: 'santa.client.reissue' })).rejects.toThrow(/not approved/);
      expect(prompts[0]).toMatch(/repair Santa’s connection/);
      expect((await santa()).clientCertRequired).toBe(true);
      await expect(santaPost('preflight', {}, at(false))).rejects.toThrow();

      approve = true;
      const r = await c.call<{ mobileconfig: string }>({ kind: 'santa.client.reissue' });
      expect(r.mobileconfig).toMatch(/<key>ClientAuthCertificateFile<\/key>/);
      // Santa is asked to sync, so it opens the new file now.
      expect(s.runs.some((run) => run.bin === 'santactl' && run.args[0] === 'sync')).toBe(true);
      const after = await santa();
      expect(after.clientCertRequired).toBe(false);
      expect(after.clientCertSeenAt).toBeNull();
      expect(requiredOnDisk(rePaths.tlsDir)).toBe(false);
      // A Santa with a profile from before the certificate syncs again...
      expect((await santaPost('preflight', {}, at(false))).sync_type).toBe('CLEAN');
      // ...the old certificate is not taken...
      await expect(santaPost('preflight', {}, at(old))).rejects.toThrow();
      // ...and Santa presenting the new one makes it required again.
      expect((await santaPost('preflight', {}, at(clientIdentity(rePaths.tlsDir)))).sync_type).toBe(
        'CLEAN',
      );
      expect((await santa()).clientCertRequired).toBe(true);
      await expect(santaPost('preflight', {}, at(false))).rejects.toThrow();
    } finally {
      c.close();
      await stopIt();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('asks no password when nothing is required, and is refused on Linux', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-reissue-exec-'));
    try {
      let reissued = 0;
      let presentDuring = false;
      const make = (sys: FakeSystem | FakeLinuxSystem) =>
        new Executor({
          sys,
          journal: new Journal(undefined),
          approvals: new Approvals({
            dir: join(dir, 'approvals'),
            requiredOwnerUid: process.getuid!(),
          }),
          rules: new RuleStore(join(dir, 'rules.json')),
          quarantine: { quarantineDir: join(dir, 'q') },
          syncPort: 47821,
          ...(sys instanceof FakeLinuxSystem
            ? {}
            : {
                santaClientReissue: {
                  required: () => false,
                  reissue: async (approved: boolean) => {
                    // Santa presented its certificate while this ran.
                    if (presentDuring && !approved) throw new IdentityApprovalNeeded();
                    reissued++;
                  },
                },
              }),
        });
      const out = await make(new FakeSystem()).execute({ kind: 'santa.client.reissue' });
      expect(out.kind).toBe('done');
      expect(reissued).toBe(1);
      // Required by the time the new identity would take over: the password after all.
      presentDuring = true;
      const late = await make(new FakeSystem()).execute({ kind: 'santa.client.reissue' });
      expect(late).toMatchObject({ kind: 'needs_approval', prompt: expect.any(String) });
      expect(reissued).toBe(1);
      expect(needsApproval({ kind: 'santa.client.reissue' })).toBe(false);
      await expect(
        make(new FakeLinuxSystem()).execute({ kind: 'santa.client.reissue' }),
      ).rejects.toThrow(/only on macOS/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('a required flag the helper cannot write down', () => {
  it('keeps the certificate required, reports it in helper.status, and writes it on a retry', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-daemon-flag-'));
    const flagPort = port + 5000;
    const flagPaths = testPaths(dir);
    await preClientCertLayout(flagPaths.tlsDir);
    let failing = false;
    const s = new FakeSystem();
    s.console = process.getuid!() === 0 ? 501 : undefined;
    const stopIt = await runDaemon({
      paths: flagPaths,
      syncPort: flagPort,
      sys: s,
      log: () => {},
      approvalOwnerUid: process.getuid!(),
      opensslBin: 'openssl',
      sensorBinaries: { santa: flagPaths.santaLog as string, osquery: join(dir, 'no-osqueryd') },
      osquery: false,
      identity: {
        beforeStep: (step: IdentityStep) => {
          if (failing && step === 'state') throw new Error('disk full');
        },
        retryMs: 50,
      },
    });
    const c = await HelperClient.connect(flagPaths.socket, async () => false);
    const at = (client: { key: Buffer; cert: Buffer } | false) => ({
      port: flagPort,
      tlsDir: flagPaths.tlsDir,
      client,
    });
    const santa = async () =>
      (await c.call<{ sensors: SensorHealth }>({ kind: 'helper.status' })).sensors.santa;
    try {
      expect((await santa()).clientCertRequired).toBe(false);
      failing = true;
      expect(
        (await santaPost('preflight', {}, at(clientIdentity(flagPaths.tlsDir)))).sync_type,
      ).toBe('CLEAN');
      for (let i = 0; i < 50 && !(await santa()).identityProblem; i++)
        await new Promise((r) => setTimeout(r, 20));
      const stuck = await santa();
      expect(stuck.identityProblem).toMatch(/Couldn’t save.*disk full/);
      // Required anyway for as long as the helper runs.
      expect(stuck.clientCertRequired).toBe(true);
      await expect(santaPost('preflight', {}, at(false))).rejects.toThrow();
      expect(requiredOnDisk(flagPaths.tlsDir)).toBe(false);

      failing = false;
      for (let i = 0; i < 100 && (await santa()).identityProblem; i++)
        await new Promise((r) => setTimeout(r, 20));
      expect((await santa()).identityProblem).toBeNull();
      expect(requiredOnDisk(flagPaths.tlsDir)).toBe(true);
    } finally {
      c.close();
      await stopIt();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
