import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createServer, request, type Server } from 'node:https';
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { deflateSync } from 'node:zlib';
import type { AddressInfo } from 'node:net';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { Readable } from 'node:stream';
import { RuleStore } from './santa/ruleStore.js';
import {
  HttpError,
  logSafe,
  MAX_LOGGED_URL,
  MAX_SYNC_SESSIONS,
  SantaSyncServer,
  SYNC_SESSION_TTL_MS,
} from './santa/syncServer.js';
import { ensureSyncTls, serverCertNeedsRenewal, syncTlsPaths } from './santa/tls.js';
import { SensorEvent } from '@vigil/core';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const MACHINE = 'ABCD-1234';

let dir: string;
let server: Server;
let port: number;
let ca: Buffer;
let store: RuleStore;
const events: SensorEvent[] = [];
let sync: SantaSyncServer;

// Santa's client sends protobuf JSON (camelCase or json_name), deflate-compressed.
function post(
  stage: string,
  body: unknown,
  machine = MACHINE,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in tests
): Promise<{ status: number; json: any }> {
  const payload = deflateSync(Buffer.from(JSON.stringify(body)));
  return new Promise((resolve, reject) => {
    const req = request(
      {
        host: '127.0.0.1',
        port,
        method: 'POST',
        path: `/${stage}/${machine}`,
        ca,
        headers: { 'content-type': 'application/json', 'content-encoding': 'deflate' },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const text = Buffer.concat(chunks).toString();
          let json: unknown = text;
          try {
            json = JSON.parse(text);
          } catch {
            /* plain text error */
          }
          resolve({ status: res.statusCode ?? 0, json });
        });
      },
    );
    req.on('error', reject);
    req.end(payload);
  });
}

async function fullSync(preflightBody: Record<string, unknown> = {}) {
  const pre = await post('preflight', {
    serial_num: 'X',
    machine_id: MACHINE,
    clientMode: 'MONITOR',
    ...preflightBody,
  });
  const rules: { identifier: string }[] = [];
  let cursor = '';
  do {
    const r = await post('ruledownload', { cursor, machine_id: MACHINE });
    expect(r.status).toBe(200);
    rules.push(...r.json.rules);
    cursor = r.json.cursor ?? '';
  } while (cursor);
  await post('postflight', {
    rules_received: rules.length,
    rules_processed: rules.length,
    machine_id: MACHINE,
  });
  return { pre: pre.json, rules };
}

beforeAll(async () => {
  dir = mkdtempSync(join(tmpdir(), 'vigil-sync-'));
  const tls = syncTlsPaths(join(dir, 'tls'));
  expect(await ensureSyncTls(tls, 'openssl')).toBe(true);
  expect(await ensureSyncTls(tls, 'openssl')).toBe(false); // idempotent
  expect(serverCertNeedsRenewal(tls)).toBe(false);
  expect(statSync(tls.caKey).mode & 0o777).toBe(0o600);
  expect(statSync(tls.serverKey).mode & 0o777).toBe(0o600);
  // santasyncservice runs as nobody and must reach ca.pem.
  expect(statSync(tls.dir).mode & 0o777).toBe(0o755);
  expect(statSync(tls.caCert).mode & 0o777).toBe(0o644);
  expect(statSync(tls.serverCert).mode & 0o777).toBe(0o644);
  // A folder left at 0700 by an earlier version is repaired.
  chmodSync(tls.dir, 0o700);
  chmodSync(tls.caCert, 0o600);
  expect(await ensureSyncTls(tls, 'openssl')).toBe(false);
  expect(statSync(tls.dir).mode & 0o777).toBe(0o755);
  expect(statSync(tls.caCert).mode & 0o777).toBe(0o644);
  expect(statSync(tls.caKey).mode & 0o777).toBe(0o600);
  ca = readFileSync(tls.caCert);
  store = new RuleStore(join(dir, 'rules.json'));
  sync = new SantaSyncServer({
    store,
    onEvent: (e) => events.push(e),
    pageSize: 2,
    eventDetailUrl: 'vigil://santa/%file_sha%',
  });
  server = createServer(
    { key: readFileSync(tls.serverKey), cert: readFileSync(tls.serverCert) },
    sync.handler,
  );
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as AddressInfo).port;
});

afterAll(async () => {
  await new Promise((r) => server.close(r));
  rmSync(dir, { recursive: true, force: true });
});

describe('Santa sync server over pinned TLS', () => {
  it('rejects a client that does not trust the pinned CA', async () => {
    await expect(
      new Promise((resolve, reject) => {
        const req = request(
          { host: '127.0.0.1', port, method: 'POST', path: `/preflight/${MACHINE}` },
          resolve,
        );
        req.on('error', reject);
        req.end('{}');
      }),
    ).rejects.toThrow(/certificate/i);
  });

  it('does a clean sync first, with pagination', async () => {
    store.upsert({ ruleType: 'BINARY', identifier: SHA_A, policy: 'BLOCKLIST', reason: 'test' });
    store.upsert({ ruleType: 'TEAMID', identifier: 'ABCDE12345', policy: 'BLOCKLIST' });
    store.upsert({
      ruleType: 'SIGNINGID',
      identifier: 'platform:com.apple.osascript',
      policy: 'SILENT_BLOCKLIST',
    });
    const { pre, rules } = await fullSync();
    expect(pre).toMatchObject({
      client_mode: 'MONITOR',
      sync_type: 'CLEAN',
      disable_unknown_event_upload: true,
      event_detail_url: 'vigil://santa/%file_sha%',
    });
    expect(rules.map((r) => r.identifier)).toEqual([
      SHA_A,
      'ABCDE12345',
      'platform:com.apple.osascript',
    ]);
    expect(rules[0]).toEqual({ identifier: SHA_A, policy: 'BLOCKLIST', rule_type: 'BINARY' });
    expect(store.cleanSyncPending).toBe(false);
    expect(store.syncedRev).toBe(store.rev);
  });

  it('then sends only changes, including removals', async () => {
    store.remove('BINARY', SHA_A);
    store.upsert({ ruleType: 'BINARY', identifier: SHA_B, policy: 'BLOCKLIST' });
    const { pre, rules } = await fullSync({
      binary_rule_count: 1,
      teamidRuleCount: 1,
      signingidRuleCount: 1,
    });
    expect(pre.sync_type).toBe('NORMAL');
    expect(rules).toEqual([
      { identifier: SHA_A, policy: 'REMOVE', rule_type: 'BINARY' },
      { identifier: SHA_B, policy: 'BLOCKLIST', rule_type: 'BINARY' },
    ]);
  });

  it('sends nothing when nothing changed, and resyncs cleanly if Santa drifted', async () => {
    const same = await fullSync({ binaryRuleCount: 1, teamidRuleCount: 1, signingidRuleCount: 1 });
    expect(same.pre.sync_type).toBe('NORMAL');
    expect(same.rules).toEqual([]);
    const drift = await fullSync({ binaryRuleCount: 0, teamidRuleCount: 0, signingidRuleCount: 0 });
    expect(drift.pre.sync_type).toBe('CLEAN');
    expect(drift.rules).toHaveLength(3);
  });

  it('still clears Santa when a clean sync has no rules to send', async () => {
    // Santa ignores an empty download, clean or not, so rules it already had
    // (here one Vigil never sent) would survive. The sentinel forces the wipe.
    const empty = new RuleStore(join(dir, 'empty-rules.json'));
    const s = new SantaSyncServer({ store: empty });
    const call = async (stage: string, body: unknown) => s.dispatch(stage, 'M2', body);
    const pre = (await call('preflight', { binaryRuleCount: 1 })) as { sync_type: string };
    expect(pre.sync_type).toBe('CLEAN');
    const down = (await call('ruledownload', { cursor: '' })) as { rules: unknown[] };
    expect(down.rules).toEqual([
      { identifier: '0'.repeat(64), policy: 'REMOVE', rule_type: 'BINARY' },
    ]);
    await call('postflight', { rules_received: 1, rules_processed: 1 });
    expect(empty.cleanSyncPending).toBe(false);
    // Once Santa matches (no rules), nothing more is sent.
    await call('preflight', { binaryRuleCount: 0 });
    expect(await call('ruledownload', { cursor: '' })).toEqual({ rules: [] });
  });

  it('does not advance when Santa failed to apply rules', async () => {
    store.upsert({ ruleType: 'CDHASH', identifier: 'c'.repeat(40), policy: 'BLOCKLIST' });
    const before = store.syncedRev;
    await post('preflight', { binaryRuleCount: 1, teamidRuleCount: 1, signingidRuleCount: 1 });
    await post('ruledownload', { cursor: '' });
    await post('postflight', { rules_received: 1, rules_processed: 0 });
    expect(store.syncedRev).toBe(before);
  });

  it('turns uploaded blocks into sensor events', async () => {
    const r = await post('eventupload', {
      machine_id: MACHINE,
      events: [
        {
          fileSha256: SHA_B,
          filePath: '/Users/a/Downloads',
          fileName: 'evil',
          executingUser: 'a',
          executionTime: 1790000000.5,
          decision: 'BLOCK_BINARY',
          pid: 77,
          ppid: 1,
          parentName: 'launchd',
          teamId: '',
          signingChain: [{ sha256: 'd'.repeat(64), cn: 'Dev' }],
        },
      ],
      file_access_events: [
        {
          rule_name: 'SSHKeys',
          target: '/Users/a/.ssh/id_ed25519',
          decision: 'FILE_ACCESS_DECISION_DENIED',
          access_time: 1790000001,
          process_chain: [{ file_path: '/tmp/stealer', pid: 88 }],
        },
      ],
    });
    expect(r.status).toBe(200);
    const [exec, faa] = events.map((e) => SensorEvent.parse(e));
    expect(exec).toMatchObject({
      kind: 'santa.decision',
      target: 'execution',
      decision: 'block',
      reason: 'BLOCK_BINARY',
      ts: 1790000000500,
      process: { pid: 77, path: '/Users/a/Downloads/evil', sha256: SHA_B, parentPath: 'launchd' },
    });
    expect(faa).toMatchObject({
      kind: 'santa.decision',
      target: 'file_access',
      decision: 'block',
      path: '/Users/a/.ssh/id_ed25519',
      reason: 'FILE_ACCESS_DECISION_DENIED:SSHKeys',
      process: { pid: 88, path: '/tmp/stealer' },
    });
  });

  it('rejects bad requests', async () => {
    expect((await post('bogus', {})).status).toBe(404);
    expect((await post('ruledownload', {}, 'never-preflighted')).status).toBe(409);
  });

  it('persists rules across restarts', () => {
    const reopened = new RuleStore(join(dir, 'rules.json'));
    expect(reopened.get('BINARY', SHA_B)?.rule.policy).toBe('BLOCKLIST');
    expect(reopened.get('BINARY', SHA_A)).toBeUndefined();
    expect(reopened.rev).toBe(store.rev);
  });

  it('refuses malformed identifiers', () => {
    expect(() =>
      store.upsert({ ruleType: 'BINARY', identifier: 'not-a-hash', policy: 'BLOCKLIST' }),
    ).toThrow();
    expect(() =>
      store.upsert({
        ruleType: 'SIGNINGID',
        identifier: 'com.apple.osascript',
        policy: 'BLOCKLIST',
      }),
    ).toThrow();
  });
});

describe('unfinished syncs', () => {
  const statusOf = (fn: () => unknown): number | undefined => {
    try {
      fn();
      return undefined;
    } catch (err) {
      return err instanceof HttpError ? err.status : -1;
    }
  };

  it('keeps only a few, and only for a while', () => {
    let clock = 1_000_000;
    const s = new SantaSyncServer({
      store: new RuleStore(join(dir, 'sessions-rules.json')),
      now: () => clock,
    });
    const download = (m: string) => () => s.dispatch('ruledownload', m, { cursor: '' });
    for (let i = 0; i <= MAX_SYNC_SESSIONS; i++) s.dispatch('preflight', `m${i}`, {});
    // The oldest made room for the newest.
    expect(statusOf(download('m0'))).toBe(409);
    for (let i = 1; i <= MAX_SYNC_SESSIONS; i++)
      expect(statusOf(download(`m${i}`))).toBeUndefined();

    clock += SYNC_SESSION_TTL_MS + 1;
    expect(statusOf(download('m1'))).toBe(409);
    s.dispatch('preflight', 'm1', {});
    expect(statusOf(download('m1'))).toBeUndefined();
  });

  it("never lets other machine ids push out the last confirmed Santa's sync", () => {
    const rules = new RuleStore(join(dir, 'known-rules.json'));
    rules.upsert({ ruleType: 'BINARY', identifier: SHA_A, policy: 'BLOCKLIST' });
    const s = new SantaSyncServer({ store: rules });
    const download = (m: string) => () => s.dispatch('ruledownload', m, { cursor: '' });
    const finish = (m: string) => {
      s.dispatch('preflight', m, {});
      s.dispatch('ruledownload', m, { cursor: '' });
      s.dispatch('postflight', m, { rules_received: 1, rules_processed: 1 });
    };
    finish('santa');
    expect(rules.syncedMachineId).toBe('santa');
    // It is kept with the store, so a restarted helper still knows it.
    expect(new RuleStore(join(dir, 'known-rules.json')).syncedMachineId).toBe('santa');

    s.dispatch('preflight', 'santa', {});
    for (let i = 0; i < MAX_SYNC_SESSIONS * 3; i++) s.dispatch('preflight', `x${i}`, {});
    expect(statusOf(download('santa'))).toBeUndefined();
    // The others share the remaining slots, oldest out first.
    const last = MAX_SYNC_SESSIONS * 3 - 1;
    for (let i = 0; i < MAX_SYNC_SESSIONS - 1; i++)
      expect(statusOf(download(`x${last - i}`))).toBeUndefined();
    expect(statusOf(download(`x${last - (MAX_SYNC_SESSIONS - 1)}`))).toBe(409);

    // With every slot taken by others, Santa's preflight still gets one.
    const t = new SantaSyncServer({ store: rules });
    for (let i = 0; i < MAX_SYNC_SESSIONS; i++) t.dispatch('preflight', `y${i}`, {});
    t.dispatch('preflight', 'santa', {});
    expect(statusOf(() => t.dispatch('ruledownload', 'santa', { cursor: '' }))).toBeUndefined();
    expect(statusOf(() => t.dispatch('ruledownload', 'y0', { cursor: '' }))).toBe(409);
  });

  it('does not remember a machine id whose postflight did not confirm everything', () => {
    const rules = new RuleStore(join(dir, 'unconfirmed-rules.json'));
    rules.upsert({ ruleType: 'BINARY', identifier: SHA_A, policy: 'BLOCKLIST' });
    const s = new SantaSyncServer({ store: rules });
    s.dispatch('preflight', 'm', {});
    s.dispatch('postflight', 'm', { rules_received: 0, rules_processed: 0 });
    expect(rules.syncedMachineId).toBeUndefined();
  });

  it('counts only a postflight that ends a live sync as Santa syncing', () => {
    let clock = 5_000;
    const s = new SantaSyncServer({
      store: new RuleStore(join(dir, 'postflight-rules.json')),
      now: () => clock,
    });
    s.dispatch('postflight', 'stray', { rules_received: 0, rules_processed: 0 });
    expect(s.lastSyncAt).toBeNull();
    s.dispatch('preflight', 'm', {});
    clock = 6_000;
    s.dispatch('postflight', 'm', { rules_received: 1, rules_processed: 1 });
    expect(s.lastSyncAt).toBe(6_000);
    // The session is gone, so repeating the postflight changes nothing.
    clock = 7_000;
    s.dispatch('postflight', 'm', {});
    expect(s.lastSyncAt).toBe(6_000);
  });
});

describe('request logging', () => {
  it('logs the request path on one line, bounded', async () => {
    const lines: string[] = [];
    const s = new SantaSyncServer({ store: new RuleStore(), log: (m) => lines.push(m) });
    const req = Object.assign(Readable.from([]), {
      method: 'POST',
      url: `/nowhere\r\n[vigil-helper] forged line\u001b[2J${'x'.repeat(5000)}`,
      headers: {},
    }) as unknown as IncomingMessage;
    await new Promise<void>((resolve) => {
      const res = { writeHead: () => res, end: () => resolve() } as unknown as ServerResponse;
      s.handler(req, res);
    });
    expect(lines).toHaveLength(1);
    for (const c of ['\r', '\n', '\u001b']) expect(lines[0]).not.toContain(c);
    expect(lines[0]).toContain('/nowhere[vigil-helper] forged line[2J');
    expect(lines[0]!.length).toBeLessThan(MAX_LOGGED_URL + 100);
  });

  it('strips control characters and truncates', () => {
    expect(logSafe('/a\u0000b\u007fc\u0085d e')).toBe('/abcde');
    expect(logSafe('y'.repeat(MAX_LOGGED_URL + 1))).toBe(`${'y'.repeat(MAX_LOGGED_URL)}...`);
    expect(logSafe('/preflight/M1')).toBe('/preflight/M1');
  });
});
