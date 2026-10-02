import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DetectionEngine, macosCoreRules, memoryStores } from '@vigil/detection';
import { fastPathRules, listDigest } from '@vigil/detection/fastpath';
import { RuleStore, type SensorEvent } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { HelperClient } from './client.js';
import { Executor, type ActionOutcome } from './executor.js';
import { FastPath, type HelperRan } from './fastpath.js';
import { Journal } from './journal.js';
import { LIST_PART_MAX, type DetectionSync } from './protocol.js';
import { HelperServer } from './server.js';
import { FakeSystem } from './testing/fakeSystem.js';

const BAD = 'b'.repeat(64);
const SELF = '/Applications/Vigil at Home.app';

let root: string;
let sys: FakeSystem;
let fast: FastPath;
let server: HelperServer;
let client: HelperClient;
let rulesFile: string;

function makeFastPath(executor: Executor): FastPath {
  return new FastPath({
    file: rulesFile,
    run: async (action) => {
      const out = await executor.execute(action);
      if (out.kind !== 'done') throw new Error('needs the admin password');
      return out.result as ActionOutcome;
    },
  });
}

let executor: Executor;

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-fastpath-'));
  rulesFile = join(root, 'helper-rules.json');
  sys = new FakeSystem();
  executor = new Executor({
    sys,
    journal: new Journal(join(root, 'journal.json')),
    approvals: new Approvals({ dir: join(root, 'approvals'), requiredOwnerUid: process.getuid!() }),
    rules: new RuleStore(join(root, 'rules.json')),
    quarantine: { quarantineDir: join(root, 'Quarantine') },
    syncPort: 47821,
    get fastPath() {
      return fast;
    },
  });
  fast = makeFastPath(executor);
  server = new HelperServer({ socketPath: join(root, 'helper.sock'), executor });
  await server.listen();
  client = await HelperClient.connect(join(root, 'helper.sock'), async () => false);
});

afterAll(async () => {
  client.close();
  await server.close();
  rmSync(root, { recursive: true, force: true });
});

beforeEach(() => {
  sys.signals.length = 0;
});

const exec = (pid: number, sha256: string, path = '/tmp/payload'): SensorEvent => ({
  id: `e-${pid}-${sha256.slice(0, 4)}`,
  ts: Date.now(),
  source: 'santa',
  kind: 'process.exec',
  process: { pid, path, sha256, signing: 'unsigned' },
});

/** What the app sends: the core pack's block rules and their lists. */
function appSet(lists: Record<string, string[]>, exceptions: DetectionSync['exceptions'] = []) {
  const set = fastPathRules(new DetectionEngine(macosCoreRules, memoryStores()).listRules());
  const sync: DetectionSync = {
    kind: 'detection.sync',
    rules: set.rules,
    exceptions,
    selfPaths: [SELF],
    lists: Object.fromEntries(set.lists.map((l) => [l, listDigest(lists[l] ?? [])])),
  };
  return { sync, lists };
}

async function sendLists(names: string[], lists: Record<string, string[]>): Promise<void> {
  for (const list of names) {
    const entries = lists[list] ?? [];
    const parts = Math.max(1, Math.ceil(entries.length / LIST_PART_MAX));
    for (let part = 0; part < parts; part++)
      await client.call({
        kind: 'detection.list.set',
        list,
        digest: listDigest(entries),
        part,
        parts,
        entries: entries.slice(part * LIST_PART_MAX, (part + 1) * LIST_PART_MAX),
      });
  }
}

describe('blocking rules in the helper', () => {
  it('takes rules from the app, asks only for lists it lacks, and blocks known malware', async () => {
    const hashes = Array.from({ length: 2500 }, (_, i) => i.toString(16).padStart(64, '0'));
    hashes.push(BAD);
    const { sync, lists } = appSet({ known_bad_sha256: hashes, known_bad_ips: ['203.0.113.9'] });
    const first = await client.call<{ needLists: string[] }>(sync);
    expect(first.needLists.sort()).toEqual([
      'known_bad_ips',
      'known_bad_sha256',
      'user_blocked_sha256',
    ]);
    await sendLists(first.needLists, lists);
    expect(fast.status().lists['known_bad_sha256']).toBe(2501);
    // Same lists again: nothing to send.
    expect((await client.call<{ needLists: string[] }>(sync)).needLists).toEqual([]);

    sys.processes.set(4242, { path: '/tmp/payload', started: 'T' });
    const ran = await fast.check(exec(4242, BAD));
    expect(sys.signals).toEqual([{ pid: 4242, signal: 'SIGKILL' }]);
    expect(ran.map((r) => r.action.kind)).toEqual(['process.kill', 'santa.rule.set']);
    expect(ran[0]!.outcome?.summary).toContain('stopped /tmp/payload');

    // Something not on the list is left alone.
    sys.processes.set(4243, { path: '/tmp/fine', started: 'T' });
    expect(await fast.check(exec(4243, 'c'.repeat(64), '/tmp/fine'))).toEqual([]);
    expect(sys.signals).toHaveLength(1);
  });

  it('respects the user’s exceptions and never touches Vigil itself', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] }, [
      { id: 'x1', ruleId: '*', match: { 'process.path': '/tmp/allowed' }, createdAt: 1 },
    ]);
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    sys.processes.set(5000, { path: '/tmp/allowed', started: 'T' });
    expect(await fast.check(exec(5000, BAD, '/tmp/allowed'))).toEqual([]);
    const self = `${SELF}/Contents/MacOS/Vigil at Home`;
    sys.processes.set(5001, { path: self, started: 'T' });
    const ran = await fast.check(exec(5001, BAD, self));
    expect(ran.some((r) => r.action.kind === 'process.kill')).toBe(false);
    expect(sys.signals).toEqual([]);
  });

  it('refuses a list that arrives damaged and keeps the old one', async () => {
    const { sync } = appSet({ known_bad_sha256: [BAD, 'd'.repeat(64)] });
    await client.call(sync);
    await expect(
      client.call({
        kind: 'detection.list.set',
        list: 'known_bad_sha256',
        digest: sync.lists['known_bad_sha256']!,
        part: 0,
        parts: 1,
        entries: ['e'.repeat(64)],
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    expect(fast.status().lists['known_bad_sha256']).toBeUndefined();
  });

  it('keeps the rules across a restart, and ignores a damaged file', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    const again = makeFastPath(executor);
    again.load();
    expect(again.status()).toEqual(fast.status());
    sys.processes.set(6000, { path: '/tmp/payload', started: 'T' });
    expect((await again.check(exec(6000, BAD))).length).toBeGreaterThan(0);

    writeFileSync(rulesFile, '{not json');
    const broken = makeFastPath(executor);
    broken.load();
    expect(broken.status().rules).toBe(0);
  });

  it('refuses rules that do not compile, without dropping the current ones', async () => {
    const before = fast.status();
    const bad = { ...appSet({}).sync };
    bad.rules = [{ ...bad.rules[0]!, condition: { field: 'path', op: 'regex', value: '(' } }];
    await expect(client.call(bad)).rejects.toMatchObject({ code: 'invalid' });
    expect(fast.status()).toEqual(before);
  });

  it('tells subscribers what it already did about each event, replays included', async () => {
    const got: { id: string; ran: HelperRan[] }[] = [];
    const ran: HelperRan[] = [
      { ruleId: 'known-bad-hash', at: 1, action: { kind: 'process.kill', pid: 1 }, error: 'gone' },
    ];
    server.publish(exec(1, BAD), ran);
    const sub = await HelperClient.connect(join(root, 'helper.sock'), async () => false);
    sub.onEvent((e, r) => got.push({ id: e.id, ran: r }));
    await sub.subscribe();
    server.publish(exec(2, BAD));
    await new Promise((r) => setTimeout(r, 50));
    expect(got).toEqual([{ id: exec(2, BAD).id, ran: [] }]);
    sub.close();

    const replay = await HelperClient.connect(join(root, 'helper.sock'), async () => false);
    const replayed: HelperRan[][] = [];
    replay.onEvent((_e, r) => replayed.push(r));
    // Subscribing from an earlier event replays the ones after it with what was done.
    server.publish(exec(3, BAD));
    server.publish(exec(4, BAD), ran);
    await replay.subscribe(exec(3, BAD).id);
    await new Promise((r) => setTimeout(r, 50));
    expect(replayed).toEqual([ran]);
    replay.close();
  });
});
