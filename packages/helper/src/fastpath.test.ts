import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DetectionEngine, macosCoreRules, memoryStores } from '@vigil/detection';
import { fastPathRules, listDigest } from '@vigil/detection/fastpath';
import { RuleStore, type SensorEvent } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { HelperClient } from './client.js';
import { Executor, type ActionOutcome } from './executor.js';
import { FastPath, RETIRE_MS, type HelperRan } from './fastpath.js';
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

// Small enough that the oversized-drop test stays fast on a busy runner.
const RETIRED_TEST_MAX = 5000;

function makeFastPath(executor: Executor): FastPath {
  return new FastPath({
    file: rulesFile,
    now: () => clock,
    retiredMax: RETIRED_TEST_MAX,
    run: async (action) => {
      const out = await executor.execute(action);
      if (out.kind !== 'done') throw new Error('needs the admin password');
      return out.result as ActionOutcome;
    },
  });
}

let executor: Executor;
let approvalsDir: string;
/** Whether the fake password dialog says yes; every answer is recorded. */
let approve = false;
const prompts: string[] = [];
let clock = 1_000_000;

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-fastpath-'));
  rulesFile = join(root, 'helper-rules.json');
  approvalsDir = join(root, 'approvals');
  sys = new FakeSystem();
  executor = new Executor({
    sys,
    journal: new Journal(join(root, 'journal.json')),
    approvals: new Approvals({ dir: approvalsDir, requiredOwnerUid: process.getuid!() }),
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
  // Stands in for the password dialog: only a yes writes the root-owned approval.
  client = await HelperClient.connect(join(root, 'helper.sock'), async (nonce, prompt, also) => {
    prompts.push(prompt);
    if (approve) for (const n of [nonce, ...(also ?? [])]) Approvals.writeApproval(approvalsDir, n);
    return approve;
  });
});

afterAll(async () => {
  client.close();
  await server.close();
  rmSync(root, { recursive: true, force: true });
});

beforeEach(() => {
  sys.signals.length = 0;
  prompts.length = 0;
  approve = false;
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

/**
 * Hold a rule change, and come back once the helper has answered that it needs
 * the password: a fixed wait for that answer fails on a busy machine.
 */
async function holdNow(command: DetectionSync): Promise<{ result: Promise<unknown> }> {
  let result!: Promise<unknown>;
  await new Promise<void>((held, failed) => {
    result = client.hold(command, held);
    result.catch(failed);
  });
  return { result };
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
    approve = true;
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    expect(prompts).toEqual(['Vigil wants to loosen its blocking rules: add an exception to *.']);
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
    // What the last good copy had, still blocking while the new one is awaited.
    expect(fast.status().lists['known_bad_sha256']).toBe(1);
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
    bad.rules = [
      ...bad.rules,
      { ...bad.rules[0]!, id: 'broken', condition: { field: 'path', op: 'regex', value: '(' } },
    ];
    await expect(client.call(bad)).rejects.toMatchObject({ code: 'invalid' });
    expect(fast.status()).toEqual(before);
  });

  it('refuses a rule whose regex or glob could take too long, as the app does', async () => {
    const before = fast.status();
    const { sync } = appSet({});
    for (const condition of [
      { field: 'path', op: 'glob' as const, value: '**a**a**a**a**a**a!' },
      { field: 'path', op: 'glob' as const, value: '**a**a**a!' },
      { field: 'path', op: 'regex' as const, value: '(a|a)*$' },
      { field: 'path', op: 'regex' as const, value: '((a+))+$' },
      { field: 'path', op: 'regex' as const, value: '(?:x|x)+y' },
      // Not one Vigil ships, so it must run in linear time, which has no lookahead.
      { field: 'path', op: 'regex' as const, value: '/tmp/(?=x)' },
    ]) {
      const bad = { ...sync, rules: [...sync.rules, { ...sync.rules[0]!, id: 'slow', condition }] };
      await expect(client.call(bad), condition.value).rejects.toMatchObject({ code: 'invalid' });
      expect(fast.status()).toEqual(before);
    }
  });

  it('drops a saved rule that no longer compiles and keeps the rest', () => {
    const { sync } = appSet({});
    const slow = {
      ...sync.rules[0]!,
      id: 'slow',
      condition: { field: 'path', op: 'glob' as const, value: '**a**a**a!' },
    };
    const file = join(root, 'saved-with-slow-rule.json');
    writeFileSync(
      file,
      JSON.stringify({ ...sync, rev: 3, rules: [...sync.rules, slow], lists: {}, retired: {} }),
    );
    const logs: string[] = [];
    const loaded = new FastPath({
      file,
      run: () => Promise.reject(new Error('not used')),
      log: (m) => logs.push(m),
    });
    loaded.load();
    expect(loaded.status().rules).toBe(sync.rules.length);
    expect(logs.join('\n')).toMatch(/slow/);
  });

  it('keeps blocking with a saved rule whose pattern only the usual engine runs', async () => {
    const { sync } = appSet({});
    // Ran before rule patterns moved to the linear-time engine, which has no lookahead.
    const older = {
      ...sync.rules[0]!,
      id: 'older-look',
      condition: { field: 'process.path', op: 'regex' as const, value: '^/tmp/(?=p)payload$' },
    };
    const file = join(root, 'saved-with-older-pattern.json');
    // Written by an earlier release: no `legacy` field.
    writeFileSync(
      file,
      JSON.stringify({ ...sync, rev: 3, rules: [...sync.rules, older], lists: {}, retired: {} }),
    );
    const logs: string[] = [];
    const loaded = new FastPath({
      file,
      run: async () => ({ ok: true }) as unknown as ActionOutcome,
      log: (m) => logs.push(m),
    });
    loaded.load();
    expect(loaded.status().rules).toBe(sync.rules.length + 1);
    const ran = await loaded.check(exec(6100, 'c'.repeat(64)));
    expect(ran.map((r) => r.ruleId)).toContain('older-look');

    // The app syncs it back, marked as an older pattern: kept, and recorded.
    loaded.sync({ ...sync, rules: [...sync.rules, older], legacy: ['older-look'], lists: {} });
    expect(loaded.status().rules).toBe(sync.rules.length + 1);
    const saved = JSON.parse(readFileSync(file, 'utf8')) as { legacyUses: unknown };
    expect(saved.legacyUses).toEqual({
      'older-look': [{ field: 'process.path', nocase: false, pattern: '^/tmp/(?=p)payload$' }],
    });

    // One this helper never had is skipped when marked, refused when not.
    const fresh = { ...older, id: 'fresh-look' };
    loaded.sync({
      ...sync,
      rules: [...sync.rules, older, fresh],
      legacy: ['older-look', 'fresh-look'],
      lists: {},
    });
    expect(loaded.status().rules).toBe(sync.rules.length + 1);
    expect(logs.join('\n')).toMatch(/skipping rule with an older pattern: rule fresh-look/);
    expect(() => loaded.sync({ ...sync, rules: [...sync.rules, older, fresh], lists: {} })).toThrow(
      /fresh-look/,
    );

    // A file this release wrote adopts nothing it does not list.
    const other = { ...older, id: 'other-look' };
    const file2 = join(root, 'saved-by-this-release.json');
    writeFileSync(
      file2,
      JSON.stringify({
        ...sync,
        rules: [...sync.rules, other],
        lists: {},
        retired: {},
        legacyUses: {},
      }),
    );
    const again = new FastPath({ file: file2, run: () => Promise.reject(new Error('unused')) });
    again.load();
    expect(again.status().rules).toBe(sync.rules.length);
  });

  it('revokes an older pattern once its rule is removed, here and in the saved file', () => {
    const { sync } = appSet({});
    const older = {
      ...sync.rules[0]!,
      id: 'older-gone',
      condition: { field: 'process.path', op: 'regex' as const, value: '^/tmp/(?=q)payload$' },
    };
    const file = join(root, 'saved-then-removed.json');
    writeFileSync(
      file,
      JSON.stringify({ ...sync, rules: [...sync.rules, older], lists: {}, retired: {} }),
    );
    const helper = () =>
      new FastPath({ file, run: async () => ({ ok: true }) as unknown as ActionOutcome });
    const h = helper();
    h.load();
    expect(h.status().rules).toBe(sync.rules.length + 1);
    // Removed (the executor asks for the password first).
    h.sync({ ...sync, lists: {} });
    const saved = JSON.parse(readFileSync(file, 'utf8')) as { legacyUses: object };
    expect(saved.legacyUses).toEqual({});
    // The same id and text again, or with the case setting or field changed: not run.
    const variants = [
      older,
      { ...older, condition: { ...older.condition, nocase: true } },
      { ...older, condition: { ...older.condition, field: 'path' } },
    ];
    for (const again of variants) {
      h.sync({ ...sync, rules: [...sync.rules, again], legacy: ['older-gone'], lists: {} });
      expect(h.status().rules).toBe(sync.rules.length);
      expect(() => h.sync({ ...sync, rules: [...sync.rules, again], lists: {} })).toThrow(
        /older-gone/,
      );
    }
    // Nor after a restart.
    const later = helper();
    later.load();
    later.sync({ ...sync, rules: [...sync.rules, older], legacy: ['older-gone'], lists: {} });
    expect(later.status().rules).toBe(sync.rules.length);
  });

  it('needs the admin password to turn a rule off, change it or add a path', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    approve = false;
    const rev = fast.status().rev;
    const [first, ...rest] = sync.rules;

    // Anything on the user's account can send these; without the password nothing changes.
    const weaker: DetectionSync[] = [
      { ...sync, rules: rest },
      {
        ...sync,
        rules: [{ ...first!, exclusions: [{ field: 'process.path', op: 'exists' }] }, ...rest],
      },
      { ...sync, selfPaths: [...sync.selfPaths, '/tmp'] },
    ];
    for (const cmd of weaker)
      await expect(client.call(cmd)).rejects.toMatchObject({ code: 'refused' });
    expect(prompts).toEqual([
      `Vigil wants to loosen its blocking rules: stop blocking with “${first!.name}”.`,
      `Vigil wants to loosen its blocking rules: change what “${first!.name}” blocks.`,
      'Vigil wants to loosen its blocking rules: never block /tmp.',
    ]);
    expect(fast.status().rev).toBe(rev);
    sys.processes.set(7000, { path: '/tmp/payload', started: 'T' });
    expect((await fast.check(exec(7000, BAD))).length).toBeGreaterThan(0);

    // Wording-only edits and the same rules again need no password.
    prompts.length = 0;
    await client.call({
      ...sync,
      rules: [{ ...first!, name: 'Renamed', reasons: ['Reworded reason'] }, ...rest],
    });
    await client.call(sync);
    expect(prompts).toEqual([]);

    // With the password, it goes through.
    approve = true;
    await client.call({ ...sync, rules: rest });
    expect(fast.status().rules).toBe(rest.length);
    expect(fast.status().rev).toBeGreaterThan(rev);
    await client.call(sync);
  });

  it('lets a held rule change ride on the next password dialog', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    prompts.length = 0;
    const exception = {
      id: 'x9',
      ruleId: 'known-bad-hash',
      match: { 'process.path': '/tmp/ok' },
      createdAt: 2,
    };
    const { result: syncing } = await holdNow({ ...sync, exceptions: [exception] });
    // A release (here: removing a Santa rule) asks for the password, for both at once.
    await client.call({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: BAD,
      policy: 'block',
    });
    await client.call({ kind: 'santa.rule.remove', ruleType: 'binary', identifier: BAD });
    expect(prompts).toHaveLength(1);
    expect(prompts[0]).toContain('add an exception to known-bad-hash');
    await client.approveHeld();
    await syncing;
    expect(prompts).toHaveLength(1);
    expect(fast.status().rules).toBeGreaterThan(0);

    // Nothing else asks: approveHeld asks once for what is still waiting, and a no settles it as refused.
    approve = false;
    const { result: refused } = await holdNow({
      ...sync,
      exceptions: [],
      selfPaths: [...sync.selfPaths, '/tmp'],
    });
    await client.approveHeld();
    await expect(refused).rejects.toMatchObject({ code: 'refused' });
    expect(prompts).toHaveLength(2);
  });

  it('refuses a held rule change when the dialog it rode on gets a no', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    await client.call({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: BAD,
      policy: 'block',
    });
    prompts.length = 0;
    approve = false;
    const { result: syncing } = await holdNow({ ...sync, selfPaths: [...sync.selfPaths, '/tmp'] });
    await expect(
      client.call({ kind: 'santa.rule.remove', ruleType: 'binary', identifier: BAD }),
    ).rejects.toMatchObject({ code: 'refused' });
    await expect(syncing).rejects.toMatchObject({ code: 'refused' });
    // Nothing is left to ask about.
    await client.approveHeld();
    expect(prompts).toHaveLength(1);
  });

  it('drops held rule changes without asking', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    prompts.length = 0;
    const { result: syncing } = await holdNow({ ...sync, selfPaths: [...sync.selfPaths, '/tmp'] });
    client.dropHeld();
    await expect(syncing).rejects.toMatchObject({ code: 'refused' });
    await client.approveHeld();
    expect(prompts).toHaveLength(0);
  });

  it('keeps an entry a list drops blocking for a week', async () => {
    const OTHER = 'a'.repeat(64);
    const { sync, lists } = appSet({ known_bad_sha256: [BAD, OTHER] });
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    // A list update without BAD, as anything on the user's account could send.
    await sendLists(['known_bad_sha256'], { known_bad_sha256: [OTHER] });
    expect(fast.status().lists['known_bad_sha256']).toBe(1);
    sys.processes.set(7100, { path: '/tmp/payload', started: 'T' });
    expect((await fast.check(exec(7100, BAD))).length).toBeGreaterThan(0);
    // Dropping the list from the sync altogether doesn't help either.
    const { known_bad_sha256: _gone, ...others } = sync.lists;
    await client.call({ ...sync, lists: others });
    sys.processes.set(7101, { path: '/tmp/payload', started: 'T' });
    expect((await fast.check(exec(7101, OTHER))).length).toBeGreaterThan(0);
    // It survives a restart.
    const again = makeFastPath(executor);
    again.load();
    sys.processes.set(7102, { path: '/tmp/payload', started: 'T' });
    expect((await again.check(exec(7102, BAD))).length).toBeGreaterThan(0);

    // A week later the feed's removal takes effect.
    clock += RETIRE_MS;
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, {
      known_bad_sha256: [OTHER],
    });
    expect(fast.status().retired).toBe(0);
    sys.processes.set(7103, { path: '/tmp/payload', started: 'T' });
    expect(await fast.check(exec(7103, BAD))).toEqual([]);
  });

  it('refuses a list that would drop more than it may in a week', async () => {
    const many = Array.from({ length: RETIRED_TEST_MAX + 1 }, (_, i) =>
      i.toString(16).padStart(64, '0'),
    );
    const { sync, lists } = appSet({ known_bad_sha256: many });
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    await expect(
      sendLists(['known_bad_sha256'], { known_bad_sha256: [BAD] }),
    ).rejects.toMatchObject({
      code: 'refused',
    });
    expect(fast.status().lists['known_bad_sha256']).toBe(RETIRED_TEST_MAX + 1);
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
