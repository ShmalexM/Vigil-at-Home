import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DetectionEngine, macosCoreRules, memoryStores } from '@vigil/detection';
import { fastPathRules, listDigest } from '@vigil/detection/fastpath';
import { RuleStore, type SensorEvent } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { HelperClient } from './client.js';
import { Executor, type ActionOutcome } from './executor.js';
import { FastPath, PolicyRefused, RETIRE_MS, type HelperRan } from './fastpath.js';
import { Journal } from './journal.js';
import { LIST_PART_MAX, type DetectionSync, type SelfGrant } from './protocol.js';
import { HelperServer } from './server.js';
import { transferLimits } from './commands/transfer.js';
import { FakeSystem } from './testing/fakeSystem.js';

const BAD = 'b'.repeat(64);
const SELF = '/Applications/Vigil at Home.app';

let root: string;
let sys: FakeSystem;
let fast: FastPath;
let server: HelperServer;
let client: HelperClient;
let rulesFile: string;

/** Files on the fake disk, by path, with their device:inode. */
const files = new Map<string, string>();

// Small enough that the oversized-drop test stays fast on a busy runner.
const RETIRED_TEST_MAX = 5000;

function makeFastPath(executor: Executor): FastPath {
  return new FastPath({
    file: rulesFile,
    now: () => clock,
    retiredMax: RETIRED_TEST_MAX,
    fileId: (p) => files.get(p),
    installed: [SELF],
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
  const sync: DetectionSync & { selfPaths: string[] } = {
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

describe('the socket', () => {
  it('refuses a request to remove the pin as a command it does not have', async () => {
    await expect(
      client.call({ kind: 'pin-remove' } as unknown as Parameters<HelperClient['call']>[0]),
    ).rejects.toMatchObject({ code: 'invalid' });
  });
});

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

  it('asks for the password for anything newly named as Vigil, even inside its folder', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await sendLists(
      (await client.call<{ needLists: string[] }>({ ...sync, selfPaths: ['/opt/Vigil at Home'] }))
        .needLists,
      lists,
    );
    approve = false;
    prompts.length = 0;
    // The same folder again needs nothing.
    await client.call({ ...sync, selfPaths: ['/opt/Vigil at Home/'] });
    expect(prompts).toEqual([]);
    // A program inside it would be exempt from every block, so it is a widening.
    await expect(
      client.call({ ...sync, selfPaths: ['/opt/Vigil at Home', '/opt/Vigil at Home/payload'] }),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(prompts).toEqual([
      'Vigil wants to loosen its blocking rules: never block /opt/Vigil at Home/payload.',
    ]);
    sys.processes.set(7001, { path: '/tmp/payload', started: 'T' });
    expect((await fast.check(exec(7001, BAD))).length).toBeGreaterThan(0);

    // An old install that was sent `/` doesn't let anything else in for free.
    approve = true;
    await client.call({ ...sync, selfPaths: ['/'] });
    approve = false;
    await expect(
      client.call({ ...sync, selfPaths: ['/', '/home/alex/payload'] }),
    ).rejects.toMatchObject({ code: 'refused' });
  });

  it('approves an AppImage by identity, so a rename while it runs asks nothing', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    const own = 'c'.repeat(64);
    const image = { path: '/home/alex/Apps/Vigil.AppImage', id: '2049:5501' };
    files.set(image.path, image.id);
    approve = true;
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    prompts.length = 0;
    await client.call({ ...sync, selfImages: [image], selfHashes: [own] });
    expect(prompts).toEqual([
      'Vigil wants to loosen its blocking rules: never block /home/alex/Apps/Vigil.AppImage; never block 1 of Vigil’s programs by hash.',
    ]);
    expect(fast.self()).toMatchObject({ images: [image.id], hashes: [own] });
    approve = false;
    prompts.length = 0;

    // Renamed while running: the app still names the old path, the id matches.
    files.delete(image.path);
    files.set('/home/alex/Vigil-old.AppImage', image.id);
    await client.call({ ...sync, selfImages: [image], selfHashes: [own] });
    expect(prompts).toEqual([]);

    // A new image needs the password, and must be the file the prompt names.
    approve = true;
    await expect(
      client.call({
        ...sync,
        selfImages: [image, { path: '/home/alex/Apps/Vigil.AppImage', id: '2049:9999' }],
      }),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(fast.self().images).toEqual([image.id]);
    // A program hash Vigil didn't name before is a widening too.
    approve = false;
    await expect(
      client.call({ ...sync, selfImages: [image], selfHashes: [own, 'd'.repeat(64)] }),
    ).rejects.toMatchObject({ code: 'refused' });

    // No block rule may name one of Vigil's own programs.
    await expect(
      client.call({ kind: 'santa.rule.set', ruleType: 'binary', identifier: own, policy: 'block' }),
    ).rejects.toMatchObject({ code: 'refused' });
    files.clear();
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

describe('what a sync may grant without the password', () => {
  let n = 0;
  const image = { path: '/home/alex/Apps/Vigil.AppImage', id: '2049:5501' };
  const disk = new Map([[image.path, image.id]]);
  /** A helper of its own, on its own file; `fresh` leaves the file absent. */
  function helper(file = join(root, `own-${n++}.json`)) {
    const fp = new FastPath({
      file,
      run: () => Promise.reject(new Error('not in these tests')),
      fileId: (p) => disk.get(p),
      installed: [SELF],
    });
    fp.load();
    return { fp, file };
  }
  const bare = (over: Partial<DetectionSync> = {}): DetectionSync => ({
    kind: 'detection.sync',
    rules: [],
    exceptions: [],
    selfPaths: [],
    lists: {},
    ...over,
  });
  const exception = { id: 'x', ruleId: '*', match: { 'process.path': '/tmp/x' }, createdAt: 1 };

  it('lets only the first sync ever name the installed app, and nothing more', () => {
    const { fp, file } = helper();
    expect(fp.loosening(bare({ selfPaths: [SELF] }))).toEqual([]);
    // Even the first sync asks for anything the installer didn't put there.
    expect(fp.loosening(bare({ selfPaths: [SELF, '/tmp'] }))).toEqual(['never block /tmp']);
    expect(fp.loosening(bare({ selfImages: [image] }))).toEqual([`never block ${image.path}`]);
    expect(fp.loosening(bare({ selfHashes: ['c'.repeat(64)] }))).toEqual([
      'never block 1 of Vigil’s programs by hash',
    ]);
    expect(fp.loosening(bare({ exceptions: [exception] }))).toEqual(['add an exception to *']);

    // Once anything was saved, even a policy with no rules, the grace is over.
    fp.sync(bare());
    expect(fp.loosening(bare({ selfPaths: [SELF] }))).toEqual([`never block ${SELF}`]);
    // And it stays over across a restart.
    expect(helper(file).fp.loosening(bare({ selfPaths: [SELF] }))).toEqual([`never block ${SELF}`]);
  });

  it('asks before weakening a policy that has no block rules yet', () => {
    const { fp } = helper();
    fp.sync(bare({ selfPaths: [SELF] }));
    expect(fp.status().rules).toBe(0);
    expect(fp.loosening(bare({ selfPaths: [SELF], exceptions: [exception] }))).toEqual([
      'add an exception to *',
    ]);
    expect(fp.loosening(bare({ selfPaths: [SELF, '/home/alex/payload'] }))).toEqual([
      'never block /home/alex/payload',
    ]);
    expect(fp.loosening(bare({ selfPaths: [SELF], selfImages: [image] }))).toEqual([
      `never block ${image.path}`,
    ]);
    // Adding or keeping what is there asks nothing.
    expect(fp.loosening(bare({ selfPaths: [SELF] }))).toEqual([]);
    expect(fp.loosening(bare())).toEqual([]);
  });

  it('refuses an AppImage that is not the file at its path before asking', () => {
    const { fp } = helper();
    expect(() =>
      fp.loosening(bare({ selfImages: [{ path: image.path, id: '2049:9999' }] })),
    ).toThrow(PolicyRefused);
  });

  it('never trusts an approved AppImage by its path', () => {
    const { fp } = helper();
    // An app that still names the image among its paths, as earlier versions did.
    fp.sync(bare({ selfPaths: [SELF, image.path], selfImages: [image] }));
    expect(fp.self()).toEqual({ paths: [SELF], images: [image.id], hashes: [] });
    // Naming it there again is no new grant.
    expect(fp.loosening(bare({ selfPaths: [SELF, image.path], selfImages: [image] }))).toEqual([]);
  });
});

describe('Vigil’s own programs, granted apart from the rules', () => {
  const DOWNLOADS = '/Users/alex/Downloads/Vigil at Home.app';
  const app = (root: string) => `${root}/Contents/MacOS/Vigil at Home`;
  let shared: FastPath;
  let n = 0;
  beforeEach(() => {
    shared = fast;
    rulesFile = join(root, `grant-${n++}.json`);
    fast = makeFastPath(executor);
    fast.load();
  });
  afterEach(() => {
    fast = shared;
  });
  const rulesOnly = () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    const { selfPaths: _, ...rest } = sync;
    return { sync: rest as DetectionSync, lists };
  };
  const grant = (selfPaths: string[], more: Partial<SelfGrant> = {}): SelfGrant => ({
    kind: 'self.grant',
    selfPaths,
    ...more,
  });

  it('takes the rules with no self set and keeps the one granted', async () => {
    const { sync, lists } = rulesOnly();
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    expect(prompts).toEqual([]);
    expect(fast.self().paths).toEqual([]);
    await client.call(grant([SELF]));
    expect(fast.self().paths).toEqual([SELF]);
    // Rules again, without a self set: the grant stays.
    await client.call(sync);
    expect(fast.self().paths).toEqual([SELF]);
    expect(prompts).toEqual([]);
  });

  it('names the installed app without the password until the first grant, rules or not', async () => {
    // The rules may reach the helper first: that doesn't end the grace.
    await client.call(rulesOnly().sync);
    await client.call(grant([SELF]));
    expect(prompts).toEqual([]);
    // Dropping it asks nothing; naming it again now does.
    await client.call(grant([]));
    await expect(client.call(grant([SELF]))).rejects.toMatchObject({ code: 'refused' });
    expect(prompts).toEqual([
      `Vigil wants to keep its blocking rules off its own programs: never block ${SELF}.`,
    ]);
    // And it stays over across a restart.
    const again = makeFastPath(executor);
    again.load();
    expect(again.selfLoosening(grant([SELF]))).toEqual([`never block ${SELF}`]);
  });

  it('asks for the password for anything else, even in the first grant', async () => {
    const image = { path: '/home/alex/Apps/Vigil.AppImage', id: '2049:5501' };
    files.set(image.path, image.id);
    const own = 'c'.repeat(64);
    expect(fast.selfLoosening(grant([SELF, DOWNLOADS]))).toEqual([`never block ${DOWNLOADS}`]);
    expect(fast.selfLoosening(grant([], { selfImages: [image], selfHashes: [own] }))).toEqual([
      `never block ${image.path}`,
      'never block 1 of Vigil’s programs by hash',
    ]);
    // An AppImage that isn't the file at its path is refused before anyone is asked.
    await expect(
      client.call(grant([], { selfImages: [{ path: image.path, id: '2049:9999' }] })),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(prompts).toEqual([]);
    // A no changes nothing, and the next ask is a new dialog.
    await expect(client.call(grant([SELF, DOWNLOADS]))).rejects.toMatchObject({ code: 'refused' });
    expect(fast.self().paths).toEqual([]);
    approve = true;
    await client.call(grant([SELF, DOWNLOADS], { selfImages: [image], selfHashes: [own] }));
    expect(fast.self()).toEqual({ paths: [SELF, DOWNLOADS], images: [image.id], hashes: [own] });
    expect(prompts).toHaveLength(2);
    files.clear();
  });

  it('leaves the rules in force when the grant is declined', async () => {
    const { sync, lists } = rulesOnly();
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    await expect(client.call(grant([DOWNLOADS]))).rejects.toMatchObject({ code: 'refused' });
    expect(fast.status().rules).toBe(sync.rules.length);
    sys.processes.set(8000, { path: '/tmp/payload', started: 'T' });
    expect((await fast.check(exec(8000, BAD))).length).toBeGreaterThan(0);
    expect(sys.signals).toEqual([{ pid: 8000, signal: 'SIGKILL' }]);
  });

  it('protects only what was granted and the installed app while a grant waits', async () => {
    const { sync, lists } = rulesOnly();
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    // The installer's folder is protected whatever was granted.
    sys.processes.set(8100, { path: app(SELF), started: 'T' });
    const kill = (await fast.check(exec(8100, BAD, app(SELF)))).find(
      (r) => r.action.kind === 'process.kill',
    );
    expect(kill?.error).toMatch(/part of macOS or Vigil/);
    expect(sys.signals).toEqual([]);
    // A request nobody approved protects nothing: anything on the socket can
    // name its own program as Vigil.
    await expect(client.call(grant([DOWNLOADS]))).rejects.toMatchObject({ code: 'refused' });
    sys.processes.set(8101, { path: app(DOWNLOADS), started: 'T' });
    await fast.check(exec(8101, BAD, app(DOWNLOADS)));
    expect(sys.signals).toEqual([{ pid: 8101, signal: 'SIGKILL' }]);
    // Once approved, it is.
    approve = true;
    await client.call(grant([DOWNLOADS]));
    sys.signals.length = 0;
    sys.processes.set(8102, { path: app(DOWNLOADS), started: 'T' });
    expect(await fast.check(exec(8102, BAD, app(DOWNLOADS)))).toEqual([]);
    expect(sys.signals).toEqual([]);
  });

  it('still takes an older app’s rules and self set together, asking as before', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    // The first sync naming the installed app needs nothing.
    await sendLists((await client.call<{ needLists: string[] }>(sync)).needLists, lists);
    expect(prompts).toEqual([]);
    expect(fast.self().paths).toEqual([SELF]);
    // The same set again needs nothing; a new path asks.
    await client.call(sync);
    await expect(client.call({ ...sync, selfPaths: [SELF, DOWNLOADS] })).rejects.toMatchObject({
      code: 'refused',
    });
    expect(prompts).toEqual([
      `Vigil wants to loosen its blocking rules: never block ${DOWNLOADS}.`,
    ]);
    // A sync that carries a self set ended the grace, as a grant does.
    expect(fast.selfLoosening(grant([]))).toEqual([]);
    await client.call({ ...sync, selfPaths: [] });
    expect(fast.selfLoosening(grant([SELF]))).toEqual([`never block ${SELF}`]);
  });
});

describe('a move that stalls', () => {
  const saved = { ...transferLimits };
  let dir: string;
  let stopped: { kill(sig: NodeJS.Signals): boolean }[];
  afterEach(() => {
    Object.assign(transferLimits, saved);
    for (const c of stopped) c.kill('SIGKILL');
    rmSync(dir, { recursive: true, force: true });
  });

  /** The known-malware rule, with a move listed before the kill and the block; every move's reader stopped. */
  function setup(moveWaitMs?: number) {
    dir = mkdtempSync(join(tmpdir(), 'vigil-fastpath-move-'));
    stopped = [];
    const fake = new FakeSystem();
    const rules = new RuleStore(join(dir, 'rules.json'));
    const ex = new Executor({
      sys: fake,
      journal: new Journal(join(dir, 'journal.json')),
      approvals: new Approvals({
        dir: join(dir, 'approvals'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules,
      quarantine: { quarantineDir: join(dir, 'Quarantine'), protectedPrefixes: [] },
      syncPort: 47821,
    });
    const { sync } = appSet({});
    const known = sync.rules.find((r) => r.id === 'known-bad-hash')!;
    const withMove = {
      ...known,
      response: [{ kind: 'file.quarantine' as const, path: '{{process.path}}' }, ...known.response],
    };
    const file = join(dir, 'helper-rules.json');
    writeFileSync(
      file,
      JSON.stringify({
        ...sync,
        rules: [withMove],
        lists: { known_bad_sha256: [BAD] },
        retired: {},
      }),
    );
    const fp = new FastPath({
      file,
      ...(moveWaitMs !== undefined ? { moveWaitMs } : {}),
      run: async (action) => {
        const out = await ex.execute(action);
        if (out.kind !== 'done') throw new Error('needs the admin password');
        return out.result as ActionOutcome;
      },
    });
    fp.load();
    // Each move is given up after a while.
    transferLimits.deadlineMs = 2_000;
    transferLimits.graceMs = 200;
    transferLimits.onSpawn = (c, op) => {
      if (op === 'pack') {
        c.kill('SIGSTOP');
        stopped.push(c);
      }
    };
    const payload = (pid: number) => {
      const path = join(dir, `payload-${pid}`);
      writeFileSync(path, 'bad');
      fake.processes.set(pid, { path, started: 'T' });
      return path;
    };
    const blocked = () =>
      rules.active().some((r) => r.rule.identifier === BAD && r.rule.policy === 'BLOCKLIST');
    return { fp, fake, payload, blocked };
  }

  it('blocks before any move, and reports a move it stopped waiting on', async () => {
    const { fp, fake, payload, blocked } = setup(300);
    const first = payload(5001);
    const second = payload(5002);
    const t0 = Date.now();
    const ran = await fp.check(exec(5001, BAD, first));
    expect(ran.map((r) => r.action.kind)).toEqual([
      'process.kill',
      'santa.rule.set',
      'file.quarantine',
    ]);
    expect(ran[2]).toMatchObject({ errorCode: 'move-stalled' });
    expect(fake.signals).toEqual([{ pid: 5001, signal: 'SIGKILL' }]);
    expect(blocked()).toBe(true);
    const ran2 = await fp.check(exec(5002, BAD, second));
    expect(Date.now() - t0).toBeLessThan(1_800);
    expect(ran2[0]).toMatchObject({ action: { kind: 'process.kill' }, outcome: expect.anything() });
    // Once the stopped moves are given up, the files are where they were and the block is in force.
    await new Promise((r) => setTimeout(r, 3_000));
    expect(existsSync(first) && existsSync(second)).toBe(true);
    expect(blocked()).toBe(true);
  }, 15_000);

  it('never delays a later event’s block, on the daemon’s one-at-a-time chain', async () => {
    // The real wait on a move (15 s): only the event's report waits on it, never the chain.
    const { fp, fake, payload, blocked } = setup();
    const first = payload(6001);
    const second = payload(6002);
    let chain = Promise.resolve();
    const reported: string[] = [];
    const deliver = (pid: number, path: string) => {
      chain = chain.then(async () => {
        const { moves } = await fp.start(exec(pid, BAD, path));
        void moves.then(() => reported.push(path));
      });
    };
    deliver(6001, first);
    // Event A's kill and block are done, and its move's reader is stopped.
    await chain;
    while (stopped.length < 1) await new Promise((r) => setTimeout(r, 5));
    expect(fake.signals).toEqual([{ pid: 6001, signal: 'SIGKILL' }]);
    const t0 = Date.now();
    deliver(6002, second);
    await chain;
    expect(Date.now() - t0).toBeLessThan(500);
    expect(fake.signals).toEqual([
      { pid: 6001, signal: 'SIGKILL' },
      { pid: 6002, signal: 'SIGKILL' },
    ]);
    expect(blocked()).toBe(true);
    expect(reported).toEqual([]);
    // The stopped moves end at their deadline; each event is reported then, the block in force.
    while (reported.length < 2) await new Promise((r) => setTimeout(r, 50));
    expect(existsSync(first) && existsSync(second)).toBe(true);
    expect(blocked()).toBe(true);
  }, 15_000);
});
