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
/** Runs while the fake password dialog is open, before its answer. */
let whilePrompting: (() => Promise<void>) | undefined;
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
    now: () => clock,
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
    await whilePrompting?.();
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
  whilePrompting = undefined;
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

/** Send a sync with the contents of every list it names, as the app does: one step. */
async function syncWith<T = { applied: boolean; needLists: string[] }>(
  sync: DetectionSync,
  lists: Record<string, string[]>,
): Promise<T> {
  const entries = Object.fromEntries(Object.keys(sync.lists).map((n) => [n, lists[n] ?? []]));
  return client.call<T>({ ...sync, entries });
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
    // Without the lists' contents nothing changes, and the helper says which it lacks.
    const first = await client.call<{ applied: boolean; needLists: string[] }>(sync);
    expect(first.applied).toBe(false);
    expect(first.needLists.sort()).toEqual([
      'known_bad_ips',
      'known_bad_sha256',
      'user_blocked_sha256',
    ]);
    expect(fast.status().rules).toBe(0);
    // Rules and lists together go in as one.
    expect(await syncWith(sync, lists)).toMatchObject({ applied: true, needLists: [] });
    expect(fast.status().lists['known_bad_sha256']).toBe(2501);
    expect(fast.status().rules).toBe(sync.rules.length);
    // Same lists again: nothing to send.
    expect(await client.call(sync)).toMatchObject({ applied: true, needLists: [] });

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
    await syncWith(sync, lists);
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
    await syncWith(sync, lists);
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

  it('answers once the rules are saved and reports Santa’s hand-off on its own', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    const out = await syncWith({ ...sync, syncId: 'sync-1' }, lists);
    expect(out).toMatchObject({ applied: true });
    const status = await client.call<{ syncId: string | null; rev: number }>({
      kind: 'detection.status',
    });
    expect(status).toMatchObject({ syncId: 'sync-1', rules: sync.rules.length });
    // A second client sees the same, and a stray list update changes no rules.
    await sendLists(['known_bad_sha256'], { known_bad_sha256: [BAD, 'c'.repeat(64)] });
    expect(fast.rules().map((r) => r.id)).toEqual(sync.rules.map((r) => r.id));
    expect(fast.syncId()).toBe('sync-1');
    // Survives a restart.
    const again = makeFastPath(executor);
    again.load();
    expect(again.syncId()).toBe('sync-1');
  });

  it('does not wait on Santa’s pre-launch rules before answering', async () => {
    let finish: (v: unknown) => void = () => {};
    const slowSanta = { apply: () => new Promise((r) => (finish = r)) };
    const own = new Executor({
      sys,
      journal: new Journal(join(root, 'journal-preexec.json')),
      approvals: new Approvals({ dir: approvalsDir, requiredOwnerUid: process.getuid!() }),
      rules: new RuleStore(join(root, 'rules-preexec.json')),
      quarantine: { quarantineDir: join(root, 'Quarantine') },
      syncPort: 47821,
      preexec: slowSanta as never,
      fastPath: new FastPath({
        file: join(root, 'preexec-rules.json'),
        run: async () => ({}) as never,
      }),
    });
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    const entries = Object.fromEntries(Object.keys(sync.lists).map((n) => [n, lists[n] ?? []]));
    const out = await own.execute({ ...sync, entries, syncId: 'with-santa' });
    // Answered with the rules saved, while Santa is still busy.
    expect(out).toMatchObject({ kind: 'done', result: { applied: true, preexec: 'pending' } });
    expect(await own.execute({ kind: 'detection.status' })).toMatchObject({
      kind: 'done',
      result: { syncId: 'with-santa', preexec: 'pending' },
    });
    finish({ installed: 1 });
    expect(await own.preexecSettled()).toEqual({ installed: 1 });
    expect(await own.execute({ kind: 'detection.status' })).toMatchObject({
      result: { preexec: { installed: 1 } },
    });
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
    await syncWith(sync, lists);
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

  it('answers detection.status only once a sync read before it is in force', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await syncWith({ ...sync, syncId: 'order-0' }, lists);
    approve = false;
    // Sent back to back on one connection, as the app does after a timeout.
    const synced = client.call({ ...sync, syncId: 'order-1' });
    const status = client.call<{ syncId: string | null }>({ kind: 'detection.status' });
    expect(await status).toMatchObject({ syncId: 'order-1' });
    await synced;
    // Handed to the helper one after the other: nothing waits between the
    // sync's checks and its save, so status can't slip in before it.
    const direct = executor.execute({ ...sync, syncId: 'order-2' });
    const after = executor.execute({ kind: 'detection.status' });
    expect(await after).toMatchObject({ kind: 'done', result: { syncId: 'order-2' } });
    await direct;
  });

  it('keeps the old sync in force while the password is asked, and after a no', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await syncWith({ ...sync, syncId: 'pw-0' }, lists);
    approve = false;
    const [, ...rest] = sync.rules;
    const other = await HelperClient.connect(join(root, 'helper.sock'), async () => false);
    const seen: unknown[] = [];
    whilePrompting = async () => {
      seen.push(await other.call({ kind: 'detection.status' }));
    };
    await expect(client.call({ ...sync, rules: rest, syncId: 'pw-1' })).rejects.toMatchObject({
      code: 'refused',
    });
    expect(seen).toMatchObject([{ syncId: 'pw-0' }]);
    expect(await other.call({ kind: 'detection.status' })).toMatchObject({ syncId: 'pw-0' });
    expect(fast.status().rules).toBe(sync.rules.length);
    other.close();
  });

  it('refuses a sync whose password came after the app stopped waiting', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await syncWith({ ...sync, syncId: 'late-0' }, lists);
    const [, ...rest] = sync.rules;
    const rev = fast.status().rev;
    // The user types the password, but only after the app gave up and
    // counted the change as cancelled.
    whilePrompting = async () => {
      clock += 60_000;
    };
    const late = { ...sync, rules: rest, syncId: 'late-1', notAfter: clock + 1000 };
    await expect(client.call(late)).rejects.toMatchObject({
      code: 'refused',
      message: 'the app stopped waiting for this change',
    });
    expect(prompts).toHaveLength(1);
    expect(fast.status()).toMatchObject({ rev, rules: sync.rules.length });
    expect(fast.syncId()).toBe('late-0');
    // Once past it, the helper doesn't even ask.
    prompts.length = 0;
    await expect(client.call({ ...late, syncId: 'late-2' })).rejects.toMatchObject({
      code: 'refused',
    });
    expect(prompts).toEqual([]);

    // A yes in time goes through.
    whilePrompting = undefined;
    const inTime = { ...sync, rules: rest, syncId: 'late-3', notAfter: clock + 1000 };
    await client.call(inTime);
    expect(fast.syncId()).toBe('late-3');
    expect(fast.status().rules).toBe(rest.length);
    await client.call({ ...sync, syncId: 'late-4' });
  });

  it('needs the admin password to turn down or loosen a blocking rule only the app runs', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    const appRule = {
      id: 'exec-from-shared-temp',
      name: 'New program started from a temporary folder',
      digest: 'a'.repeat(64),
    };
    approve = true;
    await syncWith({ ...sync, appRules: [appRule] }, lists);
    approve = false;
    prompts.length = 0;
    const rev = fast.status().rev;

    // The helper never runs it, yet turning it down or excluding from it still asks.
    for (const cmd of [
      { ...sync, appRules: [] },
      { ...sync },
      { ...sync, appRules: [{ ...appRule, digest: 'c'.repeat(64) }] },
    ])
      await expect(client.call(cmd)).rejects.toMatchObject({ code: 'refused' });
    expect(prompts).toEqual([
      `Vigil wants to loosen its blocking rules: stop blocking with “${appRule.name}”.`,
      `Vigil wants to loosen its blocking rules: stop blocking with “${appRule.name}”.`,
      `Vigil wants to loosen its blocking rules: change what “${appRule.name}” blocks.`,
    ]);
    expect(fast.status().rev).toBe(rev);

    // Renaming it or adding another blocking rule asks nothing.
    prompts.length = 0;
    const more = { id: 'my-rule', name: 'Mine', digest: 'd'.repeat(64) };
    await client.call({ ...sync, appRules: [{ ...appRule, name: 'Renamed' }, more] });
    expect(prompts).toEqual([]);

    // With the password, it goes through.
    approve = true;
    await client.call({ ...sync, appRules: [] });
    approve = false;
    prompts.length = 0;
    await client.call(sync);
    expect(prompts).toEqual([]);
  });

  it('lets a held rule change ride on the next password dialog', async () => {
    const { sync, lists } = appSet({ known_bad_sha256: [BAD] });
    approve = true;
    await syncWith(sync, lists);
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
    await syncWith(sync, lists);
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
    await syncWith(sync, lists);
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
    await syncWith(sync, lists);
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
    await syncWith(sync, lists);
    await expect(
      sendLists(['known_bad_sha256'], { known_bad_sha256: [BAD] }),
    ).rejects.toMatchObject({
      code: 'refused',
    });
    expect(fast.status().lists['known_bad_sha256']).toBe(RETIRED_TEST_MAX + 1);
  });

  it('takes rules and lists in one step, all or nothing', async () => {
    const many = Array.from({ length: RETIRED_TEST_MAX + 1 }, (_, i) =>
      i.toString(16).padStart(64, '0'),
    );
    const { sync, lists } = appSet({ known_bad_sha256: many });
    approve = true;
    await syncWith(sync, lists);
    const before = fast.status();
    const [, ...rest] = sync.rules;
    // Drops a rule (password given) and carries a list the helper will refuse.
    const next = {
      ...sync,
      rules: rest,
      lists: { ...sync.lists, known_bad_sha256: listDigest([BAD]) },
    };
    await expect(syncWith(next, { ...lists, known_bad_sha256: [BAD] })).rejects.toMatchObject({
      code: 'refused',
    });
    // Nothing of it is in force: the rule it dropped still blocks, the list is as it was.
    expect(fast.status()).toEqual(before);
    expect(fast.rules().map((r) => r.id)).toEqual(sync.rules.map((r) => r.id));
    // A list that doesn't match its digest is refused the same way.
    await expect(
      client.call({ ...next, entries: { known_bad_sha256: ['f'.repeat(64)] } }),
    ).rejects.toMatchObject({ code: 'invalid' });
    expect(fast.status()).toEqual(before);

    // The same change with an acceptable list goes in whole.
    const grown = [...many, BAD];
    const ok = { ...next, lists: { ...sync.lists, known_bad_sha256: listDigest(grown) } };
    expect(await syncWith(ok, { ...lists, known_bad_sha256: grown })).toMatchObject({
      applied: true,
    });
    expect(fast.status().rules).toBe(rest.length);
    expect(fast.status().lists['known_bad_sha256']).toBe(grown.length);
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

describe('one sync carrying big lists', () => {
  it('takes a detection.sync over the usual line limit, and nothing else that long', async () => {
    // Keeps what earlier tests left on the list, so nothing has to drop.
    const kept = Array.from({ length: RETIRED_TEST_MAX + 1 }, (_, i) =>
      i.toString(16).padStart(64, '0'),
    );
    const big = [
      ...kept,
      BAD,
      ...Array.from({ length: 20_000 }, (_, i) => i.toString(16).padStart(64, 'b')),
    ];
    const { sync, lists } = appSet({ known_bad_sha256: big });
    expect(JSON.stringify({ ...sync, entries: lists }).length).toBeGreaterThan(1024 * 1024);
    expect(await syncWith(sync, lists)).toMatchObject({ applied: true });
    expect(fast.status().lists['known_bad_sha256']).toBe(new Set(big).size);
    // Any other command that long is cut off.
    const other = await HelperClient.connect(join(root, 'helper.sock'), async () => false);
    const huge = { kind: 'helper.journal', limit: 1, pad: 'x'.repeat(2 * 1024 * 1024) };
    await expect(other.call(huge as never)).rejects.toMatchObject({ code: 'failed' });
  });
});
