import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DetectionEngine, macosCoreRules, memoryStores } from '@vigil/detection';
import { fastPathRules, listDigest } from '@vigil/detection/fastpath';
import { RuleStore, SantaSyncServer } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { ownProgramRoots } from './config.js';
import { Executor } from './executor.js';
import { FastPath } from './fastpath.js';
import type { ActionOutcome } from './executor.js';
import { Journal } from './journal.js';
import { OwnHashes } from './ownHashes.js';
import type { DetectionSync } from './protocol.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { machO } from './testing/machO.js';

const ownerUid = process.getuid!();
const sha = (data: string | Buffer) => createHash('sha256').update(data).digest('hex');

let dir: string;
beforeEach(() => {
  // Resolved up front: the helper reports real paths, and on macOS /var links to /private/var.
  dir = realpathSync.native(mkdtempSync(join(tmpdir(), 'vigil-ownhash-')));
});
afterEach(() => rmSync(dir, { recursive: true, force: true }));

/** An executable file at `path` holding `data`. */
function program(path: string, data: string | Buffer, mode = 0o755): void {
  mkdirSync(dirname(path), { recursive: true });
  // Only root (here: the test's own account) may write the folders, whatever the umask.
  for (let d = dirname(path); d.startsWith(`${dir}/`); d = dirname(d)) chmodSync(d, 0o755);
  writeFileSync(path, data);
  chmodSync(path, mode);
}

describe('OwnHashes', () => {
  it('hashes the executables under each root, and only those', async () => {
    const app = join(dir, 'Vigil.app');
    program(join(app, 'Contents/MacOS/Vigil'), 'main');
    program(join(app, 'Contents/Frameworks/Helper.app/Contents/MacOS/Helper'), 'helper');
    program(join(app, 'Contents/Info.plist'), 'plist', 0o644);
    program(join(dir, 'elsewhere'), 'elsewhere');
    // A link inside a root is not followed; a root that is a link is.
    symlinkSync(join(dir, 'elsewhere'), join(app, 'Contents/MacOS/link'));
    program(join(dir, 'opt/osqueryd'), 'osqueryd');
    symlinkSync(join(dir, 'opt/osqueryd'), join(dir, 'osqueryd-link'));
    const own = new OwnHashes({
      roots: [app, join(dir, 'osqueryd-link'), join(dir, 'missing')],
      cdhashes: false,
      ownerUid,
    });
    await own.refresh();
    await own.ready();
    expect(own.owner(sha('main'))).toBe(join(app, 'Contents/MacOS/Vigil'));
    expect(own.owner(sha('helper').toUpperCase())).toContain('Helper');
    expect(own.owner(sha('osqueryd'))).toBe(join(dir, 'opt/osqueryd'));
    expect(own.owner(sha('plist'))).toBeUndefined();
    expect(own.owner(sha('elsewhere'))).toBeUndefined();
    expect(own.size).toBe(3);
  });

  it('counts only what root owns and only root can change', async () => {
    program(join(dir, 'ok/a'), 'a');
    program(join(dir, 'ok/writable'), 'writable', 0o775);
    program(join(dir, 'open/b'), 'b');
    chmodSync(join(dir, 'open'), 0o777);
    const own = new OwnHashes({
      roots: [join(dir, 'ok'), join(dir, 'open')],
      cdhashes: false,
      ownerUid,
    });
    await own.refresh();
    expect(own.owner(sha('a'))).toBeDefined();
    expect(own.owner(sha('writable'))).toBeUndefined();
    expect(own.owner(sha('b'))).toBeUndefined();
    // Owned by anyone else, nothing counts.
    const other = new OwnHashes({
      roots: [join(dir, 'ok')],
      cdhashes: false,
      ownerUid: ownerUid + 1,
    });
    await other.refresh();
    expect(other.size).toBe(0);
  });

  it('reads the CDHash of each slice on macOS', async () => {
    const fat = machO('com.example.santad', 's1', { universal: true });
    program(join(dir, 'santad'), fat.data);
    const own = new OwnHashes({ roots: [dir], cdhashes: true, ownerUid });
    await own.refresh();
    expect(own.owner(fat.sha256)).toBe(join(dir, 'santad'));
    // The arm64 slice's, and the x86_64 one's (a different CodeDirectory).
    expect(own.owner(fat.cdhash)).toBe(join(dir, 'santad'));
    expect(own.size).toBe(3);
  });

  it('picks up a program changed or added since the last pass', async () => {
    program(join(dir, 'a'), 'v1');
    const own = new OwnHashes({ roots: [dir], cdhashes: false, ownerUid });
    await own.refresh();
    expect(own.owner(sha('v1'))).toBeDefined();
    program(join(dir, 'a'), 'v2-longer');
    program(join(dir, 'b'), 'new');
    await own.refresh();
    expect(own.owner(sha('v1'))).toBeUndefined();
    expect(own.owner(sha('v2-longer'))).toBeDefined();
    expect(own.owner(sha('new'))).toBeDefined();
  });

  it('is ready at once with nothing to hash', async () => {
    const own = new OwnHashes({ roots: [], cdhashes: false, ownerUid });
    await own.refresh();
    await expect(own.ready()).resolves.toBeUndefined();
  });

  it('stops at the file limit and logs it', async () => {
    for (let i = 0; i < 5; i++) program(join(dir, `p${i}`), `p${i}`);
    const logs: string[] = [];
    const own = new OwnHashes({
      roots: [dir],
      cdhashes: false,
      ownerUid,
      maxFiles: 2,
      log: (m) => logs.push(m),
    });
    await own.refresh();
    expect(own.size).toBe(2);
    expect(logs.join('\n')).toContain('stopped after 2 files');
  });

  it('covers the helper, its runtime, Santa, osquery and the installed app', () => {
    const mac = ownProgramRoots('darwin', '/Library/PrivilegedHelperTools/vigil-helper', '/rt');
    expect(mac).toEqual(
      expect.arrayContaining([
        '/rt',
        '/Library/PrivilegedHelperTools/vigil-helper',
        '/Library/PrivilegedHelperTools/vigil-helper.d',
        '/Applications/Santa.app',
        '/opt/osquery',
        '/usr/local/bin/osqueryd',
        '/Applications/Vigil at Home.app',
      ]),
    );
    const linux = ownProgramRoots('linux', '/usr/libexec/vigil-helper', '/rt');
    expect(linux).toEqual(
      expect.arrayContaining([
        '/rt',
        '/usr/libexec/vigil-helper',
        '/usr/libexec/vigil-helper.d',
        '/opt/osquery',
        '/usr/bin/osqueryd',
        '/opt/Vigil at Home',
      ]),
    );
    expect(ownProgramRoots('darwin', '/x')).toContain(process.execPath);
  });
});

describe('blocks naming those programs', () => {
  const SANTAD = machO('com.northpolesec.santa.daemon', 'd');
  let own: OwnHashes;
  let rules: RuleStore;
  let logs: string[];

  beforeEach(async () => {
    program(join(dir, 'roots/santad'), SANTAD.data);
    program(join(dir, 'roots/node'), 'node runtime');
    own = new OwnHashes({ roots: [join(dir, 'roots')], cdhashes: true, ownerUid });
    await own.refresh();
    rules = new RuleStore(join(dir, 'rules.json'));
    logs = [];
  });

  function executor(
    sys = new FakeSystem(),
    ownHashes: Pick<OwnHashes, 'ready' | 'owner'> = own,
    ownHashesWaitMs?: number,
  ) {
    return new Executor({
      sys,
      journal: new Journal(join(dir, 'journal.json')),
      approvals: new Approvals({
        dir: join(dir, 'approvals'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules,
      quarantine: { quarantineDir: join(dir, 'Quarantine') },
      syncPort: 47821,
      ownHashes,
      ...(ownHashesWaitMs !== undefined ? { ownHashesWaitMs } : {}),
    });
  }

  it('refuses a binary or CDHash block of one, and nothing else', async () => {
    const ex = executor();
    for (const [ruleType, identifier] of [
      ['binary', SANTAD.sha256],
      ['binary', sha('node runtime').toUpperCase()],
      ['cdhash', SANTAD.cdhash],
    ] as const) {
      for (const policy of ['block', 'silent_block'] as const)
        await expect(
          ex.execute({ kind: 'santa.rule.set', ruleType, identifier, policy }),
        ).rejects.toMatchObject({ code: 'refused' });
    }
    expect(rules.active()).toEqual([]);
    await ex.execute({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: 'e'.repeat(64),
      policy: 'block',
    });
    expect(rules.active().map((r) => r.rule.identifier)).toEqual(['e'.repeat(64)]);
  });

  it('waits for the first pass before deciding', async () => {
    const late = new OwnHashes({ roots: [join(dir, 'roots')], cdhashes: true, ownerUid });
    const ex = executor(new FakeSystem(), late);
    const pending = ex.execute({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: SANTAD.sha256,
      policy: 'block',
    });
    void late.refresh();
    await expect(pending).rejects.toMatchObject({ code: 'refused' });
  });

  it('goes on with what it knows when the first pass takes too long', async () => {
    const never = { ready: () => new Promise<void>(() => undefined), owner: () => undefined };
    const ex = executor(new FakeSystem(), never, 10);
    await expect(
      ex.execute({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: 'f'.repeat(64),
        policy: 'block',
      }),
    ).resolves.toMatchObject({ kind: 'done' });
  });

  /** The core pack's known-bad-hash rule, with a block by a hash written into it. */
  function syncWith(identifier: string): DetectionSync {
    const set = fastPathRules(new DetectionEngine(macosCoreRules, memoryStores()).listRules());
    const known = set.rules.find((r) => r.id === 'known-bad-hash')!;
    const drafted = {
      ...known,
      id: 'drafted-block',
      response: [
        { kind: 'santa.rule.set' as const, ruleType: 'binary', identifier, policy: 'block' },
      ],
    };
    return { kind: 'detection.sync', rules: [known, drafted], exceptions: [], lists: {} };
  }

  function fastPath(ownProgram: (id: string) => string | undefined) {
    return new FastPath({
      file: join(dir, 'helper-rules.json'),
      run: () => Promise.reject(new Error('not run here')),
      log: (m) => logs.push(m),
      ownProgram,
    });
  }

  it('drops a synced rule that blocks one by hash, keeps the rest, and takes the sync', () => {
    const fp = fastPath((id) => own.owner(id));
    const out = fp.sync(syncWith(SANTAD.sha256));
    expect(out.rev).toBe(1);
    expect(fp.status().rules).toBe(1);
    expect(logs.join('\n')).toMatch(/dropping rule drafted-block: it would block .*santad/);
    // A hash of anything else stays.
    const other = fastPath((id) => own.owner(id));
    other.sync(syncWith('c'.repeat(64)));
    expect(other.status().rules).toBe(2);
  });

  it('drops one already in force once the programs are hashed, and on load', () => {
    let known = false;
    const fp = fastPath((id) => (known ? own.owner(id) : undefined));
    fp.sync(syncWith(SANTAD.sha256));
    expect(fp.status().rules).toBe(2);
    known = true;
    fp.dropOwnBlocks();
    expect(fp.status()).toMatchObject({ rules: 1, rev: 2 });
    // Saved without it; a saved file that still has it loads without it.
    const again = fastPath((id) => own.owner(id));
    again.load();
    expect(again.status().rules).toBe(1);
    const old = fastPath(() => undefined);
    old.sync(syncWith(SANTAD.sha256));
    const reloaded = fastPath((id) => own.owner(id));
    reloaded.load();
    expect(reloaded.status().rules).toBe(1);
  });

  it('never holds up a kill while a block by hash waits for the hashes', async () => {
    const sys = new FakeSystem();
    sys.processes.set(4242, { path: '/tmp/payload', started: 'T' });
    // The first pass never finishes: the hash block waits its full minute.
    const never = { ready: () => new Promise<void>(() => undefined), owner: () => undefined };
    const ex = executor(sys, never);
    const fp = new FastPath({
      file: join(dir, 'helper-rules.json'),
      moveWaitMs: 50,
      run: async (action) => {
        const out = await ex.execute(action);
        if (out.kind !== 'done') throw new Error('needs the admin password');
        return out.result as ActionOutcome;
      },
    });
    // The core rule that kills a known-bad program, then blocks its hash.
    const set = fastPathRules(new DetectionEngine(macosCoreRules, memoryStores()).listRules());
    const known = set.rules.find((r) => r.id === 'known-bad-hash')!;
    const bad = 'b'.repeat(64);
    fp.sync({
      kind: 'detection.sync',
      rules: [known],
      exceptions: [],
      lists: { known_bad_sha256: listDigest([bad]) },
      entries: { known_bad_sha256: [bad] },
    });
    const started = performance.now();
    const { ran, moves } = await fp.start({
      id: 'e1',
      ts: Date.now(),
      source: 'santa',
      kind: 'process.exec',
      process: { pid: 4242, path: '/tmp/payload', sha256: bad, signing: 'unsigned' },
    });
    expect(performance.now() - started).toBeLessThan(1000);
    expect(ran.map((r) => [r.action.kind, r.error])).toEqual([['process.kill', undefined]]);
    expect(sys.signals).toEqual([{ pid: 4242, signal: 'SIGKILL' }]);
    // The block is reported as still going, worded as no move.
    const later = await moves;
    expect(later).toHaveLength(1);
    expect(later[0]).toMatchObject({ action: { kind: 'santa.rule.set' } });
    expect(later[0]!.error).toMatch(/goes on/);
    expect(later[0]!.errorCode).toBeUndefined();
  });

  describe('Santa sync', () => {
    const refuse = (rule: { identifier: string; policy: string }) =>
      rule.policy !== 'ALLOWLIST' && own.owner(rule.identifier) ? 'it is santad' : undefined;

    function serve(s: SantaSyncServer, body: Record<string, unknown> = {}) {
      const pre = s.dispatch('preflight', 'M', body) as { sync_type: string };
      const down = s.dispatch('ruledownload', 'M', { cursor: '' }) as {
        rules: { identifier: string; policy: string }[];
      };
      return { type: pre.sync_type, rules: down.rules };
    }

    it('leaves a stored block of one out of a clean sync and takes it back otherwise', () => {
      rules.upsert({ ruleType: 'BINARY', identifier: SANTAD.sha256, policy: 'BLOCKLIST' });
      rules.upsert({ ruleType: 'BINARY', identifier: 'c'.repeat(64), policy: 'BLOCKLIST' });
      const s = new SantaSyncServer({ store: rules, refuse, log: (m) => logs.push(m) });
      const clean = serve(s);
      expect(clean.type).toBe('CLEAN');
      expect(clean.rules.map((r) => r.identifier)).toEqual(['c'.repeat(64)]);
      expect(logs.join('\n')).toContain(`not sending BINARY ${SANTAD.sha256}: it is santad`);
      s.dispatch('postflight', 'M', { rules_received: 1, rules_processed: 1 });

      // Santa holds one rule, which matches: no clean sync again.
      expect(serve(s, { binary_rule_count: 1 }).type).toBe('NORMAL');
      s.dispatch('postflight', 'M', { rules_received: 0, rules_processed: 0 });

      // A block stored after the last sync goes out as REMOVE.
      rules.upsert({ ruleType: 'CDHASH', identifier: SANTAD.cdhash, policy: 'BLOCKLIST' });
      const normal = serve(s, { binary_rule_count: 1 });
      expect(normal.type).toBe('NORMAL');
      expect(normal.rules).toEqual([
        { identifier: SANTAD.cdhash, rule_type: 'CDHASH', policy: 'REMOVE' },
      ]);
      // Each refused rule is logged once, not at every sync.
      expect(logs.filter((l) => l.includes(SANTAD.sha256))).toHaveLength(1);
    });

    it('waits for the programs to be hashed before a preflight', async () => {
      let release!: () => void;
      const gate = new Promise<void>((r) => (release = r));
      const s = new SantaSyncServer({ store: rules, ready: () => gate });
      const req = Object.assign(
        (async function* () {
          yield Buffer.from('{}');
        })(),
        { method: 'POST', url: '/preflight/M', headers: {} },
      );
      let done = false;
      const p = s.handle(req as never).then(() => (done = true));
      await new Promise((r) => setTimeout(r, 20));
      expect(done).toBe(false);
      release();
      await p;
      expect(done).toBe(true);
    });
  });
});
