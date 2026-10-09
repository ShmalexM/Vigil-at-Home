import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  childCommand,
  rootOnly,
  actorFor,
  transfer,
  self,
  type Actor,
} from './commands/transfer.js';
import { quarantine, restore, type QuarantineOptions } from './commands/quarantine.js';
import { AppPinStore } from './pinStore.js';
import { realSystem, type RunResult, type System } from './system.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const isRoot = process.getuid?.() === 0;
/** The unprivileged user root-only tests act as. */
const NOBODY = 65534;

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vigil-transfer-'));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

/** Run the child program directly, as the tests' own user. */
function child(
  req: object,
  input: Buffer | string = '',
): { code: number; out: Buffer; err: string } {
  const [bin, args] = childCommand();
  const r = spawnSync(bin, args, {
    input: Buffer.concat([Buffer.from(JSON.stringify(req) + '\n'), Buffer.from(input)]),
    env: {},
  });
  return { code: r.status ?? -1, out: r.stdout, err: r.stderr.toString() };
}
const me = { uid: process.getuid!(), gid: process.getgid!() };

/** An archive, as the child writes it. */
function archive(entries: (object | Buffer)[]): Buffer {
  return Buffer.concat(
    entries.map((e) => (Buffer.isBuffer(e) ? e : Buffer.from(JSON.stringify(e) + '\n'))),
  );
}
const file = (rel: string, data: string, mode = 0o644) => [
  { t: 'f', rel, mode, uid: 0, gid: 0, mtime: '1000000000000000000', size: data.length },
  Buffer.from(data),
];
const dir = (rel: string, mode = 0o755) => ({
  t: 'd',
  rel,
  mode,
  uid: 0,
  gid: 0,
  mtime: '1000000000000000000',
});

describe('the file child', () => {
  it('packs a folder, a file and a link, and removes exactly them', () => {
    const src = join(root, 'app');
    mkdirSync(join(src, 'bin'), { recursive: true });
    writeFileSync(join(src, 'bin', 'run'), 'hello', { mode: 0o755 });
    symlinkSync('/etc/passwd', join(src, 'link'));
    const r = child({ op: 'pack', path: src, ...me }, 'remove\n');
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    const lines = r.out.toString().split('\n');
    expect(JSON.parse(lines[0]!)).toMatchObject({ t: 'd', rel: '' });
    expect(r.out.toString()).toContain('"rel":"bin/run"');
    expect(r.out.toString()).toContain('"target":"/etc/passwd"');
    expect(JSON.parse(lines.at(-2)!)).toEqual({ t: 'end' });
    expect(existsSync(src)).toBe(false);
  });

  it('refuses a FIFO, and leaves everything in place on "keep"', () => {
    const src = join(root, 'p');
    spawnSync('mkfifo', [src]);
    const t0 = Date.now();
    const r = child({ op: 'pack', path: src, ...me }, 'keep\n');
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/not a file, folder or link/);
    expect(Date.now() - t0).toBeLessThan(5000);
    writeFileSync(join(root, 'f'), 'x');
    expect(child({ op: 'pack', path: join(root, 'f'), ...me }, 'keep\n').code).toBe(0);
    expect(existsSync(join(root, 'f'))).toBe(true);
  });

  it('places an archive with its modes, and never over something already there', () => {
    const dest = join(root, 'out');
    const a = archive([dir(''), ...file('run', 'hi', 0o750), dir('sub', 0o500), { t: 'end' }]);
    const r = child({ op: 'place', path: dest, ...me }, a);
    expect(r.err).toBe('');
    expect(readFileSync(join(dest, 'run'), 'utf8')).toBe('hi');
    expect(statSync(join(dest, 'run')).mode & 0o777).toBe(0o750);
    expect(statSync(join(dest, 'sub')).mode & 0o777).toBe(0o500);
    // Already there: refused, and what is there is untouched.
    writeFileSync(join(root, 'taken'), 'mine');
    const again = child(
      { op: 'place', path: join(root, 'taken'), ...me },
      archive([...file('', 'new'), { t: 'end' }]),
    );
    expect(again.code).toBe(1);
    expect(readFileSync(join(root, 'taken'), 'utf8')).toBe('mine');
    // Nor through a link someone left at the path.
    symlinkSync(join(root, 'taken'), join(root, 'via'));
    expect(
      child(
        { op: 'place', path: join(root, 'via'), ...me },
        archive([...file('', 'new'), { t: 'end' }]),
      ).code,
    ).toBe(1);
    expect(readFileSync(join(root, 'taken'), 'utf8')).toBe('mine');
  });

  it('on failure removes only what it created, never a destination it did not create', () => {
    // Parents: `a` exists, `a/b/c` are made by the child, then the archive breaks.
    mkdirSync(join(root, 'a'));
    writeFileSync(join(root, 'a', 'keep'), 'mine');
    const dest = join(root, 'a', 'b', 'c', 'item');
    const broken = archive([
      dir(''),
      ...file('x', 'data'),
      { t: 'f', rel: '../escape', mode: 0o644, uid: 0, gid: 0, mtime: '0', size: 1 },
    ]);
    const r = child({ op: 'place', path: dest, parents: true, ...me }, broken);
    expect(r.code).toBe(1);
    expect(r.err).toMatch(/bad entry name/);
    expect(existsSync(join(root, 'a', 'b'))).toBe(false);
    expect(readFileSync(join(root, 'a', 'keep'), 'utf8')).toBe('mine');
    // An archive that ends early (the reading side died): same.
    const cut = archive([dir(''), ...file('x', 'data')]);
    expect(child({ op: 'place', path: dest, parents: true, ...me }, cut).code).toBe(1);
    expect(existsSync(join(root, 'a', 'b'))).toBe(false);
    expect(readdirNames(join(root, 'a'))).toEqual(['keep']);
  });

  it('refuses a request it cannot act on', () => {
    expect(child({ op: 'pack', path: 'relative', ...me }).err).toMatch(/bad request/);
    expect(child({ op: 'rename', path: root, ...me }).err).toMatch(/bad request/);
    if (!isRoot)
      expect(child({ op: 'pack', path: root, uid: 0, gid: 0 }).err).toMatch(/cannot act/);
  });
});

function readdirNames(path: string): string[] {
  return spawnSync('ls', ['-A', path]).stdout.toString().split('\n').filter(Boolean);
}

describe('who acts on a path', () => {
  it('is root only when every folder above is root’s alone', () => {
    expect(rootOnly('/')).toBe(true);
    expect(rootOnly(tmpdir())).toBe(false); // writable by everyone, and the last folder
    if (isRoot) {
      // /tmp is sticky: a root-owned folder in it is root's alone.
      expect(rootOnly(root)).toBe(true);
      chmodSync(root, 0o777);
      expect(rootOnly(root)).toBe(false);
    }
  });

  it.skipIf(!isRoot)(
    'is the folder’s owner for a user’s folder, and refuses root’s file in a shared one',
    async () => {
      const sys = realSystem(undefined, 'linux');
      chmodSync(root, 0o755);
      const home = join(root, 'home');
      mkdirSync(home);
      chownSync(home, NOBODY, NOBODY);
      writeFileSync(join(home, 'x'), '');
      expect(await actorFor(sys, join(home, 'x'))).toEqual({
        uid: NOBODY,
        gid: expect.any(Number),
      });
      expect(await actorFor(sys, join(root, 'x'))).toEqual({ uid: 0, gid: 0 });
      const shared = join(root, 'shared');
      mkdirSync(shared);
      chmodSync(shared, 0o777);
      writeFileSync(join(shared, 'rootfile'), '');
      await expect(actorFor(sys, join(shared, 'rootfile'))).rejects.toMatchObject({
        code: 'refused',
      });
    },
  );
});

/** A store whose flag step can be held, to keep a pin write in flight. */
function slowFlags(): System & { delay: number } {
  return {
    platform: 'linux',
    delay: 0,
    now: () => Date.now(),
    async run(this: { delay: number }): Promise<RunResult> {
      await new Promise((r) => setTimeout(r, this.delay));
      return { code: 0, stdout: '', stderr: '' };
    },
  } as unknown as System & { delay: number };
}

describe.skipIf(!isRoot)('moves as the user (root only)', () => {
  let home: string;
  let pinDir: string;
  let store: AppPinStore;
  let flags: System & { delay: number };
  const sys = realSystem(undefined, 'linux');
  const qopts = (extra: Partial<QuarantineOptions> = {}): QuarantineOptions => ({
    quarantineDir: join(root, 'Quarantine'),
    platform: 'linux',
    protectedPrefixes: [],
    protectedExact: new Set(),
    guard: () => store.intact(),
    ...extra,
  });

  beforeEach(async () => {
    chmodSync(root, 0o755);
    home = join(root, 'home');
    mkdirSync(home);
    chownSync(home, NOBODY, NOBODY);
    pinDir = join(root, 'state', 'pin');
    flags = slowFlags();
    store = new AppPinStore(flags, { dir: pinDir, ownerUid: 0 });
    await store.load();
    await store.write({ platform: 'linux', path: '/x', image: '1:2', sha256: 'a'.repeat(64) });
  });

  it('quarantines and restores a user’s file as that user', async () => {
    const f = join(home, 'evil');
    writeFileSync(f, 'payload', { mode: 0o640 });
    chownSync(f, NOBODY, NOBODY);
    const rec = await quarantine(sys, f, 'q1', qopts());
    expect(existsSync(f)).toBe(false);
    expect(statSync(rec.storedPath).mode & 0o777).toBe(0);
    expect(rec).toMatchObject({ uid: NOBODY, mode: 0o640 });
    await restore(sys, rec, qopts());
    const st = statSync(f);
    expect([st.uid, st.mode & 0o777]).toEqual([NOBODY, 0o640]);
    expect(readFileSync(f, 'utf8')).toBe('payload');
    expect(existsSync(join(root, 'Quarantine', 'q1'))).toBe(false);
  });

  it('never writes outside quarantine when the parent is swapped during a pin write', async () => {
    const parent = join(home, 'dl');
    mkdirSync(parent);
    chownSync(parent, NOBODY, NOBODY);
    writeFileSync(join(parent, 'app-pin.json'), 'x');
    chownSync(join(parent, 'app-pin.json'), NOBODY, NOBODY);
    const pinBefore = readFileSync(store.file);
    // The user swaps the folder for a link to the helper's own once the helper has decided who acts.
    const swap: QuarantineOptions['actorFor'] = async (s, path) => {
      const actor = await actorFor(s, path);
      renameSync(parent, `${parent}.old`);
      symlinkSync(pinDir, parent);
      return actor;
    };
    flags.delay = 40;
    const writing = store.write({
      platform: 'linux',
      path: '/y',
      image: '1:3',
      sha256: 'b'.repeat(64),
    });
    await expect(
      quarantine(sys, join(parent, 'app-pin.json'), 'q2', qopts({ actorFor: swap })),
    ).rejects.toMatchObject({ code: 'failed' });
    await writing;
    // The helper's file is where it was, and nothing was written beside it or put back anywhere.
    expect(lstatSync(store.file).isFile()).toBe(true);
    expect(readFileSync(store.file)).not.toEqual(pinBefore); // the write landed
    expect(store.current()?.path).toBe('/y');
    expect(readdirNames(pinDir).sort()).toEqual(['app-pin.json', 'app-pin.key']);
    expect(existsSync(join(root, 'Quarantine', 'q2'))).toBe(false);
    expect(readFileSync(join(`${parent}.old`, 'app-pin.json'), 'utf8')).toBe('x');
    expect(readlinkSync(parent)).toBe(pinDir);
  });

  it('restores into a user’s folder as the user, so a swapped folder leads nowhere of root’s', async () => {
    const dl = join(home, 'dl');
    mkdirSync(dl);
    chownSync(dl, NOBODY, NOBODY);
    const f = join(dl, 'evil');
    writeFileSync(f, 'payload');
    chownSync(f, NOBODY, NOBODY);
    const rec = await quarantine(sys, f, 'q3', qopts());
    // The user's folder now leads into root's state.
    renameSync(dl, `${dl}.old`);
    symlinkSync(join(root, 'state'), dl);
    chmodSync(join(root, 'state'), 0o700);
    await expect(restore(sys, rec, qopts())).rejects.toThrow();
    expect(existsSync(join(root, 'state', 'evil'))).toBe(false);
    expect(existsSync(rec.storedPath)).toBe(true);
  });

  it('moves a root-owned item in root’s own folder as root, keeping its owner', async () => {
    const sysDir = join(root, 'etc');
    mkdirSync(sysDir);
    writeFileSync(join(sysDir, 'unit.service'), 'x');
    chownSync(join(sysDir, 'unit.service'), 0, 0);
    const actor: Actor = await actorFor(sys, join(sysDir, 'unit.service'));
    expect(actor).toEqual({ uid: 0, gid: 0 });
    const rec = await quarantine(sys, join(sysDir, 'unit.service'), 'q4', qopts());
    await restore(sys, rec, qopts());
    expect(statSync(join(sysDir, 'unit.service')).uid).toBe(0);
  });
});

describe('transfer', () => {
  it('copies across, then removes the original only once the copy is complete', async () => {
    const src = join(root, 'src');
    writeFileSync(src, 'abc');
    const taken = join(root, 'taken');
    writeFileSync(taken, 'mine');
    await expect(
      transfer(
        { path: src, actor: self() },
        { path: taken, actor: self() },
        { removeSource: true },
      ),
    ).rejects.toMatchObject({ code: 'failed' });
    expect(readFileSync(src, 'utf8')).toBe('abc');
    expect(readFileSync(taken, 'utf8')).toBe('mine');
    await transfer(
      { path: src, actor: self() },
      { path: join(root, 'dst'), actor: self() },
      { removeSource: true },
    );
    expect(existsSync(src)).toBe(false);
    expect(readFileSync(join(root, 'dst'), 'utf8')).toBe('abc');
  });

  it('works for quarantine and restore through the fake system as the tests’ own user', async () => {
    const sys = new FakeLinuxSystem();
    const home = join(root, 'home');
    mkdirSync(home);
    writeFileSync(join(home, 'evil'), 'x');
    const opts: QuarantineOptions = {
      quarantineDir: join(root, 'Quarantine'),
      platform: 'linux',
      protectedPrefixes: [],
      actorFor: async () => self(),
    };
    const rec = await quarantine(sys, join(home, 'evil'), 'q', opts);
    expect(existsSync(join(home, 'evil'))).toBe(false);
    // Restore puts back missing parent folders too.
    rmSync(home, { recursive: true });
    await restore(sys, rec, opts);
    expect(readFileSync(join(home, 'evil'), 'utf8')).toBe('x');
  });
});
