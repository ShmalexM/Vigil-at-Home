import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { spawnSync, type ChildProcess } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  childCommand,
  macAclLetsOthersWrite,
  readAs,
  rootOnly,
  self,
  transfer,
  transferLimits,
} from './commands/transfer.js';
import { disablePersistence } from './commands/persistence.js';
import { daemonAnswers } from './socketProbe.js';
import { createServer } from 'node:net';
import { FakeSystem } from './testing/fakeSystem.js';
import { quarantine, restore, type QuarantineOptions } from './commands/quarantine.js';
import type { RunResult, System } from './system.js';
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

  it('refuses an item that is not the one checked, a file with other names, or another folder', () => {
    const f = join(root, 'f');
    writeFileSync(f, 'x');
    const st = statSync(f, { bigint: true });
    const pack = (req: object) => child({ op: 'pack', path: f, ...me, ...req }, 'keep\n');
    expect(pack({ expectId: `${st.dev}:${st.ino + 1n}` }).err).toMatch(
      /changed after it was checked/,
    );
    expect(pack({ expectId: `${st.dev}:${st.ino}` }).code).toBe(0);
    linkSync(f, join(root, 'g'));
    expect(pack({}).err).toMatch(/other hard links/);
    const a = archive([...file('', 'x'), { t: 'end' }]);
    const place = (expectParent: string) =>
      child({ op: 'place', path: join(root, 'placed'), expectParent, ...me }, a);
    expect(place('/elsewhere').err).toMatch(/not the folder that was checked/);
    expect(existsSync(join(root, 'placed'))).toBe(false);
    expect(place(realpathSync(root)).err).toBe('');
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
  const linux = new FakeLinuxSystem();
  it('is root only when every folder above is root’s alone', async () => {
    expect(await rootOnly(linux, '/')).toBe(true);
    expect(await rootOnly(linux, realpathSync(tmpdir()))).toBe(false); // writable by everyone, and the last folder
    if (isRoot) {
      // /tmp is sticky: a root-owned folder in it is root's alone.
      expect(await rootOnly(linux, realpathSync(root))).toBe(true);
      // A POSIX ACL granting a named user write shows as group write (its mask).
      chmodSync(root, 0o770);
      expect(await rootOnly(linux, realpathSync(root))).toBe(false);
      chmodSync(root, 0o777);
      expect(await rootOnly(linux, realpathSync(root))).toBe(false);
    }
  });

  it('reads macOS ACLs: an entry letting anyone but root write makes a folder not root’s alone', async () => {
    const ls = (path: string, acl: string) =>
      `drwxr-xr-x+ 3 root  wheel  96 Jan  1 00:00 ${path}\n${acl}`;
    expect(macAclLetsOthersWrite(ls('/x', ' 0: group:everyone deny delete\n'))).toBe(false);
    expect(macAclLetsOthersWrite(ls('/x', ' 0: user:root allow add_file,delete_child\n'))).toBe(
      false,
    );
    for (const acl of [
      ' 0: group:staff allow add_file\n',
      ' 0: user:alex inherited allow list,add_subdirectory\n',
      ' 0: group:everyone deny delete\n 1: user:Some Name allow delete_child\n',
      ' 0: group:admin allow writesecurity\n',
      // An entry line in a shape the parser doesn't know is not taken as harmless.
      ' 0: group:everyone deny delete\n 1: user:alex allow\n',
      ' 0: user:root allow add_file\n 1: user:alex permit add_file\n',
      ' 0: group:everyone deny delete\n 1:\n',
    ])
      expect(macAclLetsOthersWrite(ls('/x', acl)), acl).toBe(true);
    // Through rootOnly: one component with such an ACL, or one whose ACL can't be read.
    const mac = (answer: (path: string) => RunResult) =>
      ({
        platform: 'darwin',
        run: async (_bin: string, args: string[]) => answer(args.at(-1)!),
      }) as unknown as System;
    const ok = (out: string): RunResult => ({ code: 0, stdout: out, stderr: '' });
    expect(
      await rootOnly(
        mac((p) => ok(ls(p, ''))),
        '/',
      ),
    ).toBe(true);
    expect(
      await rootOnly(
        mac((p) => ok(ls(p, ' 0: group:staff allow write\n'))),
        '/',
      ),
    ).toBe(false);
    expect(
      await rootOnly(
        mac(() => ({ code: 1, stdout: '', stderr: 'no' })),
        '/',
      ),
    ).toBe(false);
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

describe('restoring what a user owns', () => {
  it('gives owners last, once nothing more is written beneath them', () => {
    // Run as the tests' own user, the placer gives no owners at all; as root it gives them at the end.
    const dest = join(root, 'placed');
    const uid = isRoot ? NOBODY : me.uid;
    const a = archive([
      { ...dir(''), uid, gid: uid },
      { t: 'f', rel: 'f', mode: 0o644, uid, gid: uid, mtime: '0', size: 1 },
      Buffer.from('x'),
      { t: 'end' },
    ]);
    const r = child({ op: 'place', path: dest, owners: true, ...me }, a);
    expect(r.err).toBe('');
    expect(statSync(dest).uid).toBe(uid);
    expect(statSync(join(dest, 'f')).uid).toBe(uid);
  });
});

describe('groups when placing as a user', () => {
  // A group of the user's other than their own, when they have one (CI's runner does).
  const other = isRoot
    ? undefined
    : process.getgroups!().find((g) => g !== process.getegid!() && g !== 0);
  const FOREIGN = 4242;

  it('keeps each entry’s group when it is one of the user’s, and the user’s own otherwise', () => {
    // As root the placer acts as NOBODY, whose only group is its own.
    const actor = isRoot ? { uid: NOBODY, gid: NOBODY } : me;
    if (isRoot) {
      chmodSync(root, 0o755);
      mkdirSync(join(root, 'home'));
      chownSync(join(root, 'home'), NOBODY, NOBODY);
    }
    const dest = join(root, isRoot ? 'home' : '', 'placed');
    const entries: (object | Buffer)[] = [
      { ...dir(''), uid: actor.uid, gid: other ?? FOREIGN },
      {
        t: 'f',
        rel: 'mine',
        mode: 0o2755,
        uid: actor.uid,
        gid: other ?? FOREIGN,
        mtime: '0',
        size: 1,
      },
      Buffer.from('x'),
      { t: 'f', rel: 'foreign', mode: 0o640, uid: actor.uid, gid: FOREIGN, mtime: '0', size: 1 },
      Buffer.from('y'),
      { t: 'l', rel: 'link', target: 'mine', uid: actor.uid, gid: other ?? FOREIGN },
      { t: 'end' },
    ];
    const r = child({ op: 'place', path: dest, ...actor }, archive(entries));
    expect(r.err).toBe('');
    expect(r.code).toBe(0);
    const want = other ?? actor.gid;
    expect(statSync(dest).gid).toBe(want);
    expect(lstatSync(join(dest, 'link')).gid).toBe(want);
    const mine = statSync(join(dest, 'mine'));
    expect(mine.gid).toBe(want);
    // Setgid survives the change of group, which would otherwise clear it.
    expect(mine.mode & 0o7777).toBe(0o2755);
    // Not a group of the user's: the system would refuse, so it keeps the user's group.
    const foreign = statSync(join(dest, 'foreign'));
    expect([foreign.gid, foreign.mode & 0o777]).toEqual([actor.gid, 0o640]);
  });
});

describe('bounds on a move', () => {
  const saved = { ...transferLimits };
  let children: ChildProcess[];
  beforeEach(() => {
    children = [];
    transferLimits.onSpawn = (c) => children.push(c);
  });
  afterEach(() => {
    for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill('SIGKILL');
    Object.assign(transferLimits, saved);
  });
  const gone = (c: ChildProcess) => c.exitCode !== null || c.signalCode !== null;
  const qopts = (): QuarantineOptions => ({
    quarantineDir: join(root, 'Quarantine'),
    platform: 'linux',
    protectedPrefixes: [],
  });
  /** Stop the reading child of the next move as soon as it starts. */
  const stopReader = () => {
    transferLimits.onSpawn = (c, op) => {
      children.push(c);
      if (op === 'pack' || op === 'read') c.kill('SIGSTOP');
    };
  };
  const sys = new FakeLinuxSystem();
  const item = (name = 'app', files = 1) => {
    const p = join(root, name);
    mkdirSync(p);
    for (let i = 0; i < files; i++) writeFileSync(join(p, `f${i}`), 'x'.repeat(10));
    return p;
  };

  it('stops a move whose reader is stopped, kills both processes and keeps the original', async () => {
    transferLimits.deadlineMs = 300;
    transferLimits.graceMs = 300;
    stopReader();
    const app = item();
    const t0 = Date.now();
    await expect(quarantine(sys, app, 's1', qopts())).rejects.toThrow(/took too long/);
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(existsSync(join(app, 'f0'))).toBe(true);
    expect(existsSync(join(root, 'Quarantine', 's1'))).toBe(false);
    await new Promise((r) => setTimeout(r, 50));
    expect(children).toHaveLength(2);
    expect(children.every(gone)).toBe(true);
  });

  it('stops a read whose process is stopped', async () => {
    transferLimits.deadlineMs = 300;
    stopReader();
    writeFileSync(join(root, 'small'), 'x');
    await expect(readAs(self(), join(root, 'small'))).rejects.toThrow(/took too long/);
    await new Promise((r) => setTimeout(r, 50));
    expect(children.every(gone)).toBe(true);
  });

  it('refuses an item with too many entries or bytes, leaving it in place', async () => {
    transferLimits.maxEntries = 3;
    const many = item('many', 5);
    await expect(quarantine(sys, many, 'c1', qopts())).rejects.toThrow(/too many files/);
    expect(existsSync(join(many, 'f4'))).toBe(true);
    transferLimits.maxEntries = saved.maxEntries;
    transferLimits.maxBytes = 15;
    const big = item('big', 2);
    await expect(quarantine(sys, big, 'c2', qopts())).rejects.toThrow(/too large/);
    expect(existsSync(join(big, 'f1'))).toBe(true);
    expect(existsSync(join(root, 'Quarantine', 'c1'))).toBe(false);
    expect(existsSync(join(root, 'Quarantine', 'c2'))).toBe(false);
  });

  it('refuses a move past the number running at once, and takes one again once they end', async () => {
    transferLimits.maxActive = 1;
    transferLimits.deadlineMs = 500;
    transferLimits.graceMs = 100;
    stopReader();
    const first = quarantine(sys, item('a'), 'm1', qopts());
    while (children.length < 2) await new Promise((r) => setTimeout(r, 5));
    transferLimits.onSpawn = (c) => children.push(c);
    await expect(quarantine(sys, item('b'), 'm2', qopts())).rejects.toThrow(/already moving/);
    await expect(first).rejects.toThrow(/took too long/);
    const rec = await quarantine(sys, join(root, 'b'), 'm3', qopts());
    expect(existsSync(join(root, 'b'))).toBe(false);
    // The stored copy is locked; unlocked here so the test's cleanup can remove it as any user.
    chmodSync(rec.storedPath, 0o700);
  });
});

describe('the daemon lock for pin-app', () => {
  it('sees a daemon on the socket, and none when nothing listens', async () => {
    const sock = join(root, 'helper.sock');
    expect(await daemonAnswers(sock)).toBe(false);
    const server = createServer(() => undefined);
    await new Promise<void>((r) => server.listen(sock, r));
    try {
      expect(await daemonAnswers(sock)).toBe(true);
    } finally {
      await new Promise<void>((r) => server.close(() => r()));
    }
    expect(await daemonAnswers(sock)).toBe(false);
  });
});

describe('startup items are read as the path’s user', () => {
  const launch = () => {
    const dir = join(root, 'LaunchAgents');
    mkdirSync(dir);
    return dir;
  };
  const opts = (): QuarantineOptions => ({
    quarantineDir: join(root, 'Quarantine'),
    protectedPrefixes: [],
    protectedExact: new Set(),
  });

  it('turns off a user’s agent only when that user asks', async () => {
    const dir = launch();
    const plist = join(dir, 'com.evil.agent.plist');
    writeFileSync(plist, '<plist/>');
    const sys = new FakeSystem();
    sys.console = process.getuid!() + 1;
    sys.labels.set(plist, 'com.evil.agent');
    await expect(
      disablePersistence(sys, plist, 'p0', opts(), /LaunchAgents$/),
    ).rejects.toMatchObject({ code: 'not-your-item', message: /another user/ });
    expect(existsSync(plist)).toBe(true);
    expect(sys.runs.filter((r) => r.bin === 'launchctl')).toEqual([]);
  });

  it('hands plutil the bytes, never the path', async () => {
    const dir = launch();
    const plist = join(dir, 'com.evil.agent.plist');
    writeFileSync(plist, '<plist/>');
    const sys = new FakeSystem();
    sys.console = process.getuid!();
    sys.labels.set(plist, 'com.evil.agent');
    const rec = await disablePersistence(sys, plist, 'p1', opts(), /LaunchAgents$/);
    expect(rec.label).toBe('com.evil.agent');
    const plutil = sys.runs.filter((r) => r.bin === 'plutil');
    expect(plutil.map((r) => r.args)).toEqual(
      ['Label', 'Program', 'ProgramArguments.0'].map((key) => [
        '-extract',
        key,
        'raw',
        '-o',
        '-',
        '-',
      ]),
    );
    for (const r of plutil) expect(Buffer.from(r.input ?? '').toString()).toBe('<plist/>');
  });

  it('refuses a link or a FIFO in place of the plist, promptly', async () => {
    const dir = launch();
    writeFileSync(join(root, 'secret'), 'x');
    symlinkSync(join(root, 'secret'), join(dir, 'link.plist'));
    spawnSync('mkfifo', [join(dir, 'fifo.plist')]);
    const sys = new FakeSystem();
    const t0 = Date.now();
    for (const name of ['link.plist', 'fifo.plist'])
      await expect(
        disablePersistence(sys, join(dir, name), 'p2', opts(), /LaunchAgents$/),
      ).rejects.toMatchObject({ code: 'refused' });
    expect(Date.now() - t0).toBeLessThan(5000);
    expect(sys.runs).toEqual([]);
    // The read itself: as the given user, a link is never followed.
    await expect(readAs(self(), join(dir, 'link.plist'))).rejects.toMatchObject({
      code: 'refused',
    });
  });
});
