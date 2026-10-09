import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals } from './approval.js';
import {
  parseCodesignIdentity,
  pinCandidate,
  pinFor,
  repinFromGrant,
  type AppPin,
  type PinOptions,
} from './appPin.js';
import { readCodeIdentity } from './codeDirectory.js';
import { AppPinStore } from './pinStore.js';
import { BINARIES, LINUX_BINARIES, realSystem } from './system.js';
import { VIGIL_BUNDLE_ID } from './config.js';
import { Executor } from './executor.js';
import { FastPath } from './fastpath.js';
import { Journal } from './journal.js';
import type { HelperCommand } from './protocol.js';
import type { BinaryName, RunResult, System } from './system.js';
import { FapolicydBlocks } from './commands/fapolicyd.js';
import { isProtectedProcess } from './commands/process.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';
import { machO, type FakeMachO } from './testing/machO.js';

const STARTED = 'Mon Oct  5 16:20:13 2026';
const VIGIL_ID = 'app.vigilathome.desktop';
/** The app as built, version 1: what the pin names in most tests. */
const V1 = machO(VIGIL_ID, 'v1');
const CDHASH = V1.cdhash;
const APP_SHA = V1.sha256;
const BUNDLE = '/Users/a/Downloads/Vigil at Home.app';
const EXE = `${BUNDLE}/Contents/MacOS/Vigil at Home`;
const INSTALLED_MAC = ['/Applications/Vigil at Home.app'];

/** A self grant's whole re-pin: bound when the password is asked for, pinned once it's given. */
async function regrant(
  sys: System,
  grant: Parameters<typeof pinCandidate>[1],
  opts: PinOptions & { store: AppPinStore },
): Promise<AppPin | undefined> {
  const bound = await pinCandidate(sys, grant, opts);
  return bound && repinFromGrant(sys, bound, opts);
}

let root: string;
let pinFile: string;
let store: AppPinStore;
beforeEach(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-pin-'));
  // The store's own system: the immutable flag is a no-op here (pinStore.test.ts covers it).
  const flags = { platform: 'linux', run: async () => ok(), now: Date.now } as unknown as System;
  store = new AppPinStore(flags, { dir: join(root, 'pin'), ownerUid: process.getuid!() });
  pinFile = store.file;
  await store.load();
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const setPin = (pin: AppPin | undefined) => store.write(pin);
const currentPin = () => store.current();

const ok = (stdout = '', stderr = ''): RunResult => ({ code: 0, stdout, stderr });

/**
 * macOS: files on disk (FakeFs), codesign reading whatever file a path names
 * when it runs, and what the kernel loaded for each pid.
 */
class MacCode extends FakeSystem {
  /** pid → cdhash of the code the kernel loaded for it. */
  code = new Map<string, string>();
  /** Runs while codesign looks at a pid or path, to stand in for something changing meanwhile. */
  duringCodesign: (() => void) | undefined;

  /** Put a program at `path` as file `id`, and name it the main executable of its bundle. */
  put(path: string, id: string, m: FakeMachO): void {
    this.fs.paths.set(path, id);
    this.fs.inodes.set(id, { data: m.data });
    const bundle = /^(.*\.app)\/Contents\/MacOS\/([^/]+)$/i.exec(path);
    if (bundle) this.labels.set(`${bundle[1]}/Contents/Info.plist`, bundle[2]!);
  }

  override async run(bin: BinaryName, args: string[], opts: { input?: string } = {}) {
    if (bin !== 'codesign') return super.run(bin, args, opts);
    this.runs.push({ bin, args, input: opts.input });
    const target = args.at(-1)!;
    this.duringCodesign?.();
    let out: string | undefined;
    if (/^\d+$/.test(target)) {
      const c = this.code.get(target);
      if (c) out = `Identifier=${VIGIL_ID}\nCDHash=${c}\n`;
    } else {
      const f = this.fs.open(target);
      this.fs.opened.pop(); // codesign's own read, not the helper's
      const c = f && readCodeIdentity((pos, len) => f.read(pos, len));
      if (c) out = `Executable=${target}\nIdentifier=${c.identifier}\nCDHash=${c.cdhash}\n`;
    }
    return out ? ok('', out) : { code: 1, stdout: '', stderr: 'code object is not signed at all' };
  }
}

const executorDeps = (sys: FakeSystem | FakeLinuxSystem) => ({
  sys,
  journal: new Journal(join(root, 'journal.json')),
  approvals: new Approvals({ dir: join(root, 'approvals'), requiredOwnerUid: process.getuid!() }),
  rules: new RuleStore(join(root, 'rules.json')),
  quarantine: { quarantineDir: join(root, 'Quarantine') },
  syncPort: 47821,
  appPin: store,
});

it('pins by the bundle id the app is built with', () => {
  const builder = readFileSync(
    join(import.meta.dirname, '../../../apps/desktop/electron-builder.yml'),
    'utf8',
  );
  expect(/^appId:\s*(\S+)\s*$/m.exec(builder)?.[1]).toBe(VIGIL_BUNDLE_ID);
  expect(VIGIL_ID).toBe(VIGIL_BUNDLE_ID);
});

it('reads the cdhash and main executable codesign prints', () => {
  expect(
    parseCodesignIdentity(`Executable=${EXE}\nIdentifier=x\nCDHash=${CDHASH}\nSignature=adhoc\n`),
  ).toEqual({ cdhash: CDHASH, executable: EXE, identifier: 'x' });
  expect(parseCodesignIdentity('code object is not signed at all')).toBeUndefined();
});

describe('codesign -d -vvv as a real Mac prints it', () => {
  // The path form names the inner Mach-O in Executable=, not the .app, and
  // everything goes to stderr. (The CDHash is padded out to its 40 digits.)
  const FINDER_APP = '/System/Library/CoreServices/Finder.app';
  const FINDER_EXE = `${FINDER_APP}/Contents/MacOS/Finder`;
  const FINDER_CDHASH = '2ff5' + '0'.repeat(36);
  const output = (cdhash: string, identifier: string) =>
    [
      `Executable=${FINDER_EXE}`,
      `Identifier=${identifier}`,
      'Format=app bundle with Mach-O universal (x86_64 arm64e)',
      'CodeDirectory v=20400 size=12345 flags=0x0(none) hashes=375+7 location=embedded',
      'Platform identifier=16',
      'Hash type=sha256 size=32',
      `CandidateCDHash sha256=${cdhash}`,
      `CandidateCDHashFull sha256=${cdhash}${'1'.repeat(24)}`,
      'Hash choices=sha256',
      `CDHash=${cdhash}`,
      'Signature size=4442',
      'Authority=Software Signing',
      'Signed Time=Sep 1, 2026 at 00:00:00',
      'Info.plist entries=40',
      'TeamIdentifier=not set',
      'Sealed Resources version=2 rules=2 files=0',
      'Internal requirements count=1 size=68',
      '',
    ].join('\n');
  const FINDER = output(FINDER_CDHASH, 'com.apple.finder');

  it('reads the inner executable and cdhash, in any line order', () => {
    const want = { cdhash: FINDER_CDHASH, executable: FINDER_EXE, identifier: 'com.apple.finder' };
    expect(parseCodesignIdentity(FINDER)).toEqual(want);
    const lines = FINDER.split('\n');
    expect(parseCodesignIdentity([...lines].reverse().join('\n'))).toEqual(want);
    // CDHash first, Executable last.
    const moved = lines.filter((l) => !/^(CDHash|Executable)=/.test(l));
    expect(
      parseCodesignIdentity(
        [`CDHash=${FINDER_CDHASH}`, ...moved, `Executable=${FINDER_EXE}`].join('\n'),
      ),
    ).toEqual(want);
  });

  /** codesign writing `out` to stderr, with nothing on stdout, for the program and its pid. */
  class StderrMac extends FakeSystem {
    constructor(private readonly out: string) {
      super();
      this.fs.paths.set(FINDER_EXE, '1:2');
      this.fs.inodes.set('1:2', { data: V1.data });
      this.labels.set(`${FINDER_APP}/Contents/Info.plist`, 'Finder');
    }
    override async run(bin: BinaryName, args: string[], opts: { input?: string } = {}) {
      if (bin !== 'codesign') return super.run(bin, args, opts);
      this.runs.push({ bin, args, input: opts.input });
      return [FINDER_EXE, '700'].includes(args.at(-1)!)
        ? ok('', this.out)
        : { code: 1, stdout: '', stderr: 'code object is not signed at all' };
    }
  }

  it('pins when codesign, read from stderr, agrees with the program’s own bytes', async () => {
    const sys = new StderrMac(output(CDHASH, VIGIL_ID));
    sys.processes.set(700, { path: FINDER_EXE, started: STARTED });
    const opts = { store, installed: INSTALLED_MAC };
    const pin = await regrant(sys, { selfPaths: [FINDER_APP] }, opts);
    expect(pin).toEqual({ platform: 'darwin', path: FINDER_EXE, cdhash: CDHASH, sha256: APP_SHA });
    expect(currentPin()).toEqual(pin);
    const ex = new Executor(executorDeps(sys));
    await expect(
      ex.execute({ kind: 'process.kill', pid: 700, path: FINDER_EXE }),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(sys.signals).toEqual([]);
  });

  it('pins nothing when codesign disagrees with the bytes read', async () => {
    const sys = new StderrMac(FINDER);
    await expect(pinFor(sys, FINDER_APP, { installed: INSTALLED_MAC })).rejects.toThrow();
  });
});

describe('the app pinned at install (macOS)', () => {
  const APP = 501;
  let sys: MacCode;
  const codesigns = () => sys.runs.filter((r) => r.bin === 'codesign').map((r) => r.args.at(-1));

  beforeEach(() => {
    sys = new MacCode();
    sys.put(EXE, '16777220:100', V1);
    sys.code.set(String(APP), CDHASH);
    sys.processes.set(APP, { path: EXE, started: STARTED });
  });

  it('pins the cdhash and sha256 of the main executable, read from one open file', async () => {
    const pin = await pinFor(sys, BUNDLE, { installed: INSTALLED_MAC });
    expect(pin).toEqual({ platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
    expect(sys.fs.opened).toEqual([EXE]);
    await setPin(pin);
    expect(currentPin()).toEqual(pin);
    expect(statSync(pinFile).mode & 0o777).toBe(0o644);
    const opts = { installed: INSTALLED_MAC };
    await expect(pinFor(sys, '/Users/a/unsigned', opts)).rejects.toThrow();
    await expect(pinFor(sys, 'relative', opts)).rejects.toThrow();
  });

  it('never pins code signed as anything but Vigil', async () => {
    const other = '/Users/a/Downloads/Other.app/Contents/MacOS/Other';
    sys.put(other, '16777220:300', machO('com.example.other', 'x'));
    await expect(pinFor(sys, other, { installed: INSTALLED_MAC })).rejects.toThrow(VIGIL_ID);
  });

  it('refuses a FIFO, folder or symlink at once, without codesign', async () => {
    const opts = { installed: INSTALLED_MAC };
    sys.fs.paths.set('/Users/a/fifo', '16777220:400');
    sys.fs.inodes.set('16777220:400', { kind: 'fifo' });
    sys.fs.paths.set('/Users/a/dir', '16777220:401');
    sys.fs.inodes.set('16777220:401', { kind: 'dir' });
    sys.fs.links.set('/Users/a/link', EXE);
    for (const path of ['/Users/a/fifo', '/Users/a/dir', '/Users/a/link'])
      await expect(pinFor(sys, path, opts), path).rejects.toThrow(/not a regular file/);
    expect(codesigns()).toEqual([]);
  });

  it('never mixes the identity and the hash of two files swapped in meanwhile', async () => {
    const opts = { installed: INSTALLED_MAC };
    // While the open file is hashed, another program takes its path...
    sys.fs.duringHash = () => sys.put(EXE, '16777220:200', machO(VIGIL_ID, 'other'));
    // ...so codesign, reading the path, no longer agrees with the bytes read: no pin.
    await expect(pinFor(sys, BUNDLE, opts)).rejects.toThrow(/changed/);
    // Swapped while codesign reads it, then put back: the open file never changed, and
    // codesign saw the other program, so still no pin.
    sys.fs.duringHash = undefined;
    sys.put(EXE, '16777220:100', V1);
    sys.duringCodesign = () => sys.put(EXE, '16777220:200', machO(VIGIL_ID, 'other'));
    await expect(pinFor(sys, BUNDLE, opts)).rejects.toThrow(/changed/);
  });

  it('pins nothing in /Applications, so nothing extra ever runs', async () => {
    const app = '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home';
    sys.put(app, '16777220:101', V1);
    expect(await pinFor(sys, app, { installed: INSTALLED_MAC })).toBeUndefined();
    expect(codesigns()).toEqual([]);
    expect(sys.fs.opened).toEqual([]);
  });

  describe('with a pin', () => {
    beforeEach(async () => {
      await setPin({ platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
    });

    it('never pauses or stops a process running the pinned code', async () => {
      const ex = new Executor(executorDeps(sys));
      for (const kind of ['process.suspend', 'process.kill'] as const)
        await expect(ex.execute({ kind, pid: APP, path: EXE })).rejects.toMatchObject({
          code: 'refused',
        });
      expect(sys.signals).toEqual([]);
      // Read from the running process, never from a file path.
      expect(codesigns()).toEqual([String(APP), String(APP)]);
      // A copy elsewhere runs the same code, so it is the app too.
      sys.processes.set(600, { path: '/tmp/copy/Vigil at Home', started: STARTED });
      sys.code.set('600', CDHASH);
      await expect(
        ex.execute({ kind: 'process.kill', pid: 600, path: '/tmp/copy/Vigil at Home' }),
      ).rejects.toMatchObject({ code: 'refused' });
    });

    it('treats a process that exec’d the pinned code as the app (accepted)', async () => {
      // pid 900 ran another program, then exec'd the pinned one: same pid and
      // start time, now running the pinned code. It is spared from then on;
      // the real app (pid 501) is a separate process either way.
      sys.processes.set(900, { path: '/tmp/evil', started: STARTED });
      sys.code.set('900', 'd'.repeat(40));
      const ex = new Executor(executorDeps(sys));
      await ex.execute({ kind: 'process.suspend', pid: 900, path: '/tmp/evil' });
      sys.processes.set(900, { path: EXE, started: STARTED });
      sys.code.set('900', CDHASH);
      await expect(ex.execute({ kind: 'process.kill', pid: 900, path: EXE })).rejects.toMatchObject(
        { code: 'refused' },
      );
      expect(sys.signals).toEqual([{ pid: 900, signal: 'SIGSTOP' }]);
    });

    it('stops a different program as before', async () => {
      sys.processes.set(777, { path: '/tmp/evil', started: STARTED });
      sys.code.set('777', 'd'.repeat(40));
      sys.processes.set(778, { path: '/tmp/unsigned', started: STARTED });
      const ex = new Executor(executorDeps(sys));
      await ex.execute({ kind: 'process.kill', pid: 777, path: '/tmp/evil' });
      await ex.execute({ kind: 'process.kill', pid: 778, path: '/tmp/unsigned' });
      expect(sys.signals.map((s) => s.pid)).toEqual([777, 778]);
    });

    it('neither spares nor hits a pid reused while codesign looked', async () => {
      const ex = new Executor(executorDeps(sys));
      // The process exits during codesign and another takes its pid.
      sys.duringCodesign = () =>
        sys.processes.set(APP, { path: '/tmp/evil', started: 'Tue Oct  6 09:00:00 2026' });
      await expect(ex.execute({ kind: 'process.kill', pid: APP, path: EXE })).rejects.toMatchObject(
        { code: 'refused' },
      );
      // And a pid already reused by another program fails the path check first.
      sys.duringCodesign = undefined;
      sys.code.set(String(APP), 'd'.repeat(40));
      await ex.execute({ kind: 'process.kill', pid: APP, path: '/tmp/evil' });
      expect(sys.signals).toEqual([{ pid: APP, signal: 'SIGKILL' }]);
    });

    it('refuses a hash block of the pinned program, and only that', async () => {
      const ex = new Executor(executorDeps(sys));
      for (const [ruleType, identifier] of [
        ['cdhash', CDHASH.toUpperCase()],
        ['binary', APP_SHA],
      ] as const)
        await expect(
          ex.execute({ kind: 'santa.rule.set', ruleType, identifier, policy: 'block' }),
        ).rejects.toMatchObject({ code: 'refused' });
      await ex.execute({
        kind: 'santa.rule.set',
        ruleType: 'cdhash',
        identifier: 'e'.repeat(40),
        policy: 'block',
      });
      // No process was looked at for a block.
      expect(codesigns()).toEqual([]);
    });
  });

  it('runs no codesign without a pin', async () => {
    const ex = new Executor(executorDeps(sys));
    await ex.execute({ kind: 'process.suspend', pid: APP, path: EXE });
    await ex.execute({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: APP_SHA,
      policy: 'block',
    });
    expect(sys.signals).toEqual([{ pid: APP, signal: 'SIGSTOP' }]);
    expect(codesigns()).toEqual([]);
  });

  it('runs no codesign for a program protected by path', async () => {
    await setPin({ platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
    const app = '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home';
    sys.processes.set(700, { path: app, started: STARTED });
    const ex = new Executor(executorDeps(sys));
    await expect(ex.execute({ kind: 'process.kill', pid: 700, path: app })).rejects.toMatchObject({
      code: 'refused',
    });
    expect(codesigns()).toEqual([]);
  });

  it('treats the installer’s folder alike for the pin and for stopping, in any case', async () => {
    await setPin({ platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
    const ex = new Executor(executorDeps(sys));
    let pid = 800;
    for (const app of [
      '/applications/vigil at home.app/Contents/MacOS/Vigil at Home',
      '/APPLICATIONS/Vigil At Home.app/Contents/MacOS/Vigil at Home',
    ]) {
      sys.put(app, `16777220:${pid}`, V1);
      expect(await pinFor(sys, app, { installed: INSTALLED_MAC }), app).toBeUndefined();
      expect(isProtectedProcess(app, 'darwin'), app).toBe(true);
      sys.processes.set(++pid, { path: app, started: STARTED });
      await expect(ex.execute({ kind: 'process.kill', pid, path: app })).rejects.toMatchObject({
        code: 'refused',
      });
    }
    expect(sys.signals).toEqual([]);
    expect(codesigns()).toEqual([]);
    // Linux paths keep their case: another folder there is not the installer's.
    expect(isProtectedProcess('/opt/Vigil at Home/vigil-at-home', 'linux')).toBe(true);
    expect(isProtectedProcess('/opt/vigil at home/vigil-at-home', 'linux')).toBe(false);
  });

  describe('re-pinned by an approved self grant', () => {
    const V2 = machO(VIGIL_ID, 'v2');
    const repin = (selfPaths: string[]) =>
      regrant(sys, { selfPaths }, { store, installed: INSTALLED_MAC });
    beforeEach(async () => {
      await setPin({ platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
      // The app in Downloads was updated: its code has a new cdhash.
      sys.put(EXE, '16777220:102', V2);
    });

    it('pins the executable the grant covers, by its cdhash on disk', async () => {
      const pin = await repin(['/Users/a/Library/not-code', BUNDLE]);
      expect(pin).toEqual({ platform: 'darwin', path: EXE, cdhash: V2.cdhash, sha256: V2.sha256 });
      expect(currentPin()).toEqual(pin);
    });

    it('leaves the pin alone for a grant inside /Applications or naming no code', async () => {
      const before = currentPin();
      const app = '/Applications/Vigil at Home.app';
      sys.put(`${app}/Contents/MacOS/Vigil at Home`, '16777220:103', V2);
      expect(await repin([app, '/Users/a/Library/not-code'])).toBeUndefined();
      expect(currentPin()).toEqual(before);
      expect(sys.runs.filter((r) => r.args.some((a) => a.startsWith(app)))).toEqual([]);
    });

    /** An executor wired as the daemon wires it. */
    const grantExecutor = () => {
      const opts = { installed: INSTALLED_MAC };
      const committed: AppPin[] = [];
      const ex = new Executor({
        ...executorDeps(sys),
        fastPath: new FastPath({
          file: join(root, 'helper-rules.json'),
          run: async () => {
            throw new Error('unused');
          },
        }),
        repin: {
          candidate: (grant) => pinCandidate(sys, grant, opts),
          commit: async (bound) => {
            const pin = await repinFromGrant(sys, bound, { ...opts, store });
            if (pin) committed.push(pin);
          },
        },
      });
      return { ex, committed };
    };
    const approve = async (ex: Executor, grant: HelperCommand) => {
      const ask = await ex.execute(grant);
      expect(ask.kind).toBe('needs_approval');
      const nonce = (ask as { nonce: string }).nonce;
      Approvals.writeApproval(join(root, 'approvals'), nonce);
      return nonce;
    };

    it('happens only when the password approved a grant', async () => {
      const { ex, committed } = grantExecutor();
      const grant: HelperCommand = { kind: 'self.grant', selfPaths: [BUNDLE] };
      const nonce = await approve(ex, grant);
      expect(committed).toEqual([]);
      // The code was read before the dialog, from the bundle the grant names.
      expect(sys.fs.opened).toEqual([EXE]);
      await ex.execute(grant, nonce);
      expect(committed).toEqual([
        { platform: 'darwin', path: EXE, cdhash: V2.cdhash, sha256: V2.sha256 },
      ]);
      expect(currentPin()).toEqual(committed[0]);
      // The same grant again names nothing new, needs no password, and re-pins nothing.
      await ex.execute(grant);
      expect(committed).toHaveLength(1);
    });

    it('pins only the code that was on disk when the password was asked for', async () => {
      const before = currentPin();
      const { ex, committed } = grantExecutor();
      const grant: HelperCommand = { kind: 'self.grant', selfPaths: [BUNDLE] };
      // Other code is put in place while the dialog is up.
      const nonce = await approve(ex, grant);
      sys.put(EXE, '16777220:104', machO(VIGIL_ID, 'v3'));
      expect((await ex.execute(grant, nonce)).kind).toBe('done');
      expect(committed).toEqual([]);
      expect(currentPin()).toEqual(before);
    });

    it('pins nothing for a grant naming code not signed as Vigil', async () => {
      const before = currentPin();
      const other = '/Users/a/Downloads/Other.app';
      sys.put(`${other}/Contents/MacOS/Other`, '16777220:105', machO('com.example.other', 'o'));
      const { ex, committed } = grantExecutor();
      const grant: HelperCommand = { kind: 'self.grant', selfPaths: [other] };
      await ex.execute(grant, await approve(ex, grant));
      expect(committed).toEqual([]);
      expect(currentPin()).toEqual(before);
    });
  });
});

describe('the app pinned at install (Linux AppImage)', () => {
  const image = '/home/alex/Apps/Vigil.AppImage';
  const mount = '/tmp/.mount_VigilaB1c2D';
  let sys: FakeLinuxSystem;
  // FakeFs gives a file without its own ctime and size ctime "1" and size 1.
  const pin: AppPin = {
    platform: 'linux',
    path: image,
    image: '2049:5501',
    ctime: '1',
    size: 1,
    sha256: APP_SHA,
  };
  const opts = { installed: ['/opt/Vigil at Home'] };

  beforeEach(() => {
    sys = new FakeLinuxSystem();
    sys.files.set(image, '2049:5501');
    sys.inodes.set('2049:5501', { sha256: APP_SHA });
    sys.mounts = [
      '22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw',
      '40 22 0:35 / /tmp rw,nosuid,nodev shared:20 - tmpfs tmpfs rw',
      `612 40 0:71 / ${mount} ro,nosuid,nodev,relatime shared:350 - fuse.Vigil.AppImage Vigil.AppImage ro,user_id=1000,group_id=1000`,
    ].join('\n');
    const proc = (pid: number, path: string, start: number, fds: [number, string][] = []) => {
      sys.processes.set(pid, { path, started: STARTED });
      sys.starts.set(pid, start);
      sys.fds.set(pid, fds);
    };
    // Vigil's main process, from the image's mount, and the mount server.
    proc(2000, `${mount}/vigil-at-home`, 500, [[3, 'pipe:[90001]']]);
    proc(2003, image, 501, [
      [4, 'pipe:[90001]'],
      [5, image],
      [6, '/dev/fuse'],
    ]);
    proc(2100, '/home/alex/.local/bin/tool', 900);
  });

  it('pins the AppImage by device and inode, and nothing in the installer’s folder', async () => {
    expect(await pinFor(sys, image, opts)).toEqual(pin);
    expect(await pinFor(sys, '/opt/Vigil at Home/vigil-at-home', opts)).toBeUndefined();
    await expect(pinFor(sys, '/home/alex/missing', opts)).rejects.toThrow();
  });

  it('refuses a FIFO, folder or symlink at once', async () => {
    sys.files.set('/home/alex/fifo.AppImage', '2049:8001');
    sys.inodes.set('2049:8001', { kind: 'fifo' });
    sys.files.set('/home/alex/dir.AppImage', '2049:8002');
    sys.inodes.set('2049:8002', { kind: 'dir' });
    sys.fs.links.set('/home/alex/link.AppImage', image);
    for (const path of ['/home/alex/fifo.AppImage', '/home/alex/dir.AppImage'])
      await expect(pinFor(sys, path, opts), path).rejects.toThrow(/not a regular file/);
    await expect(pinFor(sys, '/home/alex/link.AppImage', opts)).rejects.toThrow(
      /not a regular file/,
    );
    // Through a grant naming them, nothing is pinned either.
    const grant = {
      selfPaths: [],
      selfImages: [
        { path: '/home/alex/fifo.AppImage', id: '2049:8001' },
        { path: '/home/alex/link.AppImage', id: '2049:5501' },
      ],
    };
    expect(await regrant(sys, grant, { ...opts, store })).toBeUndefined();
  });

  it('never mixes the identity and the hash of two files swapped in meanwhile', async () => {
    // While the open image is hashed, another file takes its path.
    sys.inodes.set('2049:5502', { sha256: 'e'.repeat(64), ctime: '77', size: 9 });
    sys.fs.duringHash = () => sys.files.set(image, '2049:5502');
    // Device, inode, ctime, size and hash are all the first file's.
    expect(await pinFor(sys, image, opts)).toEqual(pin);
    // A grant naming the first file's id, after the swap, pins nothing.
    sys.fs.duringHash = undefined;
    const grant = { selfPaths: [], selfImages: [{ path: image, id: '2049:5501' }] };
    expect(await regrant(sys, grant, { ...opts, store })).toBeUndefined();
  });

  it('never stops Vigil running from the pinned image, or blocks the image by hash', async () => {
    await setPin(pin);
    const blocks = new FapolicydBlocks(sys, {
      store: join(root, 'blocked.json'),
      rulesDir: join(root, 'rules.d'),
    });
    const ex = new Executor({ ...executorDeps(sys), fapolicyd: blocks });
    await expect(
      ex.execute({ kind: 'process.kill', pid: 2000, path: `${mount}/vigil-at-home` }),
    ).rejects.toMatchObject({ code: 'refused' });
    const set = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: APP_SHA,
      policy: 'block',
    } as const;
    await expect(ex.execute(set)).rejects.toMatchObject({ code: 'refused' });
    expect(blocks.has(APP_SHA)).toBe(false);
    // Another program is stopped as before.
    await ex.execute({ kind: 'process.kill', pid: 2100, path: '/home/alex/.local/bin/tool' });
    expect(sys.signals.map((s) => s.pid)).toEqual([2100]);
  });

  it('spares nothing when the pin names another image, or there is none', async () => {
    await setPin({ ...pin, image: '2049:9999', sha256: 'b'.repeat(64) });
    const ex = new Executor(executorDeps(sys));
    await ex.execute({ kind: 'process.suspend', pid: 2000, path: `${mount}/vigil-at-home` });
    await setPin(undefined);
    await ex.execute({ kind: 'process.suspend', pid: 2000, path: `${mount}/vigil-at-home` });
    expect(sys.signals.map((s) => s.pid)).toEqual([2000, 2000]);
  });

  it('pins the image’s ctime and size, and checks its contents once they change', async () => {
    sys.inodes.set('2049:5501', {
      ctime: '1700000000123456789',
      size: 150_000_000,
      sha256: APP_SHA,
    });
    const pinned = await pinFor(sys, image, opts);
    expect(pinned).toEqual({ ...pin, ctime: '1700000000123456789', size: 150_000_000 });
    await setPin(pinned);
    let hashes = 0;
    sys.fs.duringHash = () => void hashes++;
    const ex = new Executor(executorDeps(sys));
    const kill = (pid: number) =>
      ex.execute({ kind: 'process.kill', pid, path: sys.processes.get(pid)!.path });
    // Unchanged: spared, and nothing hashed.
    await expect(kill(2000)).rejects.toMatchObject({ code: 'refused' });
    expect(hashes).toBe(0);
    // Rewritten in place, same inode, other contents: no exemption, for the
    // app on the mount or the runtime running the image itself.
    sys.inodes.set('2049:5501', {
      ctime: '1700000999000000000',
      size: 150_000_000,
      sha256: 'd'.repeat(64),
    });
    await kill(2000);
    await kill(2003);
    expect(sys.signals.map((s) => s.pid)).toEqual([2000, 2003]);
    expect(hashes).toBe(2);
    // Read through /proc, never through the image's path.
    expect(sys.fs.opened.filter((p) => p !== image)).toEqual([]);
    // Nor is an image pinned that was written to while it was being hashed.
    sys.fs.duringHash = () => sys.inodes.set('2049:5501', { ctime: '9', size: 1, sha256: APP_SHA });
    await expect(pinFor(sys, image, opts)).rejects.toThrow(/changed/);
  });

  it('spares a changed image whose contents still match the pin', async () => {
    await setPin({ ...pin, ctime: '5', size: 1 });
    sys.inodes.set('2049:5501', { ctime: '6', size: 1, sha256: APP_SHA }); // touched (chmod, say)
    let hashes = 0;
    sys.fs.duringHash = () => void hashes++;
    const ex = new Executor(executorDeps(sys));
    await expect(
      ex.execute({ kind: 'process.kill', pid: 2000, path: `${mount}/vigil-at-home` }),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(hashes).toBe(1);
    // A pin from before ctimes were kept is checked by contents too.
    await setPin({ platform: 'linux', path: image, image: '2049:5501', sha256: APP_SHA });
    sys.inodes.set('2049:5501', { ctime: '7', size: 1, sha256: 'e'.repeat(64) });
    await ex.execute({ kind: 'process.kill', pid: 2000, path: `${mount}/vigil-at-home` });
    expect(sys.signals.map((s) => s.pid)).toEqual([2000]);
  });

  it('pins an AppImage inside the installer’s folder like one anywhere else', async () => {
    const inOpt = '/opt/Vigil at Home/Vigil.AppImage';
    sys.files.set(inOpt, '2049:6601');
    sys.inodes.set('2049:6601', { sha256: APP_SHA });
    expect(await pinFor(sys, inOpt, opts)).toEqual({ ...pin, path: inOpt, image: '2049:6601' });
    // Through an approved grant too.
    const grant = { selfPaths: [], selfImages: [{ path: inOpt, id: '2049:6601' }] };
    expect(await regrant(sys, grant, { ...opts, store })).toMatchObject({
      path: inOpt,
      image: '2049:6601',
    });
    expect(currentPin()?.path).toBe(inOpt);
    // Told by its first bytes, whatever it is called.
    const renamed = '/opt/Vigil at Home/vigil';
    sys.files.set(renamed, '2049:6602');
    sys.inodes.set('2049:6602', {
      data: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0x41, 0x49, 2, 0, 0, 0, 0, 0]),
    });
    expect(await pinFor(sys, renamed, opts)).toMatchObject({ path: renamed, image: '2049:6602' });
    // An unpacked install there still needs no pin.
    const unpacked = '/opt/Vigil at Home/vigil-at-home';
    sys.files.set(unpacked, '2049:6603');
    sys.inodes.set('2049:6603', { data: Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]) });
    expect(await pinFor(sys, unpacked, opts)).toBeUndefined();
  });

  it('is re-pinned by an approved grant naming the image', async () => {
    const o = { ...opts, store };
    // An image that is no longer the file at its path is skipped.
    const moved = { path: '/home/alex/Old.AppImage', id: '2049:7777' };
    expect(await regrant(sys, { selfPaths: [], selfImages: [moved] }, o)).toBeUndefined();
    const elsewhere = { path: image, id: '2049:7777' };
    expect(await regrant(sys, { selfPaths: [], selfImages: [elsewhere] }, o)).toBeUndefined();
    expect(currentPin()).toBeUndefined();
    const grant = { selfPaths: [], selfImages: [{ path: image, id: '2049:5501' }] };
    expect(await regrant(sys, grant, o)).toEqual(pin);
    expect(currentPin()).toEqual(pin);
  });
});

describe('a FIFO on a real disk', () => {
  let dir: string;
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'vigil-fifo-'));
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  it.skipIf(process.platform === 'win32')(
    'is refused promptly as a pin candidate, on either system',
    { timeout: 5000 },
    async () => {
      const fifo = join(dir, 'Vigil.AppImage');
      execFileSync('mkfifo', [fifo]);
      const started = Date.now();
      const linux = realSystem(LINUX_BINARIES, 'linux');
      await expect(pinFor(linux, fifo, { installed: [] })).rejects.toThrow(/not a regular file/);
      const grant = { selfPaths: [], selfImages: [{ path: fifo, id: '1:1' }] };
      expect(await pinCandidate(linux, grant, { installed: [] })).toBeUndefined();
      const mac = realSystem(BINARIES, 'darwin');
      await expect(pinFor(mac, fifo, { installed: [] })).rejects.toThrow(/not a regular file/);
      expect(Date.now() - started).toBeLessThan(2000);
    },
  );
});
