import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals } from './approval.js';
import {
  parseCodesignIdentity,
  pinFor,
  readPin,
  repinFromGrant,
  writePin,
  type AppPin,
} from './appPin.js';
import { Executor } from './executor.js';
import { FastPath } from './fastpath.js';
import { Journal } from './journal.js';
import type { HelperCommand } from './protocol.js';
import type { BinaryName, RunResult } from './system.js';
import { FapolicydBlocks } from './commands/fapolicyd.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const STARTED = 'Mon Oct  5 16:20:13 2026';
const CDHASH = 'c'.repeat(40);
const APP_SHA = 'a'.repeat(64);
const BUNDLE = '/Users/a/Downloads/Vigil at Home.app';
const EXE = `${BUNDLE}/Contents/MacOS/Vigil at Home`;
const INSTALLED_MAC = ['/Applications/Vigil at Home.app'];

let root: string;
let pinFile: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vigil-pin-'));
  pinFile = join(root, 'app-pin.json');
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const ok = (stdout = '', stderr = ''): RunResult => ({ code: 0, stdout, stderr });

/** macOS, with what codesign reads for each path or pid. */
class MacCode extends FakeSystem {
  /** target (path or pid) → [cdhash, main executable]. */
  code = new Map<string, [string, string]>();
  /** Runs while codesign looks at a pid, to stand in for the pid being reused meanwhile. */
  duringCodesign: (() => void) | undefined;

  override async run(bin: BinaryName, args: string[], opts: { input?: string } = {}) {
    if (bin !== 'codesign') return super.run(bin, args, opts);
    this.runs.push({ bin, args, input: opts.input });
    const target = args.at(-1)!;
    if (/^\d+$/.test(target)) this.duringCodesign?.();
    const c = this.code.get(target);
    return c
      ? ok('', `Executable=${c[1]}\nIdentifier=com.vigilathome.app\nCDHash=${c[0]}\n`)
      : { code: 1, stdout: '', stderr: 'code object is not signed at all' };
  }
}

const executorDeps = (sys: FakeSystem | FakeLinuxSystem) => ({
  sys,
  journal: new Journal(join(root, 'journal.json')),
  approvals: new Approvals({ dir: join(root, 'approvals'), requiredOwnerUid: process.getuid!() }),
  rules: new RuleStore(join(root, 'rules.json')),
  quarantine: { quarantineDir: join(root, 'Quarantine') },
  syncPort: 47821,
  appPin: pinFile,
});

it('reads the cdhash and main executable codesign prints', () => {
  expect(
    parseCodesignIdentity(`Executable=${EXE}\nIdentifier=x\nCDHash=${CDHASH}\nSignature=adhoc\n`),
  ).toEqual({ cdhash: CDHASH, executable: EXE });
  expect(parseCodesignIdentity('code object is not signed at all')).toBeUndefined();
});

describe('the app pinned at install (macOS)', () => {
  const APP = 501;
  let sys: MacCode;
  const codesigns = () => sys.runs.filter((r) => r.bin === 'codesign').map((r) => r.args.at(-1));

  beforeEach(() => {
    sys = new MacCode();
    sys.code.set(BUNDLE, [CDHASH, EXE]);
    sys.code.set(EXE, [CDHASH, EXE]);
    sys.code.set(String(APP), [CDHASH, EXE]);
    sys.processes.set(APP, { path: EXE, started: STARTED });
  });

  it('pins the cdhash and sha256 of the main executable', async () => {
    const pin = await pinFor(sys, BUNDLE, { installed: INSTALLED_MAC, sha256: () => APP_SHA });
    expect(pin).toEqual({ platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
    writePin(pinFile, pin);
    expect(readPin(pinFile)).toEqual(pin);
    expect(statSync(pinFile).mode & 0o777).toBe(0o644);
    const opts = { installed: INSTALLED_MAC, sha256: () => APP_SHA };
    await expect(pinFor(sys, '/Users/a/unsigned', opts)).rejects.toThrow();
    await expect(pinFor(sys, 'relative', opts)).rejects.toThrow();
  });

  it('pins nothing in /Applications, so nothing extra ever runs', async () => {
    const app = '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home';
    sys.code.set(app, [CDHASH, app]);
    expect(await pinFor(sys, app, { installed: INSTALLED_MAC })).toBeUndefined();
    expect(codesigns()).toEqual([]);
  });

  describe('with a pin', () => {
    beforeEach(() => {
      writePin(pinFile, { platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
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
      sys.code.set('600', [CDHASH, '/tmp/copy/Vigil at Home']);
      await expect(
        ex.execute({ kind: 'process.kill', pid: 600, path: '/tmp/copy/Vigil at Home' }),
      ).rejects.toMatchObject({ code: 'refused' });
    });

    it('stops a different program as before', async () => {
      sys.processes.set(777, { path: '/tmp/evil', started: STARTED });
      sys.code.set('777', ['d'.repeat(40), '/tmp/evil']);
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
      sys.code.set(String(APP), ['d'.repeat(40), '/tmp/evil']);
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
    writePin(pinFile, { platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
    const app = '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home';
    sys.processes.set(700, { path: app, started: STARTED });
    const ex = new Executor(executorDeps(sys));
    await expect(ex.execute({ kind: 'process.kill', pid: 700, path: app })).rejects.toMatchObject({
      code: 'refused',
    });
    expect(codesigns()).toEqual([]);
  });

  describe('re-pinned by an approved self grant', () => {
    const NEW = 'e'.repeat(40);
    const repin = (selfPaths: string[]) =>
      repinFromGrant(
        sys,
        { selfPaths },
        { pinFile, installed: INSTALLED_MAC, sha256: () => 'b'.repeat(64) },
      );
    beforeEach(() => {
      writePin(pinFile, { platform: 'darwin', path: EXE, cdhash: CDHASH, sha256: APP_SHA });
      // The app in Downloads was updated: its code has a new cdhash.
      sys.code.set(BUNDLE, [NEW, EXE]);
    });

    it('pins the executable the grant covers, by its cdhash on disk', async () => {
      const pin = await repin(['/Users/a/Library/not-code', BUNDLE]);
      expect(pin).toEqual({ platform: 'darwin', path: EXE, cdhash: NEW, sha256: 'b'.repeat(64) });
      expect(readPin(pinFile)).toEqual(pin);
    });

    it('leaves the pin alone for a grant inside /Applications or naming no code', async () => {
      const before = readPin(pinFile);
      const app = '/Applications/Vigil at Home.app';
      sys.code.set(app, [NEW, `${app}/Contents/MacOS/Vigil at Home`]);
      expect(await repin([app, '/Users/a/Library/not-code'])).toBeUndefined();
      expect(readPin(pinFile)).toEqual(before);
      expect(sys.runs.filter((r) => r.args.at(-1) === app)).toEqual([]);
    });

    it('happens only when the password approved a grant', async () => {
      const asked: HelperCommand[] = [];
      const fast = new FastPath({
        file: join(root, 'helper-rules.json'),
        run: async () => {
          throw new Error('unused');
        },
      });
      const ex = new Executor({
        ...executorDeps(sys),
        fastPath: fast,
        repin: async (grant) => void asked.push(grant),
      });
      const grant: HelperCommand = { kind: 'self.grant', selfPaths: [BUNDLE] };
      const ask = await ex.execute(grant);
      expect(ask.kind).toBe('needs_approval');
      expect(asked).toEqual([]);
      const nonce = (ask as { nonce: string }).nonce;
      Approvals.writeApproval(join(root, 'approvals'), nonce);
      await ex.execute(grant, nonce);
      expect(asked).toEqual([grant]);
      // The same grant again names nothing new, needs no password, and re-pins nothing.
      await ex.execute(grant);
      expect(asked).toHaveLength(1);
    });
  });
});

describe('the app pinned at install (Linux AppImage)', () => {
  const image = '/home/alex/Apps/Vigil.AppImage';
  const mount = '/tmp/.mount_VigilaB1c2D';
  let sys: FakeLinuxSystem;
  const pin: AppPin = { platform: 'linux', path: image, image: '2049:5501', sha256: APP_SHA };

  beforeEach(() => {
    sys = new FakeLinuxSystem();
    sys.files.set(image, '2049:5501');
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
    const opts = { installed: ['/opt/Vigil at Home'], sha256: () => APP_SHA };
    expect(await pinFor(sys, image, opts)).toEqual(pin);
    expect(await pinFor(sys, '/opt/Vigil at Home/vigil-at-home', opts)).toBeUndefined();
    await expect(pinFor(sys, '/home/alex/missing', opts)).rejects.toThrow();
  });

  it('never stops Vigil running from the pinned image, or blocks the image by hash', async () => {
    writePin(pinFile, pin);
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
    writePin(pinFile, { ...pin, image: '2049:9999', sha256: 'b'.repeat(64) });
    const ex = new Executor(executorDeps(sys));
    await ex.execute({ kind: 'process.suspend', pid: 2000, path: `${mount}/vigil-at-home` });
    writePin(pinFile, undefined);
    await ex.execute({ kind: 'process.suspend', pid: 2000, path: `${mount}/vigil-at-home` });
    expect(sys.signals.map((s) => s.pid)).toEqual([2000, 2000]);
  });

  it('is re-pinned by an approved grant naming the image', async () => {
    const opts = { pinFile, installed: ['/opt/Vigil at Home'], sha256: () => APP_SHA };
    // An image that is no longer the file at its path is skipped.
    const moved = { path: '/home/alex/Old.AppImage', id: '2049:7777' };
    expect(await repinFromGrant(sys, { selfPaths: [], selfImages: [moved] }, opts)).toBeUndefined();
    expect(readPin(pinFile)).toBeUndefined();
    const grant = { selfPaths: [], selfImages: [{ path: image, id: '2049:5501' }] };
    expect(await repinFromGrant(sys, grant, opts)).toEqual(pin);
    expect(readPin(pinFile)).toEqual(pin);
  });
});
