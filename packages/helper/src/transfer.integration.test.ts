// The moves as they run for real: root hands each side of a move to the
// user who controls it. These need root to act as another user, so they run
// in CI's root job (ci.yml runs *.integration.test.ts with sudo) and are
// skipped elsewhere.

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
import { actorFor, type Actor } from './commands/transfer.js';
import { quarantine, restore, type QuarantineOptions } from './commands/quarantine.js';
import { AppPinStore } from './pinStore.js';
import { realSystem, type RunResult, type System } from './system.js';

const isRoot = process.getuid?.() === 0;
/** The unprivileged user these tests act as. */
const NOBODY = 65534;

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vigil-transfer-'));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

function readdirNames(path: string): string[] {
  return spawnSync('ls', ['-A', path]).stdout.toString().split('\n').filter(Boolean);
}

describe.skipIf(!isRoot)('moves made as another user (root only)', () => {
  describe('who acts on a path', () => {
    it('is the folder’s owner for a user’s folder, and refuses root’s file in a shared one', async () => {
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
        code: 'installer-owned',
      });
    });
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

  describe('moves as the user (root only)', () => {
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
      expect(readdirNames(pinDir).sort()).toEqual(['app-pin.gen', 'app-pin.json', 'app-pin.key']);
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

  describe('a root folder with something others can change inside', () => {
    it('is not root’s to move', async () => {
      const sys = realSystem(undefined, 'linux');
      chmodSync(root, 0o755);
      const item = join(root, 'svc');
      mkdirSync(join(item, 'inner'), { recursive: true });
      expect(await actorFor(sys, item)).toEqual({ uid: 0, gid: 0 });
      chmodSync(join(item, 'inner'), 0o777);
      await expect(actorFor(sys, item)).rejects.toMatchObject({ code: 'installer-owned' });
    });
  });

  describe('restoring what a user owns', () => {
    it('restores a user’s folder as that user, never as root', async () => {
      const sys = realSystem(undefined, 'linux');
      chmodSync(root, 0o755);
      const home = join(root, 'home');
      mkdirSync(home);
      chownSync(home, NOBODY, NOBODY);
      const app = join(home, 'Tool');
      mkdirSync(join(app, 'bin'), { recursive: true });
      writeFileSync(join(app, 'bin', 'run'), 'x');
      spawnSync('chown', ['-R', `${NOBODY}:${NOBODY}`, app]);
      const opts: QuarantineOptions = {
        quarantineDir: join(root, 'Quarantine'),
        platform: 'linux',
        protectedPrefixes: [],
      };
      const rec = await quarantine(sys, app, 'r1', opts);
      await restore(sys, rec, opts);
      for (const p of [app, join(app, 'bin'), join(app, 'bin', 'run')])
        expect(statSync(p).uid, p).toBe(NOBODY);
    });

    it('refuses, calmly, when the owner can’t write where it goes back (records from before too)', async () => {
      const sys = realSystem(undefined, 'linux');
      chmodSync(root, 0o755);
      // A record as the old code left it: the user's tree renamed into the store as it was.
      const q = join(root, 'Quarantine');
      mkdirSync(join(q, 'old'), { recursive: true, mode: 0o700 });
      const stored = join(q, 'old', 'agent');
      mkdirSync(stored);
      writeFileSync(join(stored, 'x.plist'), 'x');
      spawnSync('chown', ['-R', `${NOBODY}:${NOBODY}`, stored]);
      // Where it goes back is another user's folder, which its owner can't write to.
      const sysDir = join(root, 'etc');
      mkdirSync(sysDir);
      chownSync(sysDir, NOBODY - 1, NOBODY - 1);
      const rec = {
        originalPath: join(sysDir, 'agent'),
        storedPath: stored,
        mode: 0o755,
        uid: NOBODY,
        gid: NOBODY,
        isDirectory: true,
      };
      const opts: QuarantineOptions = {
        quarantineDir: q,
        platform: 'linux',
        protectedPrefixes: [],
      };
      await expect(restore(sys, rec, opts)).rejects.toMatchObject({ code: 'owner-cannot-write' });
      expect(existsSync(rec.originalPath)).toBe(false);
      expect(existsSync(join(stored, 'x.plist'))).toBe(true);
      // More than one owner: refused before anything is placed.
      chownSync(join(stored, 'x.plist'), NOBODY - 1, NOBODY - 1);
      await expect(restore(sys, rec, opts)).rejects.toMatchObject({ code: 'owner-cannot-write' });
    });

    it('puts a user’s item back into a folder only root can change, as root, with its owners', async () => {
      const sys = realSystem(undefined, 'linux');
      chmodSync(root, 0o755);
      // A user's plist in a root-only folder (like /Library/LaunchDaemons).
      const daemons = join(root, 'LaunchDaemons');
      mkdirSync(daemons, { mode: 0o755 });
      const plist = join(daemons, 'com.example.agent.plist');
      writeFileSync(plist, 'x', { mode: 0o644 });
      chownSync(plist, NOBODY, NOBODY - 1);
      const opts: QuarantineOptions = {
        quarantineDir: join(root, 'Quarantine'),
        platform: 'linux',
        protectedPrefixes: [],
      };
      const rec = await quarantine(sys, plist, 'ld1', opts);
      await restore(sys, rec, opts);
      const st = statSync(plist);
      expect([st.uid, st.gid, st.mode & 0o777]).toEqual([NOBODY, NOBODY - 1, 0o644]);
      // A folder holding more than one user's things goes back whole, each with its owner.
      const tool = join(daemons, 'tool');
      mkdirSync(join(tool, 'bin'), { recursive: true, mode: 0o755 });
      writeFileSync(join(tool, 'bin', 'run'), 'x');
      chownSync(join(tool, 'bin', 'run'), NOBODY - 1, NOBODY - 1);
      chmodSync(join(tool, 'bin', 'run'), 0o4755);
      const rec2 = await quarantine(sys, tool, 'ld2', opts);
      await restore(sys, rec2, opts);
      expect(statSync(tool).uid).toBe(0);
      const run = statSync(join(tool, 'bin', 'run'));
      // The change of owner clears setuid; the placer sets the mode again after it.
      expect([run.uid, run.gid, run.mode & 0o7777]).toEqual([NOBODY - 1, NOBODY - 1, 0o4755]);
    });
  });

  describe('a mount inside an item', () => {
    it('is never crossed, so root never moves what another disk holds', async (ctx) => {
      if (process.platform !== 'linux') return ctx.skip();
      const sys = realSystem(undefined, 'linux');
      chmodSync(root, 0o755);
      // A root-owned tree with another filesystem mounted inside it, as a bind
      // mount of a system folder would be.
      const item = join(root, 'svc');
      const inner = join(item, 'usr');
      mkdirSync(inner, { recursive: true, mode: 0o755 });
      writeFileSync(join(item, 'top'), 'x');
      if (spawnSync('mount', ['-t', 'tmpfs', '-o', 'mode=0755', 'none', inner]).status !== 0)
        return ctx.skip();
      try {
        writeFileSync(join(inner, 'system-file'), 'keep');
        expect(statSync(inner).dev).not.toBe(statSync(item).dev);
        const opts: QuarantineOptions = {
          quarantineDir: join(root, 'Quarantine'),
          platform: 'linux',
          protectedPrefixes: [],
        };
        expect(await actorFor(sys, item)).toEqual({ uid: 0, gid: 0 });
        await expect(quarantine(sys, item, 'mnt', opts)).rejects.toThrow(/another disk/);
        expect(readFileSync(join(inner, 'system-file'), 'utf8')).toBe('keep');
        expect(readFileSync(join(item, 'top'), 'utf8')).toBe('x');
        expect(existsSync(join(root, 'Quarantine', 'mnt'))).toBe(false);
      } finally {
        spawnSync('umount', [inner]);
      }
    });
  });

  describe('folders made again on restore', () => {
    it('are never left open to others when root makes them', async () => {
      const sys = realSystem(undefined, 'linux');
      chmodSync(root, 0o755);
      const sub = join(root, 'etc', 'sub');
      mkdirSync(sub, { recursive: true, mode: 0o755 });
      writeFileSync(join(sub, 'unit.service'), 'x');
      const opts: QuarantineOptions = {
        quarantineDir: join(root, 'Quarantine'),
        platform: 'linux',
        protectedPrefixes: [],
      };
      const rec = await quarantine(sys, join(sub, 'unit.service'), 'fm', opts);
      expect(rec.parent?.mode).toBe(0o755);
      // A record that says the folder was open to everyone.
      rmSync(sub, { recursive: true });
      await restore(sys, { ...rec, parent: { ...rec.parent!, mode: 0o777 } }, opts);
      expect(statSync(sub).mode & 0o777).toBe(0o755);
      expect(statSync(sub).uid).toBe(0);
    });
  });
});
