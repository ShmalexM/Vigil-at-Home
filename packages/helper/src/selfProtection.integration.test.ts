// Swaps made after the checks, against moves made as another user. These need
// root to act as another user, so they run in CI's root job (ci.yml runs
// *.integration.test.ts with sudo) and are skipped elsewhere.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  chmodSync,
  chownSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { quarantine, restore, type QuarantineOptions } from './commands/quarantine.js';
import { actorFor } from './commands/transfer.js';
import { realSystem } from './system.js';

const isRoot = process.getuid?.() === 0;
const NOBODY = 65534;
const modeOf = (p: string) => statSync(p).mode & 0o7777;

let root: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-self-')));
});
afterEach(() => {
  // The store locks what it keeps; open it up so it can be cleaned away.
  const q = join(root, 'Quarantine');
  if (existsSync(q)) chmodSync(q, 0o700);
  for (const slot of existsSync(q) ? readdirSync(q) : []) chmodSync(join(q, slot), 0o700);
  rmSync(root, { recursive: true, force: true });
});

/** The checks are done once the helper has picked who acts: swap things then. */
function afterChecks(swap: () => void): NonNullable<QuarantineOptions['actorFor']> {
  return async (s, path) => {
    const actor = await actorFor(s, path);
    swap();
    return actor;
  };
}

describe.skipIf(!isRoot)('moves made as the user (root only)', () => {
  /** A user's Downloads folder, owned by nobody, in a folder root keeps to itself. */
  function usersDownloads() {
    chmodSync(root, 0o755);
    const downloads = join(root, 'Downloads');
    const dir = join(downloads, 'stuff');
    mkdirSync(dir, { recursive: true });
    for (const d of [downloads, dir]) chownSync(d, NOBODY, NOBODY);
    const file = join(dir, 'evil');
    writeFileSync(file, 'x', { mode: 0o644 });
    chownSync(file, NOBODY, NOBODY);
    // Root's own folder, which the user can read but not change.
    const system = join(root, 'system');
    mkdirSync(system, { mode: 0o755 });
    const opts: QuarantineOptions = { quarantineDir: join(root, 'Quarantine') };
    return { downloads, dir, file, system, opts, real: realSystem() };
  }

  describe('a folder swapped for a link after the checks', () => {
    it('never takes a file from where the link leads (item 3)', async () => {
      const { downloads, dir, file, system, opts, real } = usersDownloads();
      writeFileSync(join(system, 'evil'), 'keep', { mode: 0o644 });
      const o: QuarantineOptions = {
        ...opts,
        actorFor: afterChecks(() => {
          renameSync(dir, join(downloads, 'old'));
          symlinkSync(system, dir);
        }),
      };
      await expect(quarantine(real, file, 'a', o)).rejects.toThrow();
      expect(readFileSync(join(system, 'evil'), 'utf8')).toBe('keep');
      expect(modeOf(join(system, 'evil'))).toBe(0o644);
      expect(readFileSync(join(downloads, 'old', 'evil'), 'utf8')).toBe('x');
    });

    it('never restores into a folder swapped for a link to another folder (item 5)', async () => {
      const { downloads, dir, file, system, opts, real } = usersDownloads();
      const rec = await quarantine(real, file, 'a', opts);
      const swap: QuarantineOptions = {
        ...opts,
        actorFor: afterChecks(() => {
          renameSync(dir, join(downloads, 'old'));
          symlinkSync(system, dir);
        }),
      };
      await expect(restore(real, rec, swap)).rejects.toThrow();
      expect(existsSync(join(system, 'evil'))).toBe(false);
      expect(existsSync(join(downloads, 'old', 'evil'))).toBe(false);
      // Back in the store, locked again.
      expect(modeOf(rec.storedPath)).toBe(0);
    });

    it('never recreates a missing folder through a swapped parent (item 5)', async () => {
      const { downloads, dir, file, system, opts, real } = usersDownloads();
      const rec = await quarantine(real, file, 'a', opts);
      rmSync(dir, { recursive: true });
      const swap: QuarantineOptions = {
        ...opts,
        actorFor: afterChecks(() => {
          renameSync(downloads, join(root, 'old'));
          symlinkSync(system, downloads);
        }),
      };
      await expect(restore(real, rec, swap)).rejects.toThrow();
      expect(existsSync(join(system, 'stuff'))).toBe(false);
      expect(modeOf(rec.storedPath)).toBe(0);
    });
  });

  describe('restore', () => {
    // The user's side of a move runs as the user, so a folder they swap for a
    // link leads only where they could already write.
    it('never moves back through a folder swapped for a symlink', async () => {
      chmodSync(root, 0o755);
      const q: QuarantineOptions = { quarantineDir: join(root, 'Quarantine') };
      const downloads = join(root, 'Downloads');
      const dir = join(downloads, 'stuff');
      mkdirSync(dir, { recursive: true });
      for (const d of [downloads, dir]) chownSync(d, NOBODY, NOBODY);
      writeFileSync(join(dir, 'evil'), 'x');
      chownSync(join(dir, 'evil'), NOBODY, NOBODY);
      const real = realSystem();
      const rec = await quarantine(real, join(dir, 'evil'), 'a1', q);
      // Root's own folder, which the user can't write to.
      const elsewhere = join(root, 'elsewhere');
      mkdirSync(elsewhere, { mode: 0o755 });
      renameSync(dir, join(downloads, 'old'));
      symlinkSync(elsewhere, dir);
      await expect(restore(real, rec, q)).rejects.toThrow();
      expect(existsSync(join(elsewhere, 'evil'))).toBe(false);
      expect(existsSync(rec.storedPath)).toBe(true);
    });
  });
});
