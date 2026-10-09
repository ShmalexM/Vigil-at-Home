// On a real Mac disk, other spellings of a protected path name the same
// file: a different Unicode form or letter case. Protection is decided by
// identity, so every spelling is refused. Runs in the macOS workflow.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  chmodSync,
  chownSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { quarantine, restore, type QuarantineOptions } from './commands/quarantine.js';
import { realSystem } from './system.js';

const enabled = process.platform === 'darwin' && process.env.VIGIL_MAC_INTEGRATION === '1';
const sys = realSystem();

describe.skipIf(!enabled)('protection by identity on APFS', () => {
  let root: string;
  let opts: QuarantineOptions;
  const composed = 'Vigil Café';
  const decomposed = 'vigil café';

  beforeAll(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-apfs-')));
    mkdirSync(join(root, composed));
    writeFileSync(join(root, composed, 'node'), 'runtime', { mode: 0o755 });
    opts = { quarantineDir: join(root, 'Quarantine'), selfPaths: [join(root, composed)] };
  });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it('refuses another Unicode form and case of a protected folder', async () => {
    for (const spelling of [decomposed, composed.toUpperCase(), decomposed.toUpperCase()]) {
      await expect(
        quarantine(sys, join(root, spelling, 'node'), 'a', opts),
        spelling,
      ).rejects.toMatchObject({ code: 'refused' });
      await expect(
        quarantine(sys, join(root, spelling), 'b', opts),
        spelling,
      ).rejects.toMatchObject({ code: 'refused' });
    }
    expect(readFileSync(join(root, composed, 'node'), 'utf8')).toBe('runtime');
  });

  it('still quarantines and restores an ordinary file of a user’s, folder and all', async () => {
    // The user who runs the tests (under sudo, the owner of the temporary folder).
    const user = Number(process.env.SUDO_UID ?? statSync(tmpdir()).uid);
    chmodSync(root, 0o755);
    const downloads = join(root, 'Downloads');
    const dir = join(downloads, 'stuff');
    mkdirSync(dir, { recursive: true, mode: 0o750 });
    chmodSync(dir, 0o750);
    for (const d of [downloads, dir]) chownSync(d, user, 20);
    writeFileSync(join(dir, 'evil'), 'x', { mode: 0o755 });
    chownSync(join(dir, 'evil'), user, 20);
    const rec = await quarantine(sys, join(dir, 'evil'), 'c', opts);
    rmSync(dir, { recursive: true });
    await restore(sys, rec, opts);
    expect(readFileSync(join(dir, 'evil'), 'utf8')).toBe('x');
    expect(statSync(dir).mode & 0o777).toBe(0o750);
    expect(statSync(dir).uid).toBe(user);
  });
});
