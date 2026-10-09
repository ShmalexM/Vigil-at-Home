// On a real Mac disk, other spellings of a protected path name the same
// file: a different Unicode form or letter case. Protection is decided by
// identity, so every spelling is refused. Runs in the macOS workflow.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { quarantine, restore, type QuarantineOptions } from './commands/quarantine.js';

const enabled = process.platform === 'darwin' && process.env.VIGIL_MAC_INTEGRATION === '1';

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

  it('refuses another Unicode form and case of a protected folder', () => {
    for (const spelling of [decomposed, composed.toUpperCase(), decomposed.toUpperCase()]) {
      expect(() => quarantine(join(root, spelling, 'node'), 'a', opts), spelling).toThrow(
        expect.objectContaining({ code: 'refused' }),
      );
      expect(() => quarantine(join(root, spelling), 'b', opts), spelling).toThrow(
        expect.objectContaining({ code: 'refused' }),
      );
    }
    expect(readFileSync(join(root, composed, 'node'), 'utf8')).toBe('runtime');
  });

  it('still quarantines and restores an ordinary file through the working-folder pin', () => {
    const dir = join(root, 'Downloads');
    mkdirSync(dir);
    writeFileSync(join(dir, 'evil'), 'x', { mode: 0o755 });
    const o: QuarantineOptions = { ...opts, pinning: 'cwd' };
    const rec = quarantine(join(dir, 'evil'), 'c', o);
    rmSync(dir, { recursive: true });
    restore(rec, o);
    expect(readFileSync(join(dir, 'evil'), 'utf8')).toBe('x');
  });
});
