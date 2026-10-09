import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { quarantine, restore, vetPath } from './commands/quarantine.js';
import { disablePersistence } from './commands/persistence.js';
import { isProtectedProcess } from './commands/process.js';
import { FakeSystem } from './testing/fakeSystem.js';

const opts = { quarantineDir: '/Library/Application Support/Vigil/Quarantine' };

describe('vetPath', () => {
  it("refuses Vigil's own helper, its runtime and the app", () => {
    for (const path of [
      '/Library/PrivilegedHelperTools/vigil-helper',
      '/Library/PrivilegedHelperTools/vigil-helper.d/node',
      '/Library/PrivilegedHelperTools/vigil-helper.d/helper.mjs',
      '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
    ]) {
      expect(() => vetPath(path, opts), path).toThrow(expect.objectContaining({ code: 'refused' }));
    }
  });

  it("refuses the helper's own state in its support folder, in any case", () => {
    for (const path of [
      '/Library/Application Support/Vigil',
      '/Library/Application Support/Vigil/santa-rules.json',
      '/Library/Application Support/Vigil/helper-journal.json',
      '/Library/Application Support/Vigil/helper-rules.json',
      '/Library/Application Support/Vigil/santa-sync',
      '/library/application support/vigil/santa-rules.json',
      '/APPLICATIONS/Santa.app',
    ]) {
      expect(() => vetPath(path, opts), path).toThrow(expect.objectContaining({ code: 'refused' }));
    }
  });

  it('still allows ordinary files next to them', () => {
    expect(vetPath('/Applications/Vigil at Home Evil.app', opts)).toBe(
      '/Applications/Vigil at Home Evil.app',
    );
    expect(vetPath('/Users/you/Downloads/evil', opts)).toBe('/Users/you/Downloads/evil');
    expect(vetPath('/Library/Application Support/Vigilant/x', opts)).toBe(
      '/Library/Application Support/Vigilant/x',
    );
  });
});

describe('protected processes', () => {
  it('never stops osquery on macOS', () => {
    expect(isProtectedProcess('/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd')).toBe(true);
    expect(isProtectedProcess('/usr/local/bin/osqueryd')).toBe(true);
    expect(isProtectedProcess('/usr/local/bin/other')).toBe(false);
  });
});

describe('restore', () => {
  let root: string;
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-restore-')));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('refuses to move back through a folder swapped for a symlink', () => {
    const q = { quarantineDir: join(root, 'Quarantine') };
    const dir = join(root, 'Downloads', 'stuff');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'evil'), 'x');
    const rec = quarantine(join(dir, 'evil'), 'a1', q);
    const elsewhere = join(root, 'elsewhere');
    mkdirSync(elsewhere);
    renameSync(dir, join(root, 'old'));
    symlinkSync(elsewhere, dir);
    expect(() => restore(rec, q)).toThrow(expect.objectContaining({ code: 'refused' }));
    expect(existsSync(join(elsewhere, 'evil'))).toBe(false);
    expect(existsSync(rec.storedPath)).toBe(true);
  });

  it('recreates a deleted folder and moves the file back', () => {
    const q = { quarantineDir: join(root, 'Quarantine') };
    const dir = join(root, 'Downloads', 'stuff');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'evil'), 'x');
    const rec = quarantine(join(dir, 'evil'), 'a2', q);
    rmSync(join(root, 'Downloads'), { recursive: true });
    restore(rec, q);
    expect(readFileSync(join(dir, 'evil'), 'utf8')).toBe('x');
  });
});

describe('disabling startup items', () => {
  let root: string;
  let launchDir: string;
  let sys: FakeSystem;
  const launchDirs = () => new RegExp('^' + launchDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');

  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-persist-')));
    launchDir = join(root, 'Library', 'LaunchDaemons');
    mkdirSync(launchDir, { recursive: true });
    sys = new FakeSystem();
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it("refuses Vigil's and the sensors' own plists before unloading anything", async () => {
    const q = { quarantineDir: join(root, 'Quarantine') };
    for (const name of [
      'com.vigilathome.helper.plist',
      'com.northpolesec.santa.daemon.plist',
      'com.google.santa.daemon.plist',
      'io.osquery.agent.plist',
    ]) {
      const path = join(launchDir, name);
      writeFileSync(path, '<plist/>');
      sys.labels.set(path, name.replace(/\.plist$/, ''));
      await expect(disablePersistence(sys, path, 'p', q, launchDirs())).rejects.toMatchObject({
        code: 'refused',
      });
      expect(existsSync(path)).toBe(true);
    }
    // Named innocently on disk, but Vigil's job inside.
    const renamed = join(launchDir, 'innocent.plist');
    writeFileSync(renamed, '<plist/>');
    sys.labels.set(renamed, 'com.vigilathome.helper');
    await expect(disablePersistence(sys, renamed, 'p', q, launchDirs())).rejects.toMatchObject({
      code: 'refused',
    });
    expect(existsSync(renamed)).toBe(true);
    expect(sys.runs.filter((r) => r.bin === 'launchctl')).toEqual([]);
  });

  it('vets the plist the way the quarantine will before unloading it', async () => {
    // The plist sits inside the quarantine folder, which is never moved from.
    const q = { quarantineDir: join(root, 'Library') };
    const path = join(launchDir, 'com.example.agent.plist');
    writeFileSync(path, '<plist/>');
    sys.labels.set(path, 'com.example.agent');
    await expect(disablePersistence(sys, path, 'p', q, launchDirs())).rejects.toMatchObject({
      code: 'refused',
    });
    expect(sys.runs).toEqual([]);
  });
});
