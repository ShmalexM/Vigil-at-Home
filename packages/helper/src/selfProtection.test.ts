// The helper must never let a containment action move, lock or unload Vigil,
// Santa or osquery: not by another spelling, not through a hard link, and not
// by swapping a file or folder between the checks and the move. Each side of
// a move runs as the user who controls it (transfer.ts), so what is swapped
// in late is only ever copied as that user could copy it.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  chmodSync,
  chownSync,
  existsSync,
  linkSync,
  lstatSync,
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
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  quarantine,
  resolveTarget,
  restore,
  vetPath,
  type QuarantineOptions,
} from './commands/quarantine.js';
import { protectedPaths } from './commands/protectedSet.js';
import { disablePersistence } from './commands/persistence.js';
import { disableLinuxPersistence, parseShow, startCommands } from './commands/linuxPersistence.js';
import { actorFor, self } from './commands/transfer.js';
import { realSystem } from './system.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const isRoot = process.getuid?.() === 0;
const NOBODY = 65534;
const modeOf = (p: string) => statSync(p).mode & 0o7777;
const sys = new FakeSystem();

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

/** A stand-in for Vigil's own files, protected through selfPaths, and a user's Downloads. */
function setup(extra: Partial<QuarantineOptions> = {}) {
  const helper = join(root, 'helper.d');
  mkdirSync(helper);
  const runtime = join(helper, 'node');
  writeFileSync(runtime, 'runtime', { mode: 0o755 });
  const downloads = join(root, 'Downloads');
  mkdirSync(join(downloads, 'stuff'), { recursive: true });
  const opts: QuarantineOptions = {
    quarantineDir: join(root, 'Quarantine'),
    selfPaths: [helper],
    // Moves run as the tests' own user.
    actorFor: async () => self(),
    ...extra,
  };
  return { helper, runtime, downloads, opts };
}

describe('protection by identity, not spelling (item 1)', () => {
  it('refuses a protected folder reached by a spelling the name checks do not know', async () => {
    const { helper, opts } = setup();
    // Protected under another name: only its identity links the two.
    const alias = join(root, 'alias');
    symlinkSync(helper, alias);
    const o = { ...opts, selfPaths: [alias] };
    expect(() => vetPath(join(helper, 'node'), o)).not.toThrow();
    await expect(quarantine(sys, join(helper, 'node'), 'a', o)).rejects.toMatchObject({
      code: 'refused',
    });
    await expect(quarantine(sys, helper, 'b', o)).rejects.toMatchObject({ code: 'refused' });
    expect(statSync(join(helper, 'node')).mode & 0o777).toBe(0o755);
  });

  it('refuses a folder that holds a protected path', async () => {
    const { helper, opts } = setup();
    const outer = join(root, 'outer');
    mkdirSync(outer);
    renameSync(helper, join(outer, 'helper.d'));
    const o = { ...opts, selfPaths: [join(outer, 'helper.d')] };
    await expect(quarantine(sys, outer, 'a', o)).rejects.toMatchObject({ code: 'refused' });
    expect(existsSync(join(outer, 'helper.d', 'node'))).toBe(true);
  });

  it('keeps the name checks: .., macOS case, and a stable symlinked parent', async () => {
    const { downloads, opts } = setup();
    expect(() => vetPath('/Users/you/../../Library/x', opts)).toThrow(
      expect.objectContaining({ code: 'invalid' }),
    );
    expect(() => vetPath('/LIBRARY/launchdaemons/com.vigilathome.helper.plist', opts)).toThrow(
      expect.objectContaining({ code: 'refused' }),
    );
    writeFileSync(join(downloads, 'stuff', 'evil'), 'x');
    const link = join(root, 'dl');
    symlinkSync(downloads, link);
    const rec = await quarantine(sys, join(link, 'stuff', 'evil'), 'a', opts);
    expect(rec.originalPath).toBe(join(downloads, 'stuff', 'evil'));
    await restore(sys, rec, opts);
    expect(readFileSync(join(downloads, 'stuff', 'evil'), 'utf8')).toBe('x');
  });
});

describe("Vigil's and the sensors' files are protected from quarantine (item 2)", () => {
  it('refuses the helper, its plist, socket and folder, Santa and osquery on macOS', () => {
    const opts = { quarantineDir: '/Library/Application Support/Vigil/Quarantine' };
    for (const path of [
      '/opt/osquery',
      '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd',
      '/Library/LaunchDaemons/com.vigilathome.helper.plist',
      '/Library/LaunchDaemons/io.osquery.agent.plist',
      '/var/run/vigil-helper.sock',
      '/Library/PrivilegedHelperTools',
      '/Library/PrivilegedHelperTools/vigil-helper',
      '/Applications/Santa.app',
      '/var/db/santa/rules.db',
      '/Library/Application Support',
    ]) {
      expect(() => vetPath(path, opts), path).toThrow(expect.objectContaining({ code: 'refused' }));
    }
  });

  it("refuses the helper's and the sensors' units and files on Linux", () => {
    const opts = { quarantineDir: '/var/lib/vigil/quarantine', platform: 'linux' as const };
    const paths = protectedPaths(opts).inside;
    for (const p of [
      '/etc/systemd/system/vigil-helper.service',
      '/etc/systemd/system/osqueryd.service',
      '/usr/lib/systemd/system/fapolicyd.service',
      '/etc/systemd/system/vigil-helper.service.d',
      '/etc/fapolicyd',
      '/opt/osquery',
      '/run/vigil-helper.sock',
    ]) {
      expect(paths, p).toContain(p);
    }
    // /etc is open to the startup-item code, but these stay refused there too.
    const startup = { ...opts, protectedPrefixes: ['/usr/bin/'] };
    for (const path of [
      '/etc/systemd/system/vigil-helper.service',
      '/etc/fapolicyd/rules.d/05-vigil.rules',
      '/etc/osquery/osquery.conf',
      '/etc/systemd/system',
    ]) {
      expect(() => vetPath(path, startup), path).toThrow(
        expect.objectContaining({ code: 'refused' }),
      );
    }
    expect(vetPath('/etc/systemd/system/miner.service', startup)).toBe(
      '/etc/systemd/system/miner.service',
    );
  });

  it("refuses the quarantine itself and anything holding the helper's files, by identity", async () => {
    const { helper, opts } = setup();
    expect(() => resolveTarget(helper, opts)).toThrow(expect.objectContaining({ code: 'refused' }));
    mkdirSync(opts.quarantineDir);
    const other = join(root, 'q-alias');
    symlinkSync(opts.quarantineDir, other);
    await expect(quarantine(sys, join(other, 'x'), 'a', { ...opts })).rejects.toMatchObject({
      code: 'refused',
    });
  });
});

/** The checks are done once the helper has picked who acts: swap things then. */
function afterChecks(swap: () => void): NonNullable<QuarantineOptions['actorFor']> {
  return async (s, path) => {
    const actor = isRoot ? await actorFor(s, path) : self();
    swap();
    return actor;
  };
}

describe('moves made after the checks (item 3)', () => {
  it('never changes a protected file swapped in for the target', async () => {
    const { runtime, downloads, opts } = setup();
    const target = join(downloads, 'stuff', 'evil');
    writeFileSync(target, 'x', { mode: 0o644 });
    const o: QuarantineOptions = {
      ...opts,
      actorFor: afterChecks(() => {
        renameSync(target, join(downloads, 'stuff', 'moved'));
        symlinkSync(runtime, target);
      }),
    };
    // The child moving it sees it is not what was checked, and refuses.
    await expect(quarantine(sys, target, 'a', o)).rejects.toThrow(/changed after it was checked/);
    expect(modeOf(runtime)).toBe(0o755);
    expect(readFileSync(runtime, 'utf8')).toBe('runtime');
    expect(lstatSync(target).isSymbolicLink()).toBe(true);
    expect(existsSync(join(opts.quarantineDir, 'a'))).toBe(false);
  });

  it('locks the stored copy and gives the mode back on restore', async () => {
    const { downloads, opts } = setup();
    const target = join(downloads, 'stuff', 'evil');
    writeFileSync(target, 'x', { mode: 0o755 });
    const rec = await quarantine(sys, target, 'a', opts);
    expect(modeOf(rec.storedPath)).toBe(0);
    await restore(sys, rec, opts);
    expect(modeOf(target)).toBe(0o755);
  });

  it('refuses FIFOs and other special files without waiting on them', async () => {
    const { downloads, opts } = setup();
    const fifo = join(downloads, 'stuff', 'pipe');
    execFileSync('mkfifo', [fifo]);
    await expect(quarantine(sys, fifo, 'a', opts)).rejects.toMatchObject({ code: 'refused' });
  });
});

describe('hard links (item 4)', () => {
  it('refuses hard links, to protected files or not, and leaves one swapped in late as it was', async () => {
    const { runtime, downloads, opts } = setup();
    const link = join(downloads, 'stuff', 'evil');
    linkSync(runtime, link);
    await expect(quarantine(sys, link, 'a', opts)).rejects.toMatchObject({ code: 'refused' });
    rmSync(link);
    // Not protected, but locking it would lock its other name too.
    const plain = join(downloads, 'plain');
    writeFileSync(plain, 'x');
    linkSync(plain, link);
    await expect(quarantine(sys, link, 'b', opts)).rejects.toThrow(/hard links/);
    rmSync(link);
    rmSync(plain);

    writeFileSync(link, 'x', { mode: 0o644 });
    const late: QuarantineOptions = {
      ...opts,
      actorFor: afterChecks(() => {
        rmSync(link);
        linkSync(runtime, link);
      }),
    };
    await expect(quarantine(sys, link, 'c', late)).rejects.toThrow(/changed after it was checked/);
    // The protected file is never locked or changed, and its other name stays.
    expect(modeOf(runtime)).toBe(0o755);
    expect(readFileSync(runtime, 'utf8')).toBe('runtime');
    expect(statSync(link).ino).toBe(statSync(runtime).ino);
    expect(existsSync(join(opts.quarantineDir, 'c'))).toBe(false);
  });
});

describe('recreating missing folders (item 6)', () => {
  it('makes them for the item’s owner, the inner one with the recorded mode', async () => {
    const owner = isRoot ? NOBODY : process.getuid!();
    const { downloads, opts: base } = setup();
    const o: QuarantineOptions = isRoot ? { quarantineDir: base.quarantineDir } : base;
    const s = isRoot ? realSystem() : sys;
    if (isRoot) chmodSync(root, 0o755);
    const stuff = join(downloads, 'stuff');
    const inner = join(stuff, 'inner');
    mkdirSync(inner, { mode: 0o750 });
    chmodSync(inner, 0o750);
    if (isRoot) for (const d of [downloads, stuff, inner]) chownSync(d, owner, owner);
    writeFileSync(join(inner, 'evil'), 'x');
    if (isRoot) chownSync(join(inner, 'evil'), owner, owner);
    const rec = await quarantine(s, join(inner, 'evil'), 'a', o);
    expect(rec.parent).toMatchObject({ uid: owner, mode: 0o750 });
    rmSync(stuff, { recursive: true });
    await restore(s, rec, o);
    expect(readFileSync(join(inner, 'evil'), 'utf8')).toBe('x');
    expect(modeOf(inner)).toBe(0o750);
    expect(modeOf(stuff)).toBe(0o755);
    expect(statSync(inner).uid).toBe(owner);
    expect(statSync(stuff).uid).toBe(owner);
    expect(statSync(join(inner, 'evil')).uid).toBe(owner);
  });
});

describe('startup items that run Vigil or a sensor under another name (item 7)', () => {
  it('macOS: refuses a plist with any label whose program is osquery or the helper', async () => {
    const launchDir = join(root, 'LaunchDaemons');
    mkdirSync(launchDir);
    const re = new RegExp('^' + launchDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
    const sys = new FakeSystem();
    sys.console = process.getuid!();
    const { helper, opts } = setup();
    for (const [i, program] of [
      '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd',
      '/Library/PrivilegedHelperTools/vigil-helper',
      join(helper, 'node'),
      'osqueryd',
    ].entries()) {
      const path = join(launchDir, `com.example.item${i}.plist`);
      // Each its own bytes: plutil reads them from stdin.
      writeFileSync(path, `<plist><!-- ${i} --></plist>`);
      sys.labels.set(path, `com.example.item${i}`);
      sys.programs.set(path, program);
      sys.loaded.add(`system/com.example.item${i}`);
      await expect(disablePersistence(sys, path, 'p', opts, re), program).rejects.toMatchObject({
        code: 'refused',
      });
    }
    // Through a link to the helper's files, too.
    const link = join(root, 'innocent-binary');
    symlinkSync(join(helper, 'node'), link);
    const path = join(launchDir, 'com.example.link.plist');
    writeFileSync(path, '<plist><!-- link --></plist>');
    sys.programs.set(path, link);
    await expect(disablePersistence(sys, path, 'p', opts, re)).rejects.toMatchObject({
      code: 'refused',
    });
    expect(sys.runs.filter((r) => r.bin === 'launchctl')).toEqual([]);
  });

  it('Linux: refuses an alias of a protected unit or one that starts a sensor', async () => {
    const unitDir = join(root, 'home', 'alex', '.config', 'systemd', 'user');
    const autostart = join(root, 'home', 'alex', '.config', 'autostart');
    mkdirSync(unitDir, { recursive: true });
    mkdirSync(autostart, { recursive: true });
    const re = new RegExp(
      '^(' +
        [unitDir, autostart].map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') +
        ')$',
    );
    const sys = new FakeLinuxSystem();
    sys.console = process.getuid!();
    const passwd = () => `alex:x:${process.getuid!()}:0::/home/alex:/bin/bash\n`;
    const q: QuarantineOptions = {
      quarantineDir: join(root, 'quarantine'),
      actorFor: async () => self(),
    };

    const alias = join(unitDir, 'innocent.service');
    writeFileSync(alias, '[Service]\nExecStart=/home/alex/x\n');
    sys.shown.set(
      'innocent.service',
      'Id=osqueryd.service\nNames=osqueryd.service innocent.service\n',
    );
    sys.active.add('user:alex innocent.service');
    await expect(disableLinuxPersistence(sys, alias, 'a', q, re, passwd)).rejects.toMatchObject({
      code: 'refused',
    });

    const runs = join(unitDir, 'runs.service');
    writeFileSync(runs, '[Service]\nExecStart=-/opt/osquery/bin/osqueryd --flagfile x\n');
    await expect(disableLinuxPersistence(sys, runs, 'b', q, re, passwd)).rejects.toMatchObject({
      code: 'refused',
    });

    const desktop = join(autostart, 'vigil.desktop');
    writeFileSync(desktop, '[Desktop Entry]\nExec="/opt/Vigil at Home/vigil-at-home" --hidden\n');
    await expect(disableLinuxPersistence(sys, desktop, 'c', q, re, passwd)).rejects.toMatchObject({
      code: 'refused',
    });
    expect(sys.runs.filter((r) => r.args.includes('stop'))).toEqual([]);
    expect(existsSync(alias) && existsSync(runs) && existsSync(desktop)).toBe(true);
  });

  it('reads names and programs from systemctl and unit files', () => {
    expect(
      parseShow(
        'Id=a.service\nNames=a.service b.service\nExecStart={ path=/opt/osquery/bin/osqueryd ; argv[]=/opt/osquery/bin/osqueryd --x ; ignore_errors=no }\n',
      ),
    ).toEqual({
      names: ['a.service', 'a.service', 'b.service'],
      programs: ['/opt/osquery/bin/osqueryd', '/opt/osquery/bin/osqueryd'],
    });
    expect(startCommands('[Service]\nExecStart=@/usr/bin/osqueryd osqueryd\n', false)).toEqual([
      '/usr/bin/osqueryd',
    ]);
  });
});

describe("turning off Vigil's own startup item", () => {
  const escape = (d: string) => d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

  it('macOS: refuses its plist at the real path and as written in any folder', async () => {
    const sys = new FakeSystem();
    sys.console = process.getuid!();
    const { opts } = setup();
    // Where the installer puts it, checked against the real launch folders.
    await expect(
      disablePersistence(sys, '/Library/LaunchDaemons/com.vigilathome.helper.plist', 'p', opts),
    ).rejects.toMatchObject({ code: 'refused' });
    // As written: a copy in a launch folder, in any case, and reached through a linked folder.
    const launchDir = join(root, 'LaunchDaemons');
    mkdirSync(launchDir);
    const linked = join(root, 'linked');
    symlinkSync(launchDir, linked);
    const re = new RegExp(`^(${escape(launchDir)}|${escape(linked)})$`);
    for (const name of ['com.vigilathome.helper.plist', 'COM.VigilAtHome.Helper.plist']) {
      const plist = join(launchDir, name);
      writeFileSync(plist, `<plist><!-- ${name} --></plist>`);
      sys.labels.set(plist, 'com.vigilathome.helper');
      sys.loaded.add('system/com.vigilathome.helper');
      for (const path of [plist, join(linked, name)])
        await expect(disablePersistence(sys, path, 'p', opts, re), path).rejects.toMatchObject({
          code: 'refused',
        });
      expect(existsSync(plist)).toBe(true);
      rmSync(plist);
    }
    expect(sys.runs.filter((r) => r.bin === 'launchctl')).toEqual([]);
    expect(sys.loaded.has('system/com.vigilathome.helper')).toBe(true);
  });

  it('Linux: refuses its unit at the real path and as written in any folder', async () => {
    const sys = new FakeLinuxSystem();
    sys.console = process.getuid!();
    const q: QuarantineOptions = {
      quarantineDir: join(root, 'quarantine'),
      actorFor: async () => self(),
    };
    await expect(
      disableLinuxPersistence(sys, '/etc/systemd/system/vigil-helper.service', 'a', q),
    ).rejects.toMatchObject({ code: 'refused' });
    const unitDir = join(root, 'etc', 'systemd', 'system');
    mkdirSync(unitDir, { recursive: true });
    const linked = join(root, 'linked');
    symlinkSync(unitDir, linked);
    const re = new RegExp(`^(${escape(unitDir)}|${escape(linked)})$`);
    const unit = join(unitDir, 'vigil-helper.service');
    writeFileSync(unit, '[Service]\nExecStart=/usr/libexec/vigil-helper daemon\n');
    sys.active.add('system vigil-helper.service');
    for (const path of [unit, join(linked, 'vigil-helper.service')])
      await expect(disableLinuxPersistence(sys, path, 'a', q, re), path).rejects.toMatchObject({
        code: 'refused',
      });
    expect(existsSync(unit)).toBe(true);
    expect(sys.runs.filter((r) => r.args.includes('stop'))).toEqual([]);
  });
});
