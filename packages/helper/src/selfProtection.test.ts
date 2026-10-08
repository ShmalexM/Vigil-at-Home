// The helper must never let a containment action move, lock or unload Vigil,
// Santa or osquery: not by another spelling, not through a hard link, and not
// by swapping a file or folder between the checks and the move.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
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
import { FakeSystem } from './testing/fakeSystem.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const isRoot = process.getuid?.() === 0;
const modeOf = (p: string) => statSync(p).mode & 0o7777;
const PINNINGS = existsSync('/proc/self/fd') ? (['proc', 'cwd'] as const) : (['cwd'] as const);

let root: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-self-')));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

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
    ...extra,
  };
  return { helper, runtime, downloads, opts };
}

describe('protection by identity, not spelling (item 1)', () => {
  it('refuses a protected folder reached by a spelling the name checks do not know', () => {
    const { helper, opts } = setup();
    // Protected under another name: only its identity links the two.
    const alias = join(root, 'alias');
    symlinkSync(helper, alias);
    const o = { ...opts, selfPaths: [alias] };
    expect(() => vetPath(join(helper, 'node'), o)).not.toThrow();
    expect(() => quarantine(join(helper, 'node'), 'a', o)).toThrow(
      expect.objectContaining({ code: 'refused' }),
    );
    expect(() => quarantine(helper, 'b', o)).toThrow(expect.objectContaining({ code: 'refused' }));
    expect(statSync(join(helper, 'node')).mode & 0o777).toBe(0o755);
  });

  it('refuses a folder that holds a protected path', () => {
    const { helper, opts } = setup();
    const outer = join(root, 'outer');
    mkdirSync(outer);
    renameSync(helper, join(outer, 'helper.d'));
    const o = { ...opts, selfPaths: [join(outer, 'helper.d')] };
    expect(() => quarantine(outer, 'a', o)).toThrow(expect.objectContaining({ code: 'refused' }));
    expect(existsSync(join(outer, 'helper.d', 'node'))).toBe(true);
  });

  it('keeps the name checks: .., macOS case, and a stable symlinked parent', () => {
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
    const rec = quarantine(join(link, 'stuff', 'evil'), 'a', opts);
    expect(rec.originalPath).toBe(join(downloads, 'stuff', 'evil'));
    restore(rec, opts);
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

  it("refuses the quarantine itself and anything holding the helper's files, by identity", () => {
    const { helper, opts } = setup();
    expect(() => resolveTarget(helper, opts)).toThrow(expect.objectContaining({ code: 'refused' }));
    mkdirSync(opts.quarantineDir);
    const other = join(root, 'q-alias');
    symlinkSync(opts.quarantineDir, other);
    expect(() => quarantine(join(other, 'x'), 'a', { ...opts })).toThrow(
      expect.objectContaining({ code: 'refused' }),
    );
  });
});

describe.each(PINNINGS)('moves that cannot be redirected (%s)', (pinning) => {
  const opts = (base: QuarantineOptions): QuarantineOptions => ({ ...base, pinning });

  it('never changes a protected file swapped in for the target after the checks (item 3)', () => {
    const { runtime, downloads, opts: base } = setup();
    const target = join(downloads, 'stuff', 'evil');
    writeFileSync(target, 'x', { mode: 0o644 });
    const o = opts({
      ...base,
      beforeMove: () => {
        renameSync(target, join(downloads, 'stuff', 'moved'));
        symlinkSync(runtime, target);
      },
    });
    expect(() => quarantine(target, 'a', o)).toThrow(expect.objectContaining({ code: 'refused' }));
    expect(modeOf(runtime)).toBe(0o755);
    expect(readFileSync(runtime, 'utf8')).toBe('runtime');
    expect(lstatSync(target).isSymbolicLink()).toBe(true);
    expect(existsSync(join(base.quarantineDir, 'a'))).toBe(false);
  });

  it('never takes a file from a folder swapped for a link after the checks (item 3)', () => {
    const { downloads, opts: base } = setup();
    const dir = join(downloads, 'stuff');
    writeFileSync(join(dir, 'evil'), 'x');
    const system = join(root, 'system');
    mkdirSync(system);
    writeFileSync(join(system, 'evil'), 'keep', { mode: 0o644 });
    const cwd = process.cwd();
    const o = opts({
      ...base,
      beforeMove: () => {
        renameSync(dir, join(downloads, 'old'));
        symlinkSync(system, dir);
      },
    });
    expect(() => quarantine(join(dir, 'evil'), 'a', o)).toThrow(
      expect.objectContaining({ code: 'refused' }),
    );
    expect(readFileSync(join(system, 'evil'), 'utf8')).toBe('keep');
    expect(modeOf(join(system, 'evil'))).toBe(0o644);
    expect(readFileSync(join(downloads, 'old', 'evil'), 'utf8')).toBe('x');
    expect(process.cwd()).toBe(cwd);
  });

  it('locks the file through its handle, so a link is never followed (item 3)', () => {
    const { downloads, opts: base } = setup();
    const target = join(downloads, 'stuff', 'evil');
    writeFileSync(target, 'x', { mode: 0o755 });
    const rec = quarantine(target, 'a', opts(base));
    expect(modeOf(rec.storedPath)).toBe(0);
    restore(rec, opts(base));
    expect(modeOf(target)).toBe(0o755);
  });

  it('refuses FIFOs and other special files without waiting on them (item 3)', () => {
    const { downloads, opts: base } = setup();
    const fifo = join(downloads, 'stuff', 'pipe');
    execFileSync('mkfifo', [fifo]);
    expect(() => quarantine(fifo, 'a', opts(base))).toThrow(
      expect.objectContaining({ code: 'refused' }),
    );
  });

  it('refuses hard links, to protected files or not, and one swapped in late (item 4)', () => {
    const { runtime, downloads, opts: base } = setup();
    const link = join(downloads, 'stuff', 'evil');
    linkSync(runtime, link);
    expect(() => quarantine(link, 'a', opts(base))).toThrow(
      expect.objectContaining({ code: 'refused' }),
    );
    rmSync(link);
    // Not protected, but locking it would lock its other name too.
    const plain = join(downloads, 'plain');
    writeFileSync(plain, 'x');
    linkSync(plain, link);
    expect(() => quarantine(link, 'b', opts(base))).toThrow(/hard links/);
    rmSync(link);
    rmSync(plain);

    writeFileSync(link, 'x', { mode: 0o644 });
    const late = opts({
      ...base,
      beforeMove: () => {
        rmSync(link);
        linkSync(runtime, link);
      },
    });
    expect(() => quarantine(link, 'c', late)).toThrow(expect.objectContaining({ code: 'refused' }));
    expect(modeOf(runtime)).toBe(0o755);
    expect(statSync(runtime).ino).toBe(statSync(link).ino);
  });
});

describe.each(PINNINGS)('restore through a pinned folder (%s)', (pinning) => {
  const opts = (base: QuarantineOptions): QuarantineOptions => ({ ...base, pinning });

  it('never restores into a folder swapped for a link to another folder (item 5)', () => {
    const { downloads, opts: base } = setup();
    const dir = join(downloads, 'stuff');
    writeFileSync(join(dir, 'evil'), 'x', { mode: 0o644 });
    const rec = quarantine(join(dir, 'evil'), 'a', opts(base));
    const system = join(root, 'LaunchDaemons');
    mkdirSync(system);
    const swap = opts({
      ...base,
      beforeMove: (step) => {
        if (step !== 'restore') return;
        renameSync(dir, join(downloads, 'old'));
        symlinkSync(system, dir);
      },
    });
    expect(() => restore(rec, swap)).toThrow(expect.objectContaining({ code: 'refused' }));
    expect(existsSync(join(system, 'evil'))).toBe(false);
    expect(existsSync(join(downloads, 'old', 'evil'))).toBe(false);
    // Back in the store, locked again.
    expect(modeOf(rec.storedPath)).toBe(0);
  });

  it('never recreates a missing folder through a swapped parent (item 5)', () => {
    const { downloads, opts: base } = setup();
    const dir = join(downloads, 'stuff');
    writeFileSync(join(dir, 'evil'), 'x');
    const rec = quarantine(join(dir, 'evil'), 'a', opts(base));
    rmSync(dir, { recursive: true });
    const system = join(root, 'system');
    mkdirSync(system);
    const swap = opts({
      ...base,
      beforeMove: (step) => {
        if (step !== 'mkdir' || lstatSync(downloads).isSymbolicLink()) return;
        renameSync(downloads, join(root, 'old'));
        symlinkSync(system, downloads);
      },
    });
    expect(() => restore(rec, swap)).toThrow(expect.objectContaining({ code: 'refused' }));
    expect(existsSync(join(system, 'stuff'))).toBe(false);
    expect(modeOf(rec.storedPath)).toBe(0);
  });
});

describe.each(PINNINGS)('recreating missing folders (%s, item 6)', (pinning) => {
  it('makes them for the folder owner, with the recorded mode', () => {
    const { downloads, opts: base } = setup();
    const o: QuarantineOptions = { ...base, pinning };
    const owner = isRoot ? 1000 : process.getuid!();
    const stuff = join(downloads, 'stuff');
    const inner = join(stuff, 'inner');
    mkdirSync(inner, { mode: 0o750 });
    chmodSync(inner, 0o750);
    if (isRoot) for (const d of [downloads, stuff, inner]) chownSync(d, owner, owner);
    writeFileSync(join(inner, 'evil'), 'x');
    if (isRoot) chownSync(join(inner, 'evil'), owner, owner);
    const rec = quarantine(join(inner, 'evil'), 'a', o);
    expect(rec.parent).toMatchObject({ uid: owner, mode: 0o750 });
    rmSync(stuff, { recursive: true });
    const umask = process.umask(0o077);
    try {
      restore(rec, o);
    } finally {
      process.umask(umask);
    }
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
    const { helper, opts } = setup();
    for (const [i, program] of [
      '/opt/osquery/lib/osquery.app/Contents/MacOS/osqueryd',
      '/Library/PrivilegedHelperTools/vigil-helper',
      join(helper, 'node'),
      'osqueryd',
    ].entries()) {
      const path = join(launchDir, `com.example.item${i}.plist`);
      writeFileSync(path, '<plist/>');
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
    writeFileSync(path, '<plist/>');
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
    const passwd = () => `alex:x:${process.getuid!()}:0::/home/alex:/bin/bash\n`;
    const q = { quarantineDir: join(root, 'quarantine') };

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
      argvs: [['/opt/osquery/bin/osqueryd', '--x']],
    });
    expect(startCommands('[Service]\nExecStart=@/usr/bin/osqueryd osqueryd\n', false)).toEqual([
      '/usr/bin/osqueryd',
    ]);
  });
});
