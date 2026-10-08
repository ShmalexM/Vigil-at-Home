// Every move the helper makes as root either cannot land on something else
// or is checked afterwards and undone, and an undo that fails is recorded
// with where the item is, never dropped.

import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  chmodSync,
  existsSync,
  linkSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import {
  quarantine,
  restore,
  StrandedError,
  type QuarantineOptions,
  type QuarantineRecord,
} from './commands/quarantine.js';
import {
  commandRunsProtected,
  launchedPrograms,
  LINK_WALK,
  linkTargetsIn,
  splitCommand,
} from './commands/protectedSet.js';
import { disablePersistence } from './commands/persistence.js';
import { disableLinuxPersistence } from './commands/linuxPersistence.js';
import { Approvals } from './approval.js';
import { Executor } from './executor.js';
import { Journal } from './journal.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const modeOf = (p: string) => statSync(p).mode & 0o7777;
const PINNINGS = existsSync('/proc/self/fd') ? (['proc', 'cwd'] as const) : (['cwd'] as const);
const refused = expect.objectContaining({ code: 'refused' });
const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

let root: string;
beforeEach(() => {
  root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-atomic-')));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

/** A stand-in for Vigil's own folder, protected through selfPaths, and a user's folder. */
function setup(extra: Partial<QuarantineOptions> = {}) {
  const helper = join(root, 'helper.d');
  mkdirSync(helper);
  writeFileSync(join(helper, 'node'), 'runtime', { mode: 0o755 });
  const dir = join(root, 'Downloads', 'stuff');
  mkdirSync(dir, { recursive: true });
  const opts: QuarantineOptions = {
    quarantineDir: join(root, 'Quarantine'),
    selfPaths: [helper],
    ...extra,
  };
  return { helper, dir, opts };
}

function strandedBy(fn: () => unknown): StrandedError {
  try {
    fn();
  } catch (err) {
    expect(err).toBeInstanceOf(StrandedError);
    return err as StrandedError;
  }
  throw new Error('expected the move to be stranded');
}

describe('links inside protected folders (item 1)', () => {
  it('protects what a link inside a protected folder points at', async () => {
    const { helper, opts } = setup();
    const vendor = join(root, 'vendor-sensor', 'bin');
    mkdirSync(vendor, { recursive: true });
    writeFileSync(join(vendor, 'agent'), 'sensor', { mode: 0o755 });
    symlinkSync(vendor, join(helper, 'bin'));
    expect(() => quarantine(join(vendor, 'agent'), 'a', opts)).toThrow(refused);
    expect(() => quarantine(vendor, 'b', opts)).toThrow(refused);
    expect(() => quarantine(join(root, 'vendor-sensor'), 'c', opts)).toThrow(refused);
    expect(readFileSync(join(vendor, 'agent'), 'utf8')).toBe('sensor');
    expect(modeOf(join(vendor, 'agent'))).toBe(0o755);

    // A startup item that runs it is refused too.
    const launchDir = join(root, 'LaunchDaemons');
    mkdirSync(launchDir);
    const plist = join(launchDir, 'com.example.agent.plist');
    writeFileSync(plist, '<plist/>');
    const sys = new FakeSystem();
    sys.programs.set(plist, join(vendor, 'agent'));
    await expect(
      disablePersistence(sys, plist, 'p', opts, new RegExp(`^${escape(launchDir)}$`)),
    ).rejects.toMatchObject({ code: 'refused' });
  });

  it('follows links a few folders down, within the bounds', () => {
    const { helper } = setup();
    const far = join(root, 'far');
    mkdirSync(far);
    let deep = helper;
    for (let i = 0; i < LINK_WALK.depth; i++) {
      deep = join(deep, `d${i}`);
      mkdirSync(deep);
    }
    symlinkSync(far, join(deep, 'in-reach'));
    const tooDeep = join(deep, 'd');
    mkdirSync(tooDeep);
    symlinkSync(far, join(tooDeep, 'out-of-reach'));
    expect(linkTargetsIn(helper)).toEqual([far]);
  });
});

describe.each(PINNINGS)('moves into quarantine (%s)', (pinning) => {
  it('puts back what arrived when it is not what was checked, or says where it is (item 2)', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'evil');
    writeFileSync(target, 'checked', { mode: 0o755 });
    const o: QuarantineOptions = {
      ...base,
      // Swapped for another file after the checks...
      beforeMove: () => {
        renameSync(target, join(dir, 'aside'));
        writeFileSync(target, 'swapped', { mode: 0o644 });
      },
      // ...and something takes the old name, so it cannot go back.
      afterMove: () => writeFileSync(target, 'squatter'),
    };
    const err = strandedBy(() => quarantine(target, 'a', o));
    expect(err.code).toBe('failed');
    expect(err.inStore).toBe(true);
    expect(err.recovery).toMatchObject({
      originalPath: target,
      storedPath: join(base.quarantineDir, 'a', 'evil'),
      mode: 0o644,
    });
    // Left as it was: never locked, since it is not what was checked.
    expect(readFileSync(err.recovery.storedPath, 'utf8')).toBe('swapped');
    expect(modeOf(err.recovery.storedPath)).toBe(0o644);
    // The record restores it once its place is free.
    rmSync(target);
    restore(err.recovery, { ...base });
    expect(readFileSync(target, 'utf8')).toBe('swapped');
  });

  it('puts the item back when the put-back can succeed (item 2)', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'evil');
    writeFileSync(target, 'checked');
    const o: QuarantineOptions = {
      ...base,
      beforeMove: () => {
        renameSync(target, join(dir, 'aside'));
        writeFileSync(target, 'swapped', { mode: 0o644 });
      },
    };
    expect(() => quarantine(target, 'a', o)).toThrow(refused);
    expect(readFileSync(target, 'utf8')).toBe('swapped');
    expect(modeOf(target)).toBe(0o644);
    expect(existsSync(join(base.quarantineDir, 'a'))).toBe(false);
  });

  it('refuses a file given another hard link after it was opened, and puts it back (item 3)', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'evil');
    writeFileSync(target, 'x', { mode: 0o755 });
    const other = join(root, 'other-name');
    const o: QuarantineOptions = { ...base, beforeMove: () => linkSync(target, other) };
    expect(() => quarantine(target, 'a', o)).toThrow(/another hard link/);
    expect(readFileSync(target, 'utf8')).toBe('x');
    expect(modeOf(other)).toBe(0o755);
    expect(statSync(other).ino).toBe(statSync(target).ino);
    expect(existsSync(join(base.quarantineDir, 'a'))).toBe(false);
  });
});

describe.each(PINNINGS)('moves back out of quarantine (%s, item 4)', (pinning) => {
  it('never replaces a file that appears at the name just before the move', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'evil');
    writeFileSync(target, 'x', { mode: 0o644 });
    const rec = quarantine(target, 'a', { ...base });
    const o: QuarantineOptions = {
      ...base,
      beforeMove: (step) => {
        if (step === 'restore') writeFileSync(target, 'new');
      },
    };
    expect(() => restore(rec, o)).toThrow(/something new is already at/);
    expect(readFileSync(target, 'utf8')).toBe('new');
    expect(modeOf(rec.storedPath)).toBe(0);
  });

  it('never replaces a link or a folder that appears at the name, for a folder item', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'app');
    mkdirSync(target);
    writeFileSync(join(target, 'bin'), 'x');
    const rec = quarantine(target, 'a', { ...base });
    const o: QuarantineOptions = {
      ...base,
      beforeMove: (step) => {
        if (step === 'restore') symlinkSync(join(root, 'elsewhere'), target);
      },
    };
    expect(() => restore(rec, o)).toThrow(/something new is already at/);
    expect(lstatSync(target).isSymbolicLink()).toBe(true);
    expect(modeOf(rec.storedPath)).toBe(0);
    chmodSync(rec.storedPath, 0o755); // so the test can clean up without root
  });

  it('moves a link back as a link, never over something new', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'shortcut');
    symlinkSync('/nowhere', target);
    const rec = quarantine(target, 'a', { ...base });
    restore(rec, { ...base });
    expect(lstatSync(target).isSymbolicLink()).toBe(true);
    const again = quarantine(target, 'b', { ...base });
    const o: QuarantineOptions = {
      ...base,
      beforeMove: (step) => {
        if (step === 'restore') writeFileSync(target, 'new');
      },
    };
    expect(() => restore(again, o)).toThrow(/something new is already at/);
    expect(readFileSync(target, 'utf8')).toBe('new');
    expect(lstatSync(again.storedPath).isSymbolicLink()).toBe(true);
  });

  it('takes the item back when its folder moves right after the move', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'evil');
    writeFileSync(target, 'x', { mode: 0o644 });
    const rec = quarantine(target, 'a', { ...base });
    const system = join(root, 'system');
    mkdirSync(system);
    const o: QuarantineOptions = {
      ...base,
      afterMove: (step) => {
        if (step !== 'restore') return;
        renameSync(dir, join(root, 'old'));
        symlinkSync(system, dir);
      },
    };
    expect(() => restore(rec, o)).toThrow(/back in quarantine/);
    expect(existsSync(join(root, 'old', 'evil'))).toBe(false);
    expect(existsSync(join(system, 'evil'))).toBe(false);
    expect(modeOf(rec.storedPath)).toBe(0);
    chmodSync(rec.storedPath, 0o644); // readable without root
    expect(readFileSync(rec.storedPath, 'utf8')).toBe('x');
  });

  it('says where the item is when it cannot be taken back', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'evil');
    writeFileSync(target, 'x');
    const rec = quarantine(target, 'a', { ...base });
    const o: QuarantineOptions = {
      ...base,
      afterMove: (step) => {
        if (step !== 'restore') return;
        renameSync(dir, join(root, 'old'));
        // The store's name for it is taken, so it cannot go back there.
        writeFileSync(rec.storedPath, 'blocker');
      },
    };
    const err = strandedBy(() => restore(rec, o));
    expect(err.inStore).toBe(false);
    expect(err.recovery.storedPath).toBe(join(root, 'old', 'evil'));
    expect(readFileSync(join(root, 'old', 'evil'), 'utf8')).toBe('x');
  });

  it('notices when what is at the name is no longer the item it moved', () => {
    const { dir, opts: base } = setup({ pinning });
    const target = join(dir, 'evil');
    writeFileSync(target, 'x');
    const rec = quarantine(target, 'a', { ...base });
    const o: QuarantineOptions = {
      ...base,
      afterMove: (step) => {
        if (step !== 'restore') return;
        renameSync(target, join(dir, 'moved'));
        writeFileSync(target, 'other');
        renameSync(dir, join(root, 'old'));
      },
    };
    expect(strandedBy(() => restore(rec, o)).code).toBe('failed');
    expect(readFileSync(join(root, 'old', 'evil'), 'utf8')).toBe('other');
  });
});

describe.each(PINNINGS)('folders recreated on restore (%s, item 5)', (pinning) => {
  function quarantinedDeep(base: QuarantineOptions) {
    const dir = join(root, 'Downloads', 'stuff');
    const inner = join(dir, 'inner');
    mkdirSync(inner);
    writeFileSync(join(inner, 'evil'), 'x');
    const rec = quarantine(join(inner, 'evil'), 'a', { ...base, pinning });
    rmSync(dir, { recursive: true });
    return { dir, inner, rec };
  }

  it('changes nothing on a link swapped in between mkdir and open', () => {
    const { opts: base } = setup();
    const { dir, rec } = quarantinedDeep(base);
    const system = join(root, 'system');
    mkdirSync(system, { mode: 0o755 });
    const o: QuarantineOptions = {
      ...base,
      pinning,
      afterMkdir: (name) => {
        if (name !== 'stuff') return;
        renameSync(dir, join(root, 'ours'));
        symlinkSync(system, dir);
      },
    };
    expect(() => restore(rec, o)).toThrow(refused);
    expect(readdirSync(system)).toEqual([]);
    expect(modeOf(system)).toBe(0o755);
    expect(modeOf(rec.storedPath)).toBe(0);
  });

  it('changes nothing on a folder swapped in between mkdir and open', () => {
    const { opts: base } = setup();
    const { dir, rec } = quarantinedDeep(base);
    const o: QuarantineOptions = {
      ...base,
      pinning,
      afterMkdir: (name) => {
        if (name !== 'stuff') return;
        renameSync(dir, join(root, 'ours'));
        mkdirSync(dir, { mode: 0o777 });
      },
    };
    const umask = process.umask(0);
    try {
      expect(() => restore(rec, o)).toThrow(refused);
    } finally {
      process.umask(umask);
    }
    expect(modeOf(dir)).toBe(0o777);
    expect(readdirSync(dir)).toEqual([]);
    // The folder that was made is never given away.
    expect(modeOf(join(root, 'ours'))).toBe(0o700);
    expect(modeOf(rec.storedPath)).toBe(0);
  });
});

describe('the executor records an item that could not be put back (item 2)', () => {
  it('journals a stranded item as an active quarantine that can be restored', async () => {
    const { dir, opts } = setup();
    const target = join(dir, 'evil');
    writeFileSync(target, 'checked');
    const approvalsDir = join(root, 'approvals');
    mkdirSync(approvalsDir);
    const journal = new Journal(join(root, 'journal.json'));
    const executor = new Executor({
      sys: new FakeSystem(),
      journal,
      approvals: new Approvals({ dir: approvalsDir, requiredOwnerUid: process.getuid!() }),
      rules: new RuleStore(join(root, 'rules.json')),
      quarantine: {
        ...opts,
        beforeMove: () => {
          renameSync(target, join(dir, 'aside'));
          writeFileSync(target, 'swapped');
        },
        afterMove: () => writeFileSync(target, 'squatter'),
      },
      syncPort: 47821,
    });
    await expect(executor.execute({ kind: 'file.quarantine', path: target })).rejects.toThrow(
      /recorded as quarantine/,
    );
    const [entry] = journal.active();
    expect(entry).toMatchObject({ kind: 'file.quarantine', state: 'active' });
    const rec = entry!.undo!.quarantine as QuarantineRecord;
    expect(rec.originalPath).toBe(target);
    expect(readFileSync(rec.storedPath, 'utf8')).toBe('swapped');
  });
});

describe('startup items that start a sensor through a shell or wrapper (item 6)', () => {
  const sh = ['/bin/sh', '-c', 'exec /opt/osquery/bin/osqueryd --flagfile x'];
  const env = ['/usr/bin/env', 'osqueryd'];

  it('looks one level into a shell -c string and past env, exec, nice and nohup', () => {
    expect(launchedPrograms(sh)).toEqual([
      '/bin/sh',
      'exec',
      '/opt/osquery/bin/osqueryd',
      '--flagfile',
      'x',
    ]);
    expect(launchedPrograms(env)).toEqual(['/usr/bin/env', 'osqueryd']);
    expect(launchedPrograms(['nice', '-n', '5', '/opt/x/y'])).toEqual(['nice', '/opt/x/y']);
    expect(launchedPrograms(['env', 'A=1', '-i', 'santad'])).toEqual(['env', 'santad']);
    expect(splitCommand(`a 'b c' "d\\"e";f`)).toEqual(['a', 'b c', 'd"e', 'f']);
    for (const platform of ['darwin', 'linux'] as const) {
      expect(commandRunsProtected(sh, { platform })).toBeDefined();
      expect(commandRunsProtected(env, { platform })).toBe('osqueryd');
      expect(commandRunsProtected(['/bin/zsh', '-lc', 'nohup vigil-helper &'], { platform })).toBe(
        'vigil-helper',
      );
      // Named anywhere on the line, too.
      expect(commandRunsProtected(['/usr/bin/python3', '-m', 'x', 'osqueryd'], { platform })).toBe(
        '/usr/bin/python3 -m x osqueryd',
      );
      expect(commandRunsProtected(['/bin/sh', '-c', 'exec /home/u/miner'], { platform })).toBe(
        undefined,
      );
      expect(commandRunsProtected(['/opt/osqueryd-lookalike/run'], { platform })).toBe(undefined);
    }
  });

  it('macOS: refuses a plist whose ProgramArguments wrap a sensor', async () => {
    const launchDir = join(root, 'LaunchDaemons');
    mkdirSync(launchDir);
    const re = new RegExp(`^${escape(launchDir)}$`);
    const sys = new FakeSystem();
    const { opts } = setup();
    for (const [i, argv] of [sh, env].entries()) {
      const path = join(launchDir, `com.example.wrap${i}.plist`);
      writeFileSync(path, '<plist/>');
      sys.labels.set(path, `com.example.wrap${i}`);
      sys.argv.set(path, argv);
      sys.loaded.add(`system/com.example.wrap${i}`);
      await expect(disablePersistence(sys, path, 'p', opts, re)).rejects.toMatchObject({
        code: 'refused',
      });
      expect(existsSync(path)).toBe(true);
    }
    expect(sys.runs.filter((r) => r.bin === 'launchctl')).toEqual([]);

    // An ordinary wrapped program is still disabled.
    const path = join(launchDir, 'com.example.miner.plist');
    writeFileSync(path, '<plist/>');
    sys.labels.set(path, 'com.example.miner');
    sys.argv.set(path, ['/bin/sh', '-c', 'exec /Users/you/miner']);
    await disablePersistence(sys, path, 'm', opts, re);
    expect(existsSync(path)).toBe(false);
  });

  it('Linux: refuses a unit whose ExecStart wraps a sensor', async () => {
    const unitDir = join(root, 'home', 'alex', '.config', 'systemd', 'user');
    mkdirSync(unitDir, { recursive: true });
    const re = new RegExp(`^${escape(unitDir)}$`);
    const sys = new FakeLinuxSystem();
    const passwd = () => `alex:x:${process.getuid!()}:0::/home/alex:/bin/bash\n`;
    const q = { quarantineDir: join(root, 'quarantine') };
    for (const [i, line] of [
      `/bin/sh -c 'exec /opt/osquery/bin/osqueryd --flagfile x'`,
      '/usr/bin/env osqueryd',
    ].entries()) {
      const unit = join(unitDir, `wrap${i}.service`);
      writeFileSync(unit, `[Service]\nExecStart=${line}\n`);
      sys.active.add(`user:alex wrap${i}.service`);
      await expect(disableLinuxPersistence(sys, unit, 'a', q, re, passwd)).rejects.toMatchObject({
        code: 'refused',
      });
      expect(existsSync(unit)).toBe(true);
    }
    expect(sys.runs.filter((r) => r.args.includes('stop'))).toEqual([]);
  });
});
