import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  chmodSync,
  existsSync,
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
import { RuleStore } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { quarantine, restore, vetPath, type QuarantineOptions } from './commands/quarantine.js';
import { disablePersistence } from './commands/persistence.js';
import { isProtectedProcess } from './commands/process.js';
import { self } from './commands/transfer.js';
import { Executor } from './executor.js';
import { Journal } from './journal.js';
import type { AppPinStore } from './pinStore.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

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
  const sys = new FakeSystem();
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-restore-')));
  });
  afterEach(() => {
    // The store locks what it keeps; open it up so it can be cleaned away.
    const q = join(root, 'Quarantine');
    if (existsSync(q)) chmodSync(q, 0o700);
    rmSync(root, { recursive: true, force: true });
  });

  it('recreates a deleted folder and moves the file back', async () => {
    const q: QuarantineOptions = {
      quarantineDir: join(root, 'Quarantine'),
      actorFor: async () => self(),
    };
    const dir = join(root, 'Downloads', 'stuff');
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'evil'), 'x');
    const rec = await quarantine(sys, join(dir, 'evil'), 'a2', q);
    rmSync(join(root, 'Downloads'), { recursive: true });
    await restore(sys, rec, q);
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
    sys.console = process.getuid!();
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
      writeFileSync(path, `<plist><!-- ${name} --></plist>`);
      sys.labels.set(path, name.replace(/\.plist$/, ''));
      await expect(disablePersistence(sys, path, 'p', q, launchDirs())).rejects.toMatchObject({
        code: 'refused',
      });
      expect(existsSync(path)).toBe(true);
    }
    // Named innocently on disk, but Vigil's job inside.
    const renamed = join(launchDir, 'innocent.plist');
    writeFileSync(renamed, '<plist><!-- innocent --></plist>');
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

  it("refuses everything in the helper's state folder, in any case, and what holds it", () => {
    for (const path of [
      '/Library/Application Support/Vigil/app-pin.json',
      '/Library/Application Support/Vigil/helper-rules.json',
      '/Library/Application Support/Vigil/helper-journal.json',
      '/Library/Application Support/Vigil/anything-new',
      '/library/application support/vigil/APP-PIN.json',
      '/Library/Application Support/Vigil',
      '/Library/Application Support',
    ]) {
      expect(() => vetPath(path, opts), path).toThrow(expect.objectContaining({ code: 'refused' }));
    }
    // A quarantine folder configured elsewhere doesn't leave the state folder open.
    const elsewhere = { quarantineDir: '/private/var/vigil-q' };
    expect(() => vetPath('/Library/Application Support/Vigil/app-pin.json', elsewhere)).toThrow(
      expect.objectContaining({ code: 'refused' }),
    );
    // Nor does a caller's own list of prefixes.
    expect(() =>
      vetPath('/Library/Application Support/Vigil/app-pin.json', {
        ...opts,
        protectedPrefixes: [],
      }),
    ).toThrow(expect.objectContaining({ code: 'refused' }));
    // A configured state folder is protected as a whole too.
    const custom = { quarantineDir: '/srv/q', stateDir: '/srv/vigil-state' };
    expect(() => vetPath('/srv/vigil-state/app-pin.json', custom)).toThrow();
    expect(() => vetPath('/SRV/Vigil-State/app-pin.json', custom)).toThrow();
    expect(vetPath('/srv/vigil-state-other/x', custom)).toBe('/srv/vigil-state-other/x');
  });

  it('protects /var/lib/vigil on Linux the same way, case and all', () => {
    const linux = { quarantineDir: '/var/lib/vigil/quarantine', platform: 'linux' as const };
    for (const path of ['/var/lib/vigil/app-pin.json', '/var/lib/vigil/x', '/var/lib/vigil'])
      expect(() => vetPath(path, linux), path).toThrow(
        expect.objectContaining({ code: 'refused' }),
      );
    expect(() =>
      vetPath('/var/lib/vigil/app-pin.json', { ...linux, protectedPrefixes: [] }),
    ).toThrow(expect.objectContaining({ code: 'refused' }));
    // Linux paths that differ in case are other files.
    expect(vetPath('/var/lib/Vigil/x', linux)).toBe('/var/lib/Vigil/x');
  });
});

describe("file commands against the helper's state folder", () => {
  let root: string;
  let state: string;
  let launchDir: string;
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'vigil-state-'));
    state = join(root, 'Vigil');
    launchDir = join(state, 'LaunchAgents');
    mkdirSync(launchDir, { recursive: true });
    mkdirSync(join(state, 'systemd', 'user'), { recursive: true });
    writeFileSync(join(state, 'app-pin.json'), '{}\n');
    writeFileSync(join(launchDir, 'x.plist'), '<plist/>');
    writeFileSync(join(state, 'systemd', 'user', 'x.service'), '[Service]\n');
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const executor = (sys: FakeSystem | FakeLinuxSystem, journal: Journal) =>
    new Executor({
      sys,
      journal,
      approvals: new Approvals({
        dir: join(root, 'approvals'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules: new RuleStore(join(root, 'rules.json')),
      // The quarantine folder lives elsewhere: the state folder is protected on its own.
      quarantine: { quarantineDir: join(root, 'Quarantine'), stateDir: state },
      launchDirs: /\/(LaunchAgents|LaunchDaemons|systemd\/user|autostart)$/,
      syncPort: 47821,
    });

  for (const platform of ['darwin', 'linux'] as const) {
    it(`never quarantines, disables or restores into it (${platform})`, async () => {
      const sys = platform === 'linux' ? new FakeLinuxSystem() : new FakeSystem();
      const journal = new Journal(join(root, 'journal.json'));
      const ex = executor(sys, journal);
      for (const path of [join(state, 'app-pin.json'), state, root])
        await expect(ex.execute({ kind: 'file.quarantine', path })).rejects.toMatchObject({
          code: 'refused',
        });
      expect(existsSync(join(state, 'app-pin.json'))).toBe(true);
      // A startup item kept there is refused before launchd or systemd hears of it.
      const item =
        platform === 'linux'
          ? join(state, 'systemd', 'user', 'x.service')
          : join(launchDir, 'x.plist');
      const runs = sys.runs.length;
      await expect(ex.execute({ kind: 'persistence.disable', path: item })).rejects.toMatchObject({
        code: 'refused',
      });
      expect(sys.runs.length).toBe(runs);
      expect(existsSync(item)).toBe(true);
      // A restore that would write into it is refused before the password is asked.
      journal.add({
        id: 'q1',
        kind: 'file.quarantine',
        command: { kind: 'file.quarantine', path: join(state, 'app-pin.json') },
        state: 'active',
        summary: 'old',
        undo: {
          quarantine: {
            originalPath: join(state, 'app-pin.json'),
            storedPath: join(root, 'Quarantine', 'q1', 'app-pin.json'),
            mode: 0o644,
            uid: 0,
            gid: 0,
            isDirectory: false,
          },
        },
      });
      await expect(ex.execute({ kind: 'file.restore', quarantineId: 'q1' })).rejects.toMatchObject({
        code: 'refused',
      });
    });
  }
});

describe("Vigil's own app, as pinned and as the app names it", () => {
  let root: string;
  beforeEach(() => {
    root = realpathSync(mkdtempSync(join(tmpdir(), 'vigil-ownapp-')));
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  for (const platform of ['darwin', 'linux'] as const) {
    it(`is never quarantined, nor what starts it turned off (${platform})`, async () => {
      const sys = platform === 'linux' ? new FakeLinuxSystem() : new FakeSystem();
      sys.console = process.getuid!();
      const apps = join(root, 'Applications');
      mkdirSync(apps);
      // An AppImage known only by identity, and an app known by its pinned path.
      const image = join(apps, 'Vigil.AppImage');
      writeFileSync(image, 'image', { mode: 0o755 });
      const st = statSync(image, { bigint: true });
      const pinned = join(apps, 'vigil-pinned');
      writeFileSync(pinned, 'app', { mode: 0o755 });
      const autostart = join(root, 'autostart');
      const agents = join(root, 'LaunchAgents');
      mkdirSync(autostart);
      mkdirSync(agents);
      const ex = new Executor({
        sys,
        journal: new Journal(join(root, 'journal.json')),
        approvals: new Approvals({
          dir: join(root, 'approvals'),
          requiredOwnerUid: process.getuid!(),
        }),
        rules: new RuleStore(join(root, 'rules.json')),
        quarantine: { quarantineDir: join(root, 'Quarantine'), actorFor: async () => self() },
        launchDirs: /\/(LaunchAgents|autostart)$/,
        syncPort: 47821,
        self: () => ({ paths: [], images: [`${st.dev}:${st.ino}`], hashes: [] }),
        appPin: {
          current: () => ({ platform, path: pinned }),
          intact: async () => true,
        } as unknown as AppPinStore,
      });
      for (const path of [image, pinned, apps])
        await expect(ex.execute({ kind: 'file.quarantine', path }), path).rejects.toMatchObject({
          code: 'refused',
        });
      expect(existsSync(image) && existsSync(pinned)).toBe(true);
      for (const [i, program] of [image, pinned].entries()) {
        const item =
          platform === 'linux'
            ? join(autostart, `vigil${i}.desktop`)
            : join(agents, `com.example.start${i}.plist`);
        writeFileSync(item, `[Desktop Entry]\nExec="${program}" --hidden\n`);
        if (sys instanceof FakeSystem) sys.programs.set(item, program);
        await expect(
          ex.execute({ kind: 'persistence.disable', path: item }),
          item,
        ).rejects.toMatchObject({ code: 'refused' });
        expect(existsSync(item)).toBe(true);
      }
    });
  }
});
