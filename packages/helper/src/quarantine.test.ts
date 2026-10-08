import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { vetPath } from './commands/quarantine.js';
import { Executor } from './executor.js';
import { Journal } from './journal.js';
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

  it('still allows ordinary files next to them', () => {
    expect(vetPath('/Applications/Vigil at Home Evil.app', opts)).toBe(
      '/Applications/Vigil at Home Evil.app',
    );
    expect(vetPath('/Users/you/Downloads/evil', opts)).toBe('/Users/you/Downloads/evil');
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
