import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { insideInstalledRoot } from '@vigil/core/self';
import {
  adminScriptArgs,
  appPinFile,
  appPinned,
  appPinTarget,
  helperBundleDir,
  helperDigest,
  helperInstallCommand,
  helperScriptFiles,
  helperMatch,
  inInstallerFolder,
  installedHelperFiles,
  ROOT_SHELL,
  rootStageScript,
  runHelperScript,
  shellQuote,
  type RunFile,
} from './helper-install.js';

function bundle() {
  const res = mkdtempSync(join(tmpdir(), "Vigil at Home's Resources-"));
  const dir = join(res, 'helper');
  mkdirSync(dir);
  for (const f of ['install.sh', 'uninstall.sh', 'node']) writeFileSync(join(dir, f), '');
  mkdirSync(join(dir, 'linux'));
  for (const f of ['install.sh', 'uninstall.sh']) writeFileSync(join(dir, 'linux', f), `# ${f}`);
  for (const f of ['helper.mjs', 'vigil-helper', 'com.vigilathome.helper.plist'])
    writeFileSync(join(dir, f), f);
  for (const f of ['vigil-helper', 'vigil-helper.service', 'com.vigilathome.helper.policy'])
    writeFileSync(join(dir, 'linux', f), f);
  return { res, dir };
}

describe('helper install', () => {
  it('finds the helper only in builds that carry it', () => {
    expect(helperBundleDir(mkdtempSync(join(tmpdir(), 'empty-')))).toBeNull();
    const { res, dir } = bundle();
    expect(helperBundleDir(res)).toBe(dir);
  });

  it('lets a development build use the helper pnpm build:helper made', () => {
    const empty = mkdtempSync(join(tmpdir(), 'empty-'));
    const { dir: dev } = bundle();
    expect(helperBundleDir(empty, dev)).toBe(dev);
    expect(helperBundleDir(empty, join(empty, 'missing'))).toBeNull();
    // A packaged app always installs the copy it carries.
    const { res, dir } = bundle();
    expect(helperBundleDir(res, dev)).toBe(dir);
  });

  it('gives a Terminal command that survives spaces and quotes in the path', () => {
    const { dir } = bundle();
    const files = helperScriptFiles('install', 'darwin');
    const cmd = helperInstallCommand(dir, 'darwin')!;
    expect(cmd).toBe(
      `sudo ${ROOT_SHELL.join(' ')} ${shellQuote(rootStageScript('darwin'))} vigil-helper-setup ${shellQuote(dir)} ` +
        [files[0]!, helperDigest(dir, files), appPinTarget('darwin'), ...files]
          .map(shellQuote)
          .join(' '),
    );
    const linux = helperInstallCommand(dir, 'linux')!;
    expect(
      linux.startsWith(
        `d=$(mktemp -d) && cp -R ${shellQuote(dir)}/. "$d" && sudo /usr/bin/env -i `,
      ),
    ).toBe(true);
    expect(linux).toContain(` vigil-helper-setup "$d" 'linux/install.sh' `);
    expect(shellQuote("a b'c")).toBe(`'a b'\\''c'`);
    expect(helperInstallCommand(null)).toBeUndefined();
    // A build missing a file the script needs offers no command.
    rmSync(join(dir, 'node'));
    expect(helperInstallCommand(dir, 'darwin')).toBeUndefined();
  });

  it('runs only a root-owned copy that matches the files the app checked', () => {
    const { dir } = bundle();
    const out = mkdtempSync(join(tmpdir(), 'out-'));
    writeFileSync(
      join(dir, 'linux', 'install.sh'),
      `cd "$(dirname "$0")" && pwd > ${shellQuote(join(out, 'ran-in'))}; cat "$(dirname "$0")/../helper.mjs" > ${shellQuote(join(out, 'saw'))}; printf %s "$1" > ${shellQuote(join(out, 'app'))}`,
    );
    const files = helperScriptFiles('install', 'linux');
    const want = helperDigest(dir, files);
    const stage = (src: string) =>
      execFileSync(
        ROOT_SHELL[0],
        [
          ...ROOT_SHELL.slice(1),
          rootStageScript('linux'),
          'vigil-helper-setup',
          src,
          files[0]!,
          want,
          "/home/a b/Vigil's.AppImage",
          ...files,
        ],
        // Root ignores whatever TMPDIR the caller had.
        { stdio: 'pipe', env: { ...process.env, TMPDIR: out } },
      );

    stage(dir);
    expect(readFileSync(join(out, 'saw'), 'utf8')).toBe('helper.mjs');
    // The script gets the app to pin as its one argument, as given.
    expect(readFileSync(join(out, 'app'), 'utf8')).toBe("/home/a b/Vigil's.AppImage");
    const ranIn = readFileSync(join(out, 'ran-in'), 'utf8').trim();
    expect(ranIn.startsWith(dir)).toBe(false);
    expect(ranIn).toMatch(/^\/tmp\/vigil-helper\.[^/]+\/linux$/);
    // The private copy is gone once the script has run.
    expect(existsSync(ranIn)).toBe(false);

    // A file changed after the app checked it: nothing runs.
    rmSync(join(out, 'saw'));
    writeFileSync(join(dir, 'helper.mjs'), 'something else');
    expect(() => stage(dir)).toThrow(/changed while installing/);
    expect(existsSync(join(out, 'saw'))).toBe(false);

    // A link in place of a file is refused before root reads through it.
    writeFileSync(join(dir, 'helper.mjs'), 'helper.mjs');
    rmSync(join(dir, 'node'));
    symlinkSync('/dev/zero', join(dir, 'node'));
    expect(() => stage(dir)).toThrow(/Missing node/);
    rmSync(join(dir, 'node'));
    writeFileSync(join(dir, 'node'), '');

    // Moving bytes from one file into the next changes the digest too.
    writeFileSync(join(dir, 'helper.mjs'), 'helper');
    writeFileSync(join(dir, 'node'), '.mjs');
    expect(helperDigest(dir, files)).not.toBe(want);
  });

  it('passes the command to osascript as an argument, never inside the AppleScript', () => {
    const { res } = bundle();
    const evil = join(res, 'Evil" & do shell script "rm -rf ~".app');
    mkdirSync(evil);
    const { dir } = { dir: join(res, 'helper') };
    execFileSync('cp', ['-R', dir, join(evil, 'helper')]);
    const seen: string[][] = [];
    const ok: RunFile = async (file, args) => {
      seen.push([file, ...args]);
      return { code: 0, stdout: '', stderr: '' };
    };
    return runHelperScript('install', join(evil, 'helper'), ok, 'darwin').then((r) => {
      expect(r).toEqual({ ok: true });
      const args = seen[0]!.slice(1);
      expect(args.slice(0, -1).join(' ')).not.toContain('rm -rf');
      expect(args.join(' ')).toContain('do shell script (item 1 of argv)');
      expect(args.join(' ')).toContain('with administrator privileges');
      expect(args.at(-1)).toContain(shellQuote(join(evil, 'helper')));
      expect(adminScriptArgs('x', 'install').at(-1)).toBe('x');
    });
  });

  it('reports success, a closed password dialog, and failures', async () => {
    const { dir } = bundle();
    const seen: string[][] = [];
    const answer =
      (code: number, stderr = ''): RunFile =>
      async (file, args) => {
        seen.push([file, ...args]);
        return { code, stdout: '', stderr };
      };
    expect(await runHelperScript('install', dir, answer(0), 'darwin')).toEqual({ ok: true });
    expect(seen[0]?.[0]).toBe('/usr/bin/osascript');
    expect(seen[0]?.at(-1)).toContain(` ${shellQuote(dir)} 'install.sh' `);

    expect(
      await runHelperScript(
        'install',
        dir,
        answer(1, '0:120: execution error: User canceled. (-128)'),
        'darwin',
      ),
    ).toEqual({ ok: false, error: 'cancelled' });

    expect(
      await runHelperScript(
        'uninstall',
        dir,
        answer(1, '0:120: execution error: The helper did not start. (1)\n'),
        'darwin',
      ),
    ).toEqual({ ok: false, error: 'The helper did not start.' });
    expect(seen[2]?.at(-1)).toContain(` 'uninstall.sh' `);

    expect(await runHelperScript('install', null, answer(0))).toMatchObject({ ok: false });
  });

  it('on Linux, has pkexec copy and check a private copy of the files', async () => {
    const { dir } = bundle();
    const seen: string[][] = [];
    let staged = '';
    const answer =
      (code: number, stderr = ''): RunFile =>
      async (file, args) => {
        seen.push([file, ...args]);
        staged = args[7]!;
        // The copy is there while pkexec runs, with the script it names.
        expect(readFileSync(join(staged, args[8]!), 'utf8')).toBe(
          `# ${args[8]!.endsWith('uninstall.sh') ? 'uninstall' : 'install'}.sh`,
        );
        return { code, stdout: '', stderr };
      };
    expect(await runHelperScript('install', dir, answer(0), 'linux')).toEqual({ ok: true });
    const files = helperScriptFiles('install', 'linux');
    expect(seen[0]).toEqual([
      '/usr/bin/pkexec',
      ...ROOT_SHELL,
      rootStageScript('linux'),
      'vigil-helper-setup',
      staged,
      'linux/install.sh',
      helperDigest(dir, files),
      appPinTarget('linux'),
      ...files,
    ]);
    expect(staged).toMatch(/vigil-helper-[^/]+$/);
    expect(staged.startsWith(dir)).toBe(false);
    // And it is gone afterwards.
    expect(existsSync(staged)).toBe(false);

    expect(await runHelperScript('install', dir, answer(126), 'linux')).toEqual({
      ok: false,
      error: 'cancelled',
    });
    expect(
      await runHelperScript(
        'uninstall',
        dir,
        answer(1, 'Removing…\nThe helper needs systemd.\n'),
        'linux',
      ),
    ).toEqual({ ok: false, error: 'The helper needs systemd.' });
    expect(seen.at(-1)?.[9]).toBe('linux/uninstall.sh');
    expect(await runHelperScript('install', dir, answer(0), 'win32')).toMatchObject({ ok: false });
    rmSync(join(dir, 'node'));
    expect(await runHelperScript('install', dir, answer(0), 'linux')).toMatchObject({
      ok: false,
      error: expect.stringMatching(/missing/),
    });
  });

  it('runs install.sh for an update, with a dialog that says why', async () => {
    const { dir } = bundle();
    const seen: string[][] = [];
    const ok: RunFile = async (file, args) => {
      seen.push([file, ...args]);
      return { code: 0, stdout: '', stderr: '' };
    };
    expect(await runHelperScript('update', dir, ok, 'darwin')).toEqual({ ok: true });
    expect(seen[0]?.at(-1)).toContain(` 'install.sh' `);
    expect(seen[0]?.join(' ')).toContain('was updated and wants to update its helper');
    expect(await runHelperScript('update', dir, ok, 'linux')).toEqual({ ok: true });
    expect(seen[1]?.[9]).toBe('linux/install.sh');
  });

  for (const platform of ['darwin', 'linux'] as const) {
    it(`tells an installed helper that matches the app's from an older one (${platform})`, () => {
      const { dir } = bundle();
      writeFileSync(join(dir, 'helper.mjs'), 'helper v2');
      writeFileSync(join(dir, 'node'), 'node 22');
      writeFileSync(join(dir, 'vigil-helper'), 'launcher');
      writeFileSync(join(dir, 'com.vigilathome.helper.plist'), 'plist');
      for (const f of ['vigil-helper', 'vigil-helper.service', 'com.vigilathome.helper.policy'])
        writeFileSync(join(dir, 'linux', f), f);
      const root = mkdtempSync(join(tmpdir(), 'root-'));
      const files = installedHelperFiles(dir, platform, root);
      const install = () => {
        for (const f of files) {
          mkdirSync(dirname(f.installed), { recursive: true });
          writeFileSync(f.installed, readFileSync(f.bundled));
        }
      };

      const none = helperMatch(dir, platform, root);
      expect(none.installed).toBe('none');
      install();
      expect(helperMatch(dir, platform, root)).toEqual({
        installed: 'current',
        bundle: none.bundle,
      });

      // The app was replaced by a newer one; the helper it installed stays.
      writeFileSync(join(dir, 'helper.mjs'), 'helper v3');
      const newer = helperMatch(dir, platform, root);
      expect(newer.installed).toBe('outdated');
      expect(newer.bundle).not.toBe(none.bundle);
      install();
      expect(helperMatch(dir, platform, root).installed).toBe('current');

      // A new Node release, compared by size.
      writeFileSync(join(dir, 'node'), 'node 24.1');
      expect(helperMatch(dir, platform, root).installed).toBe('outdated');
      install();
      // A changed launcher or service file needs install.sh as well.
      writeFileSync(files[2]!.installed, 'old launcher');
      expect(helperMatch(dir, platform, root).installed).toBe('outdated');
      // An installed file that is gone counts as outdated, not as a crash.
      install();
      rmSync(files[3]!.installed);
      expect(helperMatch(dir, platform, root).installed).toBe('outdated');
    });
  }

  it('never asks anything of an app updated in place in /Applications', () => {
    const { dir } = bundle();
    const root = mkdtempSync(join(tmpdir(), 'root-'));
    for (const f of installedHelperFiles(dir, 'darwin', root)) {
      mkdirSync(dirname(f.installed), { recursive: true });
      writeFileSync(f.installed, readFileSync(f.bundled));
    }
    const app = {
      execPath: '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home',
      env: {},
    };
    expect(inInstallerFolder('darwin', app)).toBe(true);
    // No pin file at all, and whatever the app's executable now is: current,
    // with the same bundle as without the app, so nothing is asked again.
    const m = helperMatch(dir, 'darwin', root, app);
    expect(m).toEqual(helperMatch(dir, 'darwin', root));
    expect(m.installed).toBe('current');
    expect(appPinned('darwin', app, root)).toBe(true);
    // Folder names compare without case on macOS, as the disk does.
    const lower = { ...app, execPath: '/applications/vigil at home.app/Contents/MacOS/x' };
    expect(helperMatch(dir, 'darwin', root, lower).installed).toBe('current');
    // The same test the helper uses for its pin and for stopping processes.
    for (const execPath of [
      app.execPath,
      lower.execPath,
      '/APPLICATIONS/VIGIL AT HOME.APP/Contents/MacOS/Vigil at Home',
      '/Users/a/Downloads/Vigil at Home.app/Contents/MacOS/Vigil at Home',
      '/Applications/Vigil at Home Evil.app/Contents/MacOS/Vigil at Home',
    ])
      expect(inInstallerFolder('darwin', { execPath, env: {} }), execPath).toBe(
        insideInstalledRoot(execPath, 'darwin'),
      );
  });

  it('asks for a helper update when a Downloads app is pinned to another build', () => {
    const { dir } = bundle();
    const root = mkdtempSync(join(tmpdir(), 'root-'));
    for (const f of installedHelperFiles(dir, 'darwin', root)) {
      mkdirSync(dirname(f.installed), { recursive: true });
      writeFileSync(f.installed, readFileSync(f.bundled));
    }
    // As run from Downloads (or translocated): outside the installer's folder.
    const exe = join(root, 'Vigil at Home');
    writeFileSync(exe, 'app v1');
    const app = { execPath: exe, env: {} };
    const sha = (s: string) => createHash('sha256').update(s).digest('hex');
    const pin = (sha256: string) => {
      mkdirSync(dirname(appPinFile('darwin', root)), { recursive: true });
      writeFileSync(appPinFile('darwin', root), JSON.stringify({ platform: 'darwin', sha256 }));
    };
    // Not pinned yet (a helper from before pins): an update pins it.
    expect(helperMatch(dir, 'darwin', root, app).installed).toBe('outdated');
    pin(sha('app v1'));
    expect(appPinned('darwin', app, root)).toBe(true);
    const v1 = helperMatch(dir, 'darwin', root, app);
    expect(v1.installed).toBe('current');
    // The app was replaced; the helper's files are the same, its pin isn't.
    writeFileSync(exe, 'app v2');
    const v2 = helperMatch(dir, 'darwin', root, app);
    expect(v2.installed).toBe('outdated');
    expect(v2.bundle).not.toBe(v1.bundle);
    pin(sha('app v2'));
    expect(helperMatch(dir, 'darwin', root, app).installed).toBe('current');
  });

  it('pins the AppImage on Linux, and nothing for the installer’s own folder', () => {
    const { dir } = bundle();
    // Real path: the pin target is resolved (tmpdir is a link on macOS).
    const root = realpathSync(mkdtempSync(join(tmpdir(), 'root-')));
    const image = join(root, 'Vigil.AppImage');
    writeFileSync(image, 'image');
    const app = { execPath: '/tmp/.mount_X/vigil-at-home', env: { APPIMAGE: image } };
    expect(appPinTarget('linux', app)).toBe(image);
    expect(appPinTarget('darwin', app)).toBe('/tmp/.mount_X/vigil-at-home');
    expect(appPinned('linux', app, root)).toBe(false);
    const st = statSync(image, { bigint: true });
    mkdirSync(dirname(appPinFile('linux', root)), { recursive: true });
    writeFileSync(appPinFile('linux', root), JSON.stringify({ image: `${st.dev}:${st.ino}` }));
    expect(appPinned('linux', app, root)).toBe(true);
    // A .deb install needs no pin: its folder is root-owned and protected already.
    const deb = { execPath: '/opt/Vigil at Home/vigil-at-home', env: {} };
    expect(inInstallerFolder('linux', deb)).toBe(true);
    // Linux paths keep their case, as the helper compares them: another folder needs a pin.
    expect(
      inInstallerFolder('linux', { ...deb, execPath: '/opt/vigil at home/vigil-at-home' }),
    ).toBe(false);
    expect(inInstallerFolder('linux', { ...deb, execPath: '/opt/Vigil at Home' })).toBe(true);
    // An AppImage there is pinned like one anywhere else: it runs from its own mount.
    const inOpt = {
      execPath: '/tmp/.mount_Y/vigil-at-home',
      env: { APPIMAGE: '/opt/Vigil at Home/Vigil.AppImage' },
    };
    expect(inInstallerFolder('linux', inOpt)).toBe(false);
    // Or by its name, without APPIMAGE set.
    const named = { execPath: '/opt/Vigil at Home/Vigil.AppImage', env: {} };
    expect(inInstallerFolder('linux', named)).toBe(false);
    expect(appPinned('linux', deb, mkdtempSync(join(tmpdir(), 'empty-')))).toBe(true);
    expect(helperMatch(dir, 'linux', root, deb).installed).toBe('none');
  });
});

describe('the uninstallers', () => {
  const script = (rel: string) =>
    readFileSync(join(import.meta.dirname, '..', '..', 'helper', rel), 'utf8');
  it.each([
    ['uninstall.sh', 'launchctl bootout', '/Library/PrivilegedHelperTools/vigil-helper'],
    ['linux/uninstall.sh', 'systemctl disable --now', '/usr/libexec/vigil-helper'],
  ])(
    '%s stops the helper before pin-remove, and runs it before removing the helper',
    (rel, stop, bin) => {
      const text = script(rel);
      const at = (needle: string) => {
        const i = text.indexOf(needle);
        expect(i, needle).toBeGreaterThanOrEqual(0);
        return i;
      };
      expect(at(stop)).toBeLessThan(at(`${bin} pin-remove`));
      expect(at(`${bin} pin-remove`)).toBeLessThan(at(`rm -f ${bin}\n`));
    },
  );
});
