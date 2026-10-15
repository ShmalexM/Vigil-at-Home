import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  existsSync,
  lstatSync,
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
  ELEVATED_ENTRY,
  elevatedArgs,
  helperBundleDir,
  helperInstallCommand,
  helperManifest,
  helperMatch,
  helperScriptFiles,
  helperPayloadDir,
  inInstallerFolder,
  installedHelperFiles,
  ROOT_SHELL,
  runHelperScript,
  shellQuote,
  unlessDemo,
  type RunFile,
} from './helper-install.js';

/**
 * A helper folder like the app's. Each script records where it ran from, the
 * lib.sh beside it, whether $VH_LEAK reached it and its argument in `out`, a path written
 * into the script since root starts it with an empty environment, so a test
 * can tell what root would have run.
 */
function bundle() {
  const res = mkdtempSync(join(tmpdir(), "Vigil at Home's Resources-"));
  const dir = join(res, 'helper');
  const out = join(mkdtempSync(join(tmpdir(), 'out-')), 'out');
  mkdirSync(dir);
  const script = (rel: string) =>
    `#!/bin/sh\nset -eu\nh=$(dirname "$0")\n. "$h/${rel}lib.sh"\n` +
    `echo "ran $0 with $LIB leak=\${VH_LEAK:-}" >${shellQuote(out)}\n` +
    `echo "app=\${1-none}" >>${shellQuote(out)}\n`;
  writeFileSync(join(dir, 'node'), 'node');
  writeFileSync(join(dir, 'lib.sh'), 'LIB=shipped\n');
  for (const f of ['install.sh', 'uninstall.sh']) writeFileSync(join(dir, f), script(''));
  for (const f of ['helper.mjs', 'vigil-helper', 'com.vigilathome.helper.plist'])
    writeFileSync(join(dir, f), f);
  mkdirSync(join(dir, 'linux'));
  for (const f of ['install.sh', 'uninstall.sh'])
    writeFileSync(join(dir, 'linux', f), script('../'));
  for (const f of ['vigil-helper', 'vigil-helper.service', 'com.vigilathome.helper.policy'])
    writeFileSync(join(dir, 'linux', f), f);
  return { res, dir, out };
}

/** The folder the entry copies from: after $0 for pkexec, right after the entry for osascript. */
const srcOf = (file: string, args: string[]) =>
  args[args.indexOf(ELEVATED_ENTRY) + (file === '/usr/bin/pkexec' ? 2 : 1)]!;

/**
 * Run what pkexec or osascript would run as root, here as this user, from the
 * caller's environment plus `env`. ROOT_SHELL empties it before the entry.
 */
function asRoot(file: string, args: string[], env: Record<string, string> = {}) {
  let argv: string[];
  if (file === '/usr/bin/pkexec') {
    expect(args.slice(0, ROOT_SHELL.length + 2)).toEqual([
      ...ROOT_SHELL,
      ELEVATED_ENTRY,
      'vigil-helper',
    ]);
    argv = args;
  } else {
    expect(file).toBe('/usr/bin/osascript');
    // The AppleScript starts the entry through ROOT_SHELL.
    expect(args.join(' ')).toContain(
      `"${ROOT_SHELL.join(' ')} " & quoted form of (item 1 of argv)`,
    );
    // After the AppleScript: the entry, then its arguments.
    const at = args.indexOf(ELEVATED_ENTRY);
    expect(at).toBeGreaterThan(0);
    argv = [...ROOT_SHELL, ELEVATED_ENTRY, 'vigil-helper', ...args.slice(at + 1)];
  }
  const r = spawnSync(argv[0]!, argv.slice(1), {
    encoding: 'utf8',
    env: { ...process.env, ...env },
  });
  return { code: r.status ?? 1, stdout: r.stdout, stderr: r.stderr };
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
    const checks = helperManifest(dir)
      .flat()
      .map((a) => shellQuote(a))
      .join(' ');
    const entry = `sudo /usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh -c ${shellQuote(ELEVATED_ENTRY)} vigil-helper`;
    // install.sh gets the app to pin as its one argument.
    const app = (p: NodeJS.Platform) => shellQuote(appPinTarget(p));
    expect(helperInstallCommand(dir, 'darwin')).toBe(
      `${entry} ${shellQuote(dir)} install.sh ${app('darwin')} ${checks}`,
    );
    expect(helperInstallCommand(dir, 'linux')).toBe(
      `d=$(mktemp -d) && cp -R ${shellQuote(dir)}/. "$d" && ${entry} "$d" linux/install.sh ${app('linux')} ${checks}; rm -rf "$d"`,
    );
    expect(shellQuote("a b'c")).toBe(`'a b'\\''c'`);
    expect(helperInstallCommand(null)).toBeUndefined();
    // A folder the entry would refuse gets no command at all.
    symlinkSync(join(dir, 'node'), join(dir, 'link'));
    expect(helperInstallCommand(dir, 'darwin')).toBeUndefined();
    rmSync(join(dir, 'link'));
    // Nor does a build missing a file the script needs.
    expect(helperInstallCommand(dir, 'darwin')).toBeDefined();
    rmSync(join(dir, 'node'));
    expect(helperInstallCommand(dir, 'darwin')).toBeUndefined();
    expect(helperInstallCommand(dir, 'linux')).toBeUndefined();
  });

  it('runs the Terminal command from a checked copy, with an empty environment', () => {
    const { dir, out } = bundle();
    for (const platform of ['darwin', 'linux'] as const) {
      // As the user would paste it, minus sudo.
      const cmd = helperInstallCommand(dir, platform)!.replace('sudo ', '');
      const r = spawnSync('/bin/sh', ['-c', cmd], {
        encoding: 'utf8',
        env: { ...process.env, VH_LEAK: 'yes', TMPDIR: dirname(out) },
      });
      expect(r.status, r.stderr).toBe(0);
      expect(readFileSync(out, 'utf8')).toMatch(
        /^ran \/tmp\/vigil-helper\.[^/]+\/.*install\.sh with shipped leak=$/m,
      );
      expect(readFileSync(out, 'utf8')).toContain(`\napp=${appPinTarget(platform)}\n`);
    }
  });

  it('keeps the elevated entry POSIX and shellcheck-clean', () => {
    const f = join(mkdtempSync(join(tmpdir(), 'entry-')), 'entry.sh');
    writeFileSync(f, `#!/bin/sh\n${ELEVATED_ENTRY}\n`);
    expect(spawnSync('/bin/sh', ['-n', f]).status).toBe(0);
    if (spawnSync('shellcheck', ['--version']).status === 0) {
      const r = spawnSync('shellcheck', ['-s', 'sh', f], { encoding: 'utf8' });
      expect(r.status, r.stdout).toBe(0);
    }
  });

  it('lists every helper file with its SHA-256, and refuses links', () => {
    const { dir } = bundle();
    const m = helperManifest(dir);
    expect(m.map(([f]) => f)).toEqual([
      'com.vigilathome.helper.plist',
      'helper.mjs',
      'install.sh',
      'lib.sh',
      'linux/com.vigilathome.helper.policy',
      'linux/install.sh',
      'linux/uninstall.sh',
      'linux/vigil-helper',
      'linux/vigil-helper.service',
      'node',
      'uninstall.sh',
      'vigil-helper',
    ]);
    // Every file a script needs is among them.
    for (const platform of ['darwin', 'linux'] as const)
      for (const kind of ['install', 'uninstall'] as const)
        for (const f of helperScriptFiles(kind, platform)) expect(m.map(([g]) => g)).toContain(f);
    expect(m.find(([f]) => f === 'node')![1]).toBe(
      createHash('sha256').update('node').digest('hex'),
    );
    // Each file has its own hash, so moving bytes from one file into the next
    // changes both, though the files together hold the same bytes.
    writeFileSync(join(dir, 'helper.mjs'), 'helper');
    writeFileSync(join(dir, 'node'), '.mjsnode');
    const moved = new Map(helperManifest(dir));
    const was = new Map(m);
    expect(moved.get('helper.mjs')).not.toBe(was.get('helper.mjs'));
    expect(moved.get('node')).not.toBe(was.get('node'));
    symlinkSync('/etc/passwd', join(dir, 'linux', 'lib.sh'));
    expect(() => helperManifest(dir)).toThrow(/not a regular file/);
  });

  it('passes the entry and every path to osascript as arguments, never inside the AppleScript', () => {
    const path = '/Applications/Evil" & do shell script "rm -rf ~".app/helper';
    const app = '/Applications/x" & do shell script "id".app/Contents/MacOS/x';
    const args = adminScriptArgs(
      elevatedArgs(path, 'install.sh', app, [['node', 'ab']]),
      'install',
    );
    expect(args.slice(-5)).toEqual([path, 'install.sh', app, 'node', 'ab']);
    expect(args.at(-6)).toBe(ELEVATED_ENTRY);
    const script = args.slice(0, -6).join(' ');
    expect(script).not.toContain('rm -rf');
    expect(script).toContain('quoted form of (item 1 of argv)');
    // Root's shell starts with an empty environment.
    expect(script).toContain(
      `"/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin /bin/sh -c " & quoted form of (item 1 of argv)`,
    );
    expect(script).toContain('quoted form of (a as text)');
    expect(script).toContain('with administrator privileges');
  });

  for (const platform of ['darwin', 'linux'] as const) {
    it(`runs the script as root only from a checked, private copy (${platform})`, async () => {
      const { dir, out } = bundle();
      let src = '';
      const run: RunFile = async (file, args) => {
        src = srcOf(file, args);
        // Root ignores the caller's TMPDIR and every other variable.
        return asRoot(file, args, { VH_LEAK: 'yes', TMPDIR: dirname(out) });
      };
      expect(await runHelperScript('install', dir, run, platform)).toEqual({ ok: true });
      const ran = readFileSync(out, 'utf8');
      const script = platform === 'linux' ? 'linux/install.sh' : 'install.sh';
      // From the copy root made, not from the app or the user's staging folder.
      expect(ran).toMatch(
        new RegExp(`^ran /tmp/vigil-helper\\.[^/]+/${script} with shipped leak=$`, 'm'),
      );
      expect(ran).not.toContain(src);
      expect(ran).not.toContain(dir);
      // And that copy is gone afterwards.
      const copy = ran.split(' ')[1]!.replace(`/${script}`, '');
      expect(copy.startsWith(dirname(out))).toBe(false);
      expect(existsSync(copy)).toBe(false);
      if (platform === 'linux') {
        expect(src.startsWith(dir)).toBe(false);
        expect(existsSync(src)).toBe(false);
      } else {
        expect(src).toBe(dir);
      }
      // install.sh gets the app to pin; uninstall.sh gets an empty argument.
      expect(ran).toContain(`\napp=${appPinTarget(platform)}\n`);
      expect(await runHelperScript('uninstall', dir, run, platform)).toEqual({ ok: true });
      expect(readFileSync(out, 'utf8')).toMatch(/uninstall\.sh with shipped leak=\napp=\n$/);
    });

    it(`refuses, and runs nothing, when a file is swapped after the app checked it (${platform})`, async () => {
      for (const swap of ['content', 'symlink', 'script'] as const) {
        const { dir, out } = bundle();
        const evil = join(mkdtempSync(join(tmpdir(), 'evil-')), 'lib.sh');
        writeFileSync(evil, 'LIB=swapped\n');
        const run: RunFile = async (file, args) => {
          // A process running as the user, while the password dialog is up.
          const src = srcOf(file, args);
          const lib = join(src, 'lib.sh');
          rmSync(lib);
          if (swap === 'content') writeFileSync(lib, 'LIB=swapped\n');
          else if (swap === 'symlink') {
            // Even a link to a file with the very same content is refused.
            writeFileSync(evil, 'LIB=shipped\n');
            symlinkSync(evil, lib);
          } else {
            writeFileSync(lib, 'LIB=shipped\n');
            const s = join(src, platform === 'linux' ? 'linux/install.sh' : 'install.sh');
            writeFileSync(s, `#!/bin/sh\necho "ran swapped" >${shellQuote(out)}\n`);
          }
          return asRoot(file, args);
        };
        const r = await runHelperScript('install', dir, run, platform);
        expect(r.ok, swap).toBe(false);
        expect(r.ok ? '' : r.error, swap).toMatch(/^Not running the helper script: /);
        expect(existsSync(out), swap).toBe(false);
      }
    });
  }

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
    const after = (run: string[]) => run.slice(run.indexOf(ELEVATED_ENTRY) + 1);
    expect(after(seen[0]!).slice(0, 2)).toEqual([dir, 'install.sh']);

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
    expect(after(seen[2]!).slice(0, 2)).toEqual([dir, 'uninstall.sh']);

    expect(await runHelperScript('install', null, answer(0))).toMatchObject({ ok: false });
    // A link in the app's helper folder: refused before any password dialog.
    symlinkSync('/etc/passwd', join(dir, 'extra'));
    const before = seen.length;
    expect(await runHelperScript('install', dir, answer(0), 'darwin')).toMatchObject({
      ok: false,
      error: expect.stringContaining('not a regular file'),
    });
    expect(await runHelperScript('install', dir, answer(0), 'linux')).toMatchObject({ ok: false });
    expect(seen.length).toBe(before);
    // A build missing a file the script needs: refused the same way.
    rmSync(join(dir, 'extra'));
    rmSync(join(dir, 'lib.sh'));
    for (const platform of ['darwin', 'linux'] as const) {
      expect(await runHelperScript('install', dir, answer(0), platform)).toEqual({
        ok: false,
        error: 'This build of Vigil is missing some of the helper’s files',
      });
      expect(await runHelperScript('uninstall', dir, answer(0), platform)).toMatchObject({
        ok: false,
        error: expect.stringMatching(/missing/),
      });
    }
    expect(seen.length).toBe(before);
  });

  it('counts only a closed dialog as a cancel, not -128 in a path', async () => {
    const { dir } = bundle();
    const answer =
      (stderr: string): RunFile =>
      async () => ({ code: 1, stdout: '', stderr });
    expect(
      await runHelperScript(
        'install',
        dir,
        answer('0:1: execution error: User canceled. (-128)\n'),
        'darwin',
      ),
    ).toEqual({ ok: false, error: 'cancelled' });
    const r = await runHelperScript(
      'install',
      dir,
      answer('0:9: execution error: sh: /Applications/Vigil-128.app/x: Permission denied (126)'),
      'darwin',
    );
    expect(r.ok).toBe(false);
    expect(r.error).toMatch(/Permission denied/);
    expect(r).toHaveProperty('command');
  });

  it('runs one install at a time, whichever window asked', async () => {
    const { dir } = bundle();
    let calls = 0;
    let finish!: () => void;
    const slow: RunFile = () => {
      calls++;
      return new Promise((resolve) => {
        finish = () => resolve({ code: 0, stdout: '', stderr: '' });
      });
    };
    const first = runHelperScript('install', dir, slow, 'darwin');
    const again = runHelperScript('install', dir, slow, 'darwin');
    expect(await runHelperScript('uninstall', dir, slow, 'darwin')).toMatchObject({
      ok: false,
      error: expect.stringMatching(/being installed/),
    });
    finish();
    expect(await first).toEqual({ ok: true });
    expect(await again).toEqual({ ok: true });
    expect(calls).toBe(1);
    // Once it finishes, the next one runs.
    const next = runHelperScript('uninstall', dir, slow, 'darwin');
    finish();
    expect(await next).toEqual({ ok: true });
    expect(calls).toBe(2);
  });

  it('on Linux, runs the entry through pkexec on a private copy of the files', async () => {
    const { dir } = bundle();
    const seen: string[][] = [];
    let staged = '';
    const answer =
      (code: number, stderr = ''): RunFile =>
      async (file, args) => {
        seen.push([file, ...args]);
        staged = args[7]!;
        // The copy is there while pkexec runs, with the files the app checked.
        expect(readFileSync(join(staged, args[8]!), 'utf8')).toBe(
          readFileSync(join(dir, args[8]!), 'utf8'),
        );
        return { code, stdout: '', stderr };
      };
    expect(await runHelperScript('install', dir, answer(0), 'linux')).toEqual({ ok: true });
    expect(seen[0]?.slice(0, 8)).toEqual([
      '/usr/bin/pkexec',
      '/usr/bin/env',
      '-i',
      'PATH=/usr/bin:/bin:/usr/sbin:/sbin',
      '/bin/sh',
      '-c',
      ELEVATED_ENTRY,
      'vigil-helper',
    ]);
    expect(seen[0]?.[9]).toBe('linux/install.sh');
    expect(seen[0]?.[10]).toBe(appPinTarget('linux'));
    expect(seen[0]?.slice(11)).toEqual(helperManifest(dir).flat());
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
  });

  it('explains a password dialog that could not open, and offers the terminal command', async () => {
    const { dir } = bundle();
    const fails =
      (r: Awaited<ReturnType<RunFile>>): RunFile =>
      async () =>
        r;
    const noPkexec = await runHelperScript(
      'install',
      dir,
      fails({ code: 1, stdout: '', stderr: '', missing: true }),
      'linux',
    );
    expect(noPkexec.error).toMatch(/no pkexec/);
    expect(noPkexec.command).toBe(helperInstallCommand(dir, 'linux'));
    expect(noPkexec.command).toContain(` vigil-helper "$d" linux/install.sh `);

    const noAgent = await runHelperScript(
      'update',
      dir,
      fails({
        code: 127,
        stdout: '',
        stderr: 'Error executing command as another user: No authentication agent found.',
      }),
      'linux',
    );
    expect(noAgent.error).toMatch(/No password dialog could open/);
    expect(noAgent.command).toBeDefined();

    expect(
      await runHelperScript(
        'install',
        dir,
        fails({ code: 127, stdout: '', stderr: 'Not authorized' }),
        'linux',
      ),
    ).toMatchObject({ error: 'Your account isn’t allowed to do this' });

    // A cancelled dialog is the user's answer: nothing to fall back to.
    expect(
      await runHelperScript('install', dir, fails({ code: 126, stdout: '', stderr: '' }), 'linux'),
    ).toEqual({ ok: false, error: 'cancelled' });
    // Root refused files that changed after Vigil checked them: no command to paste.
    const tampered = await runHelperScript(
      'install',
      dir,
      fails({
        code: 1,
        stdout: '',
        stderr:
          '0:1: execution error: Not running the helper script: install.sh changed after Vigil checked it (1)',
      }),
      'darwin',
    );
    expect(tampered.error).toMatch(/changed after Vigil checked it/);
    expect(tampered.command).toBeUndefined();
    const mac = await runHelperScript(
      'install',
      dir,
      fails({ code: 1, stdout: '', stderr: '0:1: execution error: Boom. (1)' }),
      'darwin',
    );
    expect(mac).toEqual({
      ok: false,
      error: 'Boom.',
      command: helperInstallCommand(dir, 'darwin'),
    });
    expect(mac.command).toContain(` vigil-helper ${shellQuote(dir)} install.sh `);
  });

  it('never runs the real script from the demo', async () => {
    let ran = 0;
    const real = async () => (ran++, { ok: true });
    expect(await unlessDemo(true, real)()).toMatchObject({ ok: false });
    expect(ran).toBe(0);
    expect(await unlessDemo(false, real)()).toEqual({ ok: true });
    expect(ran).toBe(1);
  });

  it('runs install.sh for an update, with a dialog that says why', async () => {
    const { dir } = bundle();
    const seen: string[][] = [];
    const ok: RunFile = async (file, args) => {
      seen.push([file, ...args]);
      return { code: 0, stdout: '', stderr: '' };
    };
    expect(await runHelperScript('update', dir, ok, 'darwin')).toEqual({ ok: true });
    const after = (run: string[]) => run.slice(run.indexOf(ELEVATED_ENTRY) + 1);
    expect(after(seen[0]!)[1]).toBe('install.sh');
    expect(seen[0]?.join(' ')).toContain('was updated and wants to update its helper');
    expect(await runHelperScript('update', dir, ok, 'linux')).toEqual({ ok: true });
    expect(after(seen[1]!)[2]).toBe('linux/install.sh');
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
      const payload = join(root, helperPayloadDir(platform));
      let n = 0;
      // As install.sh does: a new versions/<id>, then `current` pointed at it.
      const install = () => {
        const version = `v${++n}`;
        mkdirSync(join(payload, 'versions', version), { recursive: true });
        rmSync(join(payload, 'current'), { force: true });
        symlinkSync(`versions/${version}`, join(payload, 'current'));
        for (const f of files) {
          mkdirSync(dirname(f.installed), { recursive: true });
          writeFileSync(f.installed, readFileSync(f.bundled));
        }
      };
      expect(files[0]!.installed).toBe(join(payload, 'current', 'helper.mjs'));
      expect(files[1]!.installed).toBe(join(payload, 'current', 'node'));

      const none = helperMatch(dir, platform, root);
      expect(none.installed).toBe('none');
      // A helper from before versions, with its files at the top of the folder.
      mkdirSync(payload, { recursive: true });
      writeFileSync(join(payload, 'helper.mjs'), readFileSync(join(dir, 'helper.mjs')));
      writeFileSync(join(payload, 'node'), readFileSync(join(dir, 'node')));
      expect(helperMatch(dir, platform, root).installed).toBe('outdated');
      install();
      expect(lstatSync(join(payload, 'current')).isSymbolicLink()).toBe(true);
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

describe('helper launcher', () => {
  it('runs the helper only from one plain version name', () => {
    const root = mkdtempSync(join(tmpdir(), 'vigil-launcher-'));
    const d = join(root, 'vigil-helper.d');
    const version = '20261009T000000Z.1.abc';
    mkdirSync(join(d, 'versions', version), { recursive: true });
    // Both present, so only the link check refuses `versions/a` plus a newline
    // where readlink's output loses the newline.
    mkdirSync(join(d, 'versions', 'a'));
    mkdirSync(join(d, 'versions', 'a\n'));
    for (const rel of ['vigil-helper', 'linux/vigil-helper']) {
      const src = readFileSync(join(import.meta.dirname, '..', '..', 'helper', rel), 'utf8');
      const launcher = join(root, 'vigil-helper');
      writeFileSync(launcher, src.replace(/^D=.*$/m, `D=${shellQuote(d)}`));
      const run = (target: string) => {
        rmSync(join(d, 'current'), { force: true });
        symlinkSync(target, join(d, 'current'));
        return spawnSync('/bin/sh', [launcher, 'daemon'], { encoding: 'utf8' });
      };
      for (const bad of [
        'versions/..',
        'versions/.',
        'versions/',
        'versions/a/b',
        '/tmp',
        'x',
        'versions/a=b',
        'versions/.hidden',
        'versions/a\n',
      ]) {
        const r = run(bad);
        expect(r.status, `${rel} ${bad}`).toBe(1);
        expect(r.stderr, `${rel} ${bad}`).toMatch(/Unexpected/);
      }
      // A plain name gets as far as starting that version's node (absent here).
      const ok = run(`versions/${version}`);
      expect(ok.stderr).not.toMatch(/Unexpected/);
      expect(ok.stderr).toContain(`versions/${version}/node`);
    }
    rmSync(root, { recursive: true, force: true });
  });
});

describe('the uninstallers', () => {
  const script = (rel: string) =>
    readFileSync(join(import.meta.dirname, '..', '..', 'helper', rel), 'utf8');
  it.each([
    ['uninstall.sh', 'launchctl bootout', '"$TOOLS/vigil-helper"'],
    ['linux/uninstall.sh', 'systemctl disable --now', '"$LIBEXEC/vigil-helper"'],
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
