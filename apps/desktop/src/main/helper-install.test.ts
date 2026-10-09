import { execFileSync } from 'node:child_process';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  adminScriptArgs,
  helperBundleDir,
  helperDigest,
  helperInstallCommand,
  helperScriptFiles,
  helperMatch,
  installedHelperFiles,
  ROOT_SHELL,
  rootStageScript,
  runHelperScript,
  shellQuote,
  unlessDemo,
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
        [files[0]!, helperDigest(dir, files), ...files].map(shellQuote).join(' '),
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
      `cd "$(dirname "$0")" && pwd > ${shellQuote(join(out, 'ran-in'))}; cat "$(dirname "$0")/../helper.mjs" > ${shellQuote(join(out, 'saw'))}`,
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
          ...files,
        ],
        // Root ignores whatever TMPDIR the caller had.
        { stdio: 'pipe', env: { ...process.env, TMPDIR: out } },
      );

    stage(dir);
    expect(readFileSync(join(out, 'saw'), 'utf8')).toBe('helper.mjs');
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
    expect(noPkexec.command).toContain(` vigil-helper-setup "$d" 'linux/install.sh' `);

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
    expect(mac.command).toContain(` vigil-helper-setup ${shellQuote(dir)} 'install.sh' `);
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
});
