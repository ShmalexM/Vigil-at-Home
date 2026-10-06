import { existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  adminScriptArgs,
  helperBundleDir,
  helperInstallCommand,
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
    const cmd = helperInstallCommand(dir, 'darwin')!;
    expect(cmd).toBe(`sudo ${shellQuote(join(dir, 'install.sh'))}`);
    expect(helperInstallCommand(dir, 'linux')).toBe(
      `sudo sh ${shellQuote(join(dir, 'linux', 'install.sh'))}`,
    );
    expect(shellQuote("a b'c")).toBe(`'a b'\\''c'`);
    expect(helperInstallCommand(null)).toBeUndefined();
  });

  it('passes the script path to osascript as an argument, never inside the AppleScript', () => {
    const path = '/Applications/Evil" & do shell script "rm -rf ~".app/helper/install.sh';
    const args = adminScriptArgs(path, 'install');
    expect(args.at(-1)).toBe(path);
    expect(args.slice(0, -1).join(' ')).not.toContain('rm -rf');
    expect(args.join(' ')).toContain('quoted form of item 1 of argv');
    expect(args.join(' ')).toContain('with administrator privileges');
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
    expect(seen[0]?.at(-1)).toBe(join(dir, 'install.sh'));

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
    expect(seen[2]?.at(-1)).toBe(join(dir, 'uninstall.sh'));

    expect(await runHelperScript('install', null, answer(0))).toMatchObject({ ok: false });
  });

  it('on Linux, runs a private copy of the script through pkexec', async () => {
    const { dir } = bundle();
    const seen: string[][] = [];
    let staged = '';
    const answer =
      (code: number, stderr = ''): RunFile =>
      async (file, args) => {
        seen.push([file, ...args]);
        staged = args[1]!;
        // The copy is there while pkexec runs it.
        expect(readFileSync(staged, 'utf8')).toBe(
          `# ${staged.endsWith('uninstall.sh') ? 'uninstall' : 'install'}.sh`,
        );
        return { code, stdout: '', stderr };
      };
    expect(await runHelperScript('install', dir, answer(0), 'linux')).toEqual({ ok: true });
    expect(seen[0]?.slice(0, 2)).toEqual(['/usr/bin/pkexec', '/bin/sh']);
    expect(staged).toMatch(/vigil-helper-[^/]+\/linux\/install\.sh$/);
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
    expect(staged).toMatch(/linux\/uninstall\.sh$/);
    expect(await runHelperScript('install', dir, answer(0), 'win32')).toMatchObject({ ok: false });
  });
});
