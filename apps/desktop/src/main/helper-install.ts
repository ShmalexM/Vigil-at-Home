import { execFile } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { HelperInstallResult } from '../shared/ipc.js';

const hasHelper = (dir: string) =>
  existsSync(join(dir, 'node')) &&
  (existsSync(join(dir, 'install.sh')) || existsSync(join(dir, 'linux', 'install.sh')));

/**
 * The helper files shipped in the app (Contents/Resources/helper). A
 * development build doesn't carry them, so it uses `devDir` instead, which
 * `pnpm build:helper` fills (`pnpm dev` runs it first). Null when neither has them.
 */
export function helperBundleDir(
  resourcesPath: string | undefined = process.resourcesPath,
  devDir?: string,
): string | null {
  if (resourcesPath && hasHelper(join(resourcesPath, 'helper')))
    return join(resourcesPath, 'helper');
  return devDir && hasHelper(devDir) ? devDir : null;
}

/** Shell-quote one argument for a command the user pastes into Terminal. */
export function shellQuote(s: string): string {
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The script that installs or removes the helper on this OS. */
export function helperScript(
  dir: string,
  kind: 'install' | 'uninstall',
  platform: NodeJS.Platform = process.platform,
): string {
  return platform === 'linux' ? join(dir, 'linux', `${kind}.sh`) : join(dir, `${kind}.sh`);
}

/** The Terminal command that installs the helper, for the setup wizard. */
export function helperInstallCommand(
  dir = helperBundleDir(),
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  if (!dir) return undefined;
  // Linux: root can't read an AppImage's mount, so copy the helper out first,
  // as runWithPkexec does; `sh` runs the script whatever its permissions.
  if (platform === 'linux')
    return `d=$(mktemp -d) && cp -R ${shellQuote(dir)}/. "$d" && sudo sh "$d/linux/install.sh"`;
  return `sudo ${shellQuote(helperScript(dir, 'install', platform))}`;
}

const PROMPTS = {
  install:
    'Vigil at Home wants to install its helper, which blocks and quarantines threats on this Mac.',
  uninstall: 'Vigil at Home wants to remove its helper.',
} as const;

/**
 * The osascript arguments that run one of the bundled scripts as root. macOS
 * shows its own password dialog. The script path goes in as an argument and
 * through AppleScript's `quoted form of`, so no path can break out of it.
 */
export function adminScriptArgs(script: string, kind: keyof typeof PROMPTS): string[] {
  return [
    '-e',
    'on run argv',
    '-e',
    `do shell script (quoted form of item 1 of argv) with prompt ${JSON.stringify(PROMPTS[kind])} with administrator privileges`,
    '-e',
    'end run',
    script,
  ];
}

export type RunFile = (
  file: string,
  args: string[],
) => Promise<{ code: number; stdout: string; stderr: string }>;

const runFile: RunFile = (file, args) =>
  new Promise((resolve) =>
    execFile(file, args, { timeout: 3 * 60_000 }, (err, stdout, stderr) =>
      resolve({
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
        stdout: String(stdout),
        stderr: String(stderr),
      }),
    ),
  );

export const PKEXEC = '/usr/bin/pkexec';

/**
 * Linux: run the script as root through pkexec, which shows the desktop's own
 * password dialog. An AppImage's files sit on a FUSE mount that root can't
 * read, so the helper files are copied to a private temporary folder first.
 */
async function runWithPkexec(
  kind: 'install' | 'uninstall',
  dir: string,
  run: RunFile,
): Promise<HelperInstallResult> {
  const stage = mkdtempSync(join(tmpdir(), 'vigil-helper-'));
  try {
    cpSync(dir, stage, { recursive: true });
    const out = await run(PKEXEC, ['/bin/sh', helperScript(stage, kind, 'linux')]);
    if (out.code === 0) return { ok: true };
    // pkexec exits 126 when the password dialog is closed, 127 when not allowed.
    if (out.code === 126) return { ok: false, error: 'cancelled' };
    if (out.code === 127) return { ok: false, error: 'Your account isn’t allowed to do this' };
    const msg = out.stderr.trim().split('\n').at(-1)?.trim();
    return { ok: false, error: msg || `The ${kind} script failed` };
  } finally {
    rmSync(stage, { recursive: true, force: true });
  }
}

/** Install or remove the helper through the system's admin password dialog. */
export async function runHelperScript(
  kind: 'install' | 'uninstall',
  dir = helperBundleDir(),
  run: RunFile = runFile,
  platform: NodeJS.Platform = process.platform,
): Promise<HelperInstallResult> {
  if (platform !== 'darwin' && platform !== 'linux') {
    return { ok: false, error: 'The helper only runs on macOS and Linux' };
  }
  if (!dir) return { ok: false, error: 'This build of Vigil does not include the helper' };
  if (platform === 'linux') return runWithPkexec(kind, dir, run);
  const out = await run('/usr/bin/osascript', adminScriptArgs(join(dir, `${kind}.sh`), kind));
  if (out.code === 0) return { ok: true };
  // osascript reports a closed password dialog as error -128.
  if (/-128/.test(out.stderr)) return { ok: false, error: 'cancelled' };
  const msg = out.stderr
    .replace(/^\d+:\d+: execution error: /, '')
    .replace(/ \(-?\d+\)\s*$/, '')
    .trim();
  return { ok: false, error: msg || `The ${kind} script failed` };
}
