import { execFileWithin } from '@vigil/ai';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
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

/**
 * Where install.sh puts each file the app ships, so the app can tell whether
 * the installed helper is the one it carries. Node is compared by size: it is
 * large, and a new Node release always changes it.
 */
export function installedHelperFiles(
  dir: string,
  platform: NodeJS.Platform = process.platform,
  root = '',
): { bundled: string; installed: string; by: 'content' | 'size' }[] {
  const at = (p: string) => join(root, p);
  if (platform === 'linux') {
    const d = '/usr/libexec/vigil-helper.d';
    return [
      { bundled: join(dir, 'helper.mjs'), installed: at(`${d}/helper.mjs`), by: 'content' },
      { bundled: join(dir, 'node'), installed: at(`${d}/node`), by: 'size' },
      {
        bundled: join(dir, 'linux', 'vigil-helper'),
        installed: at('/usr/libexec/vigil-helper'),
        by: 'content',
      },
      {
        bundled: join(dir, 'linux', 'vigil-helper.service'),
        installed: at('/etc/systemd/system/vigil-helper.service'),
        by: 'content',
      },
      {
        bundled: join(dir, 'linux', 'com.vigilathome.helper.policy'),
        installed: at('/usr/share/polkit-1/actions/com.vigilathome.helper.policy'),
        by: 'content',
      },
    ];
  }
  const d = '/Library/PrivilegedHelperTools/vigil-helper.d';
  return [
    { bundled: join(dir, 'helper.mjs'), installed: at(`${d}/helper.mjs`), by: 'content' },
    { bundled: join(dir, 'node'), installed: at(`${d}/node`), by: 'size' },
    {
      bundled: join(dir, 'vigil-helper'),
      installed: at('/Library/PrivilegedHelperTools/vigil-helper'),
      by: 'content',
    },
    {
      bundled: join(dir, 'com.vigilathome.helper.plist'),
      installed: at('/Library/LaunchDaemons/com.vigilathome.helper.plist'),
      by: 'content',
    },
  ];
}

export interface HelperMatch {
  /** current: the installed helper is the one this app ships; outdated: it isn't. */
  installed: 'none' | 'current' | 'outdated';
  /** Names the shipped helper, so the app asks to update to it only once. */
  bundle: string;
}

/**
 * Compares the installed helper with the one this app carries. After the app
 * is updated by replacing it, the old helper keeps running until install.sh
 * runs again. Every installed file is root-owned but readable.
 */
export function helperMatch(
  dir: string,
  platform: NodeJS.Platform = process.platform,
  root = '',
): HelperMatch {
  const files = installedHelperFiles(dir, platform, root);
  const fingerprint = (path: string, by: 'content' | 'size') =>
    by === 'size'
      ? String(statSync(path).size)
      : createHash('sha256').update(readFileSync(path)).digest('hex');
  const shipped = files.filter((f) => existsSync(f.bundled));
  const bundle = createHash('sha256')
    .update(shipped.map((f) => fingerprint(f.bundled, f.by)).join('\n'))
    .digest('hex')
    .slice(0, 16);
  if (!existsSync(files[0]!.installed)) return { installed: 'none', bundle };
  const same = shipped.every((f) => {
    try {
      return fingerprint(f.bundled, f.by) === fingerprint(f.installed, f.by);
    } catch {
      return false;
    }
  });
  return { installed: same ? 'current' : 'outdated', bundle };
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
  update:
    'Vigil at Home was updated and wants to update its helper, which blocks threats on this Mac, to match.',
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

const runFile: RunFile = async (file, args) => {
  const r = await execFileWithin(file, args, 3 * 60_000);
  return { code: r.code ?? 1, stdout: r.stdout, stderr: r.stderr };
};

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

/**
 * Install or remove the helper through the system's admin password dialog.
 * An update runs install.sh too, with a dialog that says why it is asking.
 */
export async function runHelperScript(
  kind: 'install' | 'update' | 'uninstall',
  dir = helperBundleDir(),
  run: RunFile = runFile,
  platform: NodeJS.Platform = process.platform,
): Promise<HelperInstallResult> {
  if (platform !== 'darwin' && platform !== 'linux') {
    return { ok: false, error: 'The helper only runs on macOS and Linux' };
  }
  if (!dir) return { ok: false, error: 'This build of Vigil does not include the helper' };
  const script = kind === 'uninstall' ? 'uninstall' : 'install';
  if (platform === 'linux') return runWithPkexec(script, dir, run);
  const out = await run('/usr/bin/osascript', adminScriptArgs(join(dir, `${script}.sh`), kind));
  if (out.code === 0) return { ok: true };
  // osascript reports a closed password dialog as error -128.
  if (/-128/.test(out.stderr)) return { ok: false, error: 'cancelled' };
  const msg = out.stderr
    .replace(/^\d+:\d+: execution error: /, '')
    .replace(/ \(-?\d+\)\s*$/, '')
    .trim();
  return { ok: false, error: msg || `The ${script} script failed` };
}
