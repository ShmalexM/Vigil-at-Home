import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileId } from '@vigil/core/self';
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

/** The running app, as install.sh pins it (packages/helper/src/appPin.ts). */
export interface AppIdentity {
  execPath: string;
  env: NodeJS.ProcessEnv;
}

const thisApp = (): AppIdentity => ({ execPath: process.execPath, env: process.env });

/**
 * What install.sh pins as the app: the main executable on macOS, the
 * AppImage on Linux (its real path, as the kernel names it). A .deb or .rpm
 * install is pinned by its root-owned folder instead, which install.sh
 * recognises from the same path.
 */
export function appPinTarget(
  platform: NodeJS.Platform = process.platform,
  app: AppIdentity = thisApp(),
): string {
  const image = platform === 'linux' ? app.env['APPIMAGE'] : undefined;
  if (!image) return app.execPath;
  try {
    return realpathSync(image);
  } catch {
    return image;
  }
}

/** Where the helper keeps its pin; root-owned, readable by everyone. */
export function appPinFile(platform: NodeJS.Platform = process.platform, root = ''): string {
  return join(
    root,
    platform === 'linux' ? '/var/lib/vigil' : '/Library/Application Support/Vigil',
    'app-pin.json',
  );
}

/** The installer's own folder on Linux, which needs no pin (config installedSelf). */
const LINUX_INSTALLED = '/opt/Vigil at Home/';

/**
 * This app's identity in the terms of the pin: on macOS its executable's
 * sha256, on Linux its AppImage's device and inode. Undefined when nothing
 * needs pinning.
 */
function appIdentity(platform: NodeJS.Platform, app: AppIdentity): string | undefined {
  const target = appPinTarget(platform, app);
  if (platform === 'linux') {
    if (target.startsWith(LINUX_INSTALLED)) return undefined;
    const st = statSync(target, { bigint: true });
    return fileId(st.dev, st.ino);
  }
  return fileSha256(target);
}

/**
 * Whether the helper's pin names this app. After an update that replaced
 * the app it names the old one, and the helper update pins this one.
 */
export function appPinned(
  platform: NodeJS.Platform = process.platform,
  app: AppIdentity = thisApp(),
  root = '',
): boolean {
  const want = appIdentity(platform, app);
  if (want === undefined) return true;
  try {
    const pin = JSON.parse(readFileSync(appPinFile(platform, root), 'utf8')) as {
      image?: unknown;
      sha256?: unknown;
    };
    return (platform === 'linux' ? pin.image : pin.sha256) === want;
  } catch {
    return false;
  }
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
 *
 * Given `app`, a helper pinned to another app (appPinned) is outdated too,
 * and the bundle names this app as well, so each new app asks once to be
 * pinned even when the helper's own files didn't change.
 */
export function helperMatch(
  dir: string,
  platform: NodeJS.Platform = process.platform,
  root = '',
  app?: AppIdentity,
): HelperMatch {
  const files = installedHelperFiles(dir, platform, root);
  const fingerprint = (path: string, by: 'content' | 'size') =>
    by === 'size'
      ? String(statSync(path).size)
      : createHash('sha256').update(readFileSync(path)).digest('hex');
  const shipped = files.filter((f) => existsSync(f.bundled));
  let identity: string | undefined;
  try {
    identity = app && appIdentity(platform, app);
  } catch {
    identity = undefined; // the app's own file is unreadable: nothing to compare
  }
  const bundle = createHash('sha256')
    .update(
      [...shipped.map((f) => fingerprint(f.bundled, f.by)), ...(identity ? [identity] : [])].join(
        '\n',
      ),
    )
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
  const pinned = !identity || !app || appPinned(platform, app, root);
  return { installed: same && pinned ? 'current' : 'outdated', bundle };
}

/** The files each script reads, the script first, relative to the helper folder. */
export function helperScriptFiles(
  kind: 'install' | 'uninstall',
  platform: NodeJS.Platform = process.platform,
): string[] {
  if (platform === 'linux') {
    return kind === 'uninstall'
      ? ['linux/uninstall.sh']
      : [
          'linux/install.sh',
          'node',
          'helper.mjs',
          'linux/vigil-helper',
          'linux/vigil-helper.service',
          'linux/com.vigilathome.helper.policy',
        ];
  }
  return kind === 'uninstall'
    ? ['uninstall.sh']
    : ['install.sh', 'node', 'helper.mjs', 'vigil-helper', 'com.vigilathome.helper.plist'];
}

const hashCache = new Map<string, { key: string; hex: string }>();

function fileSha256(path: string): string {
  const st = statSync(path);
  const key = `${st.size}:${st.mtimeMs}:${st.ino}`;
  const hit = hashCache.get(path);
  if (hit?.key === key) return hit.hex;
  const hex = createHash('sha256').update(readFileSync(path)).digest('hex');
  hashCache.set(path, { key, hex });
  return hex;
}

/**
 * One digest over the listed files, the same one {@link rootStageScript}
 * computes as root: each file's SHA-256 on its own line, as `sha256sum` and
 * `shasum` print it for standard input, then the SHA-256 of those lines.
 */
export function helperDigest(dir: string, files: readonly string[]): string {
  const lines = files.map((f) => `${fileSha256(join(dir, f))}  -\n`).join('');
  return createHash('sha256').update(lines).digest('hex');
}

/**
 * The shell script root runs to install or remove the helper. Anything
 * running as the user can change files in a user-owned folder, so root never
 * runs the script where it finds it: it copies the listed files into a fresh
 * folder only root can write, checks them against the digest the app computed
 * from its own copy, and runs the script from there. Arguments: the folder to
 * copy from, the script, the digest, the app to pin (appPinTarget), then the
 * files.
 */
export function rootStageScript(platform: NodeJS.Platform = process.platform): string {
  const hash = platform === 'linux' ? 'sha256sum' : '/usr/bin/shasum -a 256';
  // Never follow a link; on macOS copy the data only, not extended attributes.
  const copy = platform === 'linux' ? 'cp -P' : 'cp -P -X';
  return [
    'set -eu',
    // app: what install.sh pins as the app it installs the helper for; may be empty.
    'src=$1; run=$2; want=$3; app=$4; shift 4',
    // A fixed root-owned, sticky parent: a folder made in the user's own
    // TMPDIR could be renamed away and replaced by its owner.
    't=$(mktemp -d /tmp/vigil-helper.XXXXXXXX)',
    'trap \'rm -rf "$t"\' EXIT',
    // Plain files only, never links: a FIFO or a link to a device would hang root or fill the disk.
    `for f; do [ -f "$src/$f" ] && [ ! -h "$src/$f" ] || { echo "Missing $f" >&2; exit 1; }; case $f in */*) mkdir -p "$t/\${f%/*}";; esac; ${copy} "$src/$f" "$t/$f"; [ -f "$t/$f" ] && [ ! -h "$t/$f" ] || exit 1; done`,
    `got=$(for f; do ${hash} < "$t/$f"; done | ${hash})`,
    '[ "${got%% *}" = "$want" ] || { echo "The helper files changed while installing, so nothing was changed." >&2; exit 1; }',
    'sh "$t/$run" "$app"',
  ].join('; ');
}

/**
 * How root starts {@link rootStageScript}: with an empty environment, so
 * nothing the user set (PATH, TMPDIR, NODE_OPTIONS, PERL5OPT…) reaches the
 * programs root runs.
 */
const ROOT_PATH = '/usr/bin:/bin:/usr/sbin:/sbin';

export const ROOT_SHELL = ['/usr/bin/env', '-i', `PATH=${ROOT_PATH}`, '/bin/sh', '-c'] as const;

/** The arguments after `sh -c <rootStageScript>` that run `kind` from `from`. */
function stageArgs(
  dir: string,
  from: string,
  kind: 'install' | 'uninstall',
  platform: NodeJS.Platform,
): string[] {
  const files = helperScriptFiles(kind, platform);
  const app = kind === 'install' ? appPinTarget(platform) : '';
  return ['vigil-helper-setup', from, files[0]!, helperDigest(dir, files), app, ...files];
}

/** The Terminal command that installs the helper, for the setup wizard. */
export function helperInstallCommand(
  dir = helperBundleDir(),
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  if (!dir) return undefined;
  const run = (from: string) => {
    const [name, src, ...rest] = stageArgs(dir, from, 'install', platform);
    return `sudo ${ROOT_SHELL.join(' ')} ${shellQuote(rootStageScript(platform))} ${name} ${src} ${rest.map(shellQuote).join(' ')}`;
  };
  try {
    // Linux: root can't read an AppImage's mount, so copy the helper out first,
    // as runWithPkexec does.
    if (platform === 'linux')
      return `d=$(mktemp -d) && cp -R ${shellQuote(dir)}/. "$d" && ${run('"$d"')}`;
    return run(shellQuote(dir));
  } catch {
    return undefined; // a file the script needs is missing from this build
  }
}

const PROMPTS = {
  install:
    'Vigil at Home wants to install its helper, which blocks and quarantines threats on this Mac.',
  update:
    'Vigil at Home was updated and wants to update its helper, which blocks threats on this Mac, to match.',
  uninstall: 'Vigil at Home wants to remove its helper.',
} as const;

/**
 * The osascript arguments that run a command as root. macOS shows its own
 * password dialog. The command goes in as an argument, already quoted for the
 * shell, never inside the AppleScript, so no path can break out of it.
 */
export function adminScriptArgs(command: string, kind: keyof typeof PROMPTS): string[] {
  return [
    '-e',
    'on run argv',
    '-e',
    `do shell script (item 1 of argv) with prompt ${JSON.stringify(PROMPTS[kind])} with administrator privileges`,
    '-e',
    'end run',
    command,
  ];
}

export type RunFile = (
  file: string,
  args: string[],
) => Promise<{ code: number; stdout: string; stderr: string }>;

const runFile: RunFile = (file, args) =>
  new Promise((resolve) =>
    // An empty environment: macOS's admin dialog hands it to root's shell.
    execFile(file, args, { timeout: 3 * 60_000, env: { PATH: ROOT_PATH } }, (err, stdout, stderr) =>
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
 * read, so the helper files are copied to a temporary folder first; root
 * checks its own copy of them against the digest of the app's files.
 */
async function runWithPkexec(
  kind: 'install' | 'uninstall',
  dir: string,
  run: RunFile,
): Promise<HelperInstallResult> {
  let digested: string[];
  const stage = mkdtempSync(join(tmpdir(), 'vigil-helper-'));
  try {
    digested = stageArgs(dir, stage, kind, 'linux');
    cpSync(dir, stage, { recursive: true });
  } catch {
    rmSync(stage, { recursive: true, force: true });
    return { ok: false, error: 'This build of Vigil is missing some of the helper’s files' };
  }
  try {
    const out = await run(PKEXEC, [...ROOT_SHELL, rootStageScript('linux'), ...digested]);
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
  let command: string;
  try {
    const args = stageArgs(dir, dir, script, platform).map(shellQuote).join(' ');
    command = `${ROOT_SHELL.join(' ')} ${shellQuote(rootStageScript(platform))} ${args}`;
  } catch {
    return { ok: false, error: 'This build of Vigil is missing some of the helper’s files' };
  }
  const out = await run('/usr/bin/osascript', adminScriptArgs(command, kind));
  if (out.code === 0) return { ok: true };
  // osascript reports a closed password dialog as error -128.
  if (/-128/.test(out.stderr)) return { ok: false, error: 'cancelled' };
  const msg = out.stderr
    .replace(/^\d+:\d+: execution error: /, '')
    .replace(/ \(-?\d+\)\s*$/, '')
    .trim();
  return { ok: false, error: msg || `The ${script} script failed` };
}
