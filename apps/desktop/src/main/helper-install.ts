import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  cpSync,
  existsSync,
  lstatSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
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

/** The root-owned folder install.sh keeps the helper's versions in. */
export function helperPayloadDir(platform: NodeJS.Platform = process.platform): string {
  return platform === 'linux'
    ? '/usr/libexec/vigil-helper.d'
    : '/Library/PrivilegedHelperTools/vigil-helper.d';
}

/**
 * Where install.sh puts each file the app ships, so the app can tell whether
 * the installed helper is the one it carries. Node and helper.mjs are read
 * through `current`, the link to the version the launcher runs. Node is
 * compared by size: it is large, and a new Node release always changes it.
 */
export function installedHelperFiles(
  dir: string,
  platform: NodeJS.Platform = process.platform,
  root = '',
): { bundled: string; installed: string; by: 'content' | 'size' }[] {
  const at = (p: string) => join(root, p);
  const d = `${helperPayloadDir(platform)}/current`;
  const payload = [
    { bundled: join(dir, 'helper.mjs'), installed: at(`${d}/helper.mjs`), by: 'content' },
    { bundled: join(dir, 'node'), installed: at(`${d}/node`), by: 'size' },
  ] as const;
  if (platform === 'linux') {
    return [
      ...payload,
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
  return [
    ...payload,
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
  if (!existsSync(files[0]!.installed)) {
    // A helper installed before versions keeps its files at the top of the
    // folder, with no `current`. It needs install.sh to move to the new layout.
    const legacy = existsSync(join(root, helperPayloadDir(platform), 'helper.mjs'));
    return { installed: legacy ? 'outdated' : 'none', bundle };
  }
  const same = shipped.every((f) => {
    try {
      return fingerprint(f.bundled, f.by) === fingerprint(f.installed, f.by);
    } catch {
      return false;
    }
  });
  return { installed: same ? 'current' : 'outdated', bundle };
}

/**
 * The first command that runs as root, for every way the helper is installed
 * or removed. The helper files sit in a folder the user can write (the app,
 * or on Linux a copy of it, since root can't read an AppImage's mount), and a
 * process running as the user could swap one (lib.sh for a symlink, say)
 * while the password dialog is up. So nothing elevated runs from there: this
 * fixed snippet, passed inline rather than read from any file, copies each
 * listed file into a new root-owned folder (mktemp -d, mode 700), refusing
 * symlinks and anything but regular files, and checks each copy against the
 * SHA-256 the app computed beforehand. Only then does it run the copied
 * script, which sources lib.sh from beside itself, inside that folder. The
 * folder is made under the fixed, root-owned and sticky /tmp, never the
 * user's TMPDIR, where its owner could rename it away and put another in its
 * place. `cat` copies the data only, never a link, and on macOS no extended
 * attributes. Root starts it through {@link ROOT_SHELL}, with an empty
 * environment.
 *
 * Arguments: the folder to copy from, the script to run (relative to it),
 * then pairs of a file (relative) and its SHA-256.
 *
 * The remaining limit: a process running as the user that can already change
 * the app itself can change what the app hashes and passes here. That is out
 * of scope; this guards the files between the app checking them and root
 * running them.
 *
 * One line per statement, each ending in `;` or a keyword, so it is joined
 * into a single line that also pastes into Terminal.
 */
export const ELEVATED_ENTRY = [
  'set -eu;',
  'PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH; umask 077;',
  'src=$1; script=$2; shift 2;',
  'vh_sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; };',
  'vh_refuse() { echo "Not running the helper script: $*" >&2; exit 1; };',
  'd=$(mktemp -d /tmp/vigil-helper.XXXXXX);',
  `trap 'rm -rf "$d"' EXIT; trap 'exit 129' HUP; trap 'exit 130' INT; trap 'exit 143' TERM;`,
  'found=;',
  'while [ "$#" -ge 2 ]; do',
  'f=$1; want=$2; shift 2;',
  'case $f in "" | /* | -* | *..* | *[!A-Za-z0-9._/-]*) vh_refuse "bad file name $f" ;; esac;',
  'if [ -L "$src/$f" ] || [ ! -f "$src/$f" ]; then vh_refuse "$f is not a regular file"; fi;',
  'case $f in */*) mkdir -p "$d/${f%/*}" ;; esac;',
  'cat <"$src/$f" >"$d/$f";',
  'if [ -L "$d/$f" ] || [ ! -f "$d/$f" ]; then vh_refuse "$f did not copy as a regular file"; fi;',
  'got=$(vh_sha <"$d/$f"); got=${got%% *};',
  '[ "$got" = "$want" ] || vh_refuse "$f changed after Vigil checked it";',
  '[ "$f" != "$script" ] || found=1;',
  'done;',
  'if [ "$#" -ne 0 ] || [ -z "$found" ]; then vh_refuse "$script was not among the files checked"; fi;',
  'status=0; /bin/sh "$d/$script" || status=$?; exit "$status"',
].join(' ');

const ROOT_PATH = '/usr/bin:/bin:/usr/sbin:/sbin';

/**
 * How root starts {@link ELEVATED_ENTRY}: with an empty environment, so
 * nothing the user set (PATH, TMPDIR, ENV, NODE_OPTIONS, PERL5OPT…) reaches
 * the entry or the programs the copied script runs. Followed by the entry,
 * then `$0`, then {@link elevatedArgs}.
 */
export const ROOT_SHELL = ['/usr/bin/env', '-i', `PATH=${ROOT_PATH}`, '/bin/sh', '-c'] as const;

/**
 * The files each script needs, the script first, relative to the helper
 * folder. A build missing any of them gets no password dialog and no
 * Terminal command; the entry checks each one along with the rest.
 */
export function helperScriptFiles(
  kind: 'install' | 'uninstall',
  platform: NodeJS.Platform = process.platform,
): string[] {
  if (platform === 'linux') {
    return kind === 'uninstall'
      ? ['linux/uninstall.sh', 'lib.sh']
      : [
          'linux/install.sh',
          'lib.sh',
          'node',
          'helper.mjs',
          'linux/vigil-helper',
          'linux/vigil-helper.service',
          'linux/com.vigilathome.helper.policy',
        ];
  }
  return kind === 'uninstall'
    ? ['uninstall.sh', 'lib.sh']
    : [
        'install.sh',
        'lib.sh',
        'node',
        'helper.mjs',
        'vigil-helper',
        'com.vigilathome.helper.plist',
      ];
}

const MISSING = 'This build of Vigil is missing some of the helper’s files';

const hashCache = new Map<string, string>();

/** SHA-256 of a file, remembered while its size and time stay the same (node is large). */
function sha256(path: string): string {
  const st = statSync(path);
  const key = `${path}\0${st.ino}\0${st.size}\0${st.mtimeMs}`;
  let h = hashCache.get(key);
  if (!h) {
    h = createHash('sha256').update(readFileSync(path)).digest('hex');
    hashCache.set(key, h);
  }
  return h;
}

/**
 * Every file in the helper folder, relative to it, with its SHA-256, for
 * ELEVATED_ENTRY. A symlink or anything but a regular file or folder there is
 * an error: the entry would refuse it anyway.
 */
export function helperManifest(dir: string): [string, string][] {
  const out: [string, string][] = [];
  const walk = (d: string) => {
    for (const name of readdirSync(d).sort()) {
      const path = join(d, name);
      const st = lstatSync(path);
      if (st.isDirectory()) walk(path);
      else if (st.isFile()) out.push([relative(dir, path), sha256(path)]);
      else throw new Error(`${path} in the helper folder is not a regular file`);
    }
  };
  walk(dir);
  return out;
}

/** The script for this OS, relative to the helper folder. */
function scriptFor(kind: 'install' | 'uninstall', platform: NodeJS.Platform): string {
  return helperScriptFiles(kind, platform)[0]!;
}

/** {@link helperManifest}, or an error when a file `kind` needs is missing. */
function checkedManifest(
  dir: string,
  kind: 'install' | 'uninstall',
  platform: NodeJS.Platform,
): [string, string][] {
  const manifest = helperManifest(dir);
  const have = new Set(manifest.map(([f]) => f));
  if (!helperScriptFiles(kind, platform).every((f) => have.has(f))) throw new Error(MISSING);
  return manifest;
}

/** ELEVATED_ENTRY's arguments: copy from `src`, run `script`, check these files. */
export function elevatedArgs(src: string, script: string, manifest: [string, string][]): string[] {
  return [src, script, ...manifest.flat()];
}

/** The Terminal command that installs the helper, for the setup wizard. */
export function helperInstallCommand(
  dir = helperBundleDir(),
  platform: NodeJS.Platform = process.platform,
): string | undefined {
  if (!dir) return undefined;
  let manifest: [string, string][];
  try {
    manifest = checkedManifest(dir, 'install', platform);
  } catch {
    return undefined; // a link in the folder, or a file the script needs is missing
  }
  const script = scriptFor('install', platform);
  const checks = manifest
    .flat()
    .map((a) => shellQuote(a))
    .join(' ');
  const entry = `sudo ${ROOT_SHELL.join(' ')} ${shellQuote(ELEVATED_ENTRY)} vigil-helper`;
  // Linux: root can't read an AppImage's mount, so copy the helper out first,
  // as runWithPkexec does. The entry checks the copy before root runs any of it.
  if (platform === 'linux')
    return `d=$(mktemp -d) && cp -R ${shellQuote(dir)}/. "$d" && ${entry} "$d" ${script} ${checks}`;
  return `${entry} ${shellQuote(dir)} ${script} ${checks}`;
}

const PROMPTS = {
  install:
    'Vigil at Home wants to install its helper, which blocks and quarantines threats on this Mac.',
  update:
    'Vigil at Home was updated and wants to update its helper, which blocks threats on this Mac, to match.',
  uninstall: 'Vigil at Home wants to remove its helper.',
} as const;

/**
 * The osascript arguments that run ELEVATED_ENTRY as root with `args`, through
 * {@link ROOT_SHELL}. macOS shows its own password dialog. The entry and every
 * argument go in as arguments and through AppleScript's `quoted form of`, so
 * no path can break out of them.
 */
export function adminScriptArgs(args: string[], kind: keyof typeof PROMPTS): string[] {
  return [
    '-e',
    'on run argv',
    '-e',
    `set cmd to "${ROOT_SHELL.join(' ')} " & quoted form of (item 1 of argv) & " vigil-helper"`,
    '-e',
    'repeat with a in rest of argv',
    '-e',
    'set cmd to cmd & " " & quoted form of (a as text)',
    '-e',
    'end repeat',
    '-e',
    `do shell script cmd with prompt ${JSON.stringify(PROMPTS[kind])} with administrator privileges`,
    '-e',
    'end run',
    ELEVATED_ENTRY,
    ...args,
  ];
}

export type RunFile = (
  file: string,
  args: string[],
) => Promise<{ code: number; stdout: string; stderr: string; missing?: true }>;

const runFile: RunFile = (file, args) =>
  new Promise((resolve) =>
    // An empty environment: macOS's admin dialog hands it to root's shell.
    execFile(file, args, { timeout: 3 * 60_000, env: { PATH: ROOT_PATH } }, (err, stdout, stderr) =>
      resolve({
        code: err ? (typeof err.code === 'number' ? err.code : 1) : 0,
        stdout: String(stdout),
        stderr: String(stderr),
        // The program itself isn't on this computer (no pkexec, say).
        ...(err?.code === 'ENOENT' ? { missing: true as const } : {}),
      }),
    ),
  );

export const PKEXEC = '/usr/bin/pkexec';

const FROM_TERMINAL = {
  install: 'Copy the install command and run it in a terminal instead.',
  uninstall: 'Run linux/uninstall.sh from Vigil’s helper folder with sudo instead.',
} as const;

/**
 * Linux: run the script as root through pkexec, which shows the desktop's own
 * password dialog. An AppImage's files sit on a FUSE mount that root can't
 * read, so the helper files are copied to a private temporary folder first;
 * ELEVATED_ENTRY checks them against hashes taken from the app's own files.
 */
async function runWithPkexec(
  kind: 'install' | 'uninstall',
  dir: string,
  run: RunFile,
): Promise<HelperInstallResult> {
  const manifest = checkedManifest(dir, kind, 'linux');
  const stage = mkdtempSync(join(tmpdir(), 'vigil-helper-'));
  try {
    cpSync(dir, stage, { recursive: true });
    const out = await run(PKEXEC, [
      ...ROOT_SHELL,
      ELEVATED_ENTRY,
      'vigil-helper',
      ...elevatedArgs(stage, scriptFor(kind, 'linux'), manifest),
    ]);
    if (out.code === 0) return { ok: true };
    if (out.missing) {
      return {
        ok: false,
        error: `This computer has no pkexec, so Vigil can’t ask for your password. ${FROM_TERMINAL[kind]}`,
      };
    }
    // pkexec exits 126 when the password dialog is closed, 127 when not allowed
    // or when no polkit agent is running to show the dialog.
    if (out.code === 126) return { ok: false, error: 'cancelled' };
    if (out.code === 127 && /authentication agent/i.test(out.stderr)) {
      return {
        ok: false,
        error: `No password dialog could open: nothing on this desktop answers polkit. ${FROM_TERMINAL[kind]}`,
      };
    }
    if (out.code === 127 && (/not authorized/i.test(out.stderr) || !out.stderr.trim())) {
      return { ok: false, error: 'Your account isn’t allowed to do this' };
    }
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
  let r: HelperInstallResult;
  try {
    r =
      platform === 'linux'
        ? await runWithPkexec(script, dir, run)
        : await viaOsascript(kind, dir, run);
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : String(e) };
  }
  // When the password-dialog route fails, the same install works from a terminal.
  const command = script === 'install' ? helperInstallCommand(dir, platform) : undefined;
  return !r.ok && r.error !== 'cancelled' && command ? { ...r, command } : r;
}

/**
 * macOS: run the script as root through osascript's administrator dialog.
 * Root runs only its own checked copy of the scripts (see ELEVATED_ENTRY).
 */
async function viaOsascript(
  kind: 'install' | 'update' | 'uninstall',
  dir: string,
  run: RunFile,
): Promise<HelperInstallResult> {
  const script = kind === 'uninstall' ? 'uninstall' : 'install';
  const manifest = checkedManifest(dir, script, 'darwin');
  const out = await run(
    '/usr/bin/osascript',
    adminScriptArgs(elevatedArgs(dir, scriptFor(script, 'darwin'), manifest), kind),
  );
  if (out.code === 0) return { ok: true };
  // osascript reports a closed password dialog as error -128.
  if (/-128/.test(out.stderr)) return { ok: false, error: 'cancelled' };
  const msg = out.stderr
    .replace(/^\d+:\d+: execution error: /, '')
    .replace(/ \(-?\d+\)\s*$/, '')
    .trim();
  return { ok: false, error: msg || `The ${script} script failed` };
}

/**
 * The demo (VIGIL_DEMO) shows made-up data on a real computer: its helper
 * buttons must never run the real install or uninstall script as root.
 */
export function unlessDemo(
  demo: boolean,
  run: () => Promise<HelperInstallResult>,
): () => Promise<HelperInstallResult> {
  return demo
    ? async () => ({ ok: false, error: 'The demo doesn’t install or remove the helper' })
    : run;
}
