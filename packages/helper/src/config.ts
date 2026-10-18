import { realpathSync } from 'node:fs';
import { join } from 'node:path';
import { installedRoots } from '@vigil/core/self';
import { hostPlatform, type Platform } from './platform.js';

export interface HelperPaths {
  supportDir: string;
  quarantineDir: string;
  journal: string;
  santaRules: string;
  approvalsDir: string;
  tlsDir: string;
  fileAccessPolicy: string;
  /** The blocking rules the app last handed the helper (fastpath.ts). */
  helperRules: string;
  /** A readable copy of the app pin, for the app to see what is pinned; the helper never reads it. */
  appPin: string;
  /** The pin itself and the key that signs it, in a root-only folder (pinStore.ts). */
  appPinDir: string;
  /** False on Linux, where there is no Santa. */
  santaLog: string | false;
  osqueryResults: string | false;
  socket: string;
  /** Where the helper binary lives; used in the approval dialog command. */
  helperExecutable: string;
}

/** Where the helper keeps things on this machine's OS. */
export function defaultPaths(
  supportDir?: string,
  platform: Platform = hostPlatform(),
): HelperPaths {
  return platform === 'linux' ? linuxPaths(supportDir) : macPaths(supportDir);
}

export function macPaths(supportDir = '/Library/Application Support/Vigil'): HelperPaths {
  return {
    supportDir,
    quarantineDir: join(supportDir, 'Quarantine'),
    journal: join(supportDir, 'helper-journal.json'),
    santaRules: join(supportDir, 'santa-rules.json'),
    approvalsDir: '/var/run/vigil-approvals',
    tlsDir: join(supportDir, 'santa-sync'),
    fileAccessPolicy: join(supportDir, 'santa-file-access.plist'),
    helperRules: join(supportDir, 'helper-rules.json'),
    appPin: join(supportDir, 'app-pin.json'),
    appPinDir: join(supportDir, 'pin'),
    santaLog: '/var/db/santa/santa.log',
    osqueryResults: '/var/log/osquery/osqueryd.results.log',
    socket: '/var/run/vigil-helper.sock',
    helperExecutable: '/Library/PrivilegedHelperTools/vigil-helper',
  };
}

/**
 * Linux follows the FHS: state under /var/lib, runtime files under /run, and
 * the helper next to other privileged programs in /usr/libexec. The Santa
 * entries are unused there; they still point inside the support folder so
 * nothing outside it is ever written.
 */
export function linuxPaths(supportDir = '/var/lib/vigil'): HelperPaths {
  return {
    supportDir,
    quarantineDir: join(supportDir, 'quarantine'),
    journal: join(supportDir, 'helper-journal.json'),
    santaRules: join(supportDir, 'santa-rules.json'),
    approvalsDir: '/run/vigil-approvals',
    tlsDir: join(supportDir, 'santa-sync'),
    fileAccessPolicy: join(supportDir, 'santa-file-access.plist'),
    helperRules: join(supportDir, 'helper-rules.json'),
    appPin: join(supportDir, 'app-pin.json'),
    appPinDir: join(supportDir, 'pin'),
    santaLog: false,
    osqueryResults: '/var/log/osquery/osqueryd.results.log',
    socket: '/run/vigil-helper.sock',
    helperExecutable: '/usr/libexec/vigil-helper',
  };
}

export const SANTA_SYNC_PORT = 47821;

/** The only environment given to osascript when it runs something as root. */
export const ADMIN_ENV = {
  PATH: '/usr/bin:/bin:/usr/sbin:/sbin',
  LANG: process.env.LANG ?? 'en_US.UTF-8',
};

/**
 * The app's bundle id (appId in apps/desktop/electron-builder.yml), which
 * codesign reports as the Identifier of Vigil's own code. On macOS only code
 * signed with it is ever pinned (appPin.ts).
 */
export const VIGIL_BUNDLE_ID = 'app.vigilathome.desktop';

/**
 * Paths the helper will never quarantine or unload, whoever asks. Moving
 * these could break macOS, Santa or Vigil itself. /usr/local is fine.
 */
export const PROTECTED_PREFIXES = [
  '/System/',
  '/bin/',
  '/sbin/',
  '/usr/bin/',
  '/usr/sbin/',
  '/usr/lib/',
  '/usr/libexec/',
  '/usr/share/',
  '/private/var/db/',
  '/Library/Apple/',
  // The helper's whole state folder (journal, rules, app pin); see Protection stateDir.
  '/Library/Application Support/Vigil/',
  '/Applications/Santa.app',
  '/Library/PrivilegedHelperTools/vigil-helper',
  // The helper's Node runtime and code (versions/<id> and the current link to
  // one), and the app itself.
  '/Library/PrivilegedHelperTools/vigil-helper.d/',
  '/Applications/Vigil at Home.app/',
  // The helper's own state: rules, journal, Santa sync keys and the quarantine.
  '/Library/Application Support/Vigil/',
];

/** Exact paths that must never be moved (moving a parent of everything). */
export const PROTECTED_EXACT = new Set([
  '/',
  '/Applications',
  '/Library',
  '/Users',
  '/System',
  '/private',
  '/usr',
  '/usr/local',
  '/Volumes',
  '/tmp',
  '/private/tmp',
  '/var',
  '/private/var',
]);

/** Programs the helper refuses to suspend or kill: stopping them hangs or breaks the Mac. */
export const PROTECTED_PROCESS_PREFIXES = [
  '/System/',
  '/usr/libexec/',
  '/usr/sbin/',
  '/sbin/',
  '/Applications/Santa.app/',
  '/Library/SystemExtensions/',
  '/Library/PrivilegedHelperTools/vigil-helper',
  '/Applications/Vigil.app/',
  // The installer's own folder is checked by insideInstalledRoot (process.ts).
  // osquery 5 and later lives in /opt/osquery; older releases in /usr/local/bin.
  '/opt/osquery/',
  '/usr/local/bin/osqueryd',
];

/**
 * Linux equivalents. The package manager owns the system folders, so the
 * helper never moves anything there; anything under /usr/local, /opt or a
 * home folder can be quarantined.
 */
export const LINUX_PROTECTED_PREFIXES = [
  '/bin/',
  '/sbin/',
  '/lib/',
  '/lib32/',
  '/lib64/',
  '/usr/bin/',
  '/usr/sbin/',
  '/usr/lib/',
  '/usr/lib32/',
  '/usr/lib64/',
  '/usr/libexec/',
  '/usr/share/',
  '/boot/',
  '/etc/',
  '/proc/',
  '/sys/',
  '/dev/',
  '/run/',
  '/var/lib/dpkg/',
  '/var/lib/rpm/',
  '/var/lib/vigil/',
  '/usr/libexec/vigil-helper',
  '/usr/libexec/vigil-helper.d/',
  '/opt/Vigil at Home/',
  '/opt/osquery/',
];

export const LINUX_PROTECTED_EXACT = new Set([
  '/',
  '/home',
  '/root',
  '/usr',
  '/usr/local',
  '/usr/local/bin',
  '/opt',
  '/var',
  '/var/lib',
  '/tmp',
  '/var/tmp',
  '/mnt',
  '/media',
  '/srv',
]);

/**
 * Programs the helper refuses to suspend or kill on Linux: init and systemd's
 * own services, the display server and desktop shell (stopping them locks the
 * user out of their session), and the security tools themselves. User
 * programs in /usr/bin stay stoppable, as on macOS.
 */
export const LINUX_PROTECTED_PROCESS_PREFIXES = [
  '/sbin/',
  '/usr/sbin/',
  '/lib/systemd/',
  '/usr/lib/systemd/',
  '/usr/libexec/',
  '/usr/lib/xorg/',
  '/usr/bin/Xorg',
  '/usr/bin/Xwayland',
  '/usr/bin/gnome-shell',
  '/usr/bin/kwin_wayland',
  '/usr/bin/kwin_x11',
  '/usr/bin/plasmashell',
  '/usr/bin/dbus-daemon',
  '/usr/bin/dbus-broker',
  '/usr/bin/pipewire',
  '/usr/bin/fapolicyd',
  '/usr/bin/osqueryd',
  '/opt/osquery/',
  '/usr/libexec/vigil-helper',
  // The installer's own folder is checked by insideInstalledRoot (process.ts).
];

/**
 * The files of Vigil itself and of the tools it relies on (Santa, osquery),
 * whatever the protected lists above say about their folders. Nothing the
 * helper does may move, unload or stop them, or the folders they sit in.
 */
export const SERVICE_PATHS = [
  '/Library/PrivilegedHelperTools/vigil-helper',
  '/Library/PrivilegedHelperTools/vigil-helper.d',
  '/Library/LaunchDaemons/com.vigilathome.helper.plist',
  '/Library/Application Support/Vigil',
  '/Library/Logs/Vigil',
  '/var/run/vigil-helper.sock',
  '/var/run/vigil-approvals',
  '/Applications/Vigil at Home.app',
  '/Applications/Vigil.app',
  '/Applications/Santa.app',
  '/var/db/santa',
  '/opt/osquery',
  '/var/osquery',
  '/var/log/osquery',
  '/usr/local/bin/osqueryd',
  '/Library/LaunchDaemons/io.osquery.agent.plist',
];

/** Launch items whose label or file name starts with one of these belong to Vigil or its sensors. */
export const PROTECTED_LABEL_PREFIXES = [
  'com.vigilathome.',
  'com.northpolesec.santa',
  'com.google.santa',
  'io.osquery.',
  'com.facebook.osqueryd',
];

/** Units of Vigil itself and of the tools it relies on, never stopped or moved. */
export const PROTECTED_UNITS = new Set([
  'vigil-helper.service',
  'osqueryd.service',
  'fapolicyd.service',
]);

/** Where systemd looks for unit files; protected units and their drop-ins are found there. */
export const LINUX_UNIT_DIRS = [
  '/etc/systemd/system',
  '/etc/systemd/user',
  '/run/systemd/system',
  '/usr/local/lib/systemd/system',
  '/usr/lib/systemd/system',
  '/lib/systemd/system',
];

export const LINUX_SERVICE_PATHS = [
  '/usr/libexec/vigil-helper',
  '/usr/libexec/vigil-helper.d',
  '/var/lib/vigil',
  '/run/vigil-helper.sock',
  '/run/vigil-approvals',
  '/opt/Vigil at Home',
  '/usr/share/polkit-1/actions/com.vigilathome.helper.policy',
  '/opt/osquery',
  '/etc/osquery',
  '/var/osquery',
  '/var/log/osquery',
  '/usr/bin/osqueryd',
  '/etc/fapolicyd',
  '/usr/sbin/fapolicyd',
  '/usr/bin/fapolicyd',
  '/var/lib/fapolicyd',
  '/run/fapolicyd',
  ...LINUX_UNIT_DIRS.flatMap((dir) =>
    [...PROTECTED_UNITS].flatMap((unit) => [`${dir}/${unit}`, `${dir}/${unit}.d`]),
  ),
];

/**
 * Where the installer puts Vigil itself, root-owned on both systems. The
 * helper's first-ever sync may name these as Vigil's own without the admin
 * password (FastPath `installed`); nothing else.
 */
export function installedSelf(platform: Platform = 'darwin'): string[] {
  return installedRoots(platform);
}

/**
 * The operating system's own programs that Vigil, its installer and its
 * password dialogs run, which no block by hash may name: the shells and core
 * tools in /bin and /sbin, and the tools in /usr/bin and /usr/sbin that the
 * helper, install.sh and the dialogs start. Named one by one, never as a
 * folder: on Linux /bin and /sbin are links to /usr/bin and /usr/sbin, which
 * hold thousands of programs to hash at every start. The app's safety floor
 * already keeps rules off every system folder by path (PLATFORM_PATH_GLOBS in
 * @vigil/detection). On 2026-10-10 a block by hash on /bin/sh stopped every
 * shell on the Mac, the password dialog Vigil needed to undo it included.
 */
const MAC_BIN = [
  ...['sh', 'bash', 'zsh', 'dash', 'ksh', 'csh', 'tcsh', 'cat', 'chmod', 'cp', 'date'],
  ...['echo', 'expr', 'kill', 'launchctl', 'ln', 'ls', 'mkdir', 'mv', 'ps', 'pwd'],
  ...['realpath', 'rm', 'rmdir', 'sleep', 'test', 'unlink'],
].map((t) => `/bin/${t}`);
const MAC_TOOLS = [
  ...['env', 'osascript', 'sudo', 'security', 'codesign', 'plutil', 'chflags', 'id'],
  ...['install', 'mktemp', 'xattr', 'find', 'readlink', 'touch', 'sort', 'tail'],
  ...['uname', 'dirname', 'shasum'],
].map((t) => `/usr/bin/${t}`);
export const PLATFORM_PROGRAM_ROOTS: Record<Platform, readonly string[]> = {
  darwin: [
    ...MAC_BIN,
    ...['launchd', 'pfctl', 'mount', 'umount'].map((t) => `/sbin/${t}`),
    ...MAC_TOOLS,
    '/usr/sbin/chown',
    '/usr/sbin/lsof',
  ],
  linux: [
    ...['sh', 'bash', 'dash', 'zsh', 'ksh', 'mksh'].flatMap((s) => [`/bin/${s}`, `/usr/bin/${s}`]),
    ...['env', 'sudo', 'pkexec', 'systemctl', 'install', 'mktemp', 'find', 'nft'].map(
      (t) => `/usr/bin/${t}`,
    ),
    '/bin/systemctl',
    '/usr/sbin/nft',
  ],
};

/**
 * Why this helper should not run: launchd starts it as
 * `vigil-helper.d/current/node vigil-helper.d/current/helper.mjs`, reading
 * `current` twice, and an install that switches it in between would pair one
 * version's Node with another's helper.mjs. Node reports its own real path,
 * so the real helper.mjs must sit beside it. Undefined when they match, or
 * when this Node isn't an installed version (development, tests).
 */
export function versionMismatch(
  execPath: string,
  script: string | undefined,
  realpath: (p: string) => string = realpathSync,
): string | undefined {
  if (!/\/vigil-helper\.d\/versions\/[^/]+\/node$/.test(execPath) || !script) return undefined;
  let real: string;
  try {
    real = realpath(script);
  } catch {
    return `${script} is gone`;
  }
  const dir = execPath.slice(0, execPath.lastIndexOf('/'));
  return real === `${dir}/helper.mjs` ? undefined : `${real} is not the helper beside ${execPath}`;
}

/**
 * Every folder of the operating system's own programs, hashed in the
 * background (daemon.ts osHashes) so that no block by hash names one of them,
 * wherever a copy of it runs: on 2026-10-10 Santa's log reported /bin/sh with
 * no signature, and a copy of curl or python3 in /tmp would look the same.
 * macOS: the folders SIP protects (about 2,200 programs) and Apple's
 * developer tools. Linux: the
 * distribution's folders; /bin and /sbin are often links to these.
 */
export const OS_PROGRAM_ROOTS: Record<Platform, readonly string[]> = {
  darwin: [
    '/bin',
    '/sbin',
    '/usr/bin',
    '/usr/sbin',
    '/usr/libexec',
    '/System/Library/CoreServices',
    // The developer tools that /usr/bin/git, python3 and the like hand off to
    // (those are xcrun shims): Apple's, root-owned, but not under SIP.
    '/Library/Developer/CommandLineTools/usr/bin',
    '/Library/Developer/CommandLineTools/usr/libexec',
    '/Applications/Xcode.app/Contents/Developer/usr/bin',
    '/Applications/Xcode-beta.app/Contents/Developer/usr/bin',
  ],
  linux: ['/usr/bin', '/usr/sbin', '/usr/libexec', '/usr/lib/systemd', '/bin', '/sbin'],
};

/**
 * Where the programs live that no block by hash may name (ownHashes.ts): the
 * helper's launcher and the runtime it runs under, Santa's and osquery's
 * programs, the installed app, and the system's own programs
 * (PLATFORM_PROGRAM_ROOTS), last, so a cap on how many files are hashed never
 * leaves out Vigil's own. Fixed paths plus the helper's own, never anything a
 * client sends.
 */
export function ownProgramRoots(
  platform: Platform,
  helperExecutable: string,
  runtime: string = process.execPath,
): string[] {
  const sensors =
    platform === 'linux'
      ? ['/opt/osquery', '/usr/bin/osqueryd']
      : ['/Applications/Santa.app', '/opt/osquery', '/usr/local/bin/osqueryd'];
  return [
    runtime,
    helperExecutable,
    `${helperExecutable}.d`,
    ...sensors,
    ...installedSelf(platform),
    ...PLATFORM_PROGRAM_ROOTS[platform],
  ];
}

export interface Protection {
  /**
   * The helper's own state folder as installed (defaultPaths supportDir):
   * its journal, rules, approvals and the app pin. No file command ever
   * touches anything in it or above it, whatever lists a caller passes.
   */
  stateDir: string;
  prefixes: string[];
  exact: Set<string>;
  processPrefixes: string[];
  /** Home folders and their main subfolders, which are never moved as a whole. */
  homes: RegExp[];
  /** Vigil's and its sensors' own files (SERVICE_PATHS). */
  services: string[];
  /** Folders whose entries are checked by name for Vigil's and the sensors' launch items or units. */
  serviceItemDirs: string[];
  /** Whether a file name in serviceItemDirs is one of Vigil's or the sensors' own items. */
  isServiceItem: (name: string) => boolean;
  /** Where home folders live, and the subfolders of each that are never moved as a whole. */
  homeRoot: string;
  homeSubfolders: string[];
}

function isProtectedLaunchName(name: string): boolean {
  const lower = name.toLowerCase();
  return PROTECTED_LABEL_PREFIXES.some((p) => lower.startsWith(p));
}

function isProtectedUnitName(name: string): boolean {
  return [...PROTECTED_UNITS].some((u) => name === u || name.startsWith(u + '.'));
}

const MAC_PROTECTION: Protection = {
  stateDir: macPaths().supportDir,
  prefixes: PROTECTED_PREFIXES,
  exact: PROTECTED_EXACT,
  processPrefixes: PROTECTED_PROCESS_PREFIXES,
  homes: [/^\/Users\/[^/]+$/i, /^\/Users\/[^/]+\/(Library|Desktop|Documents|Downloads)$/i],
  services: SERVICE_PATHS,
  serviceItemDirs: ['/Library/LaunchDaemons', '/Library/LaunchAgents'],
  isServiceItem: isProtectedLaunchName,
  homeRoot: '/Users',
  homeSubfolders: ['Library', 'Desktop', 'Documents', 'Downloads'],
};

const LINUX_PROTECTION: Protection = {
  stateDir: linuxPaths().supportDir,
  prefixes: LINUX_PROTECTED_PREFIXES,
  exact: LINUX_PROTECTED_EXACT,
  processPrefixes: LINUX_PROTECTED_PROCESS_PREFIXES,
  homes: [
    /^\/home\/[^/]+$/,
    /^\/home\/[^/]+\/(\.config|\.local|\.local\/share|\.ssh|Desktop|Documents|Downloads)$/,
  ],
  services: LINUX_SERVICE_PATHS,
  serviceItemDirs: LINUX_UNIT_DIRS,
  isServiceItem: isProtectedUnitName,
  homeRoot: '/home',
  homeSubfolders: [
    '.config',
    '.local',
    '.local/share',
    '.ssh',
    'Desktop',
    'Documents',
    'Downloads',
  ],
};

export function protectionFor(platform: Platform = 'darwin'): Protection {
  return platform === 'linux' ? LINUX_PROTECTION : MAC_PROTECTION;
}
