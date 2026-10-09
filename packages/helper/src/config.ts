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
