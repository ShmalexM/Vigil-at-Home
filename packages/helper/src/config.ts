import { join } from 'node:path';

export interface HelperPaths {
  supportDir: string;
  quarantineDir: string;
  journal: string;
  santaRules: string;
  approvalsDir: string;
  tlsDir: string;
  fileAccessPolicy: string;
  santaLog: string | false;
  osqueryResults: string | false;
  socket: string;
  /** Where the helper binary lives; used in the approval dialog command. */
  helperExecutable: string;
}

export function defaultPaths(supportDir = '/Library/Application Support/Vigil'): HelperPaths {
  return {
    supportDir,
    quarantineDir: join(supportDir, 'Quarantine'),
    journal: join(supportDir, 'helper-journal.json'),
    santaRules: join(supportDir, 'santa-rules.json'),
    approvalsDir: '/var/run/vigil-approvals',
    tlsDir: join(supportDir, 'santa-sync'),
    fileAccessPolicy: join(supportDir, 'santa-file-access.plist'),
    santaLog: '/var/db/santa/santa.log',
    osqueryResults: '/var/log/osquery/osqueryd.results.log',
    socket: '/var/run/vigil-helper.sock',
    helperExecutable: '/Library/PrivilegedHelperTools/vigil-helper',
  };
}

export const SANTA_SYNC_PORT = 47821;

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
  '/Applications/Santa.app',
  '/Library/PrivilegedHelperTools/vigil-helper',
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
];
