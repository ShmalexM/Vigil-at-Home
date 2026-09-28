// Generates the one-time configuration profile the user installs so Santa
// talks to Vigil, plus the file-access policy Vigil manages.
//
// Santa reads its settings only from a configuration profile (it checks
// CFPreferencesAppValueIsForced for the com.northpolesec.santa domain). On a
// Mac without MDM the user double-clicks the .mobileconfig and approves it in
// System Settings > General > Device Management.
//
// The profile points at files instead of embedding them (ServerAuthRootsFile,
// FileAccessPolicyPlist), so Vigil can rotate its certificate and change file
// protections later without asking the user to reinstall the profile.

import { randomUUID } from 'node:crypto';
import { toPlist, type PlistValue } from '../plist.js';

export const SANTA_PREFERENCE_DOMAIN = 'com.northpolesec.santa';

export const DEFAULT_PATHS = {
  supportDir: '/Library/Application Support/Vigil',
  syncCaPem: '/Library/Application Support/Vigil/santa-sync/ca.pem',
  fileAccessPolicy: '/Library/Application Support/Vigil/santa-file-access.plist',
  santaLog: '/var/db/santa/santa.log',
} as const;

export interface SantaProfileOptions {
  syncPort: number;
  /** Reverse-DNS prefix for payload identifiers. */
  identifierPrefix?: string;
  caPemPath?: string;
  fileAccessPolicyPath?: string;
  /** Opened by the button in Santa's block dialog. %file_sha% etc. are filled in by Santa. */
  eventDetailUrl?: string;
  eventDetailText?: string;
  uuid?: () => string;
}

export function santaProfile(opts: SantaProfileOptions): string {
  if (!Number.isInteger(opts.syncPort) || opts.syncPort < 1 || opts.syncPort > 65535) {
    throw new Error(`invalid sync port ${opts.syncPort}`);
  }
  const uuid = opts.uuid ?? (() => randomUUID().toUpperCase());
  const prefix = opts.identifierPrefix ?? 'com.vigilathome';
  const santaSettings: Record<string, PlistValue> = {
    // 1 = Monitor: Santa only blocks what has an explicit block rule, so a
    // personal Mac keeps working while Vigil learns. Lockdown would block
    // every program not already allowed.
    ClientMode: 1,
    SyncBaseURL: `https://127.0.0.1:${opts.syncPort}/`,
    ServerAuthRootsFile: opts.caPemPath ?? DEFAULT_PATHS.syncCaPem,
    // Vigil reads santa.log directly for real-time process events.
    EventLogType: 'file',
    EventLogPath: DEFAULT_PATHS.santaLog,
    FileAccessPolicyPlist: opts.fileAccessPolicyPath ?? DEFAULT_PATHS.fileAccessPolicy,
    FileAccessPolicyUpdateIntervalSec: 60,
    EnableSilentMode: false,
    MoreInfoURL: 'https://github.com/ShmalexM/Vigil-at-Home',
    BannedBlockMessage: 'Vigil blocked this program. Open Vigil to see why, or to allow it.',
    FileAccessBlockMessage: 'Vigil stopped this program from reading a protected file.',
  };
  if (opts.eventDetailUrl) santaSettings.EventDetailURL = opts.eventDetailUrl;
  if (opts.eventDetailText) santaSettings.EventDetailText = opts.eventDetailText;

  return toPlist({
    PayloadContent: [
      {
        ...santaSettings,
        PayloadDisplayName: 'Santa settings for Vigil',
        PayloadIdentifier: `${prefix}.santa.settings`,
        PayloadType: SANTA_PREFERENCE_DOMAIN,
        PayloadUUID: uuid(),
        PayloadVersion: 1,
      },
    ],
    PayloadDescription:
      'Lets Vigil manage Santa on this Mac: Santa gets its block rules from Vigil and reports blocks back to it.',
    PayloadDisplayName: 'Vigil: Santa settings',
    PayloadIdentifier: `${prefix}.santa`,
    PayloadOrganization: 'Vigil at Home',
    // The user can remove it any time from System Settings.
    PayloadRemovalDisallowed: false,
    PayloadScope: 'System',
    PayloadType: 'Configuration',
    PayloadUUID: uuid(),
    PayloadVersion: 1,
  });
}

export interface FileAccessOptions {
  /** Start in audit-only so a wrong rule never breaks an app; the user turns on blocking. */
  enforce?: boolean;
  version?: string;
  eventDetailUrl?: string;
}

interface WatchItem {
  paths: { path: string; prefix?: boolean }[];
  allowed: Record<string, PlistValue>[];
  allowRead?: boolean;
}

// Files infostealers go after first. Only the listed programs may open them.
// Signing IDs and team IDs come from the vendors' own code signatures.
const WATCH_ITEMS: Record<string, WatchItem> = {
  ChromeCookies: {
    paths: [
      { path: '/Users/*/Library/Application Support/Google/Chrome/*/Cookies' },
      { path: '/Users/*/Library/Application Support/Google/Chrome/*/Login Data' },
      { path: '/Users/*/Library/Application Support/Google/Chrome/Local State' },
    ],
    allowed: [{ TeamID: 'EQHXZ8M8AV' }],
    allowRead: false,
  },
  FirefoxCookies: {
    paths: [
      { path: '/Users/*/Library/Application Support/Firefox/Profiles/*/cookies.sqlite' },
      { path: '/Users/*/Library/Application Support/Firefox/Profiles/*/logins.json' },
      { path: '/Users/*/Library/Application Support/Firefox/Profiles/*/key4.db' },
    ],
    allowed: [{ TeamID: '43AQ936H96' }],
    allowRead: false,
  },
  SSHKeys: {
    paths: [{ path: '/Users/*/.ssh/id_', prefix: true }],
    // ssh, ssh-add, ssh-agent and git are Apple platform binaries.
    allowed: [{ PlatformBinary: true }],
    allowRead: false,
  },
  UserKeychains: {
    paths: [{ path: '/Users/*/Library/Keychains/', prefix: true }],
    allowed: [{ PlatformBinary: true }],
    allowRead: false,
  },
};

export function fileAccessPolicy(opts: FileAccessOptions = {}): string {
  const watchItems: Record<string, PlistValue> = {};
  for (const [name, item] of Object.entries(WATCH_ITEMS)) {
    watchItems[name] = {
      Paths: item.paths.map((p) => ({ Path: p.path, IsPrefix: p.prefix ?? false })),
      Options: {
        RuleType: 'PathsWithAllowedProcesses',
        AllowReadAccess: item.allowRead ?? true,
        AuditOnly: !opts.enforce,
      },
      Processes: item.allowed,
    };
  }
  return toPlist({
    Version: opts.version ?? 'vigil-1',
    ...(opts.eventDetailUrl
      ? { EventDetailURL: opts.eventDetailUrl, EventDetailText: 'Open Vigil' }
      : {}),
    WatchItems: watchItems,
  });
}
