// Generates the one-time configuration profile the user installs so Santa
// talks to Vigil, plus the file-access policy Vigil manages.
//
// Santa reads its settings only from a configuration profile (it checks
// CFPreferencesAppValueIsForced for the com.northpolesec.santa domain). On a
// Mac without MDM the user double-clicks the .mobileconfig and approves it in
// System Settings > General > Device Management.
//
// The profile points at files instead of embedding them (ServerAuthRootsFile,
// ClientAuthCertificateFile, FileAccessPolicyPlist), so Vigil can rotate its
// certificates and change file protections later without asking the user to
// reinstall the profile.

import { randomUUID } from 'node:crypto';
import { toPlist, type PlistValue } from '../plist.js';

export const SANTA_PREFERENCE_DOMAIN = 'com.northpolesec.santa';

export const DEFAULT_PATHS = {
  supportDir: '/Library/Application Support/Vigil',
  syncCaPem: '/Library/Application Support/Vigil/santa-sync/ca.pem',
  syncClientP12: '/Library/Application Support/Vigil/santa-sync/client.p12',
  fileAccessPolicy: '/Library/Application Support/Vigil/santa-file-access.plist',
  santaLog: '/var/db/santa/santa.log',
} as const;

export interface SantaProfileOptions {
  syncPort: number;
  /** Reverse-DNS prefix for payload identifiers. */
  identifierPrefix?: string;
  caPemPath?: string;
  /**
   * Password of Santa's client identity (tls.ts). When set, Santa presents
   * that certificate on every sync; the helper's server requires it.
   */
  clientCertPassword?: string;
  clientCertPath?: string;
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
  if (opts.clientCertPassword !== undefined) {
    // A PKCS#12 file Santa opens itself, so nothing goes into a keychain.
    santaSettings.ClientAuthCertificateFile = opts.clientCertPath ?? DEFAULT_PATHS.syncClientP12;
    santaSettings.ClientAuthCertificatePassword = opts.clientCertPassword;
  }
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
  /**
   * Report programs outside Apple's own opening files in Documents and
   * Desktop. Off by default: every document a third-party app opens becomes a
   * log line, which is more than a laptop should pay for on every Mac.
   */
  watchDocuments?: boolean;
}

type Process = Record<string, PlistValue>;

interface WatchItem {
  paths: { path: string; prefix?: boolean }[];
  processes: Process[];
  /** Data-centric (only these processes may) or process-centric (these processes may not). */
  ruleType?: 'PathsWithAllowedProcesses' | 'ProcessesWithDeniedPaths';
  allowRead?: boolean;
  /** Never block, even when the user turns blocking on (the owning app's team ID is unconfirmed). */
  alwaysAudit?: boolean;
}

const apple = (signingId: string): Process => ({ PlatformBinary: true, SigningID: signingId });
const team = (teamId: string): Process => ({ TeamID: teamId });
// Spotlight indexes most files, browsers' included.
const SPOTLIGHT = [apple('com.apple.mdworker_shared'), apple('com.apple.mds')];

// A browser profile's stolen-from files. Chromium moved Cookies into Network/ in 2021.
function chromiumProfile(root: string): WatchItem['paths'] {
  return [
    { path: `${root}/*/Cookies` },
    { path: `${root}/*/Network/Cookies` },
    { path: `${root}/*/Login Data` },
    { path: `${root}/*/Web Data` },
    { path: `${root}/*/Local Extension Settings/`, prefix: true },
    { path: `${root}/Local State` },
  ];
}

const U = '/Users/*/Library';
const KEYCHAINS = { path: `${U}/Keychains/`, prefix: true };
const SAFARI_COOKIES = [
  { path: `${U}/Cookies/Cookies.binarycookies` },
  { path: `${U}/Containers/com.apple.Safari/Data/Library/Cookies/`, prefix: true },
];

// Files infostealers go after first. Watch items log only processes they
// don't allow, so each allowlist is as narrow as the owner's own signature.
// Paths are glob(3) patterns: "*" is one path component and IsPrefix
// matches everything below. Team IDs come from the vendors' code signatures.
const WATCH_ITEMS: Record<string, WatchItem> = {
  ChromeCookies: {
    paths: chromiumProfile(`${U}/Application Support/Google/Chrome`),
    processes: [team('EQHXZ8M8AV'), ...SPOTLIGHT],
    allowRead: false,
  },
  BraveCookies: {
    paths: chromiumProfile(`${U}/Application Support/BraveSoftware/Brave-Browser`),
    processes: [team('KL8N8XSYF4'), ...SPOTLIGHT],
    allowRead: false,
  },
  EdgeCookies: {
    paths: chromiumProfile(`${U}/Application Support/Microsoft Edge`),
    processes: [team('UBF8T346G9'), ...SPOTLIGHT],
    allowRead: false,
  },
  ArcCookies: {
    paths: chromiumProfile(`${U}/Application Support/Arc/User Data`),
    processes: SPOTLIGHT,
    allowRead: false,
    alwaysAudit: true,
  },
  FirefoxCookies: {
    paths: [
      { path: `${U}/Application Support/Firefox/Profiles/*/cookies.sqlite` },
      { path: `${U}/Application Support/Firefox/Profiles/*/logins.json` },
      { path: `${U}/Application Support/Firefox/Profiles/*/key4.db` },
    ],
    processes: [team('43AQ936H96'), ...SPOTLIGHT],
    allowRead: false,
  },
  // Safari's cookies are read by several Apple processes (WebKit, nsurlsessiond).
  // Apple's script tools are caught by ScriptToolsReadingSecrets below.
  SafariCookies: {
    paths: SAFARI_COOKIES,
    processes: [{ PlatformBinary: true }],
    allowRead: false,
  },
  CryptoWallets: {
    paths: [
      { path: `${U}/Application Support/Exodus/`, prefix: true },
      { path: `${U}/Application Support/Electrum/wallets/`, prefix: true },
      { path: `${U}/Application Support/atomic/`, prefix: true },
    ],
    processes: SPOTLIGHT,
    allowRead: false,
    alwaysAudit: true,
  },
  // Only OpenSSH reads private keys (git goes through ssh). The wildcard
  // covers ssh, ssh-add, ssh-agent and ssh-keygen.
  SSHKeys: {
    paths: [{ path: '/Users/*/.ssh/id_', prefix: true }],
    processes: [apple('com.apple.ssh*')],
    allowRead: false,
  },
  // Every app that stores a password opens the keychain file itself, so this
  // one allows Apple's binaries; Apple's script tools are caught below.
  UserKeychains: {
    paths: [KEYCHAINS],
    processes: [{ PlatformBinary: true }],
    allowRead: false,
  },
  // Process-centric: Apple's own interpreters and copy tools are what
  // infostealer scripts use, and they are platform binaries the two items
  // above let through.
  ScriptToolsReadingSecrets: {
    ruleType: 'ProcessesWithDeniedPaths',
    paths: [KEYCHAINS, ...SAFARI_COOKIES],
    processes: [
      'com.apple.curl',
      'com.apple.osascript',
      'com.apple.python*',
      'com.apple.perl*',
      'com.apple.ruby',
      'com.apple.sqlite3',
      'com.apple.bash',
      'com.apple.zsh',
      'com.apple.sh',
      'com.apple.dash',
      'com.apple.ksh',
      'com.apple.cat',
      'com.apple.cp',
      'com.apple.ditto',
      'com.apple.zip',
    ].map(apple),
    allowRead: false,
  },
  // Only writes are reported (the name's "Writes" suffix tells the log parser).
  // tccd and System Settings are Apple's; anything else changing app
  // permissions behind the user's back is what tcc-database-tamper looks for.
  // Santa logs file writes only through watch items like this: Vigil sets no
  // FileChangesRegex, which would log every Apple write too.
  TCCDatabaseWrites: {
    paths: [
      { path: '/Library/Application Support/com.apple.TCC/TCC.db', prefix: true },
      { path: `${U}/Application Support/com.apple.TCC/TCC.db`, prefix: true },
    ],
    processes: [{ PlatformBinary: true }],
    allowRead: true,
  },
};

// mass-document-reads counts these. Apple's apps and Spotlight are left out.
const DOCUMENT_ITEMS: Record<string, WatchItem> = {
  UserDocuments: {
    paths: [
      { path: '/Users/*/Documents/', prefix: true },
      { path: '/Users/*/Desktop/', prefix: true },
    ],
    processes: [{ PlatformBinary: true }],
    allowRead: false,
    alwaysAudit: true,
  },
};

export function fileAccessPolicy(opts: FileAccessOptions = {}): string {
  const items = opts.watchDocuments ? { ...WATCH_ITEMS, ...DOCUMENT_ITEMS } : WATCH_ITEMS;
  const watchItems: Record<string, PlistValue> = {};
  for (const [name, item] of Object.entries(items)) {
    watchItems[name] = {
      Paths: item.paths.map((p) => ({ Path: p.path, IsPrefix: p.prefix ?? false })),
      Options: {
        RuleType: item.ruleType ?? 'PathsWithAllowedProcesses',
        AllowReadAccess: item.allowRead ?? true,
        AuditOnly: item.alwaysAudit || !opts.enforce,
      },
      Processes: item.processes,
    };
  }
  return toPlist({
    Version: opts.version ?? 'vigil-2',
    ...(opts.eventDetailUrl
      ? { EventDetailURL: opts.eventDetailUrl, EventDetailText: 'Open Vigil' }
      : {}),
    WatchItems: watchItems,
  });
}
