import type { DetectionRuleInput } from '../types.js';

/**
 * Built-in macOS rules.
 *
 * Only rules with a very low false-positive rate start in `block` mode
 * (known-bad lists, the user's own confirmed blocks, untrusted programs
 * reading browser credentials, fake password dialogs, TCC tampering). Behaviour
 * rules start in `alert`: they pop up and offer their response, but run nothing
 * until the user promotes them. Noisy-but-useful signals start in `shadow` and
 * only feed the weekly review and the AI's rule proposals.
 */

/** When this pack version was written. Rules carry it as createdAt/updatedAt. */
const PACK_DATE = Date.UTC(2026, 8, 26);

type PackRule = Omit<DetectionRuleInput, 'version' | 'origin' | 'createdAt' | 'updatedAt'> & {
  version?: number;
};

function rule(r: PackRule): DetectionRuleInput {
  return { version: 1, origin: 'builtin', createdAt: PACK_DATE, updatedAt: PACK_DATE, ...r };
}

const UNTRUSTED_SIGNING = ['unsigned', 'adhoc', 'invalid'];
const SHELLS = ['sh', 'bash', 'zsh', 'dash', 'ksh'];
const SCRIPT_RUNNERS = [
  'osascript',
  'python',
  'python3',
  'perl',
  'ruby',
  'sqlite3',
  'curl',
  ...SHELLS,
];

const SUSPEND = {
  kind: 'process.suspend',
  pid: '{{process.pid}}',
  startTime: '{{process.startTime}}',
  path: '{{process.path}}',
} as const;
const KILL = {
  kind: 'process.kill',
  pid: '{{process.pid}}',
  startTime: '{{process.startTime}}',
  path: '{{process.path}}',
} as const;
const SANTA_BLOCK_BINARY = {
  kind: 'santa.rule.set',
  ruleType: 'binary',
  identifier: '{{process.sha256}}',
  policy: 'block',
} as const;

export const CREDENTIAL_STORE_GLOBS = [
  '~/Library/Application Support/Google/Chrome/**/Cookies',
  '~/Library/Application Support/Google/Chrome/**/Login Data',
  '~/Library/Application Support/Google/Chrome/**/Web Data',
  '~/Library/Application Support/Google/Chrome/**/Local Extension Settings/**',
  '~/Library/Application Support/BraveSoftware/Brave-Browser/**/Cookies',
  '~/Library/Application Support/BraveSoftware/Brave-Browser/**/Login Data',
  '~/Library/Application Support/BraveSoftware/Brave-Browser/**/Local Extension Settings/**',
  '~/Library/Application Support/Microsoft Edge/**/Cookies',
  '~/Library/Application Support/Microsoft Edge/**/Login Data',
  '~/Library/Application Support/Arc/User Data/**/Cookies',
  '~/Library/Application Support/Arc/User Data/**/Login Data',
  '~/Library/Application Support/Firefox/Profiles/**/cookies.sqlite',
  '~/Library/Application Support/Firefox/Profiles/**/logins.json',
  '~/Library/Application Support/Firefox/Profiles/**/key4.db',
  '~/Library/Cookies/Cookies.binarycookies',
  '~/Library/Containers/com.apple.Safari/Data/Library/Cookies/**',
  '~/Library/Keychains/**',
  '~/.ssh/id_*',
  '~/Library/Application Support/Exodus/**',
  '~/Library/Application Support/Electrum/wallets/**',
  '~/Library/Application Support/atomic/**',
];

const USER_WRITABLE_EXEC_GLOBS = [
  '/tmp/**',
  '/private/tmp/**',
  '/Users/Shared/**',
  '/private/var/tmp/**',
];

export const macosCoreRules: DetectionRuleInput[] = [
  // ------------------------------------------------------------------ block
  rule({
    id: 'known-bad-hash',
    name: 'Known malware started',
    description: "The program's SHA-256 is on a known-malware list.",
    mode: 'block',
    severity: 'critical',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: { inList: { list: 'known_bad_sha256', field: 'process.sha256' } },
    response: [KILL, SANTA_BLOCK_BINARY],
    reasons: [
      '{{process.name}} matches a known-malware fingerprint.',
      'It was started from {{process.path}}.',
    ],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.execution'],
  }),
  rule({
    id: 'user-blocked-hash',
    name: 'Program you blocked started again',
    description: 'You confirmed this exact program as malicious before.',
    mode: 'block',
    severity: 'critical',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: { inList: { list: 'user_blocked_sha256', field: 'process.sha256' } },
    response: [KILL, SANTA_BLOCK_BINARY],
    reasons: ['You blocked {{process.name}} before, and it tried to run again.'],
    santa: { ruleType: 'binary', from: 'process.sha256' },
  }),
  rule({
    id: 'known-bad-destination',
    name: 'Connection to a known-malicious address',
    description:
      'A program connected to an address or host on a threat list. Vigil blocks the address; the program keeps running, so a browser that loaded a bad page is not killed.',
    mode: 'block',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['network.connection'],
    condition: {
      any: [
        { inList: { list: 'known_bad_ips', field: 'remoteAddress' } },
        { inList: { list: 'known_bad_domains', field: 'remoteHost' } },
      ],
    },
    response: [{ kind: 'network.block', address: '{{remoteAddress}}' }],
    reasons: [
      '{{process.name}} connected to {{remoteHost|remoteAddress}}, which is on a threat list.',
      'Vigil blocked the address. The program itself keeps running.',
    ],
    dedupe: { key: ['remoteAddress'], windowSec: 3600 },
    tags: ['attack.command_and_control'],
  }),
  rule({
    id: 'credential-theft-untrusted',
    name: 'Untrusted program reading passwords or cookies',
    description:
      'An unsigned program or a script tool opened browser cookies, saved passwords, the keychain, SSH keys or a crypto wallet. This is how infostealers like Atomic Stealer work.',
    mode: 'block',
    severity: 'critical',
    fidelity: 'high',
    eventKinds: ['file'],
    condition: {
      all: [
        { field: 'op', op: 'in', value: ['open', 'write', 'rename'] },
        { field: 'path', op: 'glob', value: CREDENTIAL_STORE_GLOBS },
        {
          any: [
            { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
            { field: 'process.name', op: 'in', value: SCRIPT_RUNNERS, nocase: true },
          ],
        },
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.name}} opened {{pathName}}, which holds saved passwords, cookies or keys.',
      '{{process.name}} is not an app from an identified developer (signing: {{process.signing}}).',
    ],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.credential_access', 'attack.t1555'],
  }),
  rule({
    id: 'fake-password-prompt',
    name: 'Script showing a fake password dialog',
    description:
      'osascript asked for a hidden answer, the trick infostealers use to get your login password.',
    mode: 'block',
    severity: 'critical',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.name', op: 'eq', value: 'osascript' },
        { field: 'process.commandLine', op: 'contains', value: 'display dialog', nocase: true },
        { field: 'process.commandLine', op: 'contains', value: 'hidden answer', nocase: true },
      ],
    },
    response: [KILL],
    reasons: [
      'A script opened a password box that did not come from macOS.',
      "It was started by {{process.parentName|'another program'}}. Do not type your password into it.",
    ],
    tags: ['attack.credential_access', 'attack.t1056.002'],
  }),
  rule({
    id: 'tcc-database-tamper',
    name: 'Privacy settings database modified',
    description:
      'A program other than macOS wrote to the TCC database that records camera, microphone and disk permissions.',
    mode: 'block',
    severity: 'critical',
    fidelity: 'high',
    eventKinds: ['file'],
    condition: {
      all: [
        { field: 'op', op: 'in', value: ['write', 'rename', 'create', 'delete'] },
        {
          any: [
            { field: 'path', op: 'glob', value: ['**/com.apple.TCC/TCC.db*'] },
            { field: 'newPath', op: 'glob', value: ['**/com.apple.TCC/TCC.db*'] },
          ],
        },
        { field: 'process.signing', op: 'neq', value: 'apple' },
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.name}} changed the database that controls which apps may use your camera, microphone and files.',
    ],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.defense_evasion', 'attack.t1548'],
  }),
  rule({
    id: 'santa-blocked-launch',
    name: 'Blocked before it could run',
    description: 'Santa stopped a program from launching or from opening a protected file.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['santa.decision'],
    condition: { field: 'decision', op: 'eq', value: 'block' },
    reasons: ['{{process.name}} was stopped by Santa ({{reason}}).'],
  }),

  // ------------------------------------------------------------------ alert
  rule({
    id: 'download-pipe-to-shell',
    name: 'Downloaded script run directly',
    description:
      "A shell ran something straight from curl or wget. Some installers do this, but so do fake 'paste this into Terminal' fixes.",
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.name', op: 'in', value: SHELLS },
        {
          any: [
            {
              field: 'process.commandLine',
              op: 'regex',
              value: ['(curl|wget)\\s[^|]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b'],
            },
            { field: 'process.commandLine', op: 'contains', value: ['$(curl', '$(wget'] },
          ],
        },
      ],
    },
    response: [SUSPEND],
    reasons: [
      'A command downloaded code from the internet and ran it right away.',
      'If you just pasted this from a site you trust (for example an installer), you can allow it.',
    ],
    tags: ['attack.execution', 'attack.t1059.004'],
  }),
  rule({
    id: 'base64-pipe-to-shell',
    name: 'Hidden script decoded and run',
    description:
      'A command decoded base64 text and piped it into a shell, a common way to hide what it does.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      field: 'process.commandLine',
      op: 'regex',
      value: ['base64\\s+(-d|-D|--decode)[^|]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b'],
    },
    response: [SUSPEND],
    reasons: ['A command unpacked hidden text and ran it as a script.'],
    tags: ['attack.defense_evasion', 'attack.t1140'],
  }),
  rule({
    id: 'unsigned-quarantined-exec',
    name: 'Unsigned download opened',
    description:
      'A program downloaded from the internet, with no valid signature, started running.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.quarantine', op: 'exists' },
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
      ],
    },
    response: [SUSPEND, { kind: 'file.quarantine', path: '{{process.path}}' }],
    reasons: [
      "{{process.name}} came from the internet ({{process.quarantine.originUrl|'unknown site'}}) and is not signed by an identified developer.",
    ],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.execution', 'attack.t1204.002'],
  }),
  rule({
    id: 'quarantine-removed',
    name: 'Download safety check removed',
    description: 'xattr removed the quarantine flag that makes macOS check downloaded apps.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.name', op: 'eq', value: 'xattr' },
        {
          any: [
            { field: 'process.args', op: 'eq', value: 'com.apple.quarantine' },
            { field: 'process.args', op: 'in', value: ['-c', '-cr', '-rc'] },
          ],
        },
      ],
    },
    reasons: ["Something removed macOS's downloaded-file check: {{process.commandLine}}"],
    tags: ['attack.defense_evasion', 'attack.t1553.001'],
  }),
  rule({
    id: 'gatekeeper-disabled',
    name: 'Gatekeeper turned off',
    description: 'spctl was used to turn off Gatekeeper, which checks apps before they open.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.name', op: 'eq', value: 'spctl' },
        { field: 'process.args', op: 'in', value: ['--master-disable', '--global-disable'] },
      ],
    },
    reasons: [
      "Gatekeeper, which checks apps before they open, was switched off by {{process.parentName|'a command'}}.",
    ],
    tags: ['attack.defense_evasion', 'attack.t1553.001'],
  }),
  rule({
    id: 'keychain-dump',
    name: 'Keychain dumped',
    description: 'The security tool was asked to dump the keychain.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.name', op: 'eq', value: 'security' },
        { field: 'process.args', op: 'eq', value: 'dump-keychain' },
      ],
    },
    response: [SUSPEND],
    reasons: ["{{process.parentName|'A program'}} asked macOS to dump your keychain."],
    tags: ['attack.credential_access', 'attack.t1555.001'],
  }),
  rule({
    id: 'exec-from-shared-temp',
    name: 'New program started from a temporary folder',
    description: 'An unsigned program ran from /tmp or /Users/Shared for the first time.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.path', op: 'glob', value: USER_WRITABLE_EXEC_GLOBS },
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
        { firstSeen: { key: ['process.path'] } },
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.name}} ran from {{process.path}}, a shared or temporary folder, and is not signed.',
    ],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.execution'],
  }),
  rule({
    id: 'persistence-suspicious-program',
    name: 'Something set itself to run at login',
    description:
      'A launch item was added that runs a script, a downloader, or a program in a temporary folder.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['persistence'],
    condition: {
      all: [
        { field: 'change', op: 'in', value: ['added', 'modified'] },
        {
          any: [
            { field: 'program', op: 'glob', value: USER_WRITABLE_EXEC_GLOBS },
            {
              field: 'programCommandLine',
              op: 'regex',
              value: [
                '\\b(curl|wget|osascript|base64)\\b',
                '\\bpython[0-9.]*\\s+-c\\b',
                '\\b(ba|z)?sh\\s+-c\\b',
              ],
            },
          ],
        },
      ],
    },
    response: [{ kind: 'persistence.disable', path: '{{path}}' }],
    reasons: ["{{path}} will run {{programCommandLine|'a program'}} every time you log in."],
    tags: ['attack.persistence', 'attack.t1543.001'],
  }),
  rule({
    id: 'persistence-apple-lookalike',
    name: 'Login item pretending to be Apple',
    description: 'A launch item outside /System is named like an Apple one.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['persistence'],
    condition: {
      all: [
        { field: 'change', op: 'in', value: ['added', 'modified'] },
        {
          field: 'path',
          op: 'glob',
          value: [
            '~/Library/LaunchAgents/com.apple.*',
            '/Library/LaunchAgents/com.apple.*',
            '/Library/LaunchDaemons/com.apple.*',
          ],
        },
      ],
    },
    response: [{ kind: 'persistence.disable', path: '{{path}}' }],
    reasons: ['{{pathName}} is named like an Apple item but was added outside the system folder.'],
    tags: ['attack.persistence', 'attack.t1036'],
  }),
  rule({
    id: 'persistence-first-seen',
    name: 'New login item',
    description: 'Something new set itself to start automatically.',
    mode: 'alert',
    severity: 'low',
    fidelity: 'low',
    eventKinds: ['persistence'],
    condition: {
      all: [{ field: 'change', op: 'eq', value: 'added' }, { firstSeen: { key: ['path'] } }],
    },
    response: [{ kind: 'persistence.disable', path: '{{path}}' }],
    reasons: ["{{path}} was added and will start {{programName|'a program'}} automatically."],
    tags: ['attack.persistence'],
  }),
  rule({
    id: 'new-network-listener',
    name: 'New app accepting connections from the network',
    description: 'A program that is not part of macOS started listening on all network interfaces.',
    mode: 'alert',
    severity: 'low',
    fidelity: 'low',
    eventKinds: ['network.listen'],
    condition: {
      all: [
        { field: 'localAddress', op: 'in', value: ['0.0.0.0', '::', '*'] },
        { field: 'process.signing', op: 'neq', value: 'apple' },
        { firstSeen: { key: ['process.path', 'localPort'] } },
      ],
    },
    reasons: [
      '{{process.name}} is accepting connections from other devices on port {{localPort}}.',
    ],
    tags: ['attack.command_and_control'],
  }),
  rule({
    id: 'browser-extension-broad-access',
    name: 'New browser extension that can read every site',
    description: 'An extension was installed with access to all sites, cookies or native apps.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['browser.extension'],
    condition: {
      all: [
        { field: 'change', op: 'eq', value: 'added' },
        {
          field: 'permissions',
          op: 'in',
          value: [
            '<all_urls>',
            'cookies',
            'debugger',
            'nativeMessaging',
            '*://*/*',
            'http://*/*',
            'https://*/*',
          ],
        },
        { firstSeen: { key: ['browser', 'extensionId'] } },
      ],
    },
    reasons: ['{{name}} was added to {{browser}} and can read or change what you do on websites.'],
    tags: ['attack.persistence', 'attack.t1176'],
  }),
  rule({
    id: 'mass-document-reads',
    name: 'Unsigned program reading many documents',
    description:
      'An unsigned program opened a large number of files in Documents or Desktop within a minute.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['file'],
    condition: {
      all: [
        { field: 'op', op: 'eq', value: 'open' },
        { field: 'path', op: 'glob', value: ['~/Documents/**', '~/Desktop/**'] },
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
      ],
    },
    threshold: { count: 50, windowSec: 60, groupBy: ['process.pid'] },
    response: [SUSPEND],
    reasons: ['{{process.name}} opened 50 or more of your documents in under a minute.'],
    tags: ['attack.collection', 'attack.t1005'],
  }),

  // ----------------------------------------------------------------- shadow
  rule({
    id: 'unsigned-first-network',
    name: "Unsigned program's first network connection",
    description:
      'An unsigned or ad-hoc signed program connected out for the first time. Common for developer tools, so it only records and feeds the weekly review.',
    mode: 'shadow',
    severity: 'low',
    fidelity: 'low',
    eventKinds: ['network.connection'],
    condition: {
      all: [
        { field: 'direction', op: 'eq', value: 'outbound' },
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
        { firstSeen: { key: ['process.path'] } },
      ],
    },
    reasons: [
      '{{process.name}} ({{process.path}}) connected to {{remoteAddress}} for the first time.',
    ],
    tags: ['attack.command_and_control'],
  }),
];
