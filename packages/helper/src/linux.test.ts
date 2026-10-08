import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals, pkexecArgs } from './approval.js';
import { defaultPaths, linuxPaths } from './config.js';
import { Executor, type ActionOutcome } from './executor.js';
import { Journal } from './journal.js';
import { identifyProcess, isProtectedProcess, suspendProcess } from './commands/process.js';
import { moveAcrossDisks, vetPath } from './commands/quarantine.js';
import { NFT_SETUP, NftFirewall, parseNftRules } from './commands/nftables.js';
import {
  disableLinuxPersistence,
  restoreLinuxPersistence,
  unitScope,
  userName,
} from './commands/linuxPersistence.js';
import { linuxSeatUid } from './system.js';
import { FapolicydBlocks, fapolicydRules, VIGIL_RULES_FILE } from './commands/fapolicyd.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const PASSWD = 'root:x:0:0:root:/root:/bin/bash\nalex:x:1000:1000:Alex:/home/alex:/bin/bash\n';
const STARTED = 'Mon Oct  5 16:20:13 2026';

describe('Linux paths and protection', () => {
  it('keeps state under /var/lib and runtime files under /run', () => {
    const p = linuxPaths();
    expect(p.supportDir).toBe('/var/lib/vigil');
    expect(p.socket).toBe('/run/vigil-helper.sock');
    expect(p.approvalsDir).toBe('/run/vigil-approvals');
    expect(p.santaLog).toBe(false);
    expect(defaultPaths(undefined, 'darwin').socket).toBe('/var/run/vigil-helper.sock');
  });

  it('never quarantines system or package-owned files, or a whole home folder', () => {
    const opts = { quarantineDir: '/var/lib/vigil/quarantine', platform: 'linux' as const };
    for (const path of [
      '/usr/bin/sudo',
      '/etc/passwd',
      '/lib/x86_64-linux-gnu/libc.so.6',
      '/boot/vmlinuz',
      '/home/alex',
      '/home/alex/Documents',
      '/home/alex/.ssh',
      '/opt/Vigil at Home/vigil-at-home',
      '/usr/libexec/vigil-helper',
      '/var/lib/vigil/helper-journal.json',
      '/usr/local',
    ]) {
      expect(() => vetPath(path, opts), path).toThrow(expect.objectContaining({ code: 'refused' }));
    }
    for (const path of [
      '/home/alex/Downloads/evil',
      '/home/alex/.local/bin/miner',
      '/tmp/x',
      '/usr/local/bin/x',
      '/opt/sketchy/run',
    ]) {
      expect(vetPath(path, opts)).toBe(path);
    }
  });

  it('macOS lists stay in force when no platform is given', () => {
    const opts = { quarantineDir: '/Library/Application Support/Vigil/Quarantine' };
    expect(() => vetPath('/Users/you', opts)).toThrow();
    expect(vetPath('/etc/passwd-copy', opts)).toBe('/etc/passwd-copy');
  });

  it('refuses to stop the session, systemd or the security tools', () => {
    for (const path of [
      '/usr/lib/systemd/systemd',
      '/usr/bin/gnome-shell',
      '/usr/bin/Xwayland',
      '/usr/sbin/sshd',
      '/opt/osquery/bin/osqueryd',
    ]) {
      expect(isProtectedProcess(path, 'linux'), path).toBe(true);
    }
    expect(isProtectedProcess('/usr/bin/python3', 'linux')).toBe(false);
    expect(isProtectedProcess('/home/alex/.cache/x', 'linux')).toBe(false);
  });

  it('finds the user at the screen from logind', () => {
    expect(linuxSeatUid(() => 'ACTIVE=c2\nACTIVE_UID=1000\nCAN_GRAPHICAL=yes\n')).toBe(1000);
    expect(linuxSeatUid(() => 'CAN_GRAPHICAL=yes\n')).toBeUndefined();
    expect(
      linuxSeatUid(() => {
        throw new Error('ENOENT');
      }),
    ).toBeUndefined();
  });

  it('asks for the password through pkexec without a shell', () => {
    const n = 'a'.repeat(32);
    expect(pkexecArgs('/usr/libexec/vigil-helper', [n, 'b'.repeat(32)])).toEqual([
      '--disable-internal-agent',
      '/usr/libexec/vigil-helper',
      'approve',
      n,
      'b'.repeat(32),
    ]);
    expect(() => pkexecArgs('/usr/libexec/vigil-helper', 'x; rm -rf /')).toThrow();
    expect(() => pkexecArgs('relative/helper', n)).toThrow();
  });
});

describe('processes on Linux', () => {
  it('identifies a pid by its /proc executable, not argv', async () => {
    const sys = new FakeLinuxSystem();
    sys.processes.set(4242, { path: '/home/alex/Downloads/evil', started: STARTED });
    expect(await identifyProcess(sys, 4242)).toEqual({
      pid: 4242,
      path: '/home/alex/Downloads/evil',
      started: STARTED,
    });
    expect(await identifyProcess(sys, 4243)).toBeUndefined();
    expect(sys.runs.some((r) => r.bin === 'lsof')).toBe(false);
  });
});

describe('nftables firewall', () => {
  it('reads only tagged rules in Vigil’s table', () => {
    const json = JSON.stringify({
      nftables: [
        { metainfo: {} },
        {
          rule: {
            family: 'inet',
            table: 'vigil',
            chain: 'output',
            handle: 4,
            comment: 'vigil:203.0.113.7',
          },
        },
        {
          rule: {
            family: 'inet',
            table: 'other',
            chain: 'output',
            handle: 5,
            comment: 'vigil:1.2.3.4',
          },
        },
        { rule: { family: 'inet', table: 'vigil', chain: 'input', handle: 6 } },
      ],
    });
    expect(parseNftRules(json)).toEqual([
      { chain: 'output', handle: 4, comment: 'vigil:203.0.113.7' },
    ]);
    expect(parseNftRules('not json')).toEqual([]);
  });

  it('blocks both ways, overlaps freely and removes one block at a time', async () => {
    const sys = new FakeLinuxSystem();
    const fw = new NftFirewall(sys);
    expect(await fw.block('198.51.100.0/24')).toBe('198.51.100.0/24');
    expect(sys.runs[0]).toMatchObject({ bin: 'nft', args: [NFT_SETUP] });
    expect(await fw.block('198.51.100.5')).toBe('198.51.100.5');
    expect(await fw.block('198.51.100.5')).toBe('198.51.100.5');
    expect(sys.rules.map((r) => `${r.chain} ${r.comment}`)).toEqual([
      'output vigil:198.51.100.0/24',
      'input vigil:198.51.100.0/24',
      'output vigil:198.51.100.5',
      'input vigil:198.51.100.5',
    ]);
    const script = sys.runs.find((r) => r.args[0]?.includes('198.51.100.5'))!.args[0]!;
    expect(script).toContain('add rule inet vigil output ip daddr 198.51.100.5 drop');
    expect(script).toContain('add rule inet vigil input ip saddr 198.51.100.5 drop');
    await fw.unblock('198.51.100.0/24');
    expect(await fw.list()).toEqual(['198.51.100.5']);
    await fw.block('2001:db8::1');
    expect(sys.runs.at(-1)!.args[0]).toContain('ip6 daddr 2001:db8::1 drop');
  });

  it('still refuses loopback and huge ranges', async () => {
    const fw = new NftFirewall(new FakeLinuxSystem());
    await expect(fw.block('127.0.0.1')).rejects.toMatchObject({ code: 'refused' });
    await expect(fw.block('10.0.0.0/4')).rejects.toMatchObject({ code: 'refused' });
  });
});

describe('Linux startup items', () => {
  let root: string;
  let unitDir: string;
  let autostart: string;
  let sys: FakeLinuxSystem;
  const qopts = () => ({ quarantineDir: join(root, 'quarantine') });

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'vigil-linux-'));
    unitDir = join(root, 'home', 'alex', '.config', 'systemd', 'user');
    autostart = join(root, 'home', 'alex', '.config', 'autostart');
    mkdirSync(unitDir, { recursive: true });
    mkdirSync(autostart, { recursive: true });
    sys = new FakeLinuxSystem();
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const dirs = () =>
    new RegExp(
      '^(' +
        [unitDir, autostart].map((d) => d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') +
        ')$',
    );

  it('maps folders to the systemd manager that runs them', () => {
    expect(unitScope('/etc/systemd/system/x.service', 0, () => PASSWD)).toEqual({ kind: 'system' });
    expect(unitScope('/home/alex/.config/systemd/user/x.service', 1000, () => PASSWD)).toEqual({
      kind: 'user',
      user: 'alex',
    });
    expect(unitScope('/home/alex/.config/autostart/x.desktop', 1000, () => PASSWD)).toEqual({
      kind: 'autostart',
    });
    expect(userName(1000, () => PASSWD)).toBe('alex');
    expect(userName(1001, () => PASSWD)).toBeUndefined();
    expect(userName(5, () => 'evil;rm:x:5:5::/:/bin/sh\n')).toBeUndefined();
  });

  it('stops a running user unit, moves it out and starts it again on undo', async () => {
    const path = join(unitDir, 'miner.service');
    writeFileSync(path, '[Service]\nExecStart=/home/alex/.cache/miner\n');
    sys.active.add('user:alex miner.service');
    const uid = statSync(path).uid;
    const passwd = () => `alex:x:${uid}:${uid}::/home/alex:/bin/bash\n`;
    const rec = await disableLinuxPersistence(sys, path, 'act1', qopts(), dirs(), passwd);
    expect(rec).toMatchObject({ label: 'miner.service', domain: 'user:alex', wasLoaded: true });
    expect(existsSync(path)).toBe(false);
    expect(sys.active.has('user:alex miner.service')).toBe(false);
    expect(sys.runs.map((r) => r.args.join(' '))).toEqual([
      '--user -M alex@ is-active --quiet miner.service',
      '--user -M alex@ stop miner.service',
      '--user -M alex@ daemon-reload',
    ]);

    await restoreLinuxPersistence(sys, rec);
    expect(readFileSync(path, 'utf8')).toContain('ExecStart');
    expect(sys.active.has('user:alex miner.service')).toBe(true);
  });

  it('moves an autostart entry without touching systemd', async () => {
    const path = join(autostart, 'updater.desktop');
    writeFileSync(path, '[Desktop Entry]\nExec=/tmp/x\n');
    const rec = await disableLinuxPersistence(sys, path, 'act2', qopts(), dirs(), () => PASSWD);
    expect(rec.domain).toBe('autostart');
    expect(sys.runs).toEqual([]);
    await restoreLinuxPersistence(sys, rec);
    expect(existsSync(path)).toBe(true);
  });

  it('refuses files outside startup folders and the wrong kind of file', async () => {
    const other = join(root, 'home', 'alex', 'miner.service');
    writeFileSync(other, '');
    await expect(
      disableLinuxPersistence(sys, other, 'a', qopts(), dirs(), () => PASSWD),
    ).rejects.toMatchObject({ code: 'invalid' });
    const wrong = join(autostart, 'x.service');
    writeFileSync(wrong, '');
    await expect(
      disableLinuxPersistence(sys, wrong, 'b', qopts(), dirs(), () => PASSWD),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(
      disableLinuxPersistence(sys, '/usr/lib/systemd/system/ssh.service', 'c', qopts()),
    ).rejects.toMatchObject({ code: 'invalid' });
  });
});

describe('moving across disks', () => {
  it.skipIf(!existsSync('/dev/shm'))('copies and deletes when rename would fail', () => {
    const a = mkdtempSync(join('/dev/shm', 'vigil-'));
    const b = mkdtempSync(join(tmpdir(), 'vigil-'));
    try {
      mkdirSync(join(a, 'app'));
      writeFileSync(join(a, 'app', 'run'), 'x', { mode: 0o755 });
      moveAcrossDisks(join(a, 'app'), join(b, 'app'));
      expect(existsSync(join(a, 'app'))).toBe(false);
      expect(statSync(join(b, 'app', 'run')).mode & 0o777).toBe(0o755);
    } finally {
      rmSync(a, { recursive: true, force: true });
      rmSync(b, { recursive: true, force: true });
    }
  });
});

describe('executor on Linux', () => {
  let root: string;
  let sys: FakeLinuxSystem;
  let ex: Executor;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'vigil-linux-ex-'));
    sys = new FakeLinuxSystem();
    ex = new Executor({
      sys,
      journal: new Journal(join(root, 'journal.json')),
      approvals: new Approvals({
        dir: join(root, 'approvals'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules: new RuleStore(join(root, 'rules.json')),
      quarantine: { quarantineDir: join(root, 'quarantine') },
      syncPort: 47821,
    });
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  it('blocks through nftables and re-applies blocks at start', async () => {
    const out = await ex.execute({ kind: 'network.block', address: '203.0.113.7' });
    expect((out as { result: ActionOutcome }).result.summary).toBe(
      'blocked network traffic with 203.0.113.7',
    );
    expect(await ex.firewall.list()).toEqual(['203.0.113.7']);
    sys.tableExists = false;
    sys.rules.length = 0;
    expect(await ex.reapplyFirewallBlocks()).toBe(1);
    expect(await ex.firewall.list()).toEqual(['203.0.113.7']);
  });

  it('pauses by /proc identity and refuses a reused pid', async () => {
    sys.processes.set(77, { path: '/tmp/evil', started: STARTED });
    await ex.execute({ kind: 'process.suspend', pid: 77, path: '/tmp/evil' });
    expect(sys.signals).toEqual([{ pid: 77, signal: 'SIGSTOP' }]);
    await expect(
      ex.execute({ kind: 'process.kill', pid: 77, path: '/tmp/other' }),
    ).rejects.toMatchObject({ code: 'refused' });
  });

  it('never pauses what Vigil’s AppImage started, whatever its mount', async () => {
    const image = '/home/alex/Apps/Vigil.AppImage';
    sys.processes.set(80, { path: image, started: STARTED });
    sys.processes.set(81, { path: '/tmp/.mount_VigilX/vigil-at-home', started: STARTED });
    sys.parents.set(81, 80);
    sys.processes.set(82, { path: '/tmp/.mount_Other/app', started: STARTED });
    await expect(
      suspendProcess(sys, 81, { path: '/tmp/.mount_VigilX/vigil-at-home', self: [image] }),
    ).rejects.toMatchObject({ code: 'refused' });
    await suspendProcess(sys, 82, { path: '/tmp/.mount_Other/app', self: [image] });
    expect(sys.signals).toEqual([{ pid: 82, signal: 'SIGSTOP' }]);
  });

  it('quarantines with the Linux protected list', async () => {
    await expect(
      ex.execute({ kind: 'file.quarantine', path: '/usr/bin/sudo' }),
    ).rejects.toMatchObject({ code: 'refused' });
  });

  it('says Santa is macOS-only', async () => {
    await expect(
      ex.execute({
        kind: 'santa.rule.set',
        ruleType: 'teamid',
        identifier: 'EQHXZ8M8AV',
        policy: 'block',
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
    await expect(ex.execute({ kind: 'santa.profile' })).rejects.toMatchObject({ code: 'invalid' });
  });
});

describe('fapolicyd blocks', () => {
  let root: string;
  let sys: FakeLinuxSystem;
  const SHA = 'ab'.repeat(32);
  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'vigil-fapolicyd-'));
    sys = new FakeLinuxSystem();
  });
  afterEach(() => rmSync(root, { recursive: true, force: true }));

  const make = () =>
    new FapolicydBlocks(sys, {
      store: join(root, 'support', 'blocked-programs.json'),
      rulesDir: join(root, 'etc', 'fapolicyd', 'rules.d'),
    });

  it('writes only deny lines built from hashes', () => {
    expect(fapolicydRules([SHA])).toContain(`deny_audit perm=execute all : sha256hash=${SHA}\n`);
    expect(
      fapolicydRules([])
        .split('\n')
        .filter((l) => l && !l.startsWith('#')),
    ).toEqual([]);
  });

  it('keeps the list without fapolicyd and writes the rules once it is installed', async () => {
    const blocks = make();
    expect(await blocks.block(SHA.toUpperCase())).toBe(true);
    expect(await blocks.block(SHA)).toBe(false);
    expect(blocks.status()).toEqual({ installed: false, blocked: 1, lastError: null });
    expect(sys.runs).toEqual([]);

    mkdirSync(join(root, 'etc', 'fapolicyd'), { recursive: true });
    const reloaded = make();
    expect(reloaded.has(SHA)).toBe(true);
    expect(await reloaded.apply()).toBe(true);
    const file = join(root, 'etc', 'fapolicyd', 'rules.d', VIGIL_RULES_FILE);
    expect(readFileSync(file, 'utf8')).toContain(`sha256hash=${SHA}`);
    expect(statSync(file).mode & 0o777).toBe(0o644);
    expect(sys.runs.map((r) => `${r.bin} ${r.args.join(' ')}`)).toEqual([
      'fagenrules --load',
      'systemctl try-restart fapolicyd',
    ]);

    expect(await reloaded.unblock(SHA)).toBe(true);
    expect(existsSync(file)).toBe(false);
    expect(await reloaded.unblock(SHA)).toBe(false);
  });

  it('reports a failed reload instead of throwing', async () => {
    mkdirSync(join(root, 'etc', 'fapolicyd'), { recursive: true });
    sys.fagenrulesFails = true;
    const blocks = make();
    await blocks.block(SHA);
    expect(blocks.status().lastError).toBe('rule error');
  });

  it('refuses anything but a sha256', async () => {
    await expect(make().block('/usr/bin/evil')).rejects.toMatchObject({ code: 'invalid' });
  });

  it('runs through the executor; unblocking needs the password', async () => {
    const blocks = make();
    const ex = new Executor({
      sys,
      journal: new Journal(join(root, 'journal.json')),
      approvals: new Approvals({
        dir: join(root, 'approvals'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules: new RuleStore(join(root, 'rules.json')),
      quarantine: { quarantineDir: join(root, 'quarantine') },
      syncPort: 47821,
      fapolicyd: blocks,
    });
    const set = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: SHA,
      policy: 'block',
    } as const;
    const out = await ex.execute(set);
    expect((out as { result: ActionOutcome }).result).toMatchObject({
      summary: `blocked programs with hash ${SHA}`,
      undoable: true,
    });
    expect(blocks.has(SHA)).toBe(true);
    await expect(ex.execute({ ...set, policy: 'allow' })).rejects.toMatchObject({
      code: 'invalid',
    });

    const remove = { kind: 'santa.rule.remove', ruleType: 'binary', identifier: SHA } as const;
    const ask = await ex.execute(remove);
    expect(ask).toMatchObject({ kind: 'needs_approval' });
    expect((ask as { prompt: string }).prompt).toBe(
      `Vigil wants to unblock the program with hash ${SHA}.`,
    );
    const nonce = (ask as { nonce: string }).nonce;
    Approvals.writeApproval(join(root, 'approvals'), nonce);
    await ex.execute(remove, nonce);
    expect(blocks.has(SHA)).toBe(false);
  });
});
