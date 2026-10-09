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
      '--user -M alex@ show -p Id,Names,ExecStart miner.service',
      '--user -M alex@ is-active --quiet miner.service',
      '--user -M alex@ stop miner.service',
      '--user -M alex@ daemon-reload',
    ]);

    await restoreLinuxPersistence(sys, rec, qopts());
    expect(readFileSync(path, 'utf8')).toContain('ExecStart');
    expect(sys.active.has('user:alex miner.service')).toBe(true);
  });

  it('moves an autostart entry without touching systemd', async () => {
    const path = join(autostart, 'updater.desktop');
    writeFileSync(path, '[Desktop Entry]\nExec=/tmp/x\n');
    const rec = await disableLinuxPersistence(sys, path, 'act2', qopts(), dirs(), () => PASSWD);
    expect(rec.domain).toBe('autostart');
    expect(sys.runs).toEqual([]);
    await restoreLinuxPersistence(sys, rec, qopts());
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

  it("refuses Vigil's and the sensors' own units before stopping anything", async () => {
    for (const name of ['vigil-helper.service', 'osqueryd.service', 'fapolicyd.service']) {
      const path = join(unitDir, name);
      writeFileSync(path, '[Service]\n');
      sys.active.add(`user:alex ${name}`);
      await expect(
        disableLinuxPersistence(sys, path, 'd', qopts(), dirs(), () => PASSWD),
      ).rejects.toMatchObject({ code: 'refused' });
      expect(existsSync(path)).toBe(true);
    }
    expect(sys.runs).toEqual([]);
  });

  it('vets the file before stopping its unit', async () => {
    // A startup folder inside the quarantine: the move would be refused, so nothing is stopped.
    const inside = join(root, 'quarantine', 'systemd', 'user');
    mkdirSync(inside, { recursive: true });
    const path = join(inside, 'x.service');
    writeFileSync(path, '');
    sys.active.add('user:alex x.service');
    const re = new RegExp('^' + inside.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$');
    await expect(
      disableLinuxPersistence(sys, path, 'e', qopts(), re, () => PASSWD),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(sys.runs).toEqual([]);
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

  /**
   * A real AppImage launch (type 2 runtime): the launcher starts R on the
   * image; R forks the mount server, which daemonizes (so it is nobody's
   * child), waits for the mount, then execs <mount>/AppRun, which execs
   * Vigil. R and the server share the keepalive pipe; whatever Vigil starts
   * inherits R's end.
   */
  function launchAppImage() {
    const image = '/home/alex/Apps/Vigil.AppImage';
    const mount = '/tmp/.mount_VigilaB1c2D';
    sys.files.set(image, '2049:5501');
    sys.mounts = [
      '22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw',
      '40 22 0:35 / /tmp rw,nosuid,nodev shared:20 - tmpfs tmpfs rw',
      `612 40 0:71 / ${mount} ro,nosuid,nodev,relatime shared:350 - fuse.Vigil.AppImage Vigil.AppImage ro,user_id=1000,group_id=1000`,
    ].join('\n');
    const proc = (pid: number, path: string, start: number, fds: [number, string][] = []) => {
      sys.processes.set(pid, { path, started: STARTED });
      sys.starts.set(pid, start);
      sys.fds.set(pid, fds);
    };
    proc(1500, '/usr/bin/gnome-shell', 100);
    // R: Vigil's main process, started on the image and now running from the mount.
    proc(2000, `${mount}/vigil-at-home`, 500, [
      [0, '/dev/null'],
      [3, 'pipe:[90001]'],
      [1023, mount],
    ]);
    // The mount server: runs the image, reads it, serves /dev/fuse.
    proc(2003, image, 501, [
      [0, '/dev/null'],
      [4, 'pipe:[90001]'],
      [5, image],
      [6, '/dev/fuse'],
    ]);
    // Chromium's helpers run Vigil's binary from the mount and close inherited files.
    proc(2010, `${mount}/vigil-at-home`, 520);
    proc(2011, `${mount}/chrome_crashpad_handler`, 521);
    // A connector: the user's own program, started later, with the pipe inherited.
    proc(2100, '/usr/bin/node', 900, [[3, 'pipe:[90001]']]);
    // As FastPath.self() gives it: the image by identity only, never by path.
    return { image, mount, self: { paths: [] as string[], images: ['2049:5501'] } };
  }

  it('never pauses Vigil running from its AppImage, and nothing else counts as Vigil', async () => {
    const { self } = launchAppImage();
    for (const pid of [2000, 2003, 2010, 2011]) {
      await expect(suspendProcess(sys, pid, { self })).rejects.toMatchObject({
        code: 'refused',
      });
    }
    // A connector Vigil started is contained like any other program.
    await suspendProcess(sys, 2100, { self });
    // Files on a FUSE mount are never stat'ed: a server that never answers would hang the helper.
    const asked: string[] = [];
    const fileId = sys.fileId.bind(sys);
    sys.fileId = (p: string) => (asked.push(p), fileId(p));
    await expect(suspendProcess(sys, 2010, { self })).rejects.toMatchObject({ code: 'refused' });
    expect(asked).toContain('/proc/2003/exe');
    expect(asked.filter((p) => /^\/proc\/(2000|2010|2011)\//.test(p))).toEqual([]);
    // Without an approved image, the mount grants nothing.
    await suspendProcess(sys, 2010, { self: { paths: [], images: [] } });
    expect(sys.signals.map((s) => s.pid)).toEqual([2100, 2010]);
  });

  it('protects a mounted Vigil program a connector runs, as the app’s floor does', async () => {
    const { mount, self } = launchAppImage();
    sys.processes.set(2101, { path: `${mount}/vigil-at-home`, started: STARTED });
    sys.starts.set(2101, 950);
    await expect(suspendProcess(sys, 2101, { self })).rejects.toMatchObject({ code: 'refused' });
  });

  it('gives a look-alike mount nothing, whatever its name or who started it', async () => {
    const { self } = launchAppImage();
    // Another FUSE mount named like an AppImage's, with a program that
    // started before Vigil, and one Vigil's connector started (so it holds
    // the keepalive pipe too).
    const fake = '/tmp/.mount_VigilaZZZZZZ';
    sys.mounts += `\n700 40 0:80 / ${fake} ro,nosuid,nodev,relatime - fuse.Vigil.AppImage Vigil.AppImage ro,user_id=1000,group_id=1000`;
    sys.processes.set(3000, { path: `${fake}/vigil-at-home`, started: STARTED });
    sys.starts.set(3000, 50);
    sys.processes.set(3001, { path: `${fake}/payload`, started: STARTED });
    sys.starts.set(3001, 960);
    sys.fds.set(3001, [[3, 'pipe:[90001]']]);
    // A folder that merely has the name, not a mount.
    sys.processes.set(3002, { path: '/home/alex/.mount_Vigil/vigil-at-home', started: STARTED });
    sys.starts.set(3002, 970);
    sys.fds.set(3002, [[3, 'pipe:[90001]']]);
    // The image's runtime serving a different file (a server that runs the
    // image but doesn't hold it open), for a mount of its own.
    const other = '/tmp/.mount_payloadQ';
    sys.files.set('/home/alex/payload.AppImage', '2049:7777');
    sys.mounts += `\n701 40 0:81 / ${other} ro,nosuid,nodev,relatime - fuse.squashfuse squashfuse ro,user_id=1000,group_id=1000`;
    sys.processes.set(3100, { path: '/home/alex/Apps/Vigil.AppImage', started: STARTED });
    sys.starts.set(3100, 1000);
    sys.fds.set(3100, [
      [4, 'pipe:[90002]'],
      [5, '/home/alex/payload.AppImage'],
      [6, '/dev/fuse'],
    ]);
    sys.processes.set(3101, { path: `${other}/AppRun`, started: STARTED });
    sys.starts.set(3101, 999);
    sys.fds.set(3101, [[3, 'pipe:[90002]']]);
    for (const pid of [3000, 3001, 3002, 3101]) await suspendProcess(sys, pid, { self });
    expect(sys.signals.map((s) => s.pid)).toEqual([3000, 3001, 3002, 3101]);
    // The server process itself runs the image file, so it stays protected.
    await expect(suspendProcess(sys, 3100, { self })).rejects.toMatchObject({ code: 'refused' });
  });

  it('still knows Vigil after its image is renamed, and only by its identity', async () => {
    const { image, self } = launchAppImage();
    const moved = '/home/alex/Vigil-old.AppImage';
    sys.files.delete(image);
    sys.files.set(moved, '2049:5501');
    sys.processes.set(2003, { path: moved, started: STARTED });
    sys.fds.set(2003, [
      [4, 'pipe:[90001]'],
      [5, moved],
      [6, '/dev/fuse'],
    ]);
    await expect(suspendProcess(sys, 2000, { self })).rejects.toMatchObject({ code: 'refused' });
    // Linux paths are case-sensitive: a look-alike image is another file.
    sys.files.set('/home/alex/Apps/vigil.appimage', '2049:6000');
    sys.processes.set(86, { path: '/home/alex/Apps/vigil.appimage', started: STARTED });
    await suspendProcess(sys, 86, { self });
    // Another file put at the image's old path is not Vigil.
    sys.files.set(image, '2049:6001');
    sys.processes.set(87, { path: image, started: STARTED });
    await suspendProcess(sys, 87, { self });
    expect(sys.signals.map((s) => s.pid)).toEqual([86, 87]);
  });

  it('gives nothing to a connector that execs a program, whenever it started', async () => {
    const { mount, self } = launchAppImage();
    // A program on another read-only FUSE mount the user controls, holding
    // Vigil's keepalive pipe (a connector Vigil started that exec'd it). It
    // started after R, so it cannot stand in for R.
    const fake = '/tmp/.mount_EvilaZZZZZ';
    sys.mounts += `\n700 40 0:80 / ${fake} ro,nosuid,nodev,relatime - fuse.AppImage AppImage ro,user_id=1000,group_id=1000`;
    sys.processes.set(4000, { path: `${fake}/payload`, started: STARTED });
    sys.starts.set(4000, 940);
    sys.fds.set(4000, [[7, 'pipe:[90001]']]);
    await suspendProcess(sys, 4000, { self });
    // And a second program on that same mount, with no pipe at all.
    sys.processes.set(4001, { path: `${fake}/other`, started: STARTED });
    sys.starts.set(4001, 941);
    await suspendProcess(sys, 4001, { self });
    expect(sys.signals.map((s) => s.pid)).toEqual([4000, 4001]);
    // Vigil's own mount is unaffected by the look-alike alongside it.
    await expect(suspendProcess(sys, 2010, { self })).rejects.toMatchObject({ code: 'refused' });
    expect(mount).toContain('.mount_');
  });

  it('matches a mount point with escaped spaces as the kernel wrote it', async () => {
    launchAppImage();
    // A genuine Vigil mount whose path holds a space: mountinfo escapes it as
    // \\040, /proc/<pid>/exe gives the real space. Both must line up.
    const spaced = '/tmp/.mount Vigil X';
    sys.mounts += `\n710 40 0:82 / /tmp/.mount\\040Vigil\\040X ro,nosuid,nodev,relatime - fuse.AppImage AppImage ro,user_id=1000,group_id=1000`;
    sys.files.set('/home/alex/Apps/Vigil2.AppImage', '2049:7000');
    sys.processes.set(5000, { path: `${spaced}/vigil-at-home`, started: STARTED });
    sys.starts.set(5000, 510);
    sys.processes.set(5001, { path: '/home/alex/Apps/Vigil2.AppImage', started: STARTED });
    sys.starts.set(5001, 509);
    sys.fds.set(5001, [
      [4, 'pipe:[90010]'],
      [5, '/home/alex/Apps/Vigil2.AppImage'],
      [6, '/dev/fuse'],
    ]);
    // R for this second image, on the spaced mount, earliest on the pipe.
    sys.processes.set(5002, { path: `${spaced}/vigil-at-home`, started: STARTED });
    sys.starts.set(5002, 508);
    sys.fds.set(5002, [[3, 'pipe:[90010]']]);
    await expect(
      suspendProcess(sys, 5000, { self: { paths: [], images: ['2049:7000'] } }),
    ).rejects.toMatchObject({ code: 'refused' });
    // A crafted mountinfo line that only looks like a mount point: a program
    // whose real path has no space can't match the escaped entry.
    sys.processes.set(5003, {
      path: '/tmp/.mount\\040Vigil\\040X/vigil-at-home',
      started: STARTED,
    });
    sys.starts.set(5003, 511);
    await suspendProcess(sys, 5003, { self: { paths: [], images: ['2049:7000'] } });
    expect(sys.signals.map((s) => s.pid)).toEqual([5003]);
  });

  it('refuses nothing to a server that holds a different file than the image', async () => {
    const { mount, self } = launchAppImage();
    // A server running the approved image but holding a DIFFERENT file open
    // (not the image), with its own mount and R. It does not serve the image.
    const other = '/tmp/.mount_decoyQ';
    sys.files.set('/home/alex/decoy', '2049:8000');
    sys.mounts += `\n720 40 0:83 / ${other} ro,nosuid,nodev,relatime - fuse.AppImage AppImage ro,user_id=1000,group_id=1000`;
    sys.processes.set(6000, { path: '/home/alex/Apps/Vigil.AppImage', started: STARTED });
    sys.starts.set(6000, 600);
    sys.fds.set(6000, [
      [4, 'pipe:[90020]'],
      [5, '/home/alex/decoy'],
      [6, '/dev/fuse'],
    ]);
    sys.processes.set(6001, { path: `${other}/vigil-at-home`, started: STARTED });
    sys.starts.set(6001, 599);
    sys.fds.set(6001, [[3, 'pipe:[90020]']]);
    await suspendProcess(sys, 6001, { self });
    expect(sys.signals.map((s) => s.pid)).toEqual([6001]);
    expect(mount).toBeTruthy();
  });

  it('refuses to block a program inside Vigil by hash', async () => {
    const own = 'a'.repeat(64);
    const blocking = new Executor({
      sys,
      journal: new Journal(join(root, 'journal2.json')),
      approvals: new Approvals({
        dir: join(root, 'approvals2'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules: new RuleStore(join(root, 'rules2.json')),
      quarantine: { quarantineDir: join(root, 'quarantine2') },
      syncPort: 47821,
      self: () => ({ paths: [], images: [], hashes: [own] }),
    });
    await expect(
      blocking.execute({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: own.toUpperCase(),
        policy: 'block',
      }),
    ).rejects.toMatchObject({ code: 'refused' });
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
