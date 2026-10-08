import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { connect, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { pinFor, readPin, verifyPeer, writePin, type ProtectedPeer } from './appPin.js';
import { Executor } from './executor.js';
import { Journal } from './journal.js';
import { parseLsofSockets, peerPid, ssPeerInode } from './peer.js';
import { HelperServer } from './server.js';
import { realSystem, type BinaryName, type RunResult } from './system.js';
import { FapolicydBlocks } from './commands/fapolicyd.js';
import { FakeSystem } from './testing/fakeSystem.js';
import { FakeLinuxSystem } from './testing/fakeLinuxSystem.js';

const STARTED = 'Mon Oct  5 16:20:13 2026';
const HELPER = 900;
const FD = 12;
const CDHASH = 'c'.repeat(40);
const APP_SHA = 'a'.repeat(64);
const MAC_SOCKET = '/var/run/vigil-helper.sock';
const LINUX_SOCKET = '/run/vigil-helper.sock';

let root: string;
beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'vigil-pin-'));
});
afterEach(() => rmSync(root, { recursive: true, force: true }));

const ok = (stdout = '', stderr = ''): RunResult => ({ code: 0, stdout, stderr });

/**
 * macOS: lsof's view of the Unix sockets (kernel address, peer address) and
 * the cdhash codesign reads for each running pid.
 */
class MacPeers extends FakeSystem {
  /** pid → its sockets as [fd, address, peer address]. */
  sockets = new Map<number, [number, string, string | undefined][]>();
  cdhashes = new Map<string, string>();

  override async run(bin: BinaryName, args: string[], opts: { input?: string } = {}) {
    if (bin === 'lsof' && args.includes('-U')) {
      this.runs.push({ bin, args, input: opts.input });
      const only = args.includes('-p') ? Number(args[args.indexOf('-p') + 1]) : undefined;
      const fd = args.includes('-d') ? Number(args[args.indexOf('-d') + 1]) : undefined;
      let out = '';
      for (const [pid, socks] of this.sockets) {
        if (only !== undefined && pid !== only) continue;
        out += `p${pid}\n`;
        for (const [n, addr, peer] of socks) {
          if (fd !== undefined && n !== fd) continue;
          out += `f${n}\nd${addr}\nn${peer ? `->${peer}` : MAC_SOCKET}\n`;
        }
      }
      return ok(out);
    }
    if (bin === 'codesign') {
      this.runs.push({ bin, args, input: opts.input });
      const cd = this.cdhashes.get(args.at(-1)!);
      return cd
        ? ok('', `Executable=/x\nIdentifier=com.vigilathome.app\nCDHash=${cd}\nSignature=adhoc\n`)
        : { code: 1, stdout: '', stderr: 'not signed' };
    }
    return super.run(bin, args, opts);
  }
}

/** Linux: `ss -x` lines for the helper's socket, from [own inode, peer inode] pairs. */
class LinuxPeers extends FakeLinuxSystem {
  conns: [string, string][] = [];

  override async run(bin: BinaryName, args: string[], opts: { input?: string } = {}) {
    if (bin === 'ss') {
      this.runs.push({ bin, args, input: opts.input });
      const lines = [
        'Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process',
        'u_str ESTAB  0      0      /run/systemd/journal/stdout 3001 * 3000',
        ...this.conns.map(
          ([own, peer]) => `u_str ESTAB  0      0      ${LINUX_SOCKET} ${own} * ${peer}`,
        ),
      ];
      return ok(lines.join('\n') + '\n');
    }
    return super.run(bin, args, opts);
  }
}

describe('finding the peer from the kernel’s socket tables', () => {
  it('reads the peer inode from ss for the helper’s own end only', () => {
    const out = [
      'u_str ESTAB 0 0 /run/vigil-helper.sock 5001 * 5002',
      'u_str ESTAB 0 0 /run/vigil-helper.sock 5003 * 5004',
      'u_str ESTAB 0 0 /tmp/other.sock 5001 * 6000',
    ].join('\n');
    expect(ssPeerInode(out, LINUX_SOCKET, '5001')).toBe('5002');
    expect(ssPeerInode(out, LINUX_SOCKET, '5003')).toBe('5004');
    expect(ssPeerInode(out, LINUX_SOCKET, '5005')).toBeUndefined();
    // A client that names its own socket to look like other fields still
    // can't move its peer inode: that is always the last one.
    const sly = 'u_str ESTAB 0 0 /run/vigil-helper.sock 5007 /tmp/x 5001 * 5002 5008';
    expect(ssPeerInode(sly, LINUX_SOCKET, '5007')).toBe('5008');
    expect(ssPeerInode(sly, LINUX_SOCKET, '5001')).toBeUndefined();
  });

  it('reads lsof’s socket and peer addresses', () => {
    expect(
      parseLsofSockets('p1\nf3\nd0x0A\nn->0x0b\nf4\nd0xc\nn/var/run/x.sock\np2\nf5\nd0xd\n'),
    ).toEqual([
      { pid: 1, addr: 10n, peer: 11n },
      { pid: 1, addr: 12n },
      { pid: 2, addr: 13n },
    ]);
  });
});

const hasSs = existsSync('/usr/bin/ss') || existsSync('/usr/sbin/ss');

describe('finding a real peer (Linux, with ss)', () => {
  it.skipIf(process.platform !== 'linux' || !hasSs)(
    'names the process that connected',
    async () => {
      const path = join(root, 's.sock');
      let accepted!: (fd: number) => void;
      const fd = new Promise<number>((r) => (accepted = r));
      const srv = createServer((s) =>
        accepted((s as unknown as { _handle: { fd: number } })._handle.fd),
      );
      await new Promise<void>((r) => srv.listen(path, () => r()));
      const child = spawn(process.execPath, [
        '-e',
        `require('net').connect(${JSON.stringify(path)}); setTimeout(() => {}, 10000)`,
      ]);
      try {
        expect(await peerPid(realSystem(undefined, 'linux'), await fd, path)).toBe(child.pid);
      } finally {
        child.kill();
        srv.close();
      }
    },
  );
});

describe('the app pinned at install (macOS)', () => {
  const APP = 501;
  let sys: MacPeers;
  let pinFile: string;
  const check = () => verifyPeer(sys, FD, { socketPath: MAC_SOCKET, pinFile, self: HELPER });

  beforeEach(() => {
    sys = new MacPeers();
    pinFile = join(root, 'app-pin.json');
    sys.processes.set(APP, {
      path: '/Users/a/Downloads/Vigil at Home.app/Contents/MacOS/Vigil at Home',
      started: STARTED,
    });
    // The helper's end of the connection (0xa1), its listener, and the app's end (0xb1).
    sys.sockets.set(HELPER, [
      [9, '0xa0', undefined],
      [FD, '0xa1', undefined],
    ]);
    sys.sockets.set(APP, [[30, '0xb1', '0xa1']]);
    sys.cdhashes.set(String(APP), CDHASH);
    writePin(pinFile, { platform: 'darwin', path: '/x', cdhash: CDHASH, sha256: APP_SHA });
  });

  it('pins the cdhash and sha256 of the app’s executable, as root reads them', async () => {
    sys.cdhashes.set('/Apps/Vigil/MacOS/Vigil', CDHASH);
    const pin = await pinFor(sys, '/Apps/Vigil/MacOS/Vigil', {
      installed: [],
      sha256: () => APP_SHA,
    });
    expect(pin).toEqual({
      platform: 'darwin',
      path: '/Apps/Vigil/MacOS/Vigil',
      cdhash: CDHASH,
      sha256: APP_SHA,
    });
    writePin(pinFile, pin);
    expect(readPin(pinFile)).toEqual(pin);
    expect(statSync(pinFile).mode & 0o777).toBe(0o644);
    await expect(
      pinFor(sys, '/unsigned', { installed: [], sha256: () => APP_SHA }),
    ).rejects.toThrow();
    await expect(pinFor(sys, 'relative', { installed: [] })).rejects.toThrow();
  });

  it('protects the connected process whose running code matches the pin', async () => {
    expect(await check()).toEqual({ pid: APP, started: STARTED, hashes: [CDHASH, APP_SHA] });
    // The cdhash comes from the running process, never from a file path.
    const cs = sys.runs.filter((r) => r.bin === 'codesign');
    expect(cs.map((r) => r.args.at(-1))).toEqual([String(APP)]);
  });

  it('finds the peer from either end’s address', async () => {
    // Some sockets name their peer on the helper's side instead.
    sys.sockets.set(HELPER, [[FD, '0xa1', '0xb1']]);
    sys.sockets.set(APP, [[30, '0xb1', undefined]]);
    expect((await check())?.pid).toBe(APP);
  });

  it('gives nothing to a process whose code doesn’t match the pin', async () => {
    sys.cdhashes.set(String(APP), 'd'.repeat(40));
    expect(await check()).toBeUndefined();
    // Unsigned, or gone before codesign looked.
    sys.cdhashes.delete(String(APP));
    expect(await check()).toBeUndefined();
  });

  it('gives nothing to another connected process, even while the app runs', async () => {
    const OTHER = 777;
    sys.processes.set(OTHER, { path: '/tmp/evil', started: STARTED });
    // The app runs (and matches) but holds a different connection.
    sys.sockets.set(APP, [[30, '0xb9', '0xa9']]);
    sys.sockets.set(OTHER, [[4, '0xe1', '0xa1']]);
    expect(await check()).toBeUndefined();
  });

  it('names no one when the client end is shared', async () => {
    sys.processes.set(778, { path: '/tmp/child', started: STARTED });
    sys.sockets.set(778, [[30, '0xb1', '0xa1']]);
    sys.cdhashes.set('778', CDHASH);
    expect(await check()).toBeUndefined();
  });

  it('protects nothing, and looks at nothing, without a pin', async () => {
    writePin(pinFile, undefined);
    expect(await check()).toBeUndefined();
    expect(sys.runs).toEqual([]);
    // A pin made on the other system doesn't count either.
    writePin(pinFile, { platform: 'linux', path: '/x', image: '1:2', sha256: APP_SHA });
    expect(await check()).toBeUndefined();
  });
});

describe('the app pinned at install (Linux AppImage)', () => {
  const image = '/home/alex/Apps/Vigil.AppImage';
  const mount = '/tmp/.mount_VigilaB1c2D';
  let sys: LinuxPeers;
  let pinFile: string;
  const check = () => verifyPeer(sys, FD, { socketPath: LINUX_SOCKET, pinFile, self: HELPER });

  beforeEach(() => {
    sys = new LinuxPeers();
    pinFile = join(root, 'app-pin.json');
    sys.files.set(image, '2049:5501');
    sys.mounts = [
      '22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw',
      '40 22 0:35 / /tmp rw,nosuid,nodev shared:20 - tmpfs tmpfs rw',
      `612 40 0:71 / ${mount} ro,nosuid,nodev,relatime shared:350 - fuse.Vigil.AppImage Vigil.AppImage ro,user_id=1000,group_id=1000`,
    ].join('\n');
    const proc = (pid: number, path: string, start: number, fds: [number, string][]) => {
      sys.processes.set(pid, { path, started: STARTED });
      sys.starts.set(pid, start);
      sys.fds.set(pid, fds);
    };
    // Vigil's main process, from the mount, connected on socket 5002.
    proc(2000, `${mount}/vigil-at-home`, 500, [
      [3, 'pipe:[90001]'],
      [40, 'socket:[5002]'],
    ]);
    // The image's mount server.
    proc(2003, image, 501, [
      [4, 'pipe:[90001]'],
      [5, image],
      [6, '/dev/fuse'],
    ]);
    proc(2100, '/home/alex/.local/bin/tool', 900, [[7, 'socket:[5004]']]);
    sys.fds.set(HELPER, [
      [FD, 'socket:[5001]'],
      [13, 'socket:[5003]'],
    ]);
    sys.conns = [
      ['5001', '5002'],
      ['5003', '5004'],
    ];
    writePin(pinFile, { platform: 'linux', path: image, image: '2049:5501', sha256: APP_SHA });
  });

  it('pins the AppImage by device and inode, and nothing in the installer’s folder', async () => {
    const opts = { installed: ['/opt/Vigil at Home'], sha256: () => APP_SHA };
    expect(await pinFor(sys, image, opts)).toEqual({
      platform: 'linux',
      path: image,
      image: '2049:5501',
      sha256: APP_SHA,
    });
    expect(await pinFor(sys, '/opt/Vigil at Home/vigil-at-home', opts)).toBeUndefined();
    await expect(pinFor(sys, '/home/alex/missing', opts)).rejects.toThrow();
  });

  it('protects Vigil running from the pinned image', async () => {
    expect(await check()).toEqual({ pid: 2000, started: STARTED, hashes: [APP_SHA] });
  });

  it('gives nothing when the pin names another image', async () => {
    writePin(pinFile, { platform: 'linux', path: image, image: '2049:9999', sha256: APP_SHA });
    expect(await check()).toBeUndefined();
  });

  it('gives nothing to another connected process', async () => {
    // The helper's connection on FD now leads to the user's own tool.
    sys.conns = [['5001', '5004']];
    expect(await check()).toBeUndefined();
    // And the tool's own connection is no better.
    expect(
      await verifyPeer(sys, 13, { socketPath: LINUX_SOCKET, pinFile, self: HELPER }),
    ).toBeUndefined();
  });

  it('names no one when the client end is shared', async () => {
    sys.fds.set(2100, [[7, 'socket:[5002]']]);
    expect(await check()).toBeUndefined();
  });
});

describe('what a verified peer is spared', () => {
  const APP = 501;
  const peer: ProtectedPeer = { pid: APP, started: STARTED, hashes: [CDHASH, APP_SHA] };
  let peers: ProtectedPeer[];
  const deps = (sys: FakeSystem | FakeLinuxSystem) => ({
    sys,
    journal: new Journal(join(root, 'journal.json')),
    approvals: new Approvals({ dir: join(root, 'approvals'), requiredOwnerUid: process.getuid!() }),
    rules: new RuleStore(join(root, 'rules.json')),
    quarantine: { quarantineDir: join(root, 'Quarantine') },
    syncPort: 47821,
    peers: () => peers,
  });
  beforeEach(() => {
    peers = [peer];
  });

  it('macOS: never pauses or stops it, or blocks its program by hash', async () => {
    const sys = new FakeSystem();
    const path = '/Users/a/Downloads/Vigil at Home.app/Contents/MacOS/Vigil at Home';
    sys.processes.set(APP, { path, started: STARTED });
    sys.processes.set(777, { path: '/tmp/evil', started: STARTED });
    const ex = new Executor(deps(sys));
    for (const kind of ['process.suspend', 'process.kill'] as const)
      await expect(ex.execute({ kind, pid: APP, path })).rejects.toMatchObject({ code: 'refused' });
    for (const [ruleType, identifier] of [
      ['cdhash', CDHASH.toUpperCase()],
      ['binary', APP_SHA],
    ] as const)
      await expect(
        ex.execute({ kind: 'santa.rule.set', ruleType, identifier, policy: 'block' }),
      ).rejects.toMatchObject({ code: 'refused' });
    // Everything else is blocked as before.
    await ex.execute({ kind: 'process.kill', pid: 777, path: '/tmp/evil' });
    await ex.execute({
      kind: 'santa.rule.set',
      ruleType: 'cdhash',
      identifier: 'e'.repeat(40),
      policy: 'block',
    });
    expect(sys.signals).toEqual([{ pid: 777, signal: 'SIGKILL' }]);

    // A reused pid is another process.
    sys.processes.set(APP, { path, started: 'Tue Oct  6 09:00:00 2026' });
    await ex.execute({ kind: 'process.suspend', pid: APP, path });
    // Once the app disconnects, it is an ordinary program again.
    sys.processes.set(APP, { path, started: STARTED });
    peers = [];
    await ex.execute({ kind: 'process.suspend', pid: APP, path });
    await ex.execute({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: APP_SHA,
      policy: 'block',
    });
    expect(sys.signals.map((s) => s.pid)).toEqual([777, APP, APP]);
  });

  it('Linux: no fapolicyd block of the pinned image either', async () => {
    const sys = new FakeLinuxSystem();
    const blocks = new FapolicydBlocks(sys, {
      store: join(root, 'blocked.json'),
      rulesDir: join(root, 'rules.d'),
    });
    sys.processes.set(APP, { path: '/tmp/.mount_X/vigil-at-home', started: STARTED });
    const ex = new Executor({ ...deps(sys), fapolicyd: blocks });
    const set = {
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: APP_SHA,
      policy: 'block',
    } as const;
    await expect(ex.execute(set)).rejects.toMatchObject({ code: 'refused' });
    await expect(
      ex.execute({ kind: 'process.kill', pid: APP, path: '/tmp/.mount_X/vigil-at-home' }),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(blocks.has(APP_SHA)).toBe(false);
    peers = [];
    await ex.execute(set);
    expect(blocks.has(APP_SHA)).toBe(true);
  });
});

describe('the server checks each connection once, for as long as it lasts', () => {
  let server: HelperServer;
  const socketPath = () => join(root, 'h.sock');
  const open = () =>
    new Promise<Socket>((resolve) => {
      const s = connect(socketPath());
      s.once('connect', () => resolve(s));
    });
  const until = async (cond: () => boolean) => {
    for (let i = 0; i < 200 && !cond(); i++) await new Promise((r) => setTimeout(r, 5));
    expect(cond()).toBe(true);
  };
  afterEach(() => server.close());

  it('protects a verified connection until it closes', async () => {
    const seen: number[] = [];
    let answer: ProtectedPeer | undefined = { pid: 501, started: STARTED, hashes: [APP_SHA] };
    server = new HelperServer({
      socketPath: socketPath(),
      executor: {} as Executor,
      identifyPeer: async (fd) => {
        seen.push(fd);
        return answer;
      },
    });
    await server.listen();
    const app = await open();
    await until(() => server.peers().length === 1);
    expect(typeof seen[0]).toBe('number');
    // Another client, which the kernel says is not the pinned app.
    answer = undefined;
    const other = await open();
    await until(() => seen.length === 2);
    expect(server.peers()).toEqual([{ pid: 501, started: STARTED, hashes: [APP_SHA] }]);
    app.destroy();
    await until(() => server.peers().length === 0);
    other.destroy();
  });

  it('keeps nothing for a connection that closed while it was checked', async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    server = new HelperServer({
      socketPath: socketPath(),
      executor: {} as Executor,
      identifyPeer: async () => {
        await gate;
        return { pid: 501, started: STARTED, hashes: [] } satisfies ProtectedPeer;
      },
    });
    await server.listen();
    const s = await open();
    await new Promise((r) => setTimeout(r, 20));
    s.destroy();
    await new Promise((r) => setTimeout(r, 20));
    release();
    await new Promise((r) => setTimeout(r, 20));
    expect(server.peers()).toEqual([]);
  });
});
