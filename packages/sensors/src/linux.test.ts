import { describe, expect, it } from 'vitest';
import {
  PackageIndex,
  dpkgSource,
  rpmSource,
  runnable,
  sandboxedPackage,
  usrAlias,
  type PackageSource,
} from './linux/packages.js';
import { LINUX_QUERY_NAMES, osqueryLinuxConfig, osqueryLinuxFlags } from './osquery/linuxConfig.js';
import { osqueryLineToEvents } from './osquery/resultParser.js';
import { SensorHub } from './hub.js';
import type { SensorEvent } from './types.js';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

function fakeSource(files: [string, string][], version = () => 'v1'): PackageSource {
  return { version, load: () => files };
}

const row = (name: string, columns: Record<string, string>, extra: object = {}) =>
  JSON.stringify({ name, action: 'added', counter: 3, unixTime: 1790000000, columns, ...extra });

describe('package index', () => {
  it('keeps only paths a program could run from', () => {
    expect(runnable('/usr/bin/curl')).toBe(true);
    expect(runnable('/usr/lib/firefox/firefox')).toBe(true);
    expect(runnable('/usr/share/doc/curl/copyright')).toBe(false);
    expect(runnable('/usr/lib/x86_64-linux-gnu/libc.so.6')).toBe(false);
    expect(runnable('/etc/hosts')).toBe(false);
    expect(runnable('/.')).toBe(true);
  });

  it('matches both spellings of merged-/usr paths', () => {
    expect(usrAlias('/bin/ps')).toBe('/usr/bin/ps');
    expect(usrAlias('/usr/sbin/nft')).toBe('/sbin/nft');
    expect(usrAlias('/usr/local/bin/x')).toBeUndefined();
    const index = new PackageIndex({ sources: [fakeSource([['/bin/ps', 'procps']])] });
    expect(index.trust('/usr/bin/ps')).toEqual({ signing: 'package', signingId: 'pkg:procps' });
  });

  it('trusts system snaps and Flatpaks, not user-installed Flatpaks', () => {
    expect(sandboxedPackage('/snap/firefox/4793/usr/lib/firefox/firefox')).toBe('snap:firefox');
    expect(
      sandboxedPackage('/var/lib/flatpak/app/org.gimp.GIMP/x86_64/stable/a/files/bin/gimp'),
    ).toBe('flatpak:org.gimp.GIMP');
    expect(sandboxedPackage('/home/a/.local/share/flatpak/app/org.x/files/bin/x')).toBeUndefined();
    expect(sandboxedPackage('/snap/../tmp/x')).toBeUndefined();
  });

  it('calls everything else unsigned', () => {
    const index = new PackageIndex({ sources: [fakeSource([['/usr/bin/curl', 'curl']])] });
    expect(index.trust('/usr/bin/curl')).toEqual({ signing: 'package', signingId: 'pkg:curl' });
    expect(index.trust('/home/a/.cache/miner')).toEqual({ signing: 'unsigned' });
    expect(index.trust('relative')).toBeUndefined();
  });

  it('reloads only when the package database changes', () => {
    let version = 'v1';
    let files: [string, string][] = [['/usr/bin/a', 'a']];
    let loads = 0;
    let t = 0;
    const src: PackageSource = {
      version: () => version,
      load: () => {
        loads++;
        return files;
      },
    };
    const index = new PackageIndex({ sources: [src], recheckMs: 1000, now: () => t });
    expect(index.owner('/usr/bin/a')).toBe('pkg:a');
    t = 500;
    files = [['/usr/bin/b', 'b']];
    version = 'v2';
    expect(index.owner('/usr/bin/b')).toBeUndefined(); // not rechecked yet
    t = 1500;
    expect(index.owner('/usr/bin/b')).toBe('pkg:b');
    t = 3000;
    index.owner('/usr/bin/b');
    expect(loads).toBe(2);
  });

  it('reads dpkg .list files and rpm listings', () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-dpkg-'));
    try {
      mkdirSync(join(dir, 'info'));
      writeFileSync(
        join(dir, 'info', 'curl.list'),
        '/.\n/usr\n/usr/bin/curl\n/usr/share/doc/curl\n',
      );
      writeFileSync(join(dir, 'info', 'libc-bin:amd64.list'), '/usr/sbin/ldconfig\n');
      writeFileSync(join(dir, 'info', 'curl.md5sums'), 'x usr/bin/curl\n');
      writeFileSync(join(dir, 'status'), '');
      const index = new PackageIndex({
        sources: [
          dpkgSource(join(dir, 'info'), join(dir, 'status')),
          rpmSource(() => '/usr/bin/vim\tvim-enhanced\nbad line\n', [join(dir, 'status')]),
        ],
      });
      expect(index.owner('/usr/bin/curl')).toBe('pkg:curl');
      expect(index.owner('/usr/sbin/ldconfig')).toBe('pkg:libc-bin');
      expect(index.owner('/usr/bin/vim')).toBe('pkg:vim-enhanced');
      expect(index.owner('/usr/share/doc/curl')).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('a missing database gives an empty index, not an error', () => {
    const index = new PackageIndex({
      sources: [dpkgSource('/nonexistent/info', '/nonexistent/status')],
    });
    expect(index.trust('/usr/bin/curl')).toEqual({ signing: 'unsigned' });
  });
});

describe('osquery on Linux', () => {
  it('schedules eBPF launches and the Linux startup folders', () => {
    const config = JSON.parse(osqueryLinuxConfig()) as {
      schedule: Record<string, { query: string; interval: number; denylist: boolean }>;
    };
    const exec = config.schedule[LINUX_QUERY_NAMES.processEvents]!;
    expect(exec.query).toContain('FROM bpf_process_events');
    expect(exec.interval).toBe(5);
    expect(config.schedule[LINUX_QUERY_NAMES.startup]!.query).toContain(
      "'/home/%/.config/systemd/user/%'",
    );
    expect(config.schedule.vigil_network_connections!.query).toContain('family IN (2, 10)');
    expect(config.schedule.vigil_listening_ports!.query).not.toContain('signature');
    expect(Object.values(config.schedule).every((q) => q.denylist === false)).toBe(true);
    expect(osqueryLinuxFlags()).toContain('--enable_bpf_events=true');
    expect(osqueryLinuxFlags()).toContain('--disable_events=false');
  });

  it('turns an eBPF launch into process.exec, even on the first run', () => {
    const [e] = osqueryLineToEvents(
      row(
        LINUX_QUERY_NAMES.processEvents,
        {
          pid: '4242',
          parent: '4000',
          uid: '1000',
          path: '/usr/bin/curl',
          cwd: '/home/a',
          cmdline: 'curl -s https://x.test/a b',
          json_cmdline: JSON.stringify(['curl', '-s', 'https://x.test/a b']),
          time: '1790000005',
        },
        { counter: 0 },
      ),
    );
    expect(e).toMatchObject({
      kind: 'process.exec',
      ts: 1790000005000,
      process: {
        pid: 4242,
        ppid: 4000,
        uid: 1000,
        path: '/usr/bin/curl',
        cwd: '/home/a',
        args: ['curl', '-s', 'https://x.test/a b'],
      },
    });
  });

  it('falls back to splitting cmdline and skips launches without a path', () => {
    const [e] = osqueryLineToEvents(
      row(LINUX_QUERY_NAMES.processEvents, { pid: '1', path: '/bin/sh', cmdline: 'sh -c id' }),
    );
    expect((e as Extract<SensorEvent, { kind: 'process.exec' }>).process.args).toEqual([
      'sh',
      '-c',
      'id',
    ]);
    expect(
      osqueryLineToEvents(row(LINUX_QUERY_NAMES.processEvents, { pid: '1', path: '' })),
    ).toEqual([]);
  });

  it('reports new systemd units, autostart entries and edited shell profiles', () => {
    const [unit] = osqueryLineToEvents(
      row(LINUX_QUERY_NAMES.startup, {
        path: '/home/a/.config/systemd/user/miner.service',
        sha256: 'x',
      }),
    );
    expect(unit).toMatchObject({
      kind: 'persistence',
      change: 'added',
      mechanism: 'systemd_unit',
      label: 'miner.service',
    });
    const [auto] = osqueryLineToEvents(
      row(LINUX_QUERY_NAMES.startup, {
        path: '/home/a/.config/autostart/upd.desktop',
        sha256: 'x',
      }),
    );
    expect(auto).toMatchObject({ mechanism: 'autostart' });
    const [prof] = osqueryLineToEvents(
      row(LINUX_QUERY_NAMES.shellProfiles, { path: '/home/a/.bashrc', sha256: 'y' }),
    );
    expect(prof).toMatchObject({ mechanism: 'shell_profile', change: 'modified' });
    // What was already there when Vigil started is not news.
    expect(
      osqueryLineToEvents(
        row(LINUX_QUERY_NAMES.startup, { path: '/etc/systemd/system/a.service' }, { counter: 0 }),
      ),
    ).toEqual([]);
  });
});

describe('hub trust on Linux', () => {
  it('fills in package trust on launches and later events from the same program', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-hub-'));
    const got: SensorEvent[] = [];
    const hub = new SensorHub({
      sink: (e) => got.push(e),
      santaLogPath: false,
      osqueryResultsPath: false,
      trust: (p) =>
        p === '/usr/bin/curl'
          ? { signing: 'package', signingId: 'pkg:curl' }
          : { signing: 'unsigned' },
    });
    try {
      for (const line of [
        row(LINUX_QUERY_NAMES.processEvents, { pid: '5', path: '/usr/bin/curl' }),
        row(LINUX_QUERY_NAMES.processEvents, { pid: '6', parent: '5', path: '/tmp/dropper' }),
      ])
        for (const e of osqueryLineToEvents(line)) hub.emit(e);
      expect(got.map((e) => 'process' in e && e.process?.signing)).toEqual(['package', 'unsigned']);
      expect((got[1] as Extract<SensorEvent, { kind: 'process.exec' }>).process).toMatchObject({
        parentPath: '/usr/bin/curl',
        ancestors: ['curl'],
      });
    } finally {
      await hub.stop();
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('launch hashes', () => {
  it('hashes a file once per change and skips big or missing files', async () => {
    const { FileHasher } = await import('./linux/hash.js');
    const { createHash } = await import('node:crypto');
    const dir = mkdtempSync(join(tmpdir(), 'vigil-hash-'));
    try {
      const f = join(dir, 'prog');
      writeFileSync(f, 'one');
      const h = new FileHasher({ maxBytes: 10 });
      expect(h.sha256(f)).toBe(createHash('sha256').update('one').digest('hex'));
      writeFileSync(f, 'two!');
      expect(h.sha256(f)).toBe(createHash('sha256').update('two!').digest('hex'));
      writeFileSync(f, 'x'.repeat(11));
      expect(h.sha256(f)).toBeUndefined();
      expect(h.sha256(join(dir, 'gone'))).toBeUndefined();
      expect(h.sha256(dir)).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
