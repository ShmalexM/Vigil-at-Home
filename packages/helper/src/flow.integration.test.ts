// End-to-end check of Vigil's response path on real Linux, with the app
// closed: the helper gets the blocking rules and threat lists the way the app
// hands them over, then real osquery sees harmless stand-ins for threats and
// the helper stops them on its own. The Linux counterpart of the Mac flow
// check (apps/desktop/e2e/flow.e2e.mjs, scenario 7).
//
// Run as root with VIGIL_LINUX_INTEGRATION=1 on a machine with osquery and
// systemd (CI's linux job; setup's own test installs osquery and fapolicyd
// first). It writes /etc/osquery, starts osqueryd and fapolicyd, and blocks
// 1.1.1.1 for a few seconds, so it is skipped everywhere else.
//
//   1. Known malware starts: a renamed copy of sleep whose hash is on the
//      threat list. osquery's eBPF events report the launch, the helper
//      hashes it, kills it and blocks the hash with fapolicyd, and the next
//      launch is refused before it runs.
//   2. Beacon to a command server: a real connection to an address on the
//      threat list, seen by osquery. The helper blocks the address with
//      nftables; then the user undoes it with the admin password.

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import {
  appendFileSync,
  closeSync,
  copyFileSync,
  existsSync,
  mkdtempSync,
  openSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { builtinRulesFor, type DetectionRule } from '@vigil/detection';
import { fastPathRules, listDigest } from '@vigil/detection/fastpath';
import { Approvals } from './approval.js';
import { HelperClient } from './client.js';
import { linuxPaths } from './config.js';
import { runDaemon } from './daemon.js';
import { removeLinuxOsquery } from './linuxOsquery.js';
import { removePinStore } from './pinStore.js';
import { LINUX_BINARIES, realSystem } from './system.js';
import type { SensorEvent } from '@vigil/core';
import type { HelperRan } from './fastpath.js';

const run =
  process.env.VIGIL_LINUX_INTEGRATION === '1' &&
  process.platform === 'linux' &&
  process.getuid?.() === 0;

const sys = realSystem(LINUX_BINARIES, 'linux');
const C2 = '1.1.1.1';
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

async function waitUntil(test: () => boolean | Promise<boolean>, ms: number, every = 250) {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await test()) return true;
    await sleep(every);
  }
  return test();
}

function reachable(host: string, port: number): Promise<boolean> {
  return new Promise((resolve) => {
    const s = connect({ host, port, timeout: 3000 });
    s.once('connect', () => {
      s.destroy();
      resolve(true);
    });
    s.once('timeout', () => {
      s.destroy();
      resolve(false);
    });
    s.once('error', () => resolve(false));
  });
}

function nftBlocks(address: string): boolean {
  const r = spawnSync(LINUX_BINARIES.nft, ['list', 'table', 'inet', 'vigil'], { encoding: 'utf8' });
  return r.status === 0 && r.stdout.includes(`vigil:${address}`);
}

const alive = (pid: number) => existsSync(`/proc/${pid}`) && !isZombie(pid);
function isZombie(pid: number): boolean {
  try {
    return readFileSync(`/proc/${pid}/stat`, 'utf8').split(') ')[1]![0] === 'Z';
  } catch {
    return false;
  }
}

const systemctl = (...args: string[]) => spawnSync('systemctl', args, { encoding: 'utf8' });

/** What osquery itself said, for a failure message: is eBPF up, are launches logged? */
function osqueryDiagnosis(): string {
  const sh = (cmd: string) =>
    spawnSync('sh', ['-c', cmd], { encoding: 'utf8' }).stdout.trim() || '(nothing)';
  return [
    `osquery about eBPF:\n${sh("grep -ih 'bpf' /var/log/osquery/osqueryd.* 2>/dev/null | tail -n 20")}`,
    `osqueryd journal:\n${sh('journalctl -u osqueryd --no-pager -n 30 2>/dev/null')}`,
    `launch rows logged: ${sh('grep -c vigil_process_events /var/log/osquery/osqueryd.results.log 2>/dev/null')}`,
    `last launch row:\n${sh('grep vigil_process_events /var/log/osquery/osqueryd.results.log 2>/dev/null | tail -n 1 | cut -c1-600')}`,
  ].join('\n');
}

/**
 * A second osqueryd in the foreground with eBPF on, verbose, and one query
 * of raw launch rows: shows whether eBPF launch events work on this machine
 * at all, and what their rows look like.
 */
async function bpfProbe(): Promise<string> {
  const d = mkdtempSync(join(tmpdir(), 'vigil-bpf-probe-'));
  const query = 'SELECT syscall, exit_code, probe_error, path FROM bpf_process_events;';
  writeFileSync(join(d, 'conf'), JSON.stringify({ schedule: { probe: { query, interval: 2 } } }));
  const p = spawn(
    LINUX_BINARIES.osqueryd,
    [
      `--pidfile=${join(d, 'pid')}`,
      `--database_path=${join(d, 'db')}`,
      `--logger_path=${d}`,
      `--config_path=${join(d, 'conf')}`,
      '--disable_extensions',
      '--disable_watchdog',
      '--disable_events=false',
      '--enable_bpf_events=true',
      '--disable_audit=true',
      '--enable_file_events=false',
      '--verbose',
    ],
    { stdio: ['ignore', 'pipe', 'pipe'] },
  );
  let out = '';
  p.stdout.on('data', (b: Buffer) => (out += b.toString()));
  p.stderr.on('data', (b: Buffer) => (out += b.toString()));
  await sleep(8000);
  for (let i = 0; i < 3; i++) spawnSync('/bin/true');
  await sleep(6000);
  p.kill('SIGKILL');
  let results: string;
  try {
    results = readFileSync(join(d, 'osqueryd.results.log'), 'utf8');
  } catch {
    results = '(no results log)';
  }
  rmSync(d, { recursive: true, force: true });
  const lines = out
    .split('\n')
    .filter((l) => /bpf|publisher|error|fail|memlock/i.test(l) && !l.includes('scheduler.cpp'));
  return `${lines.slice(-25).join('\n')}\nprobe rows: ${results.split('\n').filter(Boolean).length}\n${results.slice(-1500)}`;
}

/**
 * Why fapolicyd let a blocked program run: its state and rules, then
 * whether it refuses the program after a while, or after a restart.
 */
async function fapolicydDiagnosis(program: string): Promise<string> {
  const sh = (cmd: string) => {
    const r = spawnSync('sh', ['-c', cmd], { encoding: 'utf8' });
    return `${r.stdout}${r.stderr}`.trim() || '(nothing)';
  };
  // Time-limited: a launch waits on fapolicyd's answer.
  const runs = () => spawnSync(program, ['0'], { timeout: 10_000 }).status === 0;
  const out = [
    'fapolicyd let the blocked program start',
    `active: ${sh('systemctl is-active fapolicyd')}`,
    `compiled rules:\n${sh('cut -c1-120 /etc/fapolicyd/compiled.rules')}`,
    `loaded rules:\n${sh('fapolicyd-cli --list 2>&1 | cut -c1-120')}`,
    `status:\n${sh('fapolicyd-cli --check-status 2>&1 | head -n 30')}`,
    `watch_fs:\n${sh('fapolicyd-cli --check-watch_fs 2>&1 | tail -n 5')}`,
    `mount: ${sh(`findmnt -no TARGET,FSTYPE -T ${program}`)}`,
    `journal:\n${sh('journalctl -u fapolicyd --no-pager -n 25 2>&1')}`,
  ];
  out.push(`kernel: ${sh('uname -r')}`);
  out.push(
    `marks: ${sh("journalctl -u fapolicyd --no-pager 2>&1 | grep -iE 'EXEC_PERM|fanotify|mark' | tail -n 5")}`,
  );
  // fapolicyd in the foreground with every decision logged, hash included,
  // while the program starts once more.
  const conf = '/etc/fapolicyd/fapolicyd.conf';
  const log = join(tmpdir(), 'vigil-fapolicyd-debug.log');
  sh(
    `systemctl kill --signal=SIGKILL fapolicyd; systemctl stop fapolicyd; cp ${conf} ${conf}.flow`,
  );
  sh(
    `sed -i 's/^syslog_format.*/syslog_format = rule,dec,perm,pid,exe,:,path,ftype,sha256hash/' ${conf}`,
  );
  // Its log goes to a file, not a pipe: while a launch below blocks this
  // process, nothing would read a pipe, and fapolicyd would stall writing
  // to it with that very launch waiting on its answer.
  const fd = openSync(log, 'w');
  const d = spawn('fapolicyd', ['--debug'], { stdio: ['ignore', fd, fd] });
  closeSync(fd);
  await sleep(15_000);
  out.push(`under --debug, the program ${runs() ? 'still runs' : 'is refused'}`);
  await sleep(2000);
  d.kill('SIGKILL');
  sh(`mv ${conf}.flow ${conf}`);
  const debug = readFileSync(log, 'utf8');
  rmSync(log, { force: true });
  const name = program.split('/').pop()!;
  const lines = debug.split('\n');
  out.push(
    `debug log (${lines.length} lines):\n` +
      lines
        .filter((l) => /OPEN_EXEC|mark|Loaded|rule|error|fail/i.test(l) && !l.includes('dec=allow'))
        .slice(0, 15)
        .join('\n') +
      '\n...\n' +
      lines
        .filter((l) => l.includes(name))
        .slice(-6)
        .join('\n'),
  );
  return out.join('\n');
}

describe.skipIf(!run)('Vigil on real Linux, app closed', () => {
  // Made in beforeAll: the body of a skipped describe still runs on every OS.
  let dir = '';
  let paths: ReturnType<typeof linuxPaths> = linuxPaths();
  let evil = '';
  let evilHash = '';
  const children: ChildProcess[] = [];
  const seen: Array<{ e: SensorEvent; ran: HelperRan[] }> = [];
  let launchesSeen = 0;
  const logs: string[] = [];
  let stop: (() => Promise<void>) | undefined;
  let client: HelperClient | undefined;
  const fapolicyd = existsSync('/usr/sbin/fapolicyd');

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'vigil-flow-'));
    paths = { ...linuxPaths(join(dir, 'state')), socket: join(dir, 'helper.sock') };
    // A copy of sleep with a few random bytes added: runs the same, but has a
    // hash of its own, so blocking it never blocks the real sleep.
    evil = join(dir, 'evil-miner');
    copyFileSync('/usr/bin/sleep', evil);
    appendFileSync(evil, randomBytes(64));
    spawnSync('chmod', ['755', evil]);
    evilHash = createHash('sha256').update(readFileSync(evil)).digest('hex');

    expect(
      existsSync(LINUX_BINARIES.osqueryd),
      'osquery must be installed (setup installs it earlier in the same job)',
    ).toBe(true);
    if (fapolicyd) {
      expect(systemctl('enable', '--now', 'fapolicyd').status).toBe(0);
      // fapolicyd enforces nothing until it has loaded its trust database,
      // and answers no status request until then.
      const ready = await waitUntil(
        () => spawnSync('fapolicyd-cli', ['--check-status'], { timeout: 15_000 }).status === 0,
        90_000,
        3000,
      );
      const log = spawnSync('journalctl', ['-u', 'fapolicyd', '--no-pager', '-n', '8'], {
        encoding: 'utf8',
      }).stdout;
      expect(ready, `fapolicyd isn't enforcing yet:\n${log}`).toBe(true);
    }

    stop = await runDaemon({
      paths,
      sys,
      approvalOwnerUid: 0,
      log: (m) => logs.push(m),
    });

    // Hand over the rules and lists the way the app does (helper.ts syncRules).
    const rules = builtinRulesFor('linux') as DetectionRule[];
    const set = fastPathRules(rules.map((r) => ({ ...r, effectiveMode: r.mode })));
    const lists: Record<string, string[]> = Object.fromEntries(set.lists.map((l) => [l, []]));
    lists['known_bad_sha256'] = [evilHash];
    lists['known_bad_ips'] = [C2];
    const approver = async (nonce: string, _prompt: string, also: string[] = []) => {
      // Stands in for the password dialog, which runs `vigil-helper approve` as root.
      for (const n of [nonce, ...also]) Approvals.writeApproval(paths.approvalsDir, n);
      return true;
    };
    client = await HelperClient.connect(paths.socket, approver);
    // Rules and the lists they read go in as one command.
    await client.call({
      kind: 'detection.sync',
      rules: set.rules,
      exceptions: [],
      selfPaths: [],
      lists: Object.fromEntries(Object.entries(lists).map(([n, e]) => [n, listDigest(e)])),
      entries: lists,
    });
    // Only to see what happened; the helper blocks whether or not anyone listens.
    client.onEvent((e, ran) => {
      if (e.kind === 'process.exec') launchesSeen++;
      if (ran.length) seen.push({ e, ran });
    });
    await client.subscribe();

    // osquery started by the helper, with Vigil's queries, and reporting.
    const up = await waitUntil(
      () =>
        systemctl('is-active', '--quiet', 'osqueryd').status === 0 ||
        spawnSync('pgrep', ['-x', 'osqueryd']).status === 0,
      60_000,
      1000,
    );
    expect(up, logs.join('\n')).toBe(true);
    // osqueryd is up a few seconds before its eBPF probes are: a launch in
    // between is never reported. Wait until a harmless launch comes through.
    const reporting = await waitUntil(
      () => {
        spawnSync('/bin/true');
        return launchesSeen > 0;
      },
      90_000,
      2000,
    );
    expect(reporting, `osquery reports no launches\n${osqueryDiagnosis()}`).toBe(true);
    const status = await client.call<{ helperRules?: { rules: number } }>({
      kind: 'helper.status',
    });
    expect(status.helperRules?.rules ?? 0).toBeGreaterThan(0);
  }, 300_000);

  afterAll(async () => {
    for (const c of children) c.kill('SIGKILL');
    client?.close();
    if (logs.length) console.log(`helper log:\n${logs.join('\n')}`);
    // Only put back what this test's helper changed: if it never started,
    // another test may be using the same nft table.
    if (!stop) {
      if (dir) {
        await removePinStore(sys, paths.appPinDir, paths.appPin);
        rmSync(dir, { recursive: true, force: true });
      }
      return;
    }
    await stop();
    spawnSync(LINUX_BINARIES.nft, ['delete', 'table', 'inet', 'vigil']);
    rmSync('/etc/fapolicyd/rules.d/05-vigil.rules', { force: true });
    if (fapolicyd) {
      spawnSync('/usr/sbin/fagenrules', ['--load']);
      systemctl('disable', '--now', 'fapolicyd');
    }
    await removeLinuxOsquery(sys);
    // The pin files are immutable; remove them the way uninstall does.
    await removePinStore(sys, paths.appPinDir, paths.appPin);
    rmSync(dir, { recursive: true, force: true });
  }, 120_000);

  it('kills known malware when it starts, and refuses to run it again', async () => {
    const t0 = Date.now();
    const child = spawn(evil, ['600'], { stdio: 'ignore' });
    children.push(child);
    const pid = child.pid!;
    // osquery's process events arrive every 5 seconds.
    const killed = await waitUntil(() => !alive(pid), 60_000);
    // The kill comes first; the report of it reaches this client just after.
    const report = () => seen.find((s) => s.e.kind === 'process.exec' && s.e.process.pid === pid);
    if (killed) await waitUntil(() => !!report(), 10_000, 100);
    const ran = report()?.ran;
    expect(
      killed,
      `still running; helper ran ${JSON.stringify(ran)}; launches seen: ${launchesSeen}\n` +
        `${logs.join('\n')}\n${osqueryDiagnosis()}\nosquery eBPF probe:\n${killed ? '' : await bpfProbe()}`,
    ).toBe(true);
    console.log(`launch to kill: ${Date.now() - t0} ms`);
    expect(ran?.map((r) => r.ruleId)).toContain('known-bad-hash');
    expect(ran?.find((r) => r.action.kind === 'process.kill')?.error).toBeUndefined();

    // The hash is now blocked before launch.
    const status = await client!.call<{
      fapolicyd?: { blocked: number; lastError: string | null };
    }>({
      kind: 'helper.status',
    });
    expect(status.fapolicyd?.blocked).toBe(1);
    if (fapolicyd) {
      expect(status.fapolicyd?.lastError ?? null).toBeNull();
      const again = spawnSync(evil, ['0'], { timeout: 10_000 });
      const refused = again.error !== undefined || again.status !== 0;
      expect(refused, refused ? '' : await fapolicydDiagnosis(evil)).toBe(true);
      // The real sleep, with a different hash, still runs.
      expect(spawnSync('/usr/bin/sleep', ['0'], { timeout: 10_000 }).status).toBe(0);
    }
  }, 240_000);

  it('blocks a beacon to a command server, and the user can undo it', async () => {
    expect(await reachable(C2, 443)).toBe(true);
    const t0 = Date.now();
    // A long-lived connection, so osquery's 30-second socket snapshot catches it.
    const beacon = spawn(
      process.execPath,
      [
        '-e',
        `const net=require('node:net');const go=()=>{const s=net.connect(443,'${C2}');s.on('error',()=>{});s.setTimeout(60000,()=>s.destroy())};go();setInterval(go,2000)`,
      ],
      { stdio: 'ignore' },
    );
    children.push(beacon);
    const blocked = await waitUntil(() => nftBlocks(C2), 100_000, 500);
    expect(blocked, logs.join('\n')).toBe(true);
    console.log(`connect to block: ${Date.now() - t0} ms`);
    expect(await reachable(C2, 443)).toBe(false);
    beacon.kill('SIGKILL');

    // Undo, as from the alert's page: a release, so it takes the admin password.
    await client!.call({ kind: 'network.unblock', address: C2 });
    expect(nftBlocks(C2)).toBe(false);
    expect(await reachable(C2, 443)).toBe(true);
  }, 150_000);
});
