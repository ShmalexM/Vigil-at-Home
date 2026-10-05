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
import { appendFileSync, copyFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
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

describe.skipIf(!run)('Vigil on real Linux, app closed', () => {
  const dir = mkdtempSync(join(tmpdir(), 'vigil-flow-'));
  const paths = { ...linuxPaths(join(dir, 'state')), socket: join(dir, 'helper.sock') };
  const children: ChildProcess[] = [];
  const seen: Array<{ e: SensorEvent; ran: HelperRan[] }> = [];
  const logs: string[] = [];
  let stop: (() => Promise<void>) | undefined;
  let client: HelperClient | undefined;
  const fapolicyd = existsSync('/usr/sbin/fapolicyd');

  // A copy of sleep with a few random bytes added: runs the same, but has a
  // hash of its own, so blocking it never blocks the real sleep.
  const evil = join(dir, 'evil-miner');
  copyFileSync('/usr/bin/sleep', evil);
  appendFileSync(evil, randomBytes(64));
  spawnSync('chmod', ['755', evil]);
  const evilHash = createHash('sha256').update(readFileSync(evil)).digest('hex');

  beforeAll(async () => {
    expect(
      existsSync(LINUX_BINARIES.osqueryd),
      'osquery must be installed (setup installs it earlier in the same job)',
    ).toBe(true);
    if (fapolicyd) expect(systemctl('enable', '--now', 'fapolicyd').status).toBe(0);

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
    const out = await client.call<{ needLists: string[] }>({
      kind: 'detection.sync',
      rules: set.rules,
      exceptions: [],
      selfPaths: [],
      lists: Object.fromEntries(Object.entries(lists).map(([n, e]) => [n, listDigest(e)])),
    });
    for (const name of out.needLists) {
      await client.call({
        kind: 'detection.list.set',
        list: name,
        digest: listDigest(lists[name]!),
        part: 0,
        parts: 1,
        entries: lists[name]!,
      });
    }
    // Only to see what happened; the helper blocks whether or not anyone listens.
    client.onEvent((e, ran) => {
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
    const status = await client.call<{ helperRules?: { rules: number } }>({
      kind: 'helper.status',
    });
    expect(status.helperRules?.rules ?? 0).toBeGreaterThan(0);
  }, 180_000);

  afterAll(async () => {
    for (const c of children) c.kill('SIGKILL');
    client?.close();
    await stop?.();
    spawnSync(LINUX_BINARIES.nft, ['delete', 'table', 'inet', 'vigil']);
    rmSync('/etc/fapolicyd/rules.d/05-vigil.rules', { force: true });
    if (fapolicyd) {
      spawnSync('/usr/sbin/fagenrules', ['--load']);
      systemctl('disable', '--now', 'fapolicyd');
    }
    await removeLinuxOsquery(sys);
    rmSync(dir, { recursive: true, force: true });
    if (logs.length) console.log(`helper log:\n${logs.join('\n')}`);
  }, 120_000);

  it('kills known malware when it starts, and refuses to run it again', async () => {
    const t0 = Date.now();
    const child = spawn(evil, ['600'], { stdio: 'ignore' });
    children.push(child);
    const pid = child.pid!;
    // osquery's process events arrive every 5 seconds.
    const killed = await waitUntil(() => !alive(pid), 60_000);
    const ran = seen.find((s) => s.e.kind === 'process.exec' && s.e.process.pid === pid)?.ran;
    expect(killed, `still running; helper ran ${JSON.stringify(ran)}\n${logs.join('\n')}`).toBe(
      true,
    );
    console.log(`launch to kill: ${Date.now() - t0} ms`);
    expect(ran?.map((r) => r.ruleId)).toContain('known-bad-hash');
    expect(ran?.find((r) => r.action.kind === 'process.kill')?.error).toBeUndefined();

    // The hash is now blocked before launch.
    const status = await client!.call<{ fapolicyd?: { blocked: number; lastError?: string } }>({
      kind: 'helper.status',
    });
    expect(status.fapolicyd?.blocked).toBe(1);
    if (fapolicyd) {
      expect(status.fapolicyd?.lastError).toBeUndefined();
      const again = spawnSync(evil, ['0']);
      expect(again.error ?? again.status, 'fapolicyd let the blocked program start').not.toBe(0);
      // The real sleep, with a different hash, still runs.
      expect(spawnSync('/usr/bin/sleep', ['0']).status).toBe(0);
    }
  }, 90_000);

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
