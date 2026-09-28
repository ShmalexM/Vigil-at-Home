import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore, type SensorEvent } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { HelperClient, HelperCallError, type Approver } from './client.js';
import { Executor, type ActionOutcome } from './executor.js';
import { Journal } from './journal.js';
import { HelperServer } from './server.js';
import { FakeSystem } from './testing/fakeSystem.js';

let root: string;
let sock: string;
let sys: FakeSystem;
let server: HelperServer;
let client: HelperClient;
let rules: RuleStore;
let approvalsDir: string;
let launchDir: string;
let approve: boolean;
let prompts: string[];

// Stands in for "osascript ... with administrator privileges": when the user
// approves, the root CLI writes the approval file.
const approver: Approver = async (nonce, prompt) => {
  prompts.push(prompt);
  if (approve) Approvals.writeApproval(approvalsDir, nonce);
  return approve;
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- loose JSON in tests
function rawCall(line: string): Promise<any> {
  return new Promise((resolve) => {
    const s = connect(sock);
    s.on('data', (d) => {
      resolve(JSON.parse(d.toString()));
      s.destroy();
    });
    s.write(line + '\n');
  });
}

beforeAll(async () => {
  root = mkdtempSync(join(tmpdir(), 'vigil-helper-'));
  sock = join(root, 'helper.sock');
  approvalsDir = join(root, 'approvals');
  launchDir = join(root, 'Library', 'LaunchAgents');
  mkdirSync(launchDir, { recursive: true });
  sys = new FakeSystem();
  rules = new RuleStore(join(root, 'rules.json'));
  const executor = new Executor({
    sys,
    journal: new Journal(join(root, 'journal.json')),
    approvals: new Approvals({ dir: approvalsDir, requiredOwnerUid: process.getuid!() }),
    rules,
    quarantine: { quarantineDir: join(root, 'Quarantine') },
    launchDirs: new RegExp('^' + launchDir.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '$'),
    syncPort: 47821,
    triggerSantaSync: async () => {
      await sys.run('santactl', ['sync']);
    },
  });
  server = new HelperServer({ socketPath: sock, executor });
  await server.listen();
  client = await HelperClient.connect(sock, approver);
});

afterAll(async () => {
  client.close();
  await server.close();
  rmSync(root, { recursive: true, force: true });
});

beforeEach(() => {
  approve = true;
  prompts = [];
  sys.signals.length = 0;
});

describe('helper over its socket', () => {
  it('creates the socket owner-only', () => {
    expect(statSync(sock).mode & 0o777).toBe(0o600);
  });

  it('pauses a process; resuming it needs the password', async () => {
    sys.processes.set(4242, {
      path: '/Users/a/Downloads/evil',
      started: 'Sat Sep 26 21:00:00 2026',
    });
    const out = await client.call<ActionOutcome>({
      kind: 'process.suspend',
      pid: 4242,
      path: '/Users/a/Downloads/evil',
    });
    expect(sys.signals).toEqual([{ pid: 4242, signal: 'SIGSTOP' }]);
    expect(out.undoable).toBe(true);

    approve = false;
    await expect(client.call({ kind: 'process.resume', pid: 4242 })).rejects.toThrow(
      'not approved',
    );
    expect(sys.signals).toHaveLength(1);
    expect(prompts[0]).toContain('paused /Users/a/Downloads/evil');

    approve = true;
    await client.call({ kind: 'process.resume', pid: 4242 });
    expect(sys.signals.at(-1)).toEqual({ pid: 4242, signal: 'SIGCONT' });
  });

  it('matches by start time too', async () => {
    const started = 'Sat Sep 26 21:05:00 2026';
    sys.processes.set(4300, { path: '/tmp/b', started });
    const t = Date.parse(started);
    await expect(
      client.call({ kind: 'process.suspend', pid: 4300, startTime: t + 5000 }),
    ).rejects.toMatchObject({ code: 'refused' });
    await client.call({ kind: 'process.suspend', pid: 4300, startTime: t + 400 });
    expect(sys.signals).toEqual([{ pid: 4300, signal: 'SIGSTOP' }]);
    await expect(client.call({ kind: 'process.suspend', pid: 4300 })).rejects.toMatchObject({
      code: 'invalid',
    });
  });

  it('does not resume a different process that reused the pid', async () => {
    sys.processes.set(5000, { path: '/tmp/a', started: 'T1' });
    await client.call({ kind: 'process.suspend', pid: 5000, path: '/tmp/a' });
    sys.processes.set(5000, { path: '/tmp/a', started: 'T2' });
    const out = await client.call<ActionOutcome>({ kind: 'process.resume', pid: 5000 });
    expect(out.summary).toContain('already exited');
    expect(sys.signals.map((s) => s.signal)).toEqual(['SIGSTOP']);
  });

  it('only resumes what it paused', async () => {
    sys.processes.set(5100, { path: '/tmp/c', started: 'T' });
    await expect(client.call({ kind: 'process.resume', pid: 5100 })).rejects.toMatchObject({
      code: 'not_found',
    });
    expect(prompts).toEqual([]);
  });

  it('refuses the wrong process, protected processes and missing ones', async () => {
    sys.processes.set(600, { path: '/tmp/real', started: 'T' });
    await expect(
      client.call({ kind: 'process.kill', pid: 600, path: '/tmp/other' }),
    ).rejects.toMatchObject({ code: 'refused' });
    const ws = '/System/Library/PrivateFrameworks/SkyLight.framework/Resources/WindowServer';
    sys.processes.set(601, { path: ws, started: 'T' });
    await expect(
      client.call({ kind: 'process.suspend', pid: 601, path: ws }),
    ).rejects.toMatchObject({ code: 'refused' });
    await expect(
      client.call({ kind: 'process.kill', pid: 9999, path: '/tmp/x' }),
    ).rejects.toMatchObject({ code: 'not_found' });
    expect(sys.signals).toEqual([]);
  });

  it('kills a process for good', async () => {
    sys.processes.set(700, { path: '/tmp/miner', started: 'T' });
    const out = await client.call<ActionOutcome>({
      kind: 'process.kill',
      pid: 700,
      path: '/tmp/miner',
    });
    expect(out.undoable).toBe(false);
    expect(sys.signals).toEqual([{ pid: 700, signal: 'SIGKILL' }]);
  });

  it('blocks and unblocks addresses and ranges in pf', async () => {
    await client.call({ kind: 'network.block', address: '203.0.113.9' });
    expect(sys.pfTable.has('203.0.113.9')).toBe(true);
    const load = sys.runs.find((r) => r.bin === 'pfctl' && r.args.includes('-f'));
    expect(load?.args).toEqual(['-a', 'com.apple/vigil', '-f', '-']);
    expect(load?.input).toContain('block drop out quick from any to <vigil_blocked>');
    const a = await client.call<ActionOutcome>({ kind: 'network.block', address: '203.0.113.9' });
    const b = await client.call<ActionOutcome>({ kind: 'network.block', address: '203.0.113.9' });
    expect(b.actionId).toBe(a.actionId);
    await client.call({ kind: 'network.block', address: '198.51.100.0/24' });
    expect((await client.call<{ firewall: string[] }>({ kind: 'helper.status' })).firewall).toEqual(
      ['203.0.113.9', '198.51.100.0/24'],
    );
    await client.call({ kind: 'network.unblock', address: '203.0.113.9' });
    await client.call({ kind: 'network.unblock', address: '198.51.100.0/24' });
    expect(sys.pfTable.size).toBe(0);
  });

  it('refuses local addresses, huge ranges and ports', async () => {
    for (const address of [
      '127.0.0.1',
      '::1',
      '0.0.0.0',
      '169.254.1.1',
      '224.0.0.1',
      'fe80::1',
      'example.com',
      '0.0.0.0/0',
      '10.0.0.0/4',
      '1.2.3.4/33',
    ]) {
      await expect(client.call({ kind: 'network.block', address })).rejects.toBeInstanceOf(
        HelperCallError,
      );
    }
    await expect(
      client.call({ kind: 'network.block', address: '203.0.113.10', port: 443 }),
    ).rejects.toMatchObject({ code: 'invalid' });
  });

  it('quarantines a file and restores it by quarantine id', async () => {
    const dl = join(root, 'Downloads');
    mkdirSync(dl, { recursive: true });
    const file = join(dl, 'payload.sh');
    writeFileSync(file, '#!/bin/sh\necho pwned\n', { mode: 0o755 });
    const out = await client.call<ActionOutcome>({ kind: 'file.quarantine', path: file });
    expect(existsSync(file)).toBe(false);
    const stored = join(root, 'Quarantine', out.quarantineId!, 'payload.sh');
    expect(statSync(stored).mode & 0o777).toBe(0);
    await client.call({ kind: 'file.restore', quarantineId: out.quarantineId! });
    expect(readFileSync(file, 'utf8')).toContain('pwned');
    expect(statSync(file).mode & 0o777).toBe(0o755);
    await expect(
      client.call({ kind: 'file.restore', quarantineId: out.quarantineId! }),
    ).rejects.toMatchObject({ code: 'not_found' });
  });

  it('will not overwrite a new file on restore', async () => {
    const file = join(root, 'Downloads', 'again.bin');
    writeFileSync(file, 'one');
    const out = await client.call<ActionOutcome>({ kind: 'file.quarantine', path: file });
    writeFileSync(file, 'two');
    await expect(
      client.call({ kind: 'file.restore', quarantineId: out.quarantineId! }),
    ).rejects.toMatchObject({ code: 'refused' });
    expect(readFileSync(file, 'utf8')).toBe('two');
  });

  it('refuses protected, relative and symlink-redirected paths', async () => {
    for (const path of [
      '/System/Library/Kernels/kernel',
      '/usr/bin/curl',
      '/Applications',
      '/Users/alex',
      'rel/path',
      '/tmp/../etc/x',
    ]) {
      await expect(client.call({ kind: 'file.quarantine', path })).rejects.toBeInstanceOf(
        HelperCallError,
      );
    }
    // A symlinked folder pointing into Vigil's own quarantine must not work.
    mkdirSync(join(root, 'Quarantine'), { recursive: true });
    symlinkSync(join(root, 'Quarantine'), join(root, 'sneaky'));
    await expect(
      client.call({ kind: 'file.quarantine', path: join(root, 'sneaky', 'x') }),
    ).rejects.toMatchObject({ code: 'refused' });
  });

  it('disables a launch agent and re-enables it', async () => {
    const plist = join(launchDir, 'com.evil.agent.plist');
    writeFileSync(plist, '<plist/>');
    sys.labels.set(plist, 'com.evil.agent');
    // The helper works on the resolved path (tmpdir is a symlink on macOS).
    sys.labels.set(realpathSync(plist), 'com.evil.agent');
    const target = `gui/${statSync(plist).uid}/com.evil.agent`;
    sys.loaded.add(target);
    const out = await client.call<ActionOutcome>({ kind: 'persistence.disable', path: plist });
    expect(existsSync(plist)).toBe(false);
    expect(sys.loaded.has(target)).toBe(false);
    expect(out.summary).toContain('com.evil.agent');
    await client.call({ kind: 'persistence.enable', path: plist });
    expect(existsSync(plist)).toBe(true);
    expect(sys.loaded.has(target)).toBe(true);
  });

  it('only disables plists in launch folders', async () => {
    const f = join(root, 'Downloads', 'x.plist');
    writeFileSync(f, '<plist/>');
    await expect(client.call({ kind: 'persistence.disable', path: f })).rejects.toMatchObject({
      code: 'invalid',
    });
  });

  it('Santa block rules apply at once; allow and removal need the password', async () => {
    const sha = 'e'.repeat(64);
    await client.call({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: sha,
      policy: 'block',
      message: 'Known stealer',
    });
    expect(rules.get('BINARY', sha)?.rule).toEqual({
      identifier: sha,
      policy: 'BLOCKLIST',
      rule_type: 'BINARY',
      custom_msg: 'Known stealer',
    });
    expect(sys.runs.at(-1)).toMatchObject({ bin: 'santactl', args: ['sync'] });
    expect(prompts).toEqual([]);

    await client.call({
      kind: 'santa.rule.set',
      ruleType: 'binary',
      identifier: sha,
      policy: 'allow',
    });
    expect(prompts).toHaveLength(1);
    expect(rules.get('BINARY', sha)?.rule.policy).toBe('ALLOWLIST');

    await client.call({ kind: 'santa.rule.remove', ruleType: 'binary', identifier: sha });
    expect(prompts).toHaveLength(2);
    expect(rules.get('BINARY', sha)).toBeUndefined();

    await expect(
      client.call({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: 'nope',
        policy: 'block',
      }),
    ).rejects.toMatchObject({ code: 'invalid' });
  });

  it('rejects an approval replayed for the same release', async () => {
    const out = await client.call<ActionOutcome>({
      kind: 'network.block',
      address: '198.51.100.7',
    });
    expect(out.undoable).toBe(true);
    let captured = '';
    const other = await HelperClient.connect(sock, async (nonce) => {
      captured = nonce;
      Approvals.writeApproval(approvalsDir, nonce);
      return true;
    });
    await other.call({ kind: 'network.unblock', address: '198.51.100.7' });
    other.close();
    await client.call({ kind: 'network.block', address: '198.51.100.7' });
    const replay = await rawCall(
      JSON.stringify({
        id: 'x',
        command: { kind: 'network.unblock', address: '198.51.100.7' },
        approval: captured,
      }),
    );
    expect(replay.needsApproval).toBe(true);
    expect(sys.pfTable.has('198.51.100.7')).toBe(true);
  });

  it('streams sensor events to subscribers, with replay', async () => {
    const got: SensorEvent[] = [];
    const ev = (id: string): SensorEvent => ({
      id,
      ts: 1,
      source: 'santa',
      kind: 'process.exec',
      process: { pid: 1, path: '/x' },
    });
    server.publish(ev('before-1'));
    server.publish(ev('before-2'));
    const sub = await HelperClient.connect(sock, approver);
    sub.onEvent((e) => got.push(e));
    await sub.subscribe('before-1');
    server.publish(ev('after'));
    await new Promise((r) => setTimeout(r, 50));
    expect(got.map((e) => e.id)).toEqual(['before-2', 'after']);
    sub.close();
  });

  it('hands out the Santa profile and the journal', async () => {
    const r = await client.call<{ mobileconfig: string }>({ kind: 'santa.profile' });
    expect(r.mobileconfig).toContain('https://127.0.0.1:47821/');
    const j = await client.call<{ kind: string }[]>({ kind: 'helper.journal', limit: 3 });
    expect(j).toHaveLength(3);
  });

  it('answers bad input with an error, not a crash', async () => {
    const reply = await rawCall('{"id":"q","command":{"kind":"shell","cmd":"id"}}');
    expect(reply).toMatchObject({ id: 'q', ok: false, code: 'invalid' });
    expect((await client.call<{ pid: number }>({ kind: 'helper.status' })).pid).toBe(process.pid);
  });
});
