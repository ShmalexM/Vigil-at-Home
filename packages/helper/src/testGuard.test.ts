import { afterEach, describe, expect, it, vi } from 'vitest';
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals } from './approval.js';
import { HelperClient, refuseInstalledHelperInTests, testRunFromEnv } from './client.js';
import { defaultPaths, linuxPaths, macPaths } from './config.js';
import { Executor } from './executor.js';
import { Journal } from './journal.js';
import { parseRequest } from './protocol.js';
import { realSystem } from './system.js';
import { FakeSystem } from './testing/fakeSystem.js';
import {
  ALLOW_REAL_ENFORCEMENT_ENV,
  enforcingRun,
  inTestContext,
  isEnforcing,
  refuseRealEnforcement,
} from './testGuard.js';

const TEST = { VITEST: 'true' };
const OPTED_IN = { ...TEST, [ALLOW_REAL_ENFORCEMENT_ENV]: '1' };

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('test context', () => {
  it('is Vitest, NODE_ENV=test, a test run id or the e2e flag', () => {
    expect(inTestContext({})).toBe(false);
    expect(inTestContext({ NODE_ENV: 'production' })).toBe(false);
    expect(inTestContext(TEST)).toBe(true);
    expect(inTestContext({ NODE_ENV: 'test' })).toBe(true);
    expect(inTestContext({ VIGIL_TEST_RUN_ID: 'e2e-1' })).toBe(true);
    expect(inTestContext({ VIGIL_E2E: '1' })).toBe(true);
  });

  it('refuses real enforcement in a test unless the run opts in with exactly 1', () => {
    expect(() => refuseRealEnforcement('a pf block', TEST)).toThrow(
      /refusing a pf block .*VIGIL_ALLOW_REAL_ENFORCEMENT=1/,
    );
    expect(() =>
      refuseRealEnforcement('a pf block', { ...TEST, [ALLOW_REAL_ENFORCEMENT_ENV]: 'yes' }),
    ).toThrow(/refusing/);
    expect(() => refuseRealEnforcement('a pf block', OPTED_IN)).not.toThrow();
    // The installed helper: no test markers, never refused.
    expect(() => refuseRealEnforcement('a pf block', {})).not.toThrow();
  });
});

describe('what counts as enforcing', () => {
  it('names containment, not releases or queries', () => {
    expect(isEnforcing({ kind: 'network.block', address: '192.0.2.1' })).toBe(true);
    expect(isEnforcing({ kind: 'process.suspend', pid: 5 })).toBe(true);
    expect(isEnforcing({ kind: 'process.kill', pid: 5 })).toBe(true);
    expect(isEnforcing({ kind: 'persistence.disable', path: '/x.plist' })).toBe(true);
    expect(isEnforcing({ kind: 'file.quarantine', path: '/x' })).toBe(true);
    expect(
      isEnforcing({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: 'a'.repeat(64),
        policy: 'block',
      }),
    ).toBe(true);
    expect(
      isEnforcing({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: 'a'.repeat(64),
        policy: 'allow',
      }),
    ).toBe(false);
    expect(isEnforcing({ kind: 'network.unblock', address: '192.0.2.1' })).toBe(false);
    expect(isEnforcing({ kind: 'process.resume', pid: 5 })).toBe(false);
    expect(isEnforcing({ kind: 'helper.status' })).toBe(false);
  });

  it('classifies the binary runs the helper makes', () => {
    const anchor = ['-a', 'com.apple/vigil', '-t', 'vigil_blocked', '-T'];
    expect(enforcingRun('pfctl', [...anchor, 'add', '192.0.2.1'])).toBe('a pf block');
    expect(enforcingRun('pfctl', ['-a', 'com.apple/vigil', '-f', '-'])).toBeDefined();
    expect(enforcingRun('pfctl', ['-E'])).toBeDefined();
    expect(enforcingRun('pfctl', ['-k', '192.0.2.1'])).toBeDefined();
    expect(enforcingRun('pfctl', [...anchor, 'delete', '192.0.2.1'])).toBeUndefined();
    expect(enforcingRun('pfctl', [...anchor, 'show'])).toBeUndefined();
    expect(enforcingRun('pfctl', ['-X', '123'])).toBeUndefined();
    expect(enforcingRun('launchctl', ['bootout', 'gui/501/com.evil'])).toBeDefined();
    expect(enforcingRun('launchctl', ['bootstrap', 'gui/501', '/x.plist'])).toBeUndefined();
    expect(enforcingRun('launchctl', ['print', 'gui/501/com.evil'])).toBeUndefined();
    expect(enforcingRun('santactl', ['rule', '--block'])).toBeDefined();
    expect(enforcingRun('santactl', ['sync'])).toBeUndefined();
    expect(enforcingRun('nft', ['add element inet vigil blocked4 { 192.0.2.1 }'])).toBeDefined();
    expect(enforcingRun('nft', ['list', 'table', 'inet', 'vigil'])).toBeUndefined();
    expect(enforcingRun('systemctl', ['--user', 'stop', 'evil.service'])).toBeDefined();
    expect(enforcingRun('systemctl', ['--user', 'start', 'evil.service'])).toBeUndefined();
    expect(enforcingRun('fagenrules', ['--load'])).toBeDefined();
    expect(enforcingRun('ps', ['-p', '1'])).toBeUndefined();
  });
});

describe('the real system in a test', () => {
  /** A stand-in pfctl that leaves a mark when it runs. */
  function markingBinary(): { bin: string; mark: string; dir: string } {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-guard-'));
    const mark = join(dir, 'ran');
    const bin = join(dir, 'pfctl');
    writeFileSync(bin, `#!/bin/sh\necho ran > '${mark}'\n`);
    chmodSync(bin, 0o755);
    return { bin, mark, dir };
  }

  it('refuses a pf block without running pfctl', async () => {
    const { bin, mark, dir } = markingBinary();
    try {
      const sys = realSystem({ pfctl: bin }, 'darwin', TEST);
      expect(sys.real).toBe(true);
      await expect(sys.run('pfctl', ['-T', 'add', '192.0.2.1'])).rejects.toMatchObject({
        code: 'refused',
      });
      expect(existsSync(mark)).toBe(false);
      // Reads still run.
      await sys.run('pfctl', ['-T', 'show']);
      expect(existsSync(mark)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('runs it when the run opts in', async () => {
    const { bin, mark, dir } = markingBinary();
    try {
      const sys = realSystem({ pfctl: bin }, 'darwin', OPTED_IN);
      expect((await sys.run('pfctl', ['-T', 'add', '192.0.2.1'])).code).toBe(0);
      expect(existsSync(mark)).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('refuses to pause or stop a process, and allows resuming one', async () => {
    const child = spawn('/bin/sleep', ['30'], { stdio: 'ignore' });
    try {
      const sys = realSystem(undefined, 'darwin', TEST);
      expect(() => sys.signal(child.pid!, 'SIGKILL')).toThrow(/refusing SIGKILL/);
      expect(() => sys.signal(child.pid!, 'SIGSTOP')).toThrow(/refusing SIGSTOP/);
      expect(child.exitCode).toBeNull();
      expect(() => sys.signal(child.pid!, 'SIGCONT')).not.toThrow();
    } finally {
      child.kill('SIGKILL');
    }
  });
});

describe('the executor on a real system in a test', () => {
  /** FakeSystem flagged as real: what the executor sees on the real machine. */
  class RealLooking extends FakeSystem {
    readonly real = true;
  }

  function executor(sys: FakeSystem): { ex: Executor; dir: string } {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-guard-'));
    const ex = new Executor({
      sys,
      journal: new Journal(join(dir, 'journal.json')),
      approvals: new Approvals({
        dir: join(dir, 'approvals'),
        requiredOwnerUid: process.getuid!(),
      }),
      rules: new RuleStore(join(dir, 'rules.json')),
      quarantine: { quarantineDir: join(dir, 'Quarantine') },
      syncPort: 47821,
    });
    return { ex, dir };
  }

  it('refuses containment and blocks nothing', async () => {
    const sys = new RealLooking();
    const { ex, dir } = executor(sys);
    try {
      await expect(ex.execute({ kind: 'network.block', address: '192.0.2.1' })).rejects.toThrow(
        /refusing network.block/,
      );
      sys.processes.set(4242, { path: '/Users/a/evil', started: 'Sat Sep 26 21:00:00 2026' });
      await expect(ex.execute({ kind: 'process.suspend', pid: 4242 })).rejects.toThrow(
        /refusing process.suspend/,
      );
      expect(sys.pfTable.size).toBe(0);
      expect(sys.signals).toEqual([]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('acts when the run opts in, and tags the journal with its run id', async () => {
    vi.stubEnv(ALLOW_REAL_ENFORCEMENT_ENV, '1');
    const sys = new RealLooking();
    const { ex, dir } = executor(sys);
    try {
      await ex.execute({ kind: 'network.block', address: '192.0.2.1' }, undefined, {
        testRun: 'e2e-run-1',
      });
      expect(sys.pfTable.has('192.0.2.1')).toBe(true);
      const journal = await ex.execute({ kind: 'helper.journal' });
      expect(journal).toMatchObject({
        kind: 'done',
        result: [{ kind: 'network.block', testRun: 'e2e-run-1' }],
      });
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leaves fakes alone: unit tests keep exercising containment', async () => {
    const sys = new FakeSystem();
    const { ex, dir } = executor(sys);
    try {
      await ex.execute({ kind: 'network.block', address: '192.0.2.1' });
      expect(sys.pfTable.has('192.0.2.1')).toBe(true);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('the test-run tag on requests', () => {
  it('is accepted on the envelope and passed on', () => {
    const req = parseRequest(
      JSON.stringify({ id: '1', command: { kind: 'helper.status' }, testRun: 'e2e-2026.10.17_a' }),
    );
    expect(req).toMatchObject({ testRun: 'e2e-2026.10.17_a' });
  });

  it('refuses anything but a short plain id', () => {
    for (const testRun of ['', 'a b', 'x'.repeat(65), '../x', 7]) {
      const req = parseRequest(
        JSON.stringify({ id: '1', command: { kind: 'helper.status' }, testRun }),
      );
      expect(req).toHaveProperty('error');
    }
  });

  it('comes from VIGIL_TEST_RUN_ID under the e2e harness, when that is a valid id', () => {
    const e2e = { VIGIL_E2E: '1' };
    expect(testRunFromEnv({ ...e2e, VIGIL_TEST_RUN_ID: 'e2e-1' })).toBe('e2e-1');
    expect(testRunFromEnv({ ...e2e, VIGIL_TEST_RUN_ID: 'not valid!' })).toBeUndefined();
    expect(testRunFromEnv(e2e)).toBeUndefined();
    // The CLI or the app outside the harness never tags, whatever the environment holds.
    expect(testRunFromEnv({ VIGIL_TEST_RUN_ID: 'e2e-1' })).toBeUndefined();
  });
});

describe('a test connecting to the installed helper', () => {
  it('is refused unless the run opted in', async () => {
    for (const socket of [macPaths().socket, linuxPaths().socket]) {
      expect(() => refuseInstalledHelperInTests(socket, TEST)).toThrow(
        /refusing to connect a test to the installed helper/,
      );
      expect(() => refuseInstalledHelperInTests(socket, OPTED_IN)).not.toThrow();
      // The app itself, outside any test.
      expect(() => refuseInstalledHelperInTests(socket, {})).not.toThrow();
    }
    // Any other socket (an isolated helper's) is fine.
    expect(() => refuseInstalledHelperInTests('/tmp/vigil-e2e-x/helper.sock', TEST)).not.toThrow();
    // Vitest is a test context: connect() refuses before opening the socket.
    await expect(
      HelperClient.connect(defaultPaths().socket, async () => false),
    ).rejects.toMatchObject({ code: 'refused' });
  });
});
