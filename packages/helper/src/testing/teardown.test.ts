import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { HelperClient } from '../client.js';
import { defaultPaths } from '../config.js';
import type { JournalEntry } from '../journal.js';
import { startIsolatedHelper, type IsolatedHelper } from './isolatedHelper.js';
import { releaseFor, TeardownError, teardownTestRun } from './teardown.js';

let helper: IsolatedHelper;
let approve = true;

beforeAll(async () => {
  helper = await startIsolatedHelper();
});

afterAll(async () => {
  await helper?.stop();
});

/** A connection as a test run (tagged) or as the teardown and the user's app (untagged). */
const connect = (testRun?: string) =>
  HelperClient.connect(
    helper.socket,
    helper.approver(() => approve),
    testRun,
  );

describe('the isolated helper', () => {
  it('lives in its own temporary folder, never the installed helper’s', () => {
    const real = defaultPaths();
    expect(helper.socket).not.toBe(real.socket);
    expect(helper.paths.approvalsDir).not.toBe(real.approvalsDir);
    expect(helper.paths.journal.startsWith(helper.root)).toBe(true);
    expect(helper.root.includes(tmpdir().replace(/^\/private/, ''))).toBe(true);
    expect(existsSync(helper.socket)).toBe(true);
  });

  it('acts on the fake system only', async () => {
    const c = await connect();
    try {
      await c.call({ kind: 'network.block', address: '198.51.100.9' });
      expect(helper.sys.pfTable.has('198.51.100.9')).toBe(true);
      expect(helper.sys.runs.some((r) => r.bin === 'pfctl')).toBe(true);
      await c.call({ kind: 'network.unblock', address: '198.51.100.9' });
      expect(helper.sys.pfTable.has('198.51.100.9')).toBe(false);
    } finally {
      c.close();
    }
  });
});

describe('teardown of an opted-in run', () => {
  it('undoes everything the run left in force and nothing else', async () => {
    approve = true;
    const run = await connect('e2e-run-a');
    const user = await connect();
    try {
      helper.sys.processes.set(4242, {
        path: '/Users/a/Downloads/evil',
        started: 'Sat Sep 26 21:00:00 2026',
      });
      await run.call({ kind: 'process.suspend', pid: 4242, path: '/Users/a/Downloads/evil' });
      await run.call({ kind: 'network.block', address: '192.0.2.1' });
      // The run hands the helper rules, as the app does on connecting.
      await run.call({ kind: 'detection.sync', rules: [], exceptions: [], lists: {} });
      // Something the user blocked themselves while the run went on.
      await user.call({ kind: 'network.block', address: '192.0.2.2' });

      const journal = JSON.parse(readFileSync(helper.paths.journal, 'utf8')) as {
        entries: JournalEntry[];
      };
      const tags = journal.entries.map((e) => [e.kind, e.testRun ?? null]);
      expect(tags).toEqual(
        expect.arrayContaining([
          ['process.suspend', 'e2e-run-a'],
          ['network.block', 'e2e-run-a'],
          ['network.block', null],
        ]),
      );
      expect(await user.call({ kind: 'detection.status' })).toMatchObject({
        testRun: 'e2e-run-a',
      });

      const report = await teardownTestRun(user, 'e2e-run-a');
      expect(report.undone).toHaveLength(2);
      expect(report.clearedRules).toBe(true);
      expect([...helper.sys.pfTable]).toEqual(['192.0.2.2']);
      expect(helper.sys.signals.at(-1)).toEqual({ pid: 4242, signal: 'SIGCONT' });
      expect(await user.call({ kind: 'detection.status' })).toMatchObject({ testRun: null });

      // Nothing left: a second teardown has nothing to do.
      expect(await teardownTestRun(user, 'e2e-run-a')).toMatchObject({
        undone: [],
        failed: [],
        clearedRules: false,
      });
      await user.call({ kind: 'network.unblock', address: '192.0.2.2' });
    } finally {
      run.close();
      user.close();
    }
  });

  it('fails loudly when it cannot undo something', async () => {
    approve = true;
    const run = await connect('e2e-run-b');
    const user = await connect();
    try {
      await run.call({ kind: 'network.block', address: '203.0.113.7' });
      // Nobody can answer the password dialog: the release is refused.
      approve = false;
      const err = await teardownTestRun(user, 'e2e-run-b').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(TeardownError);
      expect((err as TeardownError).message).toContain('blocked network traffic with 203.0.113.7');
      expect((err as TeardownError).message).toContain('docs/e2e-safety.md');
      expect(helper.sys.pfTable.has('203.0.113.7')).toBe(true);

      approve = true;
      await teardownTestRun(user, 'e2e-run-b');
      expect(helper.sys.pfTable.has('203.0.113.7')).toBe(false);
    } finally {
      approve = true;
      run.close();
      user.close();
    }
  });
});

describe('releaseFor', () => {
  const entry = (command: JournalEntry['command'], undo?: Record<string, unknown>) =>
    ({
      id: 'abc',
      kind: command.kind,
      command,
      state: 'active',
      createdAt: 0,
      summary: '',
      ...(undo ? { undo } : {}),
    }) as JournalEntry;

  it('reverses each kind of containment', () => {
    expect(releaseFor(entry({ kind: 'process.suspend', pid: 9 }))).toEqual({
      kind: 'process.resume',
      pid: 9,
    });
    expect(
      releaseFor(
        entry({ kind: 'network.block', address: '192.0.2.1/32' }, { address: '192.0.2.1' }),
      ),
    ).toEqual({ kind: 'network.unblock', address: '192.0.2.1' });
    expect(releaseFor(entry({ kind: 'file.quarantine', path: '/x' }))).toEqual({
      kind: 'file.restore',
      quarantineId: 'abc',
    });
    expect(
      releaseFor(
        entry(
          { kind: 'persistence.disable', path: '/link/a.plist' },
          { persistence: { quarantine: { originalPath: '/real/a.plist' } } },
        ),
      ),
    ).toEqual({ kind: 'persistence.enable', path: '/real/a.plist' });
    expect(
      releaseFor(
        entry({ kind: 'santa.rule.set', ruleType: 'binary', identifier: 'ab', policy: 'block' }),
      ),
    ).toEqual({ kind: 'santa.rule.remove', ruleType: 'binary', identifier: 'ab' });
    expect(releaseFor(entry({ kind: 'process.kill', pid: 9 }))).toBeUndefined();
  });
});
