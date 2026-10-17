import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RuleStore } from '@vigil/sensors';
import { Approvals } from '../approval.js';
import { Executor } from '../executor.js';
import { Journal } from '../journal.js';
import { FakeSystem } from './fakeSystem.js';
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

describe("teardown leaves the user's own enforcement alone", () => {
  const BIN = 'b'.repeat(64);
  const rule = () => new RuleStore(helper.paths.santaRules).get('BINARY', BIN)?.rule;

  it("puts back the Santa rule the run replaced, rather than removing the user's", async () => {
    approve = true;
    const user = await connect();
    const run = await connect('e2e-santa-a');
    try {
      await user.call({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: BIN,
        policy: 'block',
        message: 'blocked by me',
      });
      await run.call({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: BIN,
        policy: 'silent_block',
      });
      expect(rule()?.policy).toBe('SILENT_BLOCKLIST');

      const report = await teardownTestRun(user, 'e2e-santa-a');
      expect(report.undone).toHaveLength(1);
      expect(rule()).toMatchObject({ policy: 'BLOCKLIST', custom_msg: 'blocked by me' });
    } finally {
      run.close();
      await user.call({ kind: 'santa.rule.remove', ruleType: 'binary', identifier: BIN });
      user.close();
    }
  });

  it('keeps a Santa rule the user set on the same program after the run', async () => {
    approve = true;
    const user = await connect();
    const run = await connect('e2e-santa-b');
    try {
      await run.call({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: BIN,
        policy: 'block',
      });
      await user.call({
        kind: 'santa.rule.set',
        ruleType: 'binary',
        identifier: BIN,
        policy: 'block',
      });

      const report = await teardownTestRun(user, 'e2e-santa-b');
      expect(report.undone).toEqual([]);
      expect(report.kept).toHaveLength(1);
      expect(rule()?.policy).toBe('BLOCKLIST');
    } finally {
      run.close();
      await user.call({ kind: 'santa.rule.remove', ruleType: 'binary', identifier: BIN });
      user.close();
    }
  });

  it('keeps a block the user asked for after the run made the same one', async () => {
    approve = true;
    const user = await connect();
    const run = await connect('e2e-net-a');
    try {
      await run.call({ kind: 'network.block', address: '192.0.2.77' });
      await user.call({ kind: 'network.block', address: '192.0.2.77' });

      const report = await teardownTestRun(user, 'e2e-net-a');
      expect(report.undone).toEqual([]);
      expect(helper.sys.pfTable.has('192.0.2.77')).toBe(true);
    } finally {
      run.close();
      await user.call({ kind: 'network.unblock', address: '192.0.2.77' });
      user.close();
    }
  });
});

describe('the run whose rules are in force', () => {
  it('is remembered across a helper restart', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'vigil-rules-run-'));
    const make = () =>
      new Executor({
        sys: new FakeSystem(),
        journal: new Journal(join(dir, 'journal.json')),
        approvals: new Approvals({
          dir: join(dir, 'approvals'),
          requiredOwnerUid: process.getuid!(),
        }),
        rules: new RuleStore(join(dir, 'rules.json')),
        quarantine: { quarantineDir: join(dir, 'Quarantine') },
        syncPort: 47821,
        rulesTestRunFile: join(dir, 'rules-test-run.json'),
      });
    try {
      expect(make().rulesTestRun).toBeUndefined();
      const first = make();
      (first as unknown as { setRulesTestRun(t?: string): void }).setRulesTestRun('e2e-restart');
      expect(make().rulesTestRun).toBe('e2e-restart');
      (first as unknown as { setRulesTestRun(t?: string): void }).setRulesTestRun(undefined);
      expect(make().rulesTestRun).toBeUndefined();
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('fails the teardown when the helper cannot say', async () => {
    const calls: unknown[] = [];
    const client = {
      call: async (cmd: { kind: string }) => {
        calls.push(cmd.kind);
        return cmd.kind === 'helper.journal' ? [] : {};
      },
    } as unknown as HelperClient;
    await expect(teardownTestRun(client, 'e2e-old')).rejects.toThrow(
      /does not report which test run set them/,
    );
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
