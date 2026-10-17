// Teardown for an e2e run that opted in to enforcing for real
// (docs/e2e-safety.md). Every action the run took carries its test-run id in
// the helper's journal (testGuard.ts); this undoes each one still in force,
// clears blocking rules the run handed the helper, and reads the journal
// again. Anything left throws, so the run fails loudly rather than leaving a
// block or a turned-off startup item behind.

import type { HelperClient } from '../client.js';
import type { JournalEntry } from '../journal.js';
import type { HelperAction } from '../protocol.js';
import type { PersistenceRecord } from '../commands/persistence.js';
import type { SantaRule } from '@vigil/sensors';

const SET_POLICY: Partial<Record<SantaRule['policy'], 'block' | 'silent_block' | 'allow'>> = {
  BLOCKLIST: 'block',
  SILENT_BLOCKLIST: 'silent_block',
  ALLOWLIST: 'allow',
};

/**
 * The command that reverses a journal entry still in force, given the
 * journal's other entries; `keep` when it must be left alone: a Santa rule
 * someone else set on the same program after the run, which replaced the
 * run's. A run's rule that replaced an earlier one is undone by putting that
 * one back, never by removing the program's rule outright.
 */
export function releaseFor(
  e: JournalEntry,
  journal: readonly JournalEntry[] = [],
): HelperAction | 'keep' | undefined {
  const cmd = e.command;
  switch (cmd.kind) {
    case 'process.suspend':
      return { kind: 'process.resume', pid: cmd.pid };
    case 'network.block':
      return { kind: 'network.unblock', address: String(e.undo?.address ?? cmd.address) };
    case 'file.quarantine':
      return { kind: 'file.restore', quarantineId: e.id };
    case 'persistence.disable': {
      const rec = e.undo?.persistence as PersistenceRecord | undefined;
      return { kind: 'persistence.enable', path: rec?.quarantine.originalPath ?? cmd.path };
    }
    case 'santa.rule.set': {
      const latest = journal
        .filter((o) => {
          const c = o.command;
          return (
            o.state === 'active' &&
            c.kind === 'santa.rule.set' &&
            c.ruleType === cmd.ruleType &&
            c.identifier === cmd.identifier
          );
        })
        .sort((a, b) => a.createdAt - b.createdAt)
        .at(-1);
      if (latest && latest.id !== e.id) return 'keep';
      const previous = e.undo?.previous as SantaRule | null | undefined;
      if (!previous)
        return { kind: 'santa.rule.remove', ruleType: cmd.ruleType, identifier: cmd.identifier };
      const policy = SET_POLICY[previous.policy];
      if (!policy) return undefined;
      return {
        kind: 'santa.rule.set',
        ruleType: cmd.ruleType,
        identifier: cmd.identifier,
        policy,
        ...(previous.custom_msg ? { message: previous.custom_msg } : {}),
      };
    }
    default:
      return undefined;
  }
}

export interface TeardownReport {
  testRun: string;
  /** Summaries of what was undone. */
  undone: string[];
  /** The run's Santa rules a later rule of someone else's replaced: left as they are. */
  kept: string[];
  /** What could not be undone, with why. */
  failed: { summary: string; error: string }[];
  /** Whether the run's blocking rules were taken off the helper. */
  clearedRules: boolean;
}

export class TeardownError extends Error {
  constructor(readonly report: TeardownReport) {
    const lines = report.failed.map((f) => `  - ${f.summary}: ${f.error}`);
    super(
      `Test run ${report.testRun} left enforcement in force on this machine:\n${lines.join('\n')}\n` +
        'Undo it from Vigil at Home (the alert or the helper journal), or remove the helper ' +
        '(apps/desktop/helper/uninstall.sh). See docs/e2e-safety.md.',
    );
    this.name = 'TeardownError';
  }
}

const JOURNAL_LIMIT = 1000;

async function journal(client: HelperClient): Promise<JournalEntry[]> {
  return client.call<JournalEntry[]>({ kind: 'helper.journal', limit: JOURNAL_LIMIT });
}

/** The run's entries still in force, with what undoes each. */
async function leftovers(client: HelperClient, testRun: string) {
  const all = await journal(client);
  return all
    .filter((e) => e.testRun === testRun && e.state === 'active')
    .map((e) => ({ e, release: releaseFor(e, all) }));
}

/**
 * Undo everything `testRun` left in force through `client`, a connection
 * whose approver can answer the password dialog (releases need it). The
 * client must not itself carry `testRun`, or the clearing sync below would
 * hand the rules back to the run. Throws TeardownError when anything stays.
 */
export async function teardownTestRun(
  client: HelperClient,
  testRun: string,
): Promise<TeardownReport> {
  const report: TeardownReport = {
    testRun,
    undone: [],
    kept: [],
    failed: [],
    clearedRules: false,
  };
  // Newest first: a later action may rest on an earlier one.
  const pending = (await leftovers(client, testRun)).sort((a, b) => b.e.createdAt - a.e.createdAt);
  for (const { e, release } of pending) {
    if (release === 'keep') {
      report.kept.push(e.summary);
      continue;
    }
    if (!release) {
      report.failed.push({ summary: e.summary, error: 'no way to undo it' });
      continue;
    }
    try {
      await client.call(release);
      report.undone.push(e.summary);
    } catch (err) {
      report.failed.push({ summary: e.summary, error: (err as Error).message });
    }
  }

  // Rules the run handed the helper keep blocking with the app closed (its
  // fast path): take them off. The user's app hands its own back when it
  // next connects. A helper that can't say whose rules are in force fails
  // the teardown rather than pass it unchecked.
  const status = await client.call<{ testRun?: string | null }>({ kind: 'detection.status' });
  if (status.testRun === undefined) {
    report.failed.push({
      summary: "the helper's blocking rules",
      error: 'this helper does not report which test run set them',
    });
  } else if (status.testRun === testRun) {
    try {
      await client.call({ kind: 'detection.sync', rules: [], exceptions: [], lists: {} });
      report.clearedRules = true;
    } catch (err) {
      report.failed.push({
        summary: "the run's blocking rules on the helper",
        error: (err as Error).message,
      });
    }
  }

  // Check, rather than trust the replies: what is left must be only rules
  // someone else's later rule replaced.
  const failedSummaries = new Set(report.failed.map((f) => f.summary));
  for (const { e, release } of await leftovers(client, testRun)) {
    if (release === 'keep') {
      // A rule put back above leaves the run's entry replaced, and so kept.
      if (!report.kept.includes(e.summary) && !report.undone.includes(e.summary))
        report.kept.push(e.summary);
      continue;
    }
    if (!failedSummaries.has(e.summary))
      report.failed.push({ summary: e.summary, error: 'still in force after its undo' });
  }
  if (report.failed.length) throw new TeardownError(report);
  return report;
}
