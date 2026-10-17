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

/** The command that reverses a journal entry still in force. */
export function releaseFor(e: JournalEntry): HelperAction | undefined {
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
    case 'santa.rule.set':
      return { kind: 'santa.rule.remove', ruleType: cmd.ruleType, identifier: cmd.identifier };
    default:
      return undefined;
  }
}

export interface TeardownReport {
  testRun: string;
  /** Summaries of what was undone. */
  undone: string[];
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

async function tagged(client: HelperClient, testRun: string): Promise<JournalEntry[]> {
  const entries = await client.call<JournalEntry[]>({
    kind: 'helper.journal',
    limit: JOURNAL_LIMIT,
  });
  return entries.filter((e) => e.testRun === testRun && e.state === 'active');
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
  const report: TeardownReport = { testRun, undone: [], failed: [], clearedRules: false };
  // Newest first: a later action may rest on an earlier one.
  for (const e of (await tagged(client, testRun)).sort((a, b) => b.createdAt - a.createdAt)) {
    const release = releaseFor(e);
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
  // next connects.
  const status = await client.call<{ testRun?: string | null }>({ kind: 'detection.status' });
  if (status.testRun === testRun) {
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

  // Check, rather than trust the replies.
  const failedSummaries = new Set(report.failed.map((f) => f.summary));
  for (const e of await tagged(client, testRun)) {
    if (!failedSummaries.has(e.summary))
      report.failed.push({ summary: e.summary, error: 'still in force after its undo' });
  }
  if (report.failed.length) throw new TeardownError(report);
  return report;
}
