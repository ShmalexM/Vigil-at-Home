import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import type { EventOfKind, Rule } from '@vigil/core';
import { listDigest } from '@vigil/detection/fastpath';
import { FastPath, type DetectionSync } from '@vigil/helper';
import { Store } from './db/store.js';
import type { Detector } from './detection.js';

export function memoryStore(): Store {
  return new Store(new DatabaseSync(':memory:'));
}

export function makeRule(over: Partial<Rule> = {}): Rule {
  return {
    id: 'test.rule',
    version: 1,
    name: 'Test rule',
    description: 'A rule for tests.',
    origin: 'builtin',
    mode: 'block',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    condition: { field: 'process.path', op: 'eq', value: '/tmp/evil' },
    response: [],
    exclusions: [],
    reasons: [],
    tags: [],
    createdAt: 1,
    updatedAt: 1,
    ...over,
  };
}

let n = 0;
export function makeExec(path = '/tmp/evil', pid = 4242): EventOfKind<'process.exec'> {
  n++;
  return {
    id: `ev-${n}`,
    ts: 1_000 + n,
    source: 'test',
    kind: 'process.exec',
    process: { pid, path, signing: 'unsigned' },
  };
}

/**
 * The helper's own rule policy behind a detector's syncs, with a password
 * dialog the test answers: `helper.approve` false cancels it, `helper.refuse`
 * makes the helper turn the rules down with that reason. `asked` holds what
 * each password prompt listed. Call `done()` to remove its saved rules.
 */
export function helperPolicy(detector: Detector) {
  const dir = mkdtempSync(join(tmpdir(), 'vigil-fp-'));
  const fast = new FastPath({
    file: join(dir, 'rules.json'),
    run: async () => ({ ok: true }) as never,
  });
  const asked: string[][] = [];
  const helper: { approve: boolean; refuse?: string } = { approve: true };
  detector.syncHelper = async (opts = {}) => {
    const set = opts.set ?? detector.helperRules();
    const cmd: DetectionSync = {
      kind: 'detection.sync',
      rules: set.rules,
      appRules: set.appRules,
      exceptions: set.exceptions,
      selfPaths: set.selfPaths,
      lists: Object.fromEntries(Object.entries(set.lists).map(([l, e]) => [l, listDigest(e)])),
    };
    if (helper.refuse) {
      opts.onError?.(helper.refuse);
      return 'failed';
    }
    const weakens = fast.loosening(cmd);
    if (weakens.length) {
      asked.push(weakens);
      if (!helper.approve) return 'declined';
    }
    const { needLists } = fast.sync(cmd);
    for (const list of needLists) {
      const entries = [...new Set(set.lists[list] ?? [])];
      fast.putList({
        kind: 'detection.list.set',
        list,
        digest: cmd.lists[list]!,
        part: 0,
        parts: 1,
        entries,
      });
    }
    return 'applied';
  };
  return { asked, helper, done: () => rmSync(dir, { recursive: true, force: true }) };
}
