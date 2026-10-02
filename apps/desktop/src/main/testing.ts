import { DatabaseSync } from 'node:sqlite';
import type { EventOfKind, Rule } from '@vigil/core';
import { Store } from './db/store.js';

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
