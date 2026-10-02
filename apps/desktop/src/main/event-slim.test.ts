import type { SensorEvent } from '@vigil/core';
import {
  AgentTracker,
  DetectionEngine,
  compileAgentMatchers,
  memoryStores,
  type DetectionRuleInput,
} from '@vigil/detection';
import { describe, expect, it } from 'vitest';
import { slimForStorage } from './event-slim.js';

const bytes = (e: SensorEvent) => Buffer.byteLength(JSON.stringify(e));
const ancestors = ['zsh', 'claude', 'zsh', 'Terminal'];
const tag = { id: 'claude-code', session: '0123456789abcdef', depth: 2 };

function git(extra: Partial<Extract<SensorEvent, { kind: 'process.exec' }>['process']> = {}) {
  return {
    id: 'e1',
    ts: 1,
    source: 'santa',
    kind: 'process.exec',
    process: {
      pid: 10,
      ppid: 9,
      path: '/usr/bin/git',
      args: ['git', 'status'],
      signing: 'apple',
      ...extra,
    },
  } satisfies SensorEvent;
}

describe('slimForStorage', () => {
  it('drops the raw record, and keeps only the parent’s name of an untagged, unmatched launch', () => {
    const today = slimForStorage(git(), false);
    const withTree = { ...git({ ancestors }), raw: { line: 'x'.repeat(500) } };
    const stored = slimForStorage(withTree, false);
    expect(stored).not.toHaveProperty('raw');
    // The parent's name: what process.parentName reads when the sensor gave no parent path.
    expect(stored).toEqual(git({ ancestors: ['zsh'] }));
    expect(bytes(stored) - bytes(today)).toBe(Buffer.byteLength(',"ancestors":["zsh"]'));
  });

  it('adds no bytes where the parent’s name is known otherwise, or is not a launch', () => {
    const withPath = git({ ancestors, parentPath: '/bin/zsh' });
    expect(slimForStorage(withPath, false)).toEqual(git({ parentPath: '/bin/zsh' }));
    const file = {
      id: 'f1',
      ts: 1,
      source: 'santa',
      kind: 'file',
      op: 'open',
      path: '/Users/you/notes.txt',
      process: { pid: 10, path: '/usr/bin/vim', ancestors },
    } satisfies SensorEvent;
    const { ancestors: _a, ...bare } = file.process;
    expect(slimForStorage(file, false)).toEqual({ ...file, process: bare });
  });

  it('judges a rule on the parent’s name the same on a stored launch as live', () => {
    // Santa's log gives no parent path: the tracker names the parent.
    const t = new AgentTracker({ matcher: () => compileAgentMatchers([]) });
    const launch = (pid: number, ppid: number, path: string, ts: number): SensorEvent =>
      t.observe({
        id: `e${pid}`,
        ts,
        source: 'santa',
        kind: 'process.exec',
        process: { pid, ppid, path, args: [path], signing: 'apple' },
      } satisfies SensorEvent);
    launch(500, 1, '/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word', 1000);
    const live = launch(600, 500, '/bin/zsh', 2000);
    expect(live.kind === 'process.exec' && live.process.ancestors).toEqual(['Microsoft Word']);
    const stored = JSON.parse(JSON.stringify(slimForStorage(live, false))) as SensorEvent;
    const rule = (id: string, condition: DetectionRuleInput['condition']): DetectionRuleInput => ({
      id,
      version: 1,
      name: id,
      description: id,
      origin: 'user',
      mode: 'shadow',
      severity: 'high',
      fidelity: 'medium',
      eventKinds: ['process.exec'],
      condition,
      response: [],
      reasons: ['A shell under Word.'],
      tags: [],
      createdAt: 0,
      updatedAt: 0,
    });
    const shell = { field: 'process.name', op: 'in', value: ['zsh', 'bash', 'sh'] } as const;
    const word = { field: 'process.parentName', op: 'in', value: ['Microsoft Word'] } as const;
    const rules = [
      rule('office-shell', { all: [shell, word] }),
      rule('not-office-shell', { all: [shell, { not: word }] }),
    ];
    // Replay and preview run stored events through an engine like this one.
    const fired = (e: SensorEvent) =>
      new DetectionEngine(rules, memoryStores()).evaluate(e).map((d) => d.match.ruleId);
    expect(fired(live)).toEqual(['office-shell']);
    expect(fired(stored)).toEqual(fired(live));
  });

  it('keeps the ancestry of events under an agent, and of events a rule matched', () => {
    const plain = slimForStorage(git(), false);
    const tagged = slimForStorage(git({ ancestors, agent: tag }), false);
    expect(tagged).toMatchObject({ process: { ancestors, agent: tag } });
    const matched = slimForStorage(git({ ancestors }), true);
    expect(matched).toMatchObject({ process: { ancestors } });
    // What keeping it costs, per event: the names plus the JSON around them.
    const treeBytes = Buffer.byteLength(JSON.stringify({ ancestors })) - 1;
    expect(bytes(matched) - bytes(plain)).toBe(treeBytes);
    expect(bytes(tagged) - bytes(plain)).toBeLessThan(treeBytes + 80);
  });

  it('leaves events without a process alone', () => {
    const e: SensorEvent = {
      id: 'p1',
      ts: 1,
      source: 'osquery',
      kind: 'persistence',
      change: 'added',
      mechanism: 'launch_agent',
      path: '/Users/you/Library/LaunchAgents/x.plist',
    };
    expect(slimForStorage(e, false)).toEqual(e);
  });

  it('does not change the event it was given', () => {
    const e = git({ ancestors });
    slimForStorage(e, false);
    expect(e.process.ancestors).toEqual(ancestors);
  });
});
