import type { SensorEvent } from '@vigil/core';
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
  it('drops the raw record and an untagged, unmatched event’s ancestry: no bytes over today', () => {
    const today = slimForStorage(git(), false);
    const withTree = { ...git({ ancestors }), raw: { line: 'x'.repeat(500) } };
    const stored = slimForStorage(withTree, false);
    expect(stored).not.toHaveProperty('raw');
    expect(stored).toEqual(today);
    expect(bytes(stored) - bytes(today)).toBe(0);
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
