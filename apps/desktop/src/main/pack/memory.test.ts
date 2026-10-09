import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { MAX_MEMORIES, PackMemory, looksSecret, memoryTainted } from './memory.js';

function setup() {
  let at = Date.UTC(2026, 9, 5, 12);
  const changes: number[] = [];
  const memory = new PackMemory(new DatabaseSync(':memory:'), {
    now: () => at,
    onChange: () => changes.push(at),
  });
  return { memory, changes, tick: (ms: number) => (at += ms) };
}

const YOU = { from: 'you' } as const;

describe('PackMemory', () => {
  it('keeps one line per fact, grouped by topic, with where it came from', () => {
    const { memory, tick, changes } = setup();
    memory.remember({ fact: 'Uses Tailscale\nat home', topic: 'network' }, YOU);
    tick(1000);
    memory.remember(
      { fact: 'Alex is a developer', topic: 'you' },
      { from: 'lead', source: 'msg-1' },
    );
    expect(memory.list().map((e) => [e.topic, e.fact, e.from])).toEqual([
      ['you', 'Alex is a developer', 'lead'],
      ['network', 'Uses Tailscale at home', 'you'],
    ]);
    expect(memory.list()[0]).toMatchObject({ source: 'msg-1' });
    expect(changes).toHaveLength(2);
  });

  it('does not keep the same fact twice, and a replacement crosses out the old one', () => {
    const { memory } = setup();
    const a = memory.remember({ fact: 'Works in Cursor', topic: 'agents' }, YOU);
    expect(memory.remember({ fact: 'works in cursor.', topic: 'agents' }, YOU).id).toBe(a.id);
    const b = memory.remember(
      { fact: 'Works in Claude Code now, not Cursor', topic: 'agents' },
      { from: 'lead', replaces: a.id },
    );
    expect(memory.list().map((e) => e.id)).toEqual([b.id]);
  });

  it('refuses secrets and lines that are too long or empty', () => {
    const { memory } = setup();
    expect(() =>
      memory.remember({ fact: 'My GitHub token is ghp_' + 'a'.repeat(36), topic: 'you' }, YOU),
    ).toThrow(/never keeps/);
    expect(() => memory.remember({ fact: 'Email me at a@b.com', topic: 'you' }, YOU)).toThrow();
    expect(() => memory.remember({ fact: 'x'.repeat(201), topic: 'you' }, YOU)).toThrow();
    expect(() => memory.remember({ fact: '  ', topic: 'you' }, YOU)).toThrow();
    expect(() => memory.remember({ fact: 'fine', topic: 'nope' }, YOU)).toThrow();
    expect(memory.count()).toBe(0);
    // A home folder path is fine: it is redacted on the way out like any other.
    expect(looksSecret('Keeps projects in /Users/alex/code')).toBe(false);
  });

  it('stops at its size limit until something is forgotten', () => {
    const { memory } = setup();
    for (let i = 0; i < MAX_MEMORIES; i++)
      memory.remember({ fact: `Fact number ${i}`, topic: 'mac' }, YOU);
    expect(() => memory.remember({ fact: 'One more', topic: 'mac' }, YOU)).toThrow(/up to/);
    // Replacing one still works when full.
    const first = memory.list()[0]!;
    memory.remember({ fact: 'One more', topic: 'mac' }, { from: 'you', replaces: first.id });
    expect(memory.count()).toBe(MAX_MEMORIES);
    memory.forget(memory.list()[0]!.id);
    expect(memory.count()).toBe(MAX_MEMORIES - 1);
    memory.forget();
    expect(memory.count()).toBe(0);
  });

  it('sends the newest entries that fit with a run, and finds the rest by words', () => {
    const { memory, tick } = setup();
    for (let i = 0; i < 60; i++) {
      memory.remember(
        { fact: `Project ${i} lives in a folder called ${'p'.repeat(80)}`, topic: 'mac' },
        YOU,
      );
      tick(1000);
    }
    memory.remember({ fact: 'Runs Little Snitch', topic: 'network' }, YOU);
    const p = memory.forPrompt();
    expect(p.entries[0]!.fact).toBe('Runs Little Snitch');
    expect(p.notShown).toBeGreaterThan(0);
    expect(p.entries.length + p.notShown).toBe(61);
    expect(memory.recall('project 3 folder')[0]!.fact).toMatch(/^Project 3 /);
    expect(memory.recall('snitch').map((e) => e.fact)).toEqual(['Runs Little Snitch']);
  });

  it('keeps provenance: unmarked facts count as tainted, and a clean repeat cleans one', () => {
    const { memory } = setup();
    const a = memory.remember({ fact: 'Trusts the updater', topic: 'apps' }, YOU);
    expect(memoryTainted(a)).toBe(true);
    expect(memoryTainted({})).toBe(true);
    expect(memory.forPrompt().entries).toEqual([
      { id: a.id, topic: 'apps', fact: 'Trusts the updater', tainted: true },
    ]);
    expect(memory.forPrompt((e) => !memoryTainted(e))).toMatchObject({ entries: [], notShown: 1 });
    // A tainted repeat never cleans it; the person's own words do.
    memory.remember({ fact: 'Trusts the updater', topic: 'apps' }, { from: 'lead', tainted: true });
    expect(memory.get(a.id)!.tainted).toBe(true);
    memory.remember(
      { fact: 'trusts the updater.', topic: 'apps' },
      { from: 'you', tainted: false },
    );
    expect(memory.get(a.id)!.tainted).toBe(false);
    expect(memory.recall('updater')[0]).not.toHaveProperty('tainted');
  });

  it('writes a MEMORY.md with one sourced, dated line per fact', () => {
    const { memory } = setup();
    expect(memory.markdown()).toContain('_Nothing yet._');
    memory.remember({ fact: 'Uses 1Password', topic: 'apps' }, YOU);
    memory.remember({ fact: 'Explain in plain words', topic: 'pack' }, { from: 'lead' });
    expect(memory.markdown()).toBe(
      [
        '# MEMORY.md',
        '',
        'What the Vigil pack remembers. One fact per line.',
        '',
        '## Apps and tools',
        '',
        '- Uses 1Password [source: you] [added: 2026-10-05]',
        '',
        '## How the pack works',
        '',
        '- Explain in plain words [source: Lead dog, from your words] [added: 2026-10-05]',
        '',
      ].join('\n'),
    );
  });
});
