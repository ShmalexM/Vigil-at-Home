import { describe, expect, it } from 'vitest';
import type { DogNote } from './pack.js';
import { notesJson, notesMarkdown, usageWords } from './notebook-export.js';

const NOTE: DogNote = {
  id: 'n1',
  at: Date.UTC(2026, 9, 8, 13, 0),
  dog: 'pip',
  kind: 'job',
  ok: true,
  ask: 'Check Downloads\nevery hour',
  lookedAt: ['vigil.search_events'],
  answer: 'One unsigned program.',
  reasons: ['search_events found one exec'],
  provider: 'codex',
  model: 'gpt-5.5',
  calls: [
    {
      tool: 'vigil.search_events',
      title: 'Vigil › Search events',
      args: '{"limit":5}',
      outcome: 'ran',
      result: 'has ``` inside',
    },
    {
      tool: 'github.create_issue',
      title: 'GitHub › Create issue',
      args: '{}',
      outcome: 'not-run',
      reason: 'it needed your OK',
    },
  ],
  usage: { inputTokens: 1234, cachedInputTokens: 200, outputTokens: 310, costUsd: 0.0123 },
};

describe('notebook export', () => {
  it('writes a dog’s notes as Markdown, calls and cost included', () => {
    const md = notesMarkdown('Pip’s notebook', [NOTE], { now: Date.UTC(2026, 9, 8, 14, 5) });
    expect(md).toContain('# Pip’s notebook');
    expect(md).toContain('Exported 2026-10-08 14:05 UTC. 1 entry');
    expect(md).toContain('## 2026-10-08 13:00 UTC · Job');
    expect(md).toContain('**Asked:** Check Downloads every hour');
    expect(md).toContain('- search_events found one exec');
    expect(md).toContain('1. Vigil › Search events (`vigil.search_events`): Ran');
    expect(md).toContain(
      '2. GitHub › Create issue (`github.create_issue`): Not run, it needed your OK',
    );
    // A result with backticks can't close its own block.
    expect(md).toContain('   ````\n   has ``` inside\n   ````');
    expect(md).toContain(
      '**Ran on:** codex · gpt-5.5 · 1,234 tokens in (200 cached), 310 out · about $0.01',
    );
    expect(notesMarkdown('x', [{ ...NOTE, ok: false, calls: [] }])).toContain('· didn’t finish');
  });

  it('writes the same notes as JSON, as stored', () => {
    const json = JSON.parse(notesJson('pip', [NOTE], 5)) as { dog: string; notes: DogNote[] };
    expect(json).toEqual({ dog: 'pip', exportedAt: 5, notes: [NOTE] });
  });

  it('words usage like the Usage page', () => {
    const u = { inputTokens: 10, cachedInputTokens: 0, outputTokens: 2 };
    expect(usageWords({ ...u, costUsd: null })).toBe(
      '10 tokens in, 2 out · no price from the provider',
    );
    expect(usageWords({ ...u, costUsd: 0 })).toBe('10 tokens in, 2 out · free');
    expect(usageWords({ ...u, costUsd: 0.0004 })).toBe('10 tokens in, 2 out · about $0.0004');
  });
});
