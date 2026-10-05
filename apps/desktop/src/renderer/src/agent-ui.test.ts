import { describe, expect, it } from 'vitest';
import { MAX_MS, WORD_MS, nextIndex, splitWords, wordsPerTick } from './agent-ui';

describe('splitWords', () => {
  it('keeps every character, line breaks included', () => {
    const text = 'Two alerts today.\n\nBoth were  Safari updating itself.';
    expect(splitWords(text).join('')).toBe(text);
  });
  it('gives nothing for an empty answer', () => {
    expect(splitWords('')).toEqual([]);
  });
});

describe('wordsPerTick', () => {
  it('shows one word a tick for short answers', () => {
    expect(wordsPerTick(10)).toBe(1);
  });
  it('speeds up long answers so the reveal stays short', () => {
    const n = 400;
    const ticks = Math.ceil(n / wordsPerTick(n));
    expect(ticks * WORD_MS).toBeLessThanOrEqual(MAX_MS);
  });
});

describe('nextIndex', () => {
  it('keeps the ask on screen when others arrive', () => {
    expect(nextIndex(['new', 'a', 'b'], 'b', 1)).toBe(2);
  });
  it('moves to the next ask when the shown one is decided', () => {
    expect(nextIndex(['a', 'c'], 'b', 1)).toBe(1);
  });
  it('stays in range when the last ask goes', () => {
    expect(nextIndex(['a'], 'b', 1)).toBe(0);
    expect(nextIndex([], 'a', 0)).toBe(0);
  });
});
