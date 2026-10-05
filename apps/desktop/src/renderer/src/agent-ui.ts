/*
 * Pure helpers for the agent UI pieces adapted from Beautiful UI
 * (https://github.com/slev12397/beautiful-ui), Copyright (c) 2026 Shane Levine,
 * MIT License. See THIRD_PARTY_NOTICES.md.
 */

/** The whole reveal takes at most this long, however long the answer. */
export const MAX_MS = 1400;
export const WORD_MS = 35;

/** Words and the spaces after them, so line breaks in the answer survive. */
export function splitWords(text: string): string[] {
  return text.match(/\S+\s*|\s+/g) ?? [];
}

/** How many words to show per tick so the reveal fits in MAX_MS. */
export function wordsPerTick(count: number): number {
  return Math.max(1, Math.ceil((count * WORD_MS) / MAX_MS));
}

/** Which ask to show after the list changes: the same one if it's still there. */
export function nextIndex(ids: string[], currentId: string | undefined, index: number): number {
  if (ids.length === 0) return 0;
  const same = currentId ? ids.indexOf(currentId) : -1;
  if (same >= 0) return same;
  return Math.min(index, ids.length - 1);
}
