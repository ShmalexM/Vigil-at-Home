import type { KeyboardEvent } from 'react';

export interface RovingOptions {
  /**
   * Whether moving also selects (clicks) the item, as tabs and radio buttons
   * do on macOS. Default true. Turn it off where picking an item commits a
   * setting, so the arrows only move focus and Space, Enter or a click picks.
   */
  select?: boolean;
  /** Whether the arrows wrap from one end to the other. Default true. */
  wrap?: boolean;
}

/**
 * Where an arrow, Home or End key moves in a row of tabs or radio buttons:
 * the arrows wrap around (unless `wrap` is false, when they stop at the
 * ends), Home and End jump to the ends. undefined for any other key.
 */
export function rovingIndex(
  key: string,
  current: number,
  count: number,
  { wrap = true }: Pick<RovingOptions, 'wrap'> = {},
): number | undefined {
  if (count === 0) return undefined;
  switch (key) {
    case 'ArrowRight':
    case 'ArrowDown':
      return wrap ? (current + 1) % count : Math.min(current + 1, count - 1);
    case 'ArrowLeft':
    case 'ArrowUp':
      return wrap ? (current - 1 + count) % count : Math.max(current - 1, 0);
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    default:
      return undefined;
  }
}

/** The bits of an item the keyboard handler touches, so it can be tested without a DOM. */
export interface RovingItem {
  focus(): void;
  click(): void;
}

/**
 * Moves focus to the item a key leads to and, when `select` is on, clicks it.
 * Returns true when the key was handled (so the caller prevents its default).
 */
export function rovingMove(
  key: string,
  items: readonly RovingItem[],
  current: number,
  { select = true, wrap = true }: RovingOptions = {},
): boolean {
  if (current < 0) return false;
  const next = rovingIndex(key, current, items.length, { wrap });
  if (next === undefined) return false;
  items[next]!.focus();
  if (select) items[next]!.click();
  return true;
}

/**
 * Keyboard for a tablist or radiogroup: put the returned handler on the
 * container. See RovingOptions for whether moving also selects.
 */
export function rovingKeyDown(options: RovingOptions = {}) {
  return (e: KeyboardEvent<HTMLElement>): void => {
    const items = [
      ...e.currentTarget.querySelectorAll<HTMLElement>('[role="tab"], [role="radio"]'),
    ].filter((el) => !(el as HTMLButtonElement).disabled);
    const current = items.findIndex((el) => el === document.activeElement);
    if (rovingMove(e.key, items, current, options)) e.preventDefault();
  };
}

/** Moving also selects, as tabs and radio buttons do on macOS. */
export const onRovingKeyDown = rovingKeyDown();

/** Only the selected item (or the first, when none is) is a Tab stop. */
export function rovingTabIndex(selected: boolean, index: number, anySelected: boolean): 0 | -1 {
  return selected || (!anySelected && index === 0) ? 0 : -1;
}
