import type { KeyboardEvent } from 'react';

export interface RovingOptions {
  /**
   * Whether moving also selects (clicks) the item. Default false: the arrows
   * only move focus and Space, Enter or a click picks (ARIA "manual
   * activation"), so arrow keys pressed to scroll a page can't flip a switch
   * or commit a setting that happens to have focus.
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
  disabled?: boolean;
}

/**
 * The item a key moves focus to from `active` in a row of tabs or radio
 * buttons, skipping disabled ones, or undefined when the key isn't one that
 * moves or focus is outside the row.
 */
export function rovingTarget<T extends RovingItem>(
  all: readonly T[],
  active: unknown,
  key: string,
  { wrap = true }: Pick<RovingOptions, 'wrap'> = {},
): T | undefined {
  const items = all.filter((el) => !el.disabled);
  const current = items.findIndex((el) => el === active);
  if (current < 0) return undefined;
  const next = rovingIndex(key, current, items.length, { wrap });
  return next === undefined ? undefined : items[next];
}

/**
 * Moves focus to the item a key leads to and, when `select` is on, clicks it.
 * Returns true when the key was handled (so the caller prevents its default).
 */
export function rovingMove(
  key: string,
  items: readonly RovingItem[],
  current: number,
  { select = false, wrap = true }: RovingOptions = {},
): boolean {
  if (current < 0) return false;
  const target = rovingTarget(items, items[current], key, { wrap });
  if (!target) return false;
  target.focus();
  if (select) target.click();
  return true;
}

/**
 * Keyboard for a tablist or radiogroup: put the returned handler on the
 * container. See RovingOptions for whether moving also selects.
 */
export function rovingKeyDown(options: RovingOptions = {}) {
  return (e: KeyboardEvent<HTMLElement>): void => {
    const items = [
      ...e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"], [role="radio"]'),
    ];
    const current = items.findIndex((el) => el === document.activeElement);
    if (rovingMove(e.key, items, current, options)) e.preventDefault();
  };
}

/** The usual handler: the arrows, Home and End move focus only. */
export const onRovingKeyDown = rovingKeyDown();

/** Only the selected item (or the first, when none is) is a Tab stop. */
export function rovingTabIndex(selected: boolean, index: number, anySelected: boolean): 0 | -1 {
  return selected || (!anySelected && index === 0) ? 0 : -1;
}
