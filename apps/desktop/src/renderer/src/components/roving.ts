import type { KeyboardEvent } from 'react';

/**
 * Where an arrow, Home or End key moves in a row of tabs or radio buttons:
 * the arrows wrap around, Home and End jump to the ends. undefined for any
 * other key.
 */
export function rovingIndex(key: string, current: number, count: number): number | undefined {
  if (count === 0) return undefined;
  switch (key) {
    case 'ArrowRight':
    case 'ArrowDown':
      return (current + 1) % count;
    case 'ArrowLeft':
    case 'ArrowUp':
      return (current - 1 + count) % count;
    case 'Home':
      return 0;
    case 'End':
      return count - 1;
    default:
      return undefined;
  }
}

/** The keyboard-reachable parts of a focusable item, for `rovingTarget`. */
export interface RovingItem {
  focus(): void;
  disabled?: boolean;
}

/**
 * The item a key moves focus to in a row of tabs or radio buttons, or
 * undefined when the key isn't one that moves. Moving never selects: the
 * items are buttons, so Space, Enter or a click selects (ARIA "manual
 * activation"). That way arrow keys pressed to scroll a page can't flip a
 * switch that happens to have focus.
 */
export function rovingTarget<T extends RovingItem>(
  all: readonly T[],
  active: unknown,
  key: string,
): T | undefined {
  const items = all.filter((el) => !el.disabled);
  const current = items.findIndex((el) => el === active);
  if (current < 0) return undefined;
  const next = rovingIndex(key, current, items.length);
  return next === undefined ? undefined : items[next];
}

/** Keyboard for a tablist or radiogroup: put it on the container. Moves focus only. */
export function onRovingKeyDown(e: KeyboardEvent<HTMLElement>): void {
  const items = [
    ...e.currentTarget.querySelectorAll<HTMLButtonElement>('[role="tab"], [role="radio"]'),
  ];
  const target = rovingTarget(items, document.activeElement, e.key);
  if (!target) return;
  e.preventDefault();
  target.focus();
}

/** Only the selected item (or the first, when none is) is a Tab stop. */
export function rovingTabIndex(selected: boolean, index: number, anySelected: boolean): 0 | -1 {
  return selected || (!anySelected && index === 0) ? 0 : -1;
}
