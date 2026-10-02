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

/**
 * Keyboard for a tablist or radiogroup: put it on the container. Moving also
 * selects, as tabs and radio buttons do on macOS.
 */
export function onRovingKeyDown(e: KeyboardEvent<HTMLElement>): void {
  const items = [
    ...e.currentTarget.querySelectorAll<HTMLElement>('[role="tab"], [role="radio"]'),
  ].filter((el) => !(el as HTMLButtonElement).disabled);
  const current = items.findIndex((el) => el === document.activeElement);
  if (current < 0) return;
  const next = rovingIndex(e.key, current, items.length);
  if (next === undefined) return;
  e.preventDefault();
  items[next]!.focus();
  items[next]!.click();
}

/** Only the selected item (or the first, when none is) is a Tab stop. */
export function rovingTabIndex(selected: boolean, index: number, anySelected: boolean): 0 | -1 {
  return selected || (!anySelected && index === 0) ? 0 : -1;
}
