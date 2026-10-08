import { describe, expect, it } from 'vitest';
import { rovingIndex, rovingTabIndex, rovingTarget } from './roving';

describe('rovingIndex', () => {
  it('moves with the arrows and wraps around', () => {
    expect(rovingIndex('ArrowRight', 0, 3)).toBe(1);
    expect(rovingIndex('ArrowDown', 2, 3)).toBe(0);
    expect(rovingIndex('ArrowLeft', 0, 3)).toBe(2);
    expect(rovingIndex('ArrowUp', 1, 3)).toBe(0);
  });

  it('jumps to the ends with Home and End and ignores other keys', () => {
    expect(rovingIndex('Home', 2, 3)).toBe(0);
    expect(rovingIndex('End', 0, 3)).toBe(2);
    expect(rovingIndex('Enter', 1, 3)).toBeUndefined();
    expect(rovingIndex('ArrowRight', 0, 0)).toBeUndefined();
  });
});

describe('rovingTabIndex', () => {
  it('makes only the selected item, or the first, a Tab stop', () => {
    expect(rovingTabIndex(true, 2, true)).toBe(0);
    expect(rovingTabIndex(false, 0, true)).toBe(-1);
    expect(rovingTabIndex(false, 0, false)).toBe(0);
    expect(rovingTabIndex(false, 1, false)).toBe(-1);
  });
});

describe('rovingTarget', () => {
  /** A button that records focus and selection like the real ones. */
  function buttons(n: number, disabled: number[] = []) {
    const log: string[] = [];
    let selected = 0;
    const items = Array.from({ length: n }, (_, i) => ({
      disabled: disabled.includes(i),
      focus: () => log.push(`focus ${i}`),
      // What the browser does for Space or Enter on a focused <button>.
      click: () => {
        selected = i;
        log.push(`select ${i}`);
      },
    }));
    return { items, log, selected: () => selected };
  }

  it('moves focus with the arrows, Home and End, and never selects', () => {
    const { items, log, selected } = buttons(3);
    rovingTarget(items, items[0], 'ArrowRight')!.focus();
    rovingTarget(items, items[1], 'End')!.focus();
    rovingTarget(items, items[2], 'ArrowDown')!.focus();
    expect(log).toEqual(['focus 1', 'focus 2', 'focus 0']);
    expect(selected()).toBe(0);
  });

  it('leaves Space and Enter to the focused button, so keyboard users still choose', () => {
    const { items, log, selected } = buttons(2);
    expect(rovingTarget(items, items[0], ' ')).toBeUndefined();
    expect(rovingTarget(items, items[0], 'Enter')).toBeUndefined();
    // On / Off: move to Off, then press Space.
    const off = rovingTarget(items, items[0], 'ArrowRight')!;
    off.focus();
    off.click();
    expect(log).toEqual(['focus 1', 'select 1']);
    expect(selected()).toBe(1);
  });

  it('skips disabled items and ignores keys when focus is elsewhere', () => {
    const { items } = buttons(3, [1]);
    expect(rovingTarget(items, items[0], 'ArrowRight')).toBe(items[2]);
    expect(rovingTarget(items, undefined, 'ArrowRight')).toBeUndefined();
  });
});
