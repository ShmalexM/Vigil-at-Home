import { describe, expect, it } from 'vitest';
import { rovingIndex, rovingMove, rovingTabIndex, rovingTarget, type RovingItem } from './roving';

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

  it('stops at the ends instead of wrapping when asked', () => {
    expect(rovingIndex('ArrowLeft', 0, 3, { wrap: false })).toBe(0);
    expect(rovingIndex('ArrowUp', 0, 3, { wrap: false })).toBe(0);
    expect(rovingIndex('ArrowRight', 2, 3, { wrap: false })).toBe(2);
    expect(rovingIndex('ArrowDown', 1, 3, { wrap: false })).toBe(2);
    expect(rovingIndex('ArrowLeft', 2, 3, { wrap: false })).toBe(1);
  });
});

/** Three items like the Pack page's modes: ask, auto, full. */
function items() {
  const log: string[] = [];
  const list: RovingItem[] = ['ask', 'auto', 'full'].map((id) => ({
    focus: () => log.push(`focus ${id}`),
    click: () => log.push(`click ${id}`),
  }));
  return { list, log };
}

describe('rovingMove', () => {
  it('only moves focus by default, and focuses and selects when asked', () => {
    const { list, log } = items();
    expect(rovingMove('ArrowRight', list, 0)).toBe(true);
    expect(rovingMove('ArrowRight', list, 1, { select: true })).toBe(true);
    expect(log).toEqual(['focus auto', 'focus full', 'click full']);
  });

  it('only moves focus when select is off, so an arrow never commits Full access', () => {
    const { list, log } = items();
    const mode = { select: false, wrap: false };
    expect(rovingMove('ArrowRight', list, 1, mode)).toBe(true);
    expect(rovingMove('End', list, 0, mode)).toBe(true);
    expect(log).toEqual(['focus full', 'focus full']);
    expect(log.some((l) => l.startsWith('click'))).toBe(false);
  });

  it('does not wrap from the first mode round to Full access', () => {
    const { list, log } = items();
    rovingMove('ArrowLeft', list, 0, { select: false, wrap: false });
    rovingMove('ArrowUp', list, 0, { select: false, wrap: false });
    expect(log).toEqual(['focus ask', 'focus ask']);
  });

  it('leaves other keys, and focus outside the group, alone', () => {
    const { list, log } = items();
    expect(rovingMove(' ', list, 0, { select: false })).toBe(false);
    expect(rovingMove('Enter', list, 0, { select: false })).toBe(false);
    expect(rovingMove('ArrowRight', list, -1)).toBe(false);
    expect(log).toEqual([]);
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
