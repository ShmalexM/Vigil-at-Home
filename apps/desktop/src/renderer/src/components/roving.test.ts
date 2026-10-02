import { describe, expect, it } from 'vitest';
import { rovingIndex, rovingTabIndex } from './roving';

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
