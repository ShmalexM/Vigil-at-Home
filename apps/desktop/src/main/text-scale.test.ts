import { describe, expect, it } from 'vitest';
import { scaledSize, textScale } from './text-scale.js';

describe('textScale', () => {
  it('is 1 at or below the default size and 2 at 200%', () => {
    expect(textScale(13)).toBe(1);
    expect(textScale(11)).toBe(1);
    expect(textScale(26)).toBe(2);
    expect(textScale(40)).toBe(2);
  });
});

describe('scaledSize', () => {
  const area = { width: 1440, height: 875 };
  it('leaves the window alone at normal size', () => {
    expect(scaledSize({ width: 380, height: 540 }, 1, area)).toEqual({ width: 380, height: 540 });
  });

  it('grows with the text and keeps within the screen', () => {
    expect(scaledSize({ width: 380, height: 540 }, 2, area)).toEqual({ width: 760, height: 851 });
    expect(scaledSize({ width: 420, height: 400 }, 2, { width: 600, height: 500 })).toEqual({
      width: 576,
      height: 476,
    });
  });
});
