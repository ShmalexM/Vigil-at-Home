import { DEFAULT_UI_FONT_SIZE } from '../shared/themes.js';

/**
 * How much larger than normal the popover and popup draw, from the text size
 * in Appearance: 1 at the default, 2 at 200%. Smaller text leaves them at
 * their fitted size.
 */
export function textScale(uiFontSize: number): number {
  return Math.min(2, Math.max(1, uiFontSize / DEFAULT_UI_FONT_SIZE));
}

/**
 * A small window's size at a text scale, so its page keeps the layout it was
 * fitted for. Both stay inside the work area, and the page scrolls past that.
 */
export function scaledSize(
  base: { width: number; height: number },
  scale: number,
  area: { width: number; height: number },
): { width: number; height: number } {
  return {
    width: Math.min(Math.round(base.width * scale), area.width - 24),
    height: Math.min(Math.round(base.height * scale), area.height - 24),
  };
}
