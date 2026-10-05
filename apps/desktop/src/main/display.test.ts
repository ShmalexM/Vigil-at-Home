import { describe, expect, it } from 'vitest';
import { wantsX11 } from './display.js';

describe('display platform', () => {
  it('runs under XWayland on Linux unless the user chose a platform', () => {
    expect(wantsX11('linux', ['vigil'], {})).toBe(true);
    expect(wantsX11('linux', ['vigil', '--ozone-platform=wayland'], {})).toBe(false);
    expect(wantsX11('linux', ['vigil'], { ELECTRON_OZONE_PLATFORM_HINT: 'wayland' })).toBe(false);
    expect(wantsX11('darwin', ['vigil'], {})).toBe(false);
  });
});
