import { describe, expect, it, vi } from 'vitest';

vi.stubGlobal('navigator', { platform: 'MacIntel' });
const { navKey, navShortcut } = await import('./nav-keys');

const key = (k: string, o: Partial<KeyboardEvent> = {}) => ({
  key: k,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  ...o,
});

describe('navKey', () => {
  it('opens pages with ⌘ on a Mac and Ctrl elsewhere', () => {
    expect(navKey(key('1', { metaKey: true }), true, false)).toBe('home');
    expect(navKey(key(',', { metaKey: true }), true, false)).toBe('settings');
    expect(navKey(key('2', { ctrlKey: true }), false, false)).toBe('history');
    expect(navKey(key('2', { ctrlKey: true }), true, false)).toBeUndefined();
  });

  it('leaves typing, other modifiers and other keys alone', () => {
    expect(navKey(key('1', { metaKey: true }), true, true)).toBeUndefined();
    expect(navKey(key('1', { metaKey: true, shiftKey: true }), true, false)).toBeUndefined();
    expect(navKey(key('9', { metaKey: true }), true, false)).toBeUndefined();
  });

  it('names the shortcut for a tooltip', () => {
    expect(navShortcut('history')).toBe('⌘2');
    expect(navShortcut('pack')).toBeUndefined();
  });
});
