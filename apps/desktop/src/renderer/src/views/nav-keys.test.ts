import { describe, expect, it, vi } from 'vitest';

vi.stubGlobal('navigator', { platform: 'MacIntel' });
const { isAskKey, isTyping, navKey, navKeys, navShortcut } = await import('./nav-keys');

const keys = navKeys(['home', 'history', 'settings', 'alerts', 'rules']);
const key = (k: string, o: Partial<KeyboardEvent> = {}) => ({
  key: k,
  metaKey: false,
  ctrlKey: false,
  altKey: false,
  shiftKey: false,
  ...o,
});

describe('navKey', () => {
  it('numbers the pages in sidebar order, with ⌘, for Settings', () => {
    expect(keys).toMatchObject({ '1': 'home', '3': 'settings', '4': 'alerts', ',': 'settings' });
  });

  it('opens pages with ⌘ on a Mac and Ctrl elsewhere', () => {
    expect(navKey(key('1', { metaKey: true }), keys, true, false)).toBe('home');
    expect(navKey(key(',', { metaKey: true }), keys, true, false)).toBe('settings');
    expect(navKey(key('2', { ctrlKey: true }), keys, false, false)).toBe('history');
    expect(navKey(key('2', { ctrlKey: true }), keys, true, false)).toBeUndefined();
  });

  it('leaves typing, other modifiers and other keys alone', () => {
    expect(navKey(key('1', { metaKey: true }), keys, true, true)).toBeUndefined();
    expect(navKey(key('1', { metaKey: true, shiftKey: true }), keys, true, false)).toBeUndefined();
    expect(navKey(key('9', { metaKey: true }), keys, true, false)).toBeUndefined();
  });

  it('names the shortcut for a tooltip and for assistive tech', () => {
    expect(navShortcut('history', keys, true)).toEqual({ label: '⌘2', aria: 'Meta+2' });
    expect(navShortcut('history', keys, false)).toEqual({ label: 'Ctrl+2', aria: 'Control+2' });
    expect(navShortcut('pack', keys)).toBeUndefined();
  });
});

describe('isTyping', () => {
  const el = (tagName: string, extra: object = {}) =>
    ({ tagName, ...extra }) as unknown as EventTarget;
  it('counts text fields, not checkboxes, radios or sliders', () => {
    expect(isTyping(el('INPUT', { type: 'search' }))).toBe(true);
    expect(isTyping(el('TEXTAREA'))).toBe(true);
    expect(isTyping(el('INPUT', { type: 'checkbox' }))).toBe(false);
    expect(isTyping(el('INPUT', { type: 'range' }))).toBe(false);
    expect(isTyping(el('BUTTON'))).toBe(false);
    expect(isTyping(null)).toBe(false);
  });
});

describe('isAskKey', () => {
  it('opens Ask on ⌘K, never while typing in a field', () => {
    expect(isAskKey(key('k', { metaKey: true }), true, false)).toBe(true);
    expect(isAskKey(key('K', { ctrlKey: true }), false, false)).toBe(true);
    expect(isAskKey(key('k', { metaKey: true }), true, true)).toBe(false);
    expect(isAskKey(key('k', { ctrlKey: true }), false, true)).toBe(false);
    expect(isAskKey(key('k', { metaKey: true, altKey: true }), true, false)).toBe(false);
    expect(isAskKey(key('k'), true, false)).toBe(false);
  });
});
