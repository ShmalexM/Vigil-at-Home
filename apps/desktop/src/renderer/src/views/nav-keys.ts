/** ⌘ on a Mac, Ctrl elsewhere, as the app shows it. */
export const MOD = navigator.platform.toLowerCase().includes('mac') ? '⌘' : 'Ctrl+';

/** The pages ⌘1…⌘6 open, in sidebar order, and ⌘, for Settings as on every Mac app. */
export const NAV_KEYS: Record<string, string> = {
  '1': 'home',
  '2': 'history',
  '3': 'alerts',
  '4': 'rules',
  '5': 'activity',
  '6': 'agents',
  ',': 'settings',
};

/** The route a key press asks for, or undefined. Typing in a field never navigates. */
export function navKey(
  e: Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey' | 'altKey' | 'shiftKey'>,
  mac: boolean,
  typing: boolean,
): string | undefined {
  if (typing || e.altKey || e.shiftKey || !(mac ? e.metaKey : e.ctrlKey)) return undefined;
  return NAV_KEYS[e.key];
}

/** The shortcut for a page, for its tooltip. */
export function navShortcut(route: string): string | undefined {
  const key = Object.keys(NAV_KEYS).find((k) => NAV_KEYS[k] === route);
  return key ? `${MOD}${key}` : undefined;
}
