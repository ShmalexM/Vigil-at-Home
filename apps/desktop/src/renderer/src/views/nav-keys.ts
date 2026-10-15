const mac = () => navigator.platform.toLowerCase().includes('mac');

/** ⌘ on a Mac, Ctrl elsewhere, as the app shows it. */
export const MOD = mac() ? '⌘' : 'Ctrl+';

/**
 * ⌘1…⌘9 open the sidebar's pages in the order the sidebar lists them
 * (Home, History, Settings, then Advanced), and ⌘, opens Settings as on
 * every Mac app.
 */
export function navKeys(order: readonly string[]): Record<string, string> {
  const keys: Record<string, string> = {};
  order.slice(0, 9).forEach((route, i) => (keys[String(i + 1)] = route));
  keys[','] = 'settings';
  return keys;
}

/** Input types that take typing; a checkbox, radio or slider doesn't. */
const TEXT_INPUTS = new Set([
  'text',
  'search',
  'email',
  'url',
  'tel',
  'password',
  'number',
  'date',
  'datetime-local',
  'month',
  'time',
  'week',
]);

/** Whether a key press lands in something the user types into. */
export function isTyping(t: EventTarget | null): boolean {
  if (!t || typeof (t as HTMLElement).tagName !== 'string') return false;
  const el = t as HTMLElement;
  if (el.isContentEditable || el.tagName === 'TEXTAREA' || el.tagName === 'SELECT') return true;
  return el.tagName === 'INPUT' && TEXT_INPUTS.has((el as HTMLInputElement).type || 'text');
}

/** The route a key press asks for, or undefined. Typing in a field never navigates. */
export function navKey(
  e: Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey' | 'altKey' | 'shiftKey'>,
  keys: Record<string, string>,
  isMac: boolean,
  typing: boolean,
): string | undefined {
  if (typing || e.altKey || e.shiftKey || !(isMac ? e.metaKey : e.ctrlKey)) return undefined;
  if (isMac ? e.ctrlKey : e.metaKey) return undefined;
  return keys[e.key];
}

/** Whether a key press is ⌘K (Ctrl+K elsewhere), which opens Ask. Typing in a field never does. */
export function isAskKey(
  e: Pick<KeyboardEvent, 'key' | 'metaKey' | 'ctrlKey' | 'altKey'>,
  isMac: boolean,
  typing: boolean,
): boolean {
  return !typing && e.key.toLowerCase() === 'k' && (isMac ? e.metaKey : e.ctrlKey) && !e.altKey;
}

/** The first key that opens a page, for its tooltip and aria-keyshortcuts. */
export function navShortcut(
  route: string,
  keys: Record<string, string>,
  isMac = mac(),
): { label: string; aria: string } | undefined {
  const key = Object.keys(keys).find((k) => keys[k] === route);
  if (!key) return undefined;
  return {
    label: `${isMac ? '⌘' : 'Ctrl+'}${key}`,
    aria: `${isMac ? 'Meta' : 'Control'}+${key}`,
  };
}
