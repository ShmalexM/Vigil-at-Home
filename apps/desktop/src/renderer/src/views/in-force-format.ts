import type { InForceFlag, InForceItem, InForceKind } from '../../../shared/in-force';

/** Section headings, in the order the page shows them. */
export const KIND_LABEL: Record<InForceKind, string> = {
  'block-list': 'Your block list',
  program: 'Blocked programs',
  prelaunch: 'Stopped before launch',
  network: 'Blocked connections',
  quarantine: 'In quarantine',
  paused: 'Paused processes',
  startup: 'Startup items turned off',
};

export const FLAG_LABEL: Record<InForceFlag, string> = {
  'apple-program': 'Part of the system',
  'test-leftover': 'Left by a test',
  'long-running': 'Forgotten?',
};

export const FLAG_WHY: Record<InForceFlag, string> = {
  'apple-program':
    'This blocks a program that comes with the system. Apps and scripts may need it.',
  'test-leftover': 'This points at a folder only Vigil’s own tests use.',
  'long-running':
    'Vigil did this on its own more than a week ago and nobody has looked at it since.',
};

const DAY = 24 * 60 * 60 * 1000;

/** "for 12 days", "since today": how long it has been in force. */
export function ageWords(since: number | undefined, now = Date.now()): string | undefined {
  if (since === undefined) return undefined;
  const days = Math.floor((now - since) / DAY);
  if (days < 1) return 'since today';
  return days === 1 ? 'for 1 day' : `for ${days} days`;
}

/** "stops in 3 days": when a block-list entry the app dropped stops on its own. */
export function untilWords(until: number | undefined, now = Date.now()): string | undefined {
  if (until === undefined) return undefined;
  const days = Math.ceil((until - now) / DAY);
  if (days <= 1) return 'stops within a day';
  return `stops in ${days} days`;
}

/** Items grouped by kind, in KIND_LABEL's order, empty groups left out. */
export function groupItems(items: readonly InForceItem[]): [InForceKind, InForceItem[]][] {
  const order = Object.keys(KIND_LABEL) as InForceKind[];
  return order
    .map((k) => [k, items.filter((i) => i.kind === k)] as [InForceKind, InForceItem[]])
    .filter(([, list]) => list.length > 0);
}
