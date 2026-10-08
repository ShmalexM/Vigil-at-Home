import type { Alert } from '@vigil/core';

/** One row in Needs you: a single alert, or a pile of alerts that share a rule and an agent run or program. */
export type Row =
  { kind: 'alert'; alert: Alert } | { kind: 'pile'; key: string; who: string; alerts: Alert[] };

/**
 * Groups alerts into rows, keeping their order (the first alert of a pile
 * places its row). A pile needs two or more alerts that are still open,
 * undecided and holding nothing; anything else shows on its own.
 */
export function pileUp(alerts: readonly Alert[]): Row[] {
  const rows: Row[] = [];
  const piles = new Map<string, Extract<Row, { kind: 'pile' }>>();
  for (const a of alerts) {
    const key = pileable(a) ? a.pile!.key : undefined;
    const pile = key ? piles.get(key) : undefined;
    if (pile) {
      pile.alerts.push(a);
      continue;
    }
    if (key) {
      const row = { kind: 'pile' as const, key, who: a.pile!.who, alerts: [a] };
      piles.set(key, row);
      rows.push(row);
    } else {
      rows.push({ kind: 'alert', alert: a });
    }
  }
  // A pile of one is just that alert.
  return rows.map((r) =>
    r.kind === 'pile' && r.alerts.length === 1 ? { kind: 'alert', alert: r.alerts[0]! } : r,
  );
}

function pileable(a: Alert): boolean {
  return !!a.pile && closableUnasked(a);
}

/**
 * An alert that can be closed in bulk without asking about it: open,
 * undecided, holding nothing back, with no action taken or suggested (an
 * AI suggestion would otherwise expire unseen).
 */
export function closableUnasked(a: Alert): boolean {
  return (
    !a.decision &&
    a.status === 'open' &&
    a.containment === 'none' &&
    a.actionIds.length === 0 &&
    (a.ai?.proposalIds.length ?? 0) === 0
  );
}

/** The alerts in the same pile as `alert` among `alerts` (itself included), or just it. */
export function pileMates(alert: Alert, alerts: readonly Alert[]): Alert[] {
  for (const r of pileUp(alerts)) {
    if (r.kind === 'pile' && r.alerts.some((a) => a.id === alert.id)) return r.alerts;
  }
  return [alert];
}

/** The folder every path starts with (ending in `/`), or '' when they share none or there is one path. */
export function commonFolder(paths: readonly string[]): string {
  if (paths.length < 2) return '';
  let prefix = paths[0]!;
  for (const p of paths) {
    while (!p.startsWith(prefix)) prefix = prefix.slice(0, -1);
  }
  const cut = prefix.lastIndexOf('/');
  return cut > 0 ? prefix.slice(0, cut + 1) : '';
}
