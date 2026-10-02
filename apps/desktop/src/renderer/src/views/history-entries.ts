import type { ActionRecord, Alert } from '@vigil/core';

/** How far back History looks. Older detail stays under Advanced › Activity. */
export const DAYS = 30;
export const LIMIT = 150;

export type Entry =
  | { kind: 'alert'; at: number; alert: Alert; actions: ActionRecord[] }
  | { kind: 'action'; at: number; record: ActionRecord };

/** What happened to a handled alert, in one short sentence. */
export function outcome(a: Alert): string {
  if (a.containment === 'active') return 'Still blocked';
  const v = a.decision?.verdict;
  if (v === 'malicious') return 'You kept it blocked';
  if (v === 'benign' || v === 'expected') {
    return a.containment === 'released' ? 'You allowed it' : 'You marked it fine';
  }
  return 'Closed';
}

/**
 * Handled alerts, with what was done about each, and every other action
 * (including those on alerts still open, which Home shows). Newest first.
 */
export function historyEntries(
  alerts: Alert[],
  actions: ActionRecord[],
  now = Date.now(),
): Entry[] {
  const since = now - DAYS * 86_400_000;
  const handled = new Set(alerts.map((a) => a.id));
  const byAlert = new Map<string, ActionRecord[]>();
  const loose: ActionRecord[] = [];
  for (const r of actions) {
    if (r.alertId && handled.has(r.alertId)) {
      byAlert.set(r.alertId, [...(byAlert.get(r.alertId) ?? []), r]);
    } else loose.push(r);
  }
  const entries: Entry[] = [
    ...alerts.map((a): Entry => ({
      kind: 'alert',
      at: a.updatedAt,
      alert: a,
      actions: byAlert.get(a.id) ?? [],
    })),
    ...loose.map((r): Entry => ({ kind: 'action', at: r.requestedAt, record: r })),
  ];
  return entries
    .filter((e) => e.at >= since)
    .sort((a, b) => b.at - a.at)
    .slice(0, LIMIT);
}
