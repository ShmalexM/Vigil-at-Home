import type { ActionRecord, Alert } from '@vigil/core';
import { responseProvenance } from '../decision';
import { simulatedNote } from '../format';

/** How far back History looks. Older detail stays under Advanced › Activity. */
export const DAYS = 30;
export const LIMIT = 150;

export type Entry =
  | { kind: 'alert'; at: number; alert: Alert; actions: ActionRecord[] }
  | { kind: 'action'; at: number; record: ActionRecord };

/**
 * What happened to a handled alert, in one short sentence. Worded from what
 * its actions really did (responseProvenance, as the popup is), so a
 * simulated or unrecorded block is never told as a real one.
 */
export function outcome(a: Alert, actions: readonly ActionRecord[]): string {
  const response = responseProvenance(actions);
  const note = simulatedNote(response);
  if (a.containment === 'active') {
    if (response === 'real') return 'Still blocked';
    if (response === 'simulated') return 'Would have been blocked (simulated)';
    if (response === 'mixed') return 'Still blocked (partly simulated)';
    return 'Vigil acted (may have been simulated)';
  }
  const v = a.decision?.verdict;
  if (v === 'malicious') {
    if (response === 'real') return 'You kept it blocked';
    if (response === 'mixed') return 'You kept it blocked (partly simulated)';
    return `You marked it malicious${note ? ` (${note})` : ''}`;
  }
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

/**
 * The entries whose words match every word of the search, ignoring case. The
 * words are what the row shows plus what's behind it: the alert's title and
 * summary, its subject's name and path, and each action's description.
 */
export function filterEntries(
  entries: Entry[],
  query: string,
  describe: (r: ActionRecord) => string,
): Entry[] {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  if (words.length === 0) return entries;
  return entries.filter((e) => {
    const text = (
      e.kind === 'alert'
        ? [
            e.alert.title,
            e.alert.summary,
            e.alert.subject?.label ?? '',
            e.alert.subject?.path ?? '',
            outcome(e.alert, e.actions),
            ...e.actions.map(describe),
          ]
        : [describe(e.record), e.record.reason]
    )
      .join('\n')
      .toLowerCase();
    return words.every((w) => text.includes(w));
  });
}
