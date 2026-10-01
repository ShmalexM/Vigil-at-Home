import type { Alert, Severity } from '@vigil/core';

const rank: Record<Severity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

/**
 * Whether an open alert asks the user for a decision ("Needs you"), or is only
 * something Vigil noticed ("Noticed"). An alert needs the user when Vigil is
 * holding something for them to release, when it is high or critical, or when
 * it was trustworthy enough to pop up. Everything else is usually the user's own
 * doing (an installer, a dev tool), so it stays out of the badge and the level.
 */
export function needsDecision(a: Alert): boolean {
  if (a.decision || a.status !== 'open') return false;
  return a.containment === 'active' || rank[a.severity] >= rank.high || a.notify === 'popup';
}

/** Open, undecided, and not asking for a decision. */
export function isNoticed(a: Alert): boolean {
  return !a.decision && a.status === 'open' && !needsDecision(a);
}
