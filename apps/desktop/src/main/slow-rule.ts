import type { Alert, Rule, SensorEvent } from '@vigil/core';
import { SLOW_RULE_WINDOW_MS } from '@vigil/detection';
import type { AlertService } from './alerts.js';

/**
 * A rule you or an AI wrote that spends too long matching (the engine's
 * onSlowRule). Vigil keeps it on and keeps every answer it gives: turning it
 * off would let a crafted command line switch off the rule meant to catch it.
 * It is only noted, once, in Noticed (low, silent, no actions), and flagged in
 * Rules for you to review.
 */
export const SLOW_RULE: Rule = {
  id: 'vigil.slow-rule',
  version: 1,
  name: 'Slow rule',
  description:
    'One of your rules took longer than it should to match. It is still on and still decides every event in full; nothing was blocked or changed because of this.',
  origin: 'builtin',
  mode: 'alert',
  severity: 'low',
  fidelity: 'low',
  eventKinds: ['process.exec'],
  condition: { field: 'process.path', op: 'eq', value: '' },
  response: [],
  exclusions: [],
  reasons: [],
  tags: [],
  createdAt: 0,
  updatedAt: 0,
};

export function noteSlowRule(
  alerts: Pick<AlertService, 'raise'>,
  rule: { id: string; name: string },
  ms: number,
  event: SensorEvent,
): Promise<Alert> {
  const minute = SLOW_RULE_WINDOW_MS / 60_000;
  return alerts.raise({
    rule: SLOW_RULE,
    events: [event],
    actions: [],
    title: `Slow rule: ${rule.name}`,
    summary: `"${rule.name}" spent ${Math.round(ms)} ms matching events within ${minute === 1 ? 'a minute' : `${minute} minutes`}. It stays on and keeps deciding every event in full. Look at its patterns in Rules: a narrower field or a shorter pattern usually fixes it.`,
    standalone: true,
  });
}
