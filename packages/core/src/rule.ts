import { z } from 'zod';
import { ActionKind, type Actor } from './action.js';
import { Severity, Timestamp } from './common.js';
import { EventKind } from './event.js';

/**
 * Deterministic detection rules. Rules decide inline, in milliseconds, with no
 * AI in the loop. The AI helps offline: it can draft rules from traffic it has
 * analysed, but a drafted rule starts in `shadow` and only the user promotes it.
 * That keeps the AI's false positives out of anything that blocks or pops up.
 */

/** A leaf test on one event field. `field` is a dotted path, e.g. `process.teamId`. */
export const FieldTest = z.object({
  field: z.string(),
  op: z.enum([
    'eq',
    'neq',
    'in',
    'contains',
    'startsWith',
    'endsWith',
    'glob',
    'regex',
    'gt',
    'lt',
    'exists',
    'cidr',
  ]),
  value: z
    .union([z.string(), z.number(), z.boolean(), z.array(z.union([z.string(), z.number()]))])
    .optional(),
  /** Case-insensitive string comparison. */
  nocase: z.boolean().optional(),
});
export type FieldTest = z.infer<typeof FieldTest>;

export type Condition =
  FieldTest | { all: Condition[] } | { any: Condition[] } | { not: Condition };

export const Condition: z.ZodType<Condition> = z.lazy(() =>
  z.union([
    FieldTest,
    z.object({ all: z.array(Condition).min(1) }),
    z.object({ any: z.array(Condition).min(1) }),
    z.object({ not: Condition }),
  ]),
);

/** Fire only after `count` matches within `windowSec`, grouped by the given fields. */
export const Threshold = z.object({
  count: z.number().int().min(2),
  windowSec: z.number().int().positive(),
  groupBy: z.array(z.string()).optional(),
});
export type Threshold = z.infer<typeof Threshold>;

/**
 * What a matching rule does.
 * - disabled: nothing.
 * - shadow: records the match for review; no alert, no popup, no block.
 * - alert: raises an alert and popup; proposes its response for the user.
 * - block: runs its response immediately, then raises the alert and popup.
 */
export const RuleMode = z.enum(['disabled', 'shadow', 'alert', 'block']);
export type RuleMode = z.infer<typeof RuleMode>;

export const RuleOrigin = z.enum(['builtin', 'user', 'ai', 'feed']);
export type RuleOrigin = z.infer<typeof RuleOrigin>;

/**
 * An action template. String values may reference event fields as `{{field.path}}`,
 * resolved by the engine at match time, e.g. `{ kind: 'process.suspend', pid: '{{process.pid}}' }`.
 */
export const ResponseTemplate = z
  .object({ kind: ActionKind })
  .catchall(z.union([z.string(), z.number(), z.boolean()]));
export type ResponseTemplate = z.infer<typeof ResponseTemplate>;

export const Rule = z.object({
  /** Stable slug, e.g. `persistence.unsigned-launch-agent`. */
  id: z.string().regex(/^[a-z0-9][a-z0-9._-]*$/),
  version: z.number().int().positive(),
  name: z.string(),
  description: z.string(),
  origin: RuleOrigin,
  mode: RuleMode,
  severity: Severity,
  /** Expected false-positive rate, used to rank alerts and in the popup copy. */
  fidelity: z.enum(['high', 'medium', 'low']),
  eventKinds: z.array(EventKind).min(1),
  condition: Condition,
  threshold: Threshold.optional(),
  response: z.array(ResponseTemplate).default([]),
  /** MITRE ATT&CK technique ids and free tags. */
  tags: z.array(z.string()).default([]),
  createdAt: Timestamp,
  updatedAt: Timestamp,
  /** For AI-drafted rules: why, and the events it was built from. */
  provenance: z
    .object({
      provider: z.string().optional(),
      rationale: z.string(),
      sampleEventIds: z.array(z.string()).default([]),
    })
    .optional(),
});
export type Rule = z.infer<typeof Rule>;

/** Every match, in any mode except disabled. Shadow stats come from here. */
export const RuleMatch = z.object({
  id: z.string(),
  ruleId: z.string(),
  ruleVersion: z.number().int(),
  mode: RuleMode,
  ts: Timestamp,
  eventIds: z.array(z.string()).min(1),
  /** Set when the match raised an alert. */
  alertId: z.string().optional(),
});
export type RuleMatch = z.infer<typeof RuleMatch>;

const modeRank: Record<RuleMode, number> = { disabled: 0, shadow: 1, alert: 2, block: 3 };

/**
 * Only the user may make a rule louder (shadow to alert, alert to block).
 * Anyone may make it quieter: the engine can auto-demote a noisy rule.
 * The AI may create rules only as disabled or shadow.
 */
export function canChangeMode(actor: Actor, from: RuleMode | null, to: RuleMode): boolean {
  if (actor === 'user') return true;
  if (from === null) return modeRank[to] <= modeRank.shadow;
  return modeRank[to] <= modeRank[from];
}
