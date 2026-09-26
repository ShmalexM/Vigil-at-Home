import type { Alert } from '@vigil/core';
import {
  EventKind as CoreEventKind,
  FieldTest as CoreFieldTest,
  Id,
  ProcessRef,
  Rule as CoreRule,
  SantaRuleType,
  Timestamp,
  type Action,
  type RuleMatch,
  type RuleMode,
  type SensorEvent,
} from '@vigil/core';
import { z } from 'zod';

/**
 * Detection's additions to @vigil/core. Each one is an `.extend()` of a core
 * schema and has been proposed for core; once core carries it, the local copy
 * here is deleted and nothing else changes.
 */

// ---------------------------------------------------------------- events

/** Set when the executable carries the com.apple.quarantine attribute (it came from the internet). */
export const Quarantine = z.object({
  originUrl: z.string().optional(),
  agent: z.string().optional(),
});

export const DetectionProcessRef = ProcessRef.extend({ quarantine: Quarantine.optional() });
export type DetectionProcessRef = z.infer<typeof DetectionProcessRef>;

const extraBase = {
  id: Id,
  ts: Timestamp,
  source: z.enum(['osquery', 'santa', 'vigil', 'test']),
  raw: z.unknown().optional(),
};

/** A program started accepting connections. */
export const NetworkListenEvent = z.object({
  ...extraBase,
  kind: z.literal('network.listen'),
  protocol: z.enum(['tcp', 'udp', 'other']),
  localAddress: z.string(),
  localPort: z.number().int(),
  process: DetectionProcessRef.optional(),
});
export type NetworkListenEvent = z.infer<typeof NetworkListenEvent>;

export const BrowserExtensionEvent = z.object({
  ...extraBase,
  kind: z.literal('browser.extension'),
  change: z.enum(['added', 'modified', 'removed']),
  browser: z.string(),
  extensionId: z.string(),
  name: z.string().optional(),
  permissions: z.array(z.string()).optional(),
});
export type BrowserExtensionEvent = z.infer<typeof BrowserExtensionEvent>;

/** Everything the engine can evaluate: core events (whose process may carry `quarantine`) plus the two above. */
export type DetectionEvent = SensorEvent | NetworkListenEvent | BrowserExtensionEvent;

export const DetectionEventKind = z.enum([
  ...CoreEventKind.options,
  'network.listen',
  'browser.extension',
]);
export type DetectionEventKind = z.infer<typeof DetectionEventKind>;

// ---------------------------------------------------------------- rules

export const MATCH_OPS = [...CoreFieldTest.shape.op.options, 'notIn'] as const;
export type MatchOp = (typeof MATCH_OPS)[number];

export const FieldPath = z
  .string()
  .regex(
    /^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)*$/,
    'field paths look like process.teamId or remoteHost',
  );

export const FieldTest = CoreFieldTest.extend({
  field: FieldPath,
  op: z.enum(MATCH_OPS),
  value: z
    .union([
      z.string().max(1024),
      z.number(),
      z.boolean(),
      z.array(z.union([z.string().max(1024), z.number()])).max(500),
    ])
    .optional(),
}).strict();
export type FieldTest = z.infer<typeof FieldTest>;

/** True when this combination of values was never seen on this Mac for this rule's event kinds. */
export interface FirstSeenCondition {
  firstSeen: { key: string[] };
}
/** True when the field's value is on a named local list. IPs match by CIDR, domains by parent domain. */
export interface InListCondition {
  inList: { list: string; field: string };
}
export type Condition =
  | FieldTest
  | { all: Condition[] }
  | { any: Condition[] }
  | { not: Condition }
  | FirstSeenCondition
  | InListCondition;

export const Condition: z.ZodType<Condition> = z.lazy(() =>
  z.union([
    FieldTest,
    z.object({ all: z.array(Condition).min(1).max(50) }).strict(),
    z.object({ any: z.array(Condition).min(1).max(50) }).strict(),
    z.object({ not: Condition }).strict(),
    z.object({ firstSeen: z.object({ key: z.array(FieldPath).min(1).max(4) }).strict() }).strict(),
    z
      .object({
        inList: z
          .object({ list: z.string().regex(/^[a-z][a-z0-9_]{1,63}$/), field: FieldPath })
          .strict(),
      })
      .strict(),
  ]),
) as z.ZodType<Condition>;

/** A core Rule with the fields detection needs: first-seen and list conditions, exclusions, popup text, dedupe. */
export const DetectionRule = CoreRule.extend({
  eventKinds: z.array(DetectionEventKind).min(1),
  condition: Condition,
  /** Any exclusion matching stops the rule firing. AI tuning adds these. */
  exclusions: z.array(Condition).max(50).default([]),
  /** Plain-language reasons for the popup, rendered locally with no AI. `{{field.path}}` is filled from the event. */
  reasons: z.array(z.string().min(3).max(300)).min(1).max(6),
  /** The same rule and key raise one alert per window (default 1 hour). Containment still runs every time. */
  dedupe: z
    .object({
      key: z.array(FieldPath).min(1).max(4),
      windowSec: z
        .number()
        .int()
        .min(0)
        .max(7 * 86_400),
    })
    .strict()
    .optional(),
  /** The Santa rule to install when the user confirms a detection as malicious. */
  santa: z.object({ ruleType: SantaRuleType, from: FieldPath }).strict().optional(),
});
export type DetectionRule = z.infer<typeof DetectionRule>;
export type DetectionRuleInput = z.input<typeof DetectionRule>;

// ---------------------------------------------------------------- output

/** What one rule firing on one event means for the app. */
export interface Detection {
  /** Always present. Shadow statistics and replay are built from these. */
  match: RuleMatch;
  /**
   * Present when the rule's effective mode is alert or block and this is not a
   * repeat inside the dedupe window. The app stores it and shows the popup.
   */
  alert?: Alert;
  /** Mode block: run these now as actor "rule", after the safety floor. */
  execute: Action[];
  /** Mode alert: offer these in the popup for the user to approve. */
  propose: Action[];
  /** Plain-language reasons (also the alert summary). */
  reasons: string[];
  /** Why the effective mode or actions are weaker than the rule asks for. */
  downgrades: string[];
  /** The rule's own mode and the one actually applied. */
  ruleMode: RuleMode;
  mode: RuleMode;
  /** True when the rule already alerted for this key inside its dedupe window. */
  deduped: boolean;
  /** The Santa rule to add if the user confirms this as malicious. */
  santa?: Extract<Action, { kind: 'santa.rule.set' }>;
  /** The event, for the app's own records. */
  event: DetectionEvent;
}

export type { Action, Alert, RuleMatch, RuleMode, SensorEvent };
