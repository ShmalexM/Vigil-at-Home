import { z } from "zod";
import { ACTIONS, EVENT_KINDS, SEVERITIES, STAGES, TARGETS } from "../types.js";

/**
 * The rule language. Rules are plain JSON so that built-in packs, user rules
 * and AI proposals all go through the same validator, linter and compiler.
 * There is no way to embed code: every operator below is implemented in
 * compile.ts and runs in bounded time.
 */

/** Dotted path into a SensorEvent, plus a few computed fields (see fields.ts). */
export const FieldPath = z
  .string()
  .regex(/^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)*$/, "field paths look like process.signing.status");

const Scalar = z.union([z.string().max(1024), z.number(), z.boolean()]);

export const MATCH_OPS = [
  "eq",
  "neq",
  "in",
  "notIn",
  "startsWith",
  "endsWith",
  "contains",
  "glob",
  "regex",
  "exists",
  "cidr",
  "gt",
  "lt",
] as const;
export type MatchOp = (typeof MATCH_OPS)[number];

export interface MatchCondition {
  field: string;
  op: MatchOp;
  value?: string | number | boolean | Array<string | number>;
  ignoreCase?: boolean;
}
export interface AllCondition {
  all: Condition[];
}
export interface AnyCondition {
  any: Condition[];
}
export interface NotCondition {
  not: Condition;
}
/** True when this combination of values has never been seen on this machine before. */
export interface FirstSeenCondition {
  firstSeen: { key: string[] };
}
/** True when the field's value is on a named local list (known-bad hashes, domains, IPs...). */
export interface InListCondition {
  inList: { list: string; field: string };
}
export type Condition =
  | MatchCondition
  | AllCondition
  | AnyCondition
  | NotCondition
  | FirstSeenCondition
  | InListCondition;

export const MatchConditionSchema = z
  .object({
    field: FieldPath,
    op: z.enum(MATCH_OPS),
    value: z.union([Scalar, z.array(z.union([z.string().max(1024), z.number()])).max(500)]).optional(),
    ignoreCase: z.boolean().optional(),
  })
  .strict();

export const ConditionSchema: z.ZodType<Condition> = z.lazy(() =>
  z.union([
    MatchConditionSchema,
    z.object({ all: z.array(ConditionSchema).min(1).max(50) }).strict(),
    z.object({ any: z.array(ConditionSchema).min(1).max(50) }).strict(),
    z.object({ not: ConditionSchema }).strict(),
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

export const RuleIdSchema = z.string().regex(/^[a-z0-9][a-z0-9-]{2,63}$/, "rule ids are kebab-case");

export const RuleSchema = z
  .object({
    id: RuleIdSchema,
    version: z.number().int().min(1).default(1),
    title: z.string().min(3).max(120),
    description: z.string().max(2000).default(""),
    /** Event kinds the rule looks at. The engine indexes rules by kind. */
    kinds: z.array(z.enum(EVENT_KINDS)).min(1),
    severity: z.enum(SEVERITIES),
    /** What the rule asks for when it matches and is fully trusted. */
    action: z.enum(ACTIONS),
    stage: z.enum(STAGES).default("shadow"),
    /** What a suspend or block acts on. */
    target: z.enum(TARGETS).default("process"),
    condition: ConditionSchema,
    /** Any exclusion matching stops the rule from firing. Tuning adds these. */
    exclusions: z.array(ConditionSchema).max(50).default([]),
    /** Fire only after `count` matches for the same group inside `withinSec`. */
    threshold: z
      .object({
        count: z.number().int().min(2).max(10_000),
        withinSec: z.number().int().min(1).max(86_400),
        groupBy: z.array(FieldPath).min(1).max(4),
      })
      .strict()
      .optional(),
    /** Plain-language reasons. `{{field.path}}` is filled from the event. */
    reasons: z.array(z.string().min(3).max(300)).min(1).max(6),
    dedupe: z
      .object({
        key: z.array(FieldPath).min(1).max(4),
        windowSec: z.number().int().min(0).max(7 * 86_400),
      })
      .strict()
      .optional(),
    /** How to turn a confirmed detection into a Santa rule. */
    santa: z
      .object({
        ruleType: z.enum(["BINARY", "CERTIFICATE", "TEAMID", "SIGNINGID", "CDHASH"]),
        from: FieldPath,
      })
      .strict()
      .optional(),
    tags: z.array(z.string().max(64)).max(20).default([]),
    origin: z.enum(["builtin", "user", "ai"]).default("builtin"),
  })
  .strict();

export type Rule = z.output<typeof RuleSchema>;
export type RuleInput = z.input<typeof RuleSchema>;

export function parseRule(input: unknown): Rule {
  return RuleSchema.parse(input);
}
