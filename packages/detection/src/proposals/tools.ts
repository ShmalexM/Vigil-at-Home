import { z } from "zod";
import type { DetectionEngine } from "../engine.js";
import { MATCH_OPS, RuleSchema } from "../rules/schema.js";
import { COMPUTED_FIELDS, KNOWN_FIELDS } from "../rules/fields.js";
import type { EventHistory } from "../state/stores.js";
import { ProposeRuleInput, ProposeTuningInput, type RulePipeline, type SubmitResult } from "./pipeline.js";
import { summarizeTelemetry, type TelemetrySummary } from "./telemetry.js";

/**
 * The only detection capabilities an AI agent gets. Two of them only queue a
 * proposal; the other two only read. None can change a live rule, allow a
 * program or touch the Mac. The subscription-integration layer registers
 * these as MCP tools with the input schemas below.
 */
export interface ToolContext {
  engine: DetectionEngine;
  pipeline: RulePipeline;
  history: EventHistory;
  /** Which provider is running (claude, codex, copilot, ollama...), for the audit trail and rate limits. */
  provider: string;
  now?: () => number;
}

export const TelemetrySummaryInput = z
  .object({ sinceHours: z.number().int().min(1).max(24 * 30).default(24 * 7) })
  .strict();

export const RuleLanguageInput = z.object({}).strict();

export const detectionTools = {
  get_telemetry_summary: {
    description:
      "Read a redacted summary of recent activity on this Mac (top network talkers, unsigned programs, new login items, listeners, browser extensions) and how each detection rule is performing, including rules the user marked as wrong and proposals they rejected with their reasons. Use this to find gaps and noisy rules.",
    input: TelemetrySummaryInput,
  },
  get_rule_language: {
    description:
      "Read the rule format: fields, operators, and the constraints proposals must meet. Call this before proposing.",
    input: RuleLanguageInput,
  },
  propose_rule: {
    description:
      "Propose a new deterministic detection rule. It is checked, replayed against this Mac's recent history, and shown to the user, who decides whether it goes live. You cannot enable it yourself. Errors come back so you can fix and resubmit.",
    input: ProposeRuleInput,
  },
  propose_tuning: {
    description:
      "Propose an exclusion that stops an existing rule firing on something specific (a program, signer, domain) that is clearly benign. The change is replayed and shown to the user; it is refused if it would hide a confirmed threat.",
    input: ProposeTuningInput,
  },
} as const;

export type DetectionToolName = keyof typeof detectionTools;

/** JSON Schemas for MCP registration. */
export function detectionToolJsonSchemas(): Record<DetectionToolName, { description: string; inputSchema: unknown }> {
  const out = {} as Record<DetectionToolName, { description: string; inputSchema: unknown }>;
  for (const [name, t] of Object.entries(detectionTools) as Array<[DetectionToolName, (typeof detectionTools)[DetectionToolName]]>) {
    out[name] = { description: t.description, inputSchema: z.toJSONSchema(t.input, { io: "input" }) };
  }
  return out;
}

export function ruleLanguageGuide() {
  return {
    ruleJsonSchema: z.toJSONSchema(RuleSchema, { io: "input" }),
    fields: [...KNOWN_FIELDS],
    computedFields: COMPUTED_FIELDS,
    operators: MATCH_OPS,
    constraints: [
      'Your rule id gets an "ai-" prefix. Stage is always chosen by the user; anything you set is ignored.',
      "block needs a specific anchor: a hash, signer (teamId/signingId), domain, address, extension id, launch item, or a list.",
      "Behaviour-only rules may ask for suspend only at high or critical severity; otherwise use alert or record.",
      "suspend applies to processes. Network and persistence rules use block or alert.",
      "Regexes: at most 256 characters, no backreferences or nested quantifiers.",
      "Prefer narrow rules. A rule that would interrupt the user more than once a day on replay is marked noisy.",
      "firstSeen means never seen on this Mac before. On a new install Vigil is still learning, so these only record at first.",
      "Explain in reasons, in plain language, what happened. Use {{field.path}} to fill values from the event.",
    ],
  };
}

export type ToolResult =
  | { ok: true; summary: TelemetrySummary }
  | { ok: true; guide: ReturnType<typeof ruleLanguageGuide> }
  | SubmitResult
  | { ok: false; errors: string[] };

export function handleDetectionTool(name: string, input: unknown, ctx: ToolContext): ToolResult {
  const now = ctx.now ?? Date.now;
  switch (name) {
    case "get_telemetry_summary": {
      const parsed = TelemetrySummaryInput.safeParse(input ?? {});
      if (!parsed.success) return { ok: false, errors: parsed.error.issues.map((i) => i.message) };
      const to = now();
      return {
        ok: true,
        summary: summarizeTelemetry({
          history: ctx.history,
          engine: ctx.engine,
          pipeline: ctx.pipeline,
          from: to - parsed.data.sinceHours * 3_600_000,
          to,
        }),
      };
    }
    case "get_rule_language":
      return { ok: true, guide: ruleLanguageGuide() };
    case "propose_rule":
      return ctx.pipeline.submitRule(input, ctx.provider);
    case "propose_tuning":
      return ctx.pipeline.submitTuning(input, ctx.provider);
    default:
      return { ok: false, errors: [`unknown tool ${name}`] };
  }
}
