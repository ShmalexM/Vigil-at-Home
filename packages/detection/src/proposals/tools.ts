import { z } from 'zod';
import type { DetectionEngine } from '../engine.js';
import { COMPUTED_FIELDS, KNOWN_FIELDS } from '../rules/fields.js';
import type { EventHistory } from '../state/stores.js';
import { DetectionRule, MATCH_OPS } from '../types.js';
import {
  ProposeRuleInput,
  ProposeTuningInput,
  type RulePipeline,
  type SubmitResult,
} from './pipeline.js';
import { RULE_REVIEW_PROMPT } from './prompt.js';
import { summarizeTelemetry } from './telemetry.js';

/**
 * How detection plugs into the AI layer (@vigil/ai). The agent gets two
 * read-only tools. Its answer is a structured list of proposals, which Vigil
 * (not the agent) submits to the pipeline, where they are checked, replayed
 * and queued for the user. Nothing the agent does changes a live rule.
 *
 * The shapes here match @vigil/ai's ReadTool and RunRequest structurally, so
 * this package does not depend on it.
 */
export interface DetectionToolContext {
  engine: DetectionEngine;
  pipeline: RulePipeline;
  history: EventHistory;
  now?: () => number;
}

export interface ReadToolLike<Shape extends z.ZodRawShape = z.ZodRawShape> {
  readonly name: string;
  readonly description: string;
  readonly input: Shape;
  run(args: z.infer<z.ZodObject<Shape>>): Promise<unknown>;
}

export function ruleLanguageGuide() {
  const schema = z.toJSONSchema(DetectionRule, { io: 'input' }) as Record<string, unknown>;
  delete schema.$schema;
  return {
    ruleJsonSchema: schema,
    fields: [...KNOWN_FIELDS],
    computedFields: COMPUTED_FIELDS,
    operators: MATCH_OPS,
    constraints: [
      'Your rule id gets an "ai-" prefix. Every proposed rule starts in shadow mode; only the user makes it louder. Any mode, origin, version or dates you set are ignored.',
      'Responses that kill, block, quarantine, disable or add a Santa rule need a specific anchor: a hash, team ID, signing ID, host, address or extension ID, or a list.',
      'A behaviour-only rule may respond with process.suspend only at high or critical severity; otherwise give no response and let it alert.',
      'Responses may only contain a threat: nothing that resumes, unblocks, restores or allows.',
      'Regexes: at most 256 characters, with no backreferences or nested quantifiers.',
      'Prefer narrow rules. A rule that would alert more than once a day on replay is marked noisy.',
      'firstSeen means never seen on this Mac before. On a new install Vigil is still learning, so these only record at first.',
      'Write reasons in plain language for someone who is not a security expert. Use {{field.path}} to fill values from the event.',
    ],
  };
}

export function detectionReadTools(ctx: DetectionToolContext): ReadToolLike[] {
  const now = ctx.now ?? Date.now;
  const telemetry: ReadToolLike<{ sinceHours: z.ZodDefault<z.ZodNumber> }> = {
    name: 'get_telemetry_summary',
    description:
      "Read a redacted summary of recent activity on this Mac (top network talkers, unsigned programs, new login items, listeners, browser extensions), how each detection rule is doing, and the user's notes on proposals they rejected. Use it to find gaps and noisy rules.",
    input: {
      sinceHours: z
        .number()
        .int()
        .min(1)
        .max(24 * 30)
        .default(24 * 7),
    },
    run: async ({ sinceHours }) => {
      const to = now();
      return summarizeTelemetry({
        history: ctx.history,
        engine: ctx.engine,
        pipeline: ctx.pipeline,
        from: to - sinceHours * 3_600_000,
        to,
      });
    },
  };
  const guide: ReadToolLike<Record<string, never>> = {
    name: 'get_rule_language',
    description:
      'Read the rule format: fields, operators, and the constraints proposals must meet. Call this before proposing.',
    input: {},
    run: async () => ruleLanguageGuide(),
  };
  return [telemetry as unknown as ReadToolLike, guide as unknown as ReadToolLike];
}

/** The structured answer of a rule-review run. */
export const RuleReviewOutput = z.object({
  newRules: z.array(ProposeRuleInput).max(3),
  tunings: z.array(ProposeTuningInput).max(5),
  /** One or two sentences for the user on what was proposed and why. */
  summary: z.string().max(1000),
});
export type RuleReviewOutput = z.infer<typeof RuleReviewOutput>;

export interface ReviewSubmission {
  results: Array<{ kind: 'new_rule' | 'tuning'; ref: string; result: SubmitResult }>;
  accepted: number;
  rejected: number;
}

/** Submit a review run's proposals. Vigil does this, not the agent. */
export function submitReview(
  output: RuleReviewOutput,
  pipeline: RulePipeline,
  provider: string,
): ReviewSubmission {
  const results: ReviewSubmission['results'] = [];
  for (const r of output.newRules) {
    const ref = typeof r.rule.id === 'string' ? r.rule.id : '(no id)';
    results.push({ kind: 'new_rule', ref, result: pipeline.submitRule(r, provider) });
  }
  for (const t of output.tunings) {
    results.push({ kind: 'tuning', ref: t.ruleId, result: pipeline.submitTuning(t, provider) });
  }
  const accepted = results.filter((r) => r.result.ok).length;
  return { results, accepted, rejected: results.length - accepted };
}

/** What a runner (@vigil/ai's AiRunner) must accept. */
export interface AnalyzeRunner {
  run<T>(req: {
    purpose: 'analyze';
    urgency: 'background';
    instructions: string;
    data: unknown;
    output: z.ZodType<T>;
    tools?: readonly ReadToolLike[];
    deadlineMs: number;
  }): Promise<
    { ok: true; value: T; provider: string } | { ok: false; reason: string; detail?: string }
  >;
}

/**
 * One scheduled rule review: the agent reads, answers with proposals, Vigil
 * submits them. If some fail the checks, the agent gets one more run with the
 * errors so it can fix them.
 */
export async function runRuleReview(
  runner: AnalyzeRunner,
  ctx: DetectionToolContext,
  opts: { deadlineMs?: number } = {},
): Promise<{ ok: boolean; submissions: ReviewSubmission[]; summary?: string; error?: string }> {
  const tools = detectionReadTools(ctx);
  const deadlineMs = opts.deadlineMs ?? 5 * 60_000;
  const submissions: ReviewSubmission[] = [];
  let data: unknown = {};
  let summary: string | undefined;
  for (let round = 0; round < 2; round++) {
    const res = await runner.run({
      purpose: 'analyze',
      urgency: 'background',
      instructions: RULE_REVIEW_PROMPT,
      data,
      output: RuleReviewOutput,
      tools,
      deadlineMs,
    });
    if (!res.ok) {
      const out: { ok: boolean; submissions: ReviewSubmission[]; summary?: string; error: string } =
        {
          ok: submissions.length > 0,
          submissions,
          error: res.detail ? `${res.reason}: ${res.detail}` : res.reason,
        };
      if (summary !== undefined) out.summary = summary;
      return out;
    }
    summary = res.value.summary;
    const sub = submitReview(res.value, ctx.pipeline, res.provider);
    submissions.push(sub);
    const failed = sub.results.filter((r) => !r.result.ok && r.result.errors.length > 0);
    if (failed.length === 0) break;
    data = {
      previousAttemptFailedChecks: failed.map((f) => ({
        kind: f.kind,
        ref: f.ref,
        errors: f.result.errors,
      })),
      note: 'Fix these and resubmit only the ones you still believe in. The accepted ones are already queued.',
    };
  }
  const out: { ok: boolean; submissions: ReviewSubmission[]; summary?: string } = {
    ok: true,
    submissions,
  };
  if (summary !== undefined) out.summary = summary;
  return out;
}
