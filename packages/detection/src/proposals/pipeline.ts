import { newId, type RuleMode } from '@vigil/core';
import { z } from 'zod';
import { compileRule, type DetectionEngine } from '../engine.js';
import { USER_BLOCKED_HASHES } from '../feedback.js';
import { assertUserOrigin, type UserOrigin } from '../origin.js';
import { lintRule, type LintResult } from '../rules/lint.js';
import type { EventHistory } from '../state/stores.js';
import { Condition, DetectionRule } from '../types.js';
import { proveChange, type ImpactReport } from './prover.js';
import { replayRule, type ReplayReport } from './replay.js';

export type ProposalStatus =
  'rejected_by_checks' | 'awaiting_review' | 'approved' | 'rejected' | 'withdrawn';

export interface Proposal {
  id: string;
  /** new_rule adds a rule; tuning adds an exclusion; retire turns a rule down (shadow or off). */
  kind: 'new_rule' | 'tuning' | 'retire';
  createdAt: number;
  /** Which AI provider proposed it (e.g. "claude", "codex", "ollama"). */
  provider: string;
  rationale: string;
  evidence: string[];
  /** For a new rule, the rule; for tuning, the rule as it would be after the change. */
  rule: DetectionRule;
  baseRuleId?: string;
  baseRuleVersion?: number;
  status: ProposalStatus;
  lint: LintResult;
  replay?: ReplayReport;
  /** For tuning: what the change removes. */
  tuning?: {
    hitsBefore: number;
    hitsAfter: number;
    removed: number;
    removedConfirmedThreats: number;
  };
  /** For retire: the quieter mode the rule would move to (alert only for Vigil's own suggestions). */
  retireTo?: 'alert' | 'shadow' | 'disabled';
  /** What approving it would stop catching, including look-alikes that would slip through. */
  impact?: ImpactReport;
  decidedAt?: number;
  decidedVia?: string;
  decisionNote?: string;
  approvedMode?: RuleMode;
}

export interface ProposalStore {
  put(p: Proposal): void;
  get(id: string): Proposal | undefined;
  list(): Proposal[];
}

export class MemoryProposalStore implements ProposalStore {
  private readonly m = new Map<string, Proposal>();
  put(p: Proposal): void {
    this.m.set(p.id, structuredClone(p));
  }
  get(id: string): Proposal | undefined {
    const p = this.m.get(id);
    return p && structuredClone(p);
  }
  list(): Proposal[] {
    return [...this.m.values()]
      .map((p) => structuredClone(p))
      .sort((a, b) => b.createdAt - a.createdAt);
  }
}

/** What an AI may send when proposing a new rule. Mode, origin, version and dates are set by Vigil. */
export const ProposeRuleInput = z
  .object({
    rule: z.record(z.string(), z.unknown()),
    rationale: z.string().min(10).max(2000),
    evidence: z.array(z.string().max(500)).max(20).default([]),
  })
  .strict();
export type ProposeRuleInput = z.input<typeof ProposeRuleInput>;

export const ProposeTuningInput = z
  .object({
    ruleId: z.string(),
    addExclusion: Condition,
    rationale: z.string().min(10).max(2000),
    evidence: z.array(z.string().max(500)).max(20).default([]),
  })
  .strict();
export type ProposeTuningInput = z.input<typeof ProposeTuningInput>;

/** What an AI may send when proposing to turn a noisy or stale rule down. */
export const ProposeRetirementInput = z
  .object({
    ruleId: z.string().min(1).max(100),
    toMode: z.enum(['shadow', 'disabled']),
    rationale: z.string().min(1).max(2000),
    evidence: z.array(z.string().max(500)).min(1).max(20),
  })
  .strict();
export type ProposeRetirementInput = z.input<typeof ProposeRetirementInput>;

const MODE_RANK: Record<RuleMode, number> = { disabled: 0, shadow: 1, alert: 2, block: 3 };

export interface SubmitResult {
  ok: boolean;
  proposalId?: string;
  status?: ProposalStatus;
  /** Problems the AI can fix and resubmit. */
  errors: string[];
  /** Resubmitting cannot help (a budget, or the same proposal already waiting). */
  final?: boolean;
  warnings: string[];
  replay?: ReplayReport;
}

export interface PipelineOptions {
  /** How much history to replay against. */
  replayDays?: number;
  /** Most proposals waiting for review at once. */
  maxPending?: number;
  /** Most proposals accepted per provider per day. */
  maxPerDay?: number;
  now?: () => number;
  /** Where approved rules are saved so they survive a restart. */
  repository?: { save(rule: DetectionRule, ts: number): void };
}

/** More alerts a day than this from a new AI rule means it matches ordinary use. */
const MAX_NEW_RULE_ALERTS_PER_DAY = 3;
/** Provider name on suggestions Vigil makes from the user's own answers, not an AI. */
export const VIGIL_PROVIDER = 'vigil';
const DAY = 86_400_000;

/**
 * The out-of-band path from AI analysis to live rules:
 *
 *   AI proposes -> schema check -> linter -> replay on this Mac's history
 *     -> waits for the user -> user approves (choosing the mode) -> live
 *
 * Nothing here runs on the inline path, and nothing an AI can call changes
 * a live rule: approve() and reject() need a UserOrigin.
 */
export class RulePipeline {
  private readonly opts: Required<Omit<PipelineOptions, 'repository'>>;
  private readonly repository: PipelineOptions['repository'];

  constructor(
    private readonly engine: DetectionEngine,
    private readonly history: EventHistory,
    private readonly store: ProposalStore = new MemoryProposalStore(),
    opts: PipelineOptions = {},
  ) {
    this.opts = {
      replayDays: opts.replayDays ?? 14,
      maxPending: opts.maxPending ?? 20,
      maxPerDay: opts.maxPerDay ?? 10,
      now: opts.now ?? Date.now,
    };
    this.repository = opts.repository;
  }

  list(): Proposal[] {
    return this.store.list();
  }

  get(id: string): Proposal | undefined {
    return this.store.get(id);
  }

  private budgetProblem(provider: string): string | undefined {
    const now = this.opts.now();
    const all = this.store.list();
    if (all.filter((p) => p.status === 'awaiting_review').length >= this.opts.maxPending) {
      return `There are already ${this.opts.maxPending} proposals waiting for the user. Wait until they review some.`;
    }
    const today = all.filter((p) => p.provider === provider && now - p.createdAt < DAY).length;
    if (today >= this.opts.maxPerDay)
      return `Limit of ${this.opts.maxPerDay} proposals a day reached.`;
    return undefined;
  }

  private prove(
    before: DetectionRule | undefined,
    after: DetectionRule | undefined,
    afterMode?: RuleMode,
  ): ImpactReport {
    const to = this.opts.now();
    const input: Parameters<typeof proveChange>[0] = {
      history: this.history,
      lists: this.engine.stores.lists,
      from: to - this.opts.replayDays * DAY,
      to,
    };
    if (before) {
      input.before = before;
      input.beforeMode = this.engine.modeOf(before);
    }
    if (after) input.after = after;
    if (afterMode) input.afterMode = afterMode;
    return proveChange(input);
  }

  private replay(rule: DetectionRule) {
    const to = this.opts.now();
    return replayRule(
      rule,
      {
        history: this.history,
        lists: this.engine.stores.lists,
        userExceptions: this.engine.stores.exceptions,
        existingRules: this.engine.allRules(),
      },
      { from: to - this.opts.replayDays * DAY, to },
    );
  }

  submitRule(raw: unknown, provider: string): SubmitResult {
    const parsedInput = ProposeRuleInput.safeParse(raw);
    if (!parsedInput.success)
      return { ok: false, errors: formatZod(parsedInput.error), warnings: [] };
    const input = parsedInput.data;
    const budget = this.budgetProblem(provider);
    if (budget) return { ok: false, errors: [budget], warnings: [], final: true };

    const now = this.opts.now();
    const draft: Record<string, unknown> = {
      description: input.rationale,
      fidelity: 'low',
      ...input.rule,
    };
    if (typeof draft.id === 'string' && !draft.id.startsWith('ai-')) draft.id = `ai-${draft.id}`;
    // Vigil, not the AI, decides these. An AI-made rule starts in shadow (core's canChangeMode).
    draft.mode = 'shadow';
    draft.origin = 'ai';
    draft.version = 1;
    draft.createdAt = now;
    draft.updatedAt = now;
    draft.provenance = { provider, rationale: input.rationale, sampleEventIds: [] };
    const parsed = DetectionRule.safeParse(draft);
    if (!parsed.success) return { ok: false, errors: formatZod(parsed.error), warnings: [] };
    const rule = parsed.data;
    if (this.engine.getRule(rule.id)) {
      return {
        ok: false,
        errors: [`A rule called ${rule.id} already exists. Use propose_tuning to change it.`],
        warnings: [],
      };
    }
    if (this.store.list().some((p) => p.status === 'awaiting_review' && p.rule.id === rule.id)) {
      return {
        ok: false,
        errors: [`${rule.id} is already waiting for the user's review.`],
        warnings: [],
        final: true,
      };
    }
    return this.checkAndQueue({
      kind: 'new_rule',
      rule,
      provider,
      rationale: input.rationale,
      evidence: input.evidence,
    });
  }

  submitTuning(raw: unknown, provider: string): SubmitResult {
    const parsedInput = ProposeTuningInput.safeParse(raw);
    if (!parsedInput.success)
      return { ok: false, errors: formatZod(parsedInput.error), warnings: [] };
    const input = parsedInput.data;
    const budget = this.budgetProblem(provider);
    if (budget) return { ok: false, errors: [budget], warnings: [], final: true };
    const base = this.engine.getRule(input.ruleId);
    if (!base) return { ok: false, errors: [`No rule called ${input.ruleId}.`], warnings: [] };
    const tuned: DetectionRule = {
      ...base,
      version: base.version + 1,
      updatedAt: this.opts.now(),
      exclusions: [...base.exclusions, input.addExclusion],
    };
    return this.checkAndQueue({
      kind: 'tuning',
      rule: tuned,
      base,
      provider,
      rationale: input.rationale,
      evidence: input.evidence,
    });
  }

  /**
   * Turn a rule down to shadow (still recorded, never alerts) or off. Refused
   * when the rule caught something confirmed malicious in the replay window,
   * so maintenance can never quietly remove real protection.
   */
  submitRetirement(raw: unknown, provider: string): SubmitResult {
    const parsedInput = ProposeRetirementInput.safeParse(raw);
    if (!parsedInput.success)
      return { ok: false, errors: formatZod(parsedInput.error), warnings: [] };
    const input = parsedInput.data;
    const budget = this.budgetProblem(provider);
    if (budget) return { ok: false, errors: [budget], warnings: [], final: true };
    const base = this.engine.getRule(input.ruleId);
    if (!base) return { ok: false, errors: [`No rule called ${input.ruleId}.`], warnings: [] };
    const current = this.engine.modeOf(base);
    if (MODE_RANK[input.toMode] >= MODE_RANK[current]) {
      return {
        ok: false,
        errors: [
          `${input.ruleId} is already in ${current} mode; ${input.toMode} would not turn it down.`,
        ],
        warnings: [],
      };
    }
    return this.queueRetirement(base, input.toMode, input.rationale, input.evidence, provider);
  }

  /**
   * Vigil's own suggestion to move a rule the user keeps marking safe down a
   * mode. Not on the AI tool surface and not counted against the AI budget.
   * Skipped while one is waiting, or for 30 days after the user said no.
   */
  suggestDemotion(
    s: { ruleId: string; to: 'alert' | 'shadow' | 'disabled'; message: string },
    evidence: string[] = [],
  ): SubmitResult | undefined {
    const base = this.engine.getRule(s.ruleId);
    if (!base) return undefined;
    const now = this.opts.now();
    const blocked = this.store
      .list()
      .some(
        (p) =>
          p.rule.id === s.ruleId &&
          (p.status === 'awaiting_review' ||
            (p.kind === 'retire' &&
              p.status === 'rejected' &&
              now - (p.decidedAt ?? 0) < 30 * DAY)),
      );
    if (blocked) return undefined;
    return this.queueRetirement(base, s.to, s.message, evidence, VIGIL_PROVIDER);
  }

  private queueRetirement(
    base: DetectionRule,
    toMode: 'alert' | 'shadow' | 'disabled',
    rationale: string,
    evidence: string[],
    provider: string,
  ): SubmitResult {
    const now = this.opts.now();
    const before = this.replay(base);
    const threats = this.countConfirmedThreats(
      [...before.hitEventIds],
      before.report.windowStart,
      before.report.windowEnd,
    );
    const errors: string[] = [];
    if (threats > 0)
      errors.push(
        `This rule caught ${threats} programs you or a threat list marked as malicious in the last ${this.opts.replayDays} days. It stays on.`,
      );
    const proposal: Proposal = {
      id: newId(now),
      kind: 'retire',
      createdAt: now,
      provider,
      rationale: rationale,
      evidence: evidence,
      rule: base,
      baseRuleId: base.id,
      baseRuleVersion: base.version,
      retireTo: toMode,
      status: errors.length ? 'rejected_by_checks' : 'awaiting_review',
      lint: { errors, warnings: [] },
      replay: before.report,
      impact: this.prove(
        base,
        toMode === 'disabled' ? undefined : base,
        toMode === 'disabled' ? undefined : toMode,
      ),
    };
    this.store.put(proposal);
    return {
      ok: errors.length === 0,
      proposalId: proposal.id,
      status: proposal.status,
      errors,
      warnings: [],
      replay: before.report,
    };
  }

  private checkAndQueue(p: {
    kind: Proposal['kind'];
    rule: DetectionRule;
    base?: DetectionRule;
    provider: string;
    rationale: string;
    evidence: string[];
  }): SubmitResult {
    const lint = lintRule(p.rule, {
      aiProposed: p.kind === 'new_rule',
      knownLists: this.engine.stores.lists.names(),
    });
    try {
      compileRule(p.rule);
    } catch (err) {
      lint.errors.push((err as Error).message);
    }
    const proposal: Proposal = {
      id: newId(this.opts.now()),
      kind: p.kind,
      createdAt: this.opts.now(),
      provider: p.provider,
      rationale: p.rationale,
      evidence: p.evidence,
      rule: p.rule,
      status: 'awaiting_review',
      lint,
    };
    if (p.base) {
      proposal.baseRuleId = p.base.id;
      proposal.baseRuleVersion = p.base.version;
    }

    if (lint.errors.length === 0) {
      const after = this.replay(p.rule);
      proposal.replay = after.report;
      if (!p.base) proposal.impact = this.prove(undefined, p.rule);
      // A new AI rule that would pester the user goes back for narrowing rather than to them.
      if (p.kind === 'new_rule' && after.report.popupsPerDay > MAX_NEW_RULE_ALERTS_PER_DAY) {
        const seen = after.report.samples
          .slice(0, 3)
          .map((x) => x.subject)
          .join('; ');
        lint.errors.push(
          `On this Mac's last ${this.opts.replayDays} days it would alert about ${after.report.popupsPerDay.toFixed(1)} times a day, mostly on ${after.report.topPrograms
            .slice(0, 3)
            .map((t) => t.program)
            .join(
              ', ',
            )} (e.g. ${seen}). That is ordinary use here; narrow it to what only the attack does.`,
        );
      }
      if (p.base) {
        const before = this.replay(p.base);
        const removed = [...before.hitEventIds].filter((id) => !after.hitEventIds.has(id));
        const threats = this.countConfirmedThreats(
          removed,
          before.report.windowStart,
          before.report.windowEnd,
        );
        proposal.tuning = {
          hitsBefore: before.report.hits,
          hitsAfter: after.report.hits,
          removed: removed.length,
          removedConfirmedThreats: threats,
        };
        if (threats > 0) {
          lint.errors.push(
            `This exclusion would hide ${threats} detections of programs you or a threat list marked as malicious.`,
          );
        }
        const impact = this.prove(p.base, p.rule, this.engine.modeOf(p.base));
        proposal.impact = impact;
        // Look-alikes go back to the AI as warnings so its fix-up can narrow the exclusion.
        for (const l of impact.lookAlikes.slice(0, 3))
          lint.warnings.push(
            `Too broad: ${l.how} would also be skipped. Exclude by team ID and signing ID or by hash instead.`,
          );
        if (before.report.hits > 0 && after.report.hits === 0 && before.report.hits >= 5) {
          lint.warnings.push(
            'This exclusion silences the rule completely on your history. Consider turning the rule off instead.',
          );
        }
      }
    }

    if (lint.errors.length > 0) proposal.status = 'rejected_by_checks';
    this.store.put(proposal);
    const result: SubmitResult = {
      ok: proposal.status === 'awaiting_review',
      proposalId: proposal.id,
      status: proposal.status,
      errors: lint.errors,
      warnings: lint.warnings,
    };
    if (proposal.replay) result.replay = proposal.replay;
    return result;
  }

  private countConfirmedThreats(eventIds: string[], from: number, to: number): number {
    if (eventIds.length === 0) return 0;
    const ids = new Set(eventIds);
    const { lists } = this.engine.stores;
    let n = 0;
    for (const e of this.history.range(from, to)) {
      if (!ids.has(e.id)) continue;
      const h = 'process' in e ? e.process?.sha256 : undefined;
      if (h && (lists.has(USER_BLOCKED_HASHES, h) || lists.has('known_bad_sha256', h))) n++;
    }
    return n;
  }

  /** The user approves a proposal. The rule goes live in the mode they choose (default alert: may warn, never acts). */
  approve(
    id: string,
    origin: UserOrigin,
    opts: { mode?: RuleMode; note?: string } = {},
  ): DetectionRule {
    assertUserOrigin(origin);
    const p = this.store.get(id);
    if (!p) throw new Error(`no proposal ${id}`);
    if (p.status !== 'awaiting_review') throw new Error(`proposal ${id} is ${p.status}`);
    if (p.kind === 'tuning' || p.kind === 'retire') {
      const current = p.baseRuleId ? this.engine.getRule(p.baseRuleId) : undefined;
      if (!current || current.version !== p.baseRuleVersion) {
        throw new Error('The rule changed since this was proposed. Ask for a fresh proposal.');
      }
    }
    const now = this.opts.now();
    let live: DetectionRule;
    let mode: RuleMode;
    if (p.kind === 'retire') {
      // Only the mode changes; the rule itself stays as it is.
      mode = p.retireTo ?? 'shadow';
      live = this.engine.getRule(p.rule.id) ?? p.rule;
      // A turn-down never turns a rule up, even if the user moved it lower since.
      if (MODE_RANK[mode] >= MODE_RANK[this.engine.modeOf(live)])
        throw new Error(`${live.name} is already in ${this.engine.modeOf(live)} mode.`);
      this.engine._setMode(live.id, mode);
    } else {
      mode = opts.mode ?? (p.kind === 'tuning' ? this.engine.modeOf(p.rule) : 'alert');
      live = this.engine.upsertRule({ ...p.rule, mode, updatedAt: now });
      this.engine._setMode(live.id, mode);
      this.repository?.save(live, now);
    }
    const decided: Proposal = {
      ...p,
      status: 'approved',
      decidedAt: now,
      decidedVia: origin.via,
      approvedMode: mode,
    };
    if (opts.note !== undefined) decided.decisionNote = opts.note;
    this.store.put(decided);
    return live;
  }

  /** The user says no. The note is shown to the AI in later telemetry summaries so it learns. */
  reject(id: string, origin: UserOrigin, note?: string): void {
    assertUserOrigin(origin);
    const p = this.store.get(id);
    if (!p) throw new Error(`no proposal ${id}`);
    if (p.status !== 'awaiting_review') throw new Error(`proposal ${id} is ${p.status}`);
    const decided: Proposal = {
      ...p,
      status: 'rejected',
      decidedAt: this.opts.now(),
      decidedVia: origin.via,
    };
    if (note !== undefined) decided.decisionNote = note;
    this.store.put(decided);
  }
}

export function formatZod(err: z.ZodError): string[] {
  return err.issues.slice(0, 20).map((i) => `${i.path.join('.') || 'input'}: ${i.message}`);
}
