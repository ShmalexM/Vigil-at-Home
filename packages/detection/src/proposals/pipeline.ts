import { newId, type RuleMode } from '@vigil/core';
import { z } from 'zod';
import { conditionUsesAgentFields, exclusionHidesAgent, isAgentField } from '../agents/fields.js';
import { compileRule, type DetectionEngine } from '../engine.js';
import { USER_BLOCKED_HASHES } from '../feedback.js';
import type { FeedList } from '../feeds/sources.js';
import { assertUserOrigin, type UserOrigin } from '../origin.js';
import { lintRule, type LintResult } from '../rules/lint.js';
import type { EventHistory } from '../state/stores.js';
import { Condition, DetectionRule } from '../types.js';
import { proveChange, type ImpactReport } from './prover.js';
import {
  PARENT_REPLAY_NOTE,
  replayMissesParents,
  replayRule,
  type ReplayReport,
} from './replay.js';

export type ProposalStatus =
  'rejected_by_checks' | 'awaiting_review' | 'approved' | 'rejected' | 'withdrawn';

export interface Proposal {
  id: string;
  /** new_rule adds a rule; tuning adds an exclusion; retire turns a rule down (shadow or off). */
  kind: 'new_rule' | 'tuning' | 'retire';
  createdAt: number;
  /** Which AI provider proposed it (e.g. "claude", "codex", "ollama"). */
  provider: string;
  /** Who asked for it outside the scheduled review: the Lead dog's name, when it drafted this in chat. */
  by?: string;
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
  /**
   * For a change drafted from alerts: every source alert's program (the same
   * change asked for again from another alert adds its own), each checked
   * against the blocklists until the change is decided.
   */
  subjects?: ProposalSubject[];
  /** Saved before `subjects`: a single source alert's program. */
  subject?: ProposalSubject;
  /**
   * For tuning and retire: the sha256 of each program whose detections the
   * change would hide, so a proposal can be withdrawn the moment one of them
   * is blocked or listed as bad.
   */
  hides?: string[];
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

/** Every list a threat feed fills. */
const FEED_LISTS: readonly FeedList[] = ['known_bad_sha256', 'known_bad_domains', 'known_bad_ips'];

const MODE_RANK: Record<RuleMode, number> = { disabled: 0, shadow: 1, alert: 2, block: 3 };

export interface SubmitResult {
  ok: boolean;
  proposalId?: string;
  status?: ProposalStatus;
  /** Problems the AI can fix and resubmit. */
  errors: string[];
  /** Resubmitting cannot help (a budget, or the same proposal already waiting). */
  final?: boolean;
  /** Set with `final` when the same change is already waiting: the one that waits. */
  duplicateOf?: string;
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

export const BLOCKED_EXCLUSION =
  "That program is on your blocked list, so Vigil won't stop alerting on it.";

/** Rules about watched agents and their tool requests. Only the user tunes or retires them. */
const USER_TUNED_TAGS = ['agent-watch', 'agent-preflight'];
export const USER_TUNED_ONLY = 'Agent rules are tuned only by you.';
export const AGENT_EXCLUSION =
  'An exclusion may not use agent or tool-request fields (process.agent, process.ancestors, process.parentName, process.parentPath, agent, tool, command, filePath, url and the like): that would hide what an agent does. Exclude a specific program by hash, or by team ID and signing ID.';

/**
 * Tagged agent-watch or agent-preflight, on agent.tool_request, or whose
 * condition reads an agent field (a rule the user wrote about agents),
 * including a sequence step's kinds and condition and the sequence's key. An
 * exclusion on an agent field only carves agents out of an ordinary rule, so
 * it does not count.
 */
function userTunedOnly(rule: DetectionRule): boolean {
  const steps = rule.sequence?.steps ?? [];
  return (
    rule.tags.some((t) => USER_TUNED_TAGS.includes(t)) ||
    rule.eventKinds.includes('agent.tool_request') ||
    conditionUsesAgentFields(rule.condition) ||
    steps.some(
      (st) =>
        st.eventKinds.includes('agent.tool_request') || conditionUsesAgentFields(st.condition),
    ) ||
    (rule.sequence?.key ?? []).some(isAgentField)
  );
}

export const INDICATOR_EXCLUSION =
  'An exclusion may not look anything up in a blocked or threat list.';
export const INDICATOR_RULE =
  'This rule stops programs or addresses on your blocked list or a threat list. Only you can turn it down or add an exception to it.';

/**
 * Lists that say something is bad: the user's own blocked lists and the threat
 * feeds' known-bad lists. A rule that looks one up is a blocked-indicator rule.
 */
export function isIndicatorList(list: string): boolean {
  return (
    list === USER_BLOCKED_HASHES ||
    list.startsWith('user_blocked_') ||
    list.startsWith('known_bad_') ||
    (FEED_LISTS as readonly string[]).includes(list)
  );
}

/** True when a list lookup on a blocked or known-bad list appears anywhere in `v`, at any depth. */
function mentionsIndicatorList(v: unknown): boolean {
  if (Array.isArray(v)) return v.some(mentionsIndicatorList);
  if (!v || typeof v !== 'object') return false;
  for (const [k, x] of Object.entries(v)) {
    if (k === 'inList' && x && typeof x === 'object') {
      const list = (x as { list?: unknown }).list;
      if (typeof list === 'string' && isIndicatorList(list)) return true;
    }
    if (mentionsIndicatorList(x)) return true;
  }
  return false;
}

/**
 * A rule that looks a value up in a blocked or known-bad list anywhere: its
 * condition, a sequence step or an exclusion, at any depth (known-bad-hash,
 * user-blocked-hash, the feed rules, or the user's own). No AI may propose
 * changing one, whatever the replay shows.
 */
export function isIndicatorRule(rule: DetectionRule): boolean {
  return mentionsIndicatorList({
    condition: rule.condition,
    sequence: rule.sequence,
    exclusions: rule.exclusions,
  });
}

export const BLOCKING_RULE =
  'This rule is blocking right now. Only you can turn it down or add an exception to it.';

/**
 * The one check on what an AI may ask to change. Anything an AI proposes (a
 * review provider, or a pack dog drafting in chat) must leave alone a rule
 * about agents, a rule blocking right now, and a rule that looks up a blocked
 * or known-bad list. Returns why not, or undefined when it may. The person can
 * still change any of these themselves, with the admin password where it
 * weakens blocking.
 */
export function aiMayNotChange(rule: DetectionRule, mode: RuleMode): string | undefined {
  if (userTunedOnly(rule)) return USER_TUNED_ONLY;
  if (isIndicatorRule(rule)) return INDICATOR_RULE;
  if (mode === 'block') return BLOCKING_RULE;
  return undefined;
}

/** Lists of signers known to be bad, checked by name even before a feed has filled them. */
const SIGNER_LISTS = ['known_bad_signing_ids', 'user_blocked_signing_ids', 'known_bad_team_ids'];

/** Every source program on a proposal, including one saved before `subjects`. */
function subjectsOf(p: Proposal): ProposalSubject[] {
  return [...(p.subjects ?? []), ...(p.subject ? [p.subject] : [])];
}

/** What an alert's program was, carried into a change drafted from it. */
export interface ProposalSubject {
  sha256?: string;
  teamId?: string;
  signingId?: string;
}

/** More alerts a day than this from a new AI rule means it matches ordinary use. */
const MAX_NEW_RULE_ALERTS_PER_DAY = 3;
/** Provider name on suggestions Vigil makes from the user's own answers, not an AI. */
export const VIGIL_PROVIDER = 'vigil';
const DAY = 86_400_000;
export const HIDES_THREAT =
  'This exclusion would now hide a program you or a threat list marked as malicious.';
export const STILL_CATCHES_THREAT =
  'This rule caught a program you or a threat list marked as malicious. It stays on.';
export const ALREADY_WAITING = 'The same change is already waiting for the user’s review.';

/** JSON with sorted keys, so two conditions that say the same thing compare equal. */
function canonical(v: unknown): string {
  return JSON.stringify(v, (_, x: unknown) =>
    x && typeof x === 'object' && !Array.isArray(x)
      ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => a.localeCompare(b)))
      : x,
  );
}

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

  /** Every proposal, newest first. Pending ones the threat lists now rule out are withdrawn first. */
  list(): Proposal[] {
    this.withdrawAffected();
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
    if (rule.exclusions.some(exclusionHidesAgent))
      return { ok: false, errors: [AGENT_EXCLUSION], warnings: [] };
    if (mentionsIndicatorList(rule.exclusions))
      return { ok: false, errors: [INDICATOR_EXCLUSION], warnings: [] };
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

  /** Who asked, for a proposal drafted outside the scheduled review (the Lead dog's name). */
  submitTuning(
    raw: unknown,
    provider: string,
    by?: string,
    subject?: ProposalSubject,
  ): SubmitResult {
    const parsedInput = ProposeTuningInput.safeParse(raw);
    if (!parsedInput.success)
      return { ok: false, errors: formatZod(parsedInput.error), warnings: [] };
    const input = parsedInput.data;
    const base = this.engine.getRule(input.ruleId);
    if (!base) return { ok: false, errors: [`No rule called ${input.ruleId}.`], warnings: [] };
    const outOfScope = aiMayNotChange(base, this.engine.modeOf(base));
    if (outOfScope) return { ok: false, errors: [outOfScope], warnings: [], final: true };
    if (exclusionHidesAgent(input.addExclusion))
      return { ok: false, errors: [AGENT_EXCLUSION], warnings: [] };
    if (mentionsIndicatorList(input.addExclusion))
      return { ok: false, errors: [INDICATOR_EXCLUSION], warnings: [] };
    if (subject && this.isBlockedSubject(subject))
      return { ok: false, errors: [BLOCKED_EXCLUSION], warnings: [], final: true };
    if (this.excludesBlockedHash(input.addExclusion))
      return { ok: false, errors: [BLOCKED_EXCLUSION], warnings: [], final: true };
    const same = this.waiting(
      (p) =>
        p.kind === 'tuning' &&
        p.baseRuleId === base.id &&
        p.baseRuleVersion === base.version &&
        canonical(p.rule.exclusions.at(-1)) === canonical(input.addExclusion),
      subject,
    );
    if (same) return same;
    const budget = this.budgetProblem(provider);
    if (budget) return { ok: false, errors: [budget], warnings: [], final: true };
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
      ...(by ? { by } : {}),
      ...(subject ? { subject } : {}),
    });
  }

  /** A refusal pointing at a proposal already waiting that matches, if there is one. */
  private waiting(
    match: (p: Proposal) => boolean,
    subject?: ProposalSubject,
  ): SubmitResult | undefined {
    const p = this.store.list().find((x) => x.status === 'awaiting_review' && match(x));
    if (!p) return undefined;
    // The new request's source program joins the waiting one's, so every alert it was asked from is checked.
    if (subject) {
      const all = subjectsOf(p);
      if (!all.some((x) => canonical(x) === canonical(subject)))
        this.store.put({ ...p, subjects: [...all, subject] });
    }
    return { ok: false, errors: [ALREADY_WAITING], warnings: [], final: true, duplicateOf: p.id };
  }

  /**
   * Turn a rule down to shadow (still recorded, never alerts) or off. Refused
   * when the rule caught something confirmed malicious in the replay window,
   * so maintenance can never quietly remove real protection.
   */
  submitRetirement(
    raw: unknown,
    provider: string,
    by?: string,
    subject?: ProposalSubject,
  ): SubmitResult {
    const parsedInput = ProposeRetirementInput.safeParse(raw);
    if (!parsedInput.success)
      return { ok: false, errors: formatZod(parsedInput.error), warnings: [] };
    const input = parsedInput.data;
    const base = this.engine.getRule(input.ruleId);
    if (!base) return { ok: false, errors: [`No rule called ${input.ruleId}.`], warnings: [] };
    const current = this.engine.modeOf(base);
    const outOfScope = aiMayNotChange(base, current);
    if (outOfScope) return { ok: false, errors: [outOfScope], warnings: [], final: true };
    if (subject && this.isBlockedSubject(subject))
      return { ok: false, errors: [STILL_CATCHES_THREAT], warnings: [], final: true };
    if (MODE_RANK[input.toMode] >= MODE_RANK[current]) {
      return {
        ok: false,
        errors: [
          `${input.ruleId} is already in ${current} mode; ${input.toMode} would not turn it down.`,
        ],
        warnings: [],
      };
    }
    const same = this.waiting(
      (p) =>
        p.kind === 'retire' &&
        p.baseRuleId === base.id &&
        p.baseRuleVersion === base.version &&
        p.retireTo === input.toMode,
      subject,
    );
    if (same) return same;
    const budget = this.budgetProblem(provider);
    if (budget) return { ok: false, errors: [budget], warnings: [], final: true };
    return this.queueRetirement(
      base,
      input.toMode,
      input.rationale,
      input.evidence,
      provider,
      by,
      subject,
    );
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
    by?: string,
    subject?: ProposalSubject,
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
      hides: this.hashesOf(
        [...before.hitEventIds],
        before.report.windowStart,
        before.report.windowEnd,
      ),
      impact: this.prove(
        base,
        toMode === 'disabled' ? undefined : base,
        toMode === 'disabled' ? undefined : toMode,
      ),
    };
    if (by) proposal.by = by;
    if (subject) proposal.subjects = [subject];
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
    by?: string;
    subject?: ProposalSubject;
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
    if (p.by) proposal.by = p.by;
    if (p.subject) proposal.subjects = [p.subject];
    if (p.base) {
      proposal.baseRuleId = p.base.id;
      proposal.baseRuleVersion = p.base.version;
    }

    // The noise gate below cannot see these rules' noise; say so rather than pass them silently.
    if (p.kind === 'new_rule' && replayMissesParents(p.rule))
      lint.warnings.push(PARENT_REPLAY_NOTE);
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
        proposal.hides = this.hashesOf(removed, before.report.windowStart, before.report.windowEnd);
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

  /** True when an alert's program is on the user's blocked list or a threat list, by hash or signer. */
  isBlockedSubject(s: ProposalSubject): boolean {
    if (s.sha256 && this.isBlockedHash(s.sha256)) return true;
    const { lists } = this.engine.stores;
    // By signer: the team ID, the signing ID (known_bad_signing_ids, the
    // user's blocked signing IDs) or both as "TEAMID:signing.id", on any
    // blocked or known-bad list.
    const values = [s.teamId, s.signingId, s.teamId && s.signingId && `${s.teamId}:${s.signingId}`]
      .filter((v): v is string => typeof v === 'string' && v.length > 0)
      .flatMap((v) => [v, v.toLowerCase()]);
    if (values.length === 0) return false;
    const names = new Set([...lists.names(), ...SIGNER_LISTS]);
    return [...names].some((l) => isIndicatorList(l) && values.some((v) => lists.has(l, v)));
  }

  /**
   * Run every check again just before an approved proposal is made, after the
   * password came back: it must still be waiting (not withdrawn meanwhile), on
   * the same rule version, and pass the checks it passed when queued. Returns
   * why not, and withdraws it, or undefined when it may go ahead.
   */
  commitProblem(id: string): string | undefined {
    const p = this.store.get(id);
    if (!p) return `There is no suggestion ${id}.`;
    if (p.status !== 'awaiting_review')
      return p.decisionNote ?? `This suggestion was ${p.status.replace(/_/g, ' ')}.`;
    if (p.baseRuleId) {
      const current = this.engine.getRule(p.baseRuleId);
      if (!current || current.version !== p.baseRuleVersion)
        return 'The rule changed since this was proposed. Ask for a fresh proposal.';
    }
    const problem = this.problemNow(p, true);
    if (problem) this.withdraw(p, problem);
    return problem;
  }

  /** True when a sha256 is on the user's blocked list or a known-bad feed. */
  isBlockedHash(h: string): boolean {
    const { lists } = this.engine.stores;
    return [h, h.toLowerCase()].some(
      (v) => lists.has(USER_BLOCKED_HASHES, v) || lists.has('known_bad_sha256', v),
    );
  }

  /**
   * An exclusion that names, by sha256, a program the user confirmed malicious
   * or a feed lists as bad, so the rule would stop alerting on it. Looks inside
   * all/any; a `not` never carves a single program out. There is no cdhash
   * blocklist, so cdhash exclusions are not checked here.
   */
  private excludesBlockedHash(c: Condition): boolean {
    if ('all' in c) return c.all.some((x) => this.excludesBlockedHash(x));
    if ('any' in c) return c.any.some((x) => this.excludesBlockedHash(x));
    if (!('field' in c) || c.field !== 'process.sha256') return false;
    if (c.op !== 'eq' && c.op !== 'in') return false;
    const values = Array.isArray(c.value) ? c.value : [c.value];
    return values.some((v) => typeof v === 'string' && this.isBlockedHash(v));
  }

  /** The distinct program hashes behind these events, at most 1000. */
  private hashesOf(eventIds: string[], from: number, to: number): string[] {
    if (eventIds.length === 0) return [];
    const ids = new Set(eventIds);
    const out = new Set<string>();
    for (const e of this.history.range(from, to)) {
      if (!ids.has(e.id)) continue;
      const h = 'process' in e ? e.process?.sha256 : undefined;
      if (h) out.add(h.toLowerCase());
      if (out.size >= 1000) break;
    }
    return [...out];
  }

  /**
   * Why a waiting proposal may no longer go ahead, from what is known now: an
   * AI asking to weaken a blocked-indicator rule, an exclusion naming a program
   * now blocked or listed as bad, or a change hiding one. With `replay`, the
   * confirmed-threat check is run again on the history, as at submission.
   */
  private problemNow(p: Proposal, replay: boolean): string | undefined {
    const ai = p.provider !== VIGIL_PROVIDER || p.by !== undefined;
    const base = p.baseRuleId ? this.engine.getRule(p.baseRuleId) : undefined;
    if (ai && p.kind !== 'new_rule') {
      const rule = base ?? p.rule;
      const outOfScope = aiMayNotChange(rule, this.engine.modeOf(rule));
      if (outOfScope) return outOfScope;
    }
    if (
      ai &&
      mentionsIndicatorList(
        p.kind === 'tuning'
          ? p.rule.exclusions.slice(-1)
          : p.kind === 'new_rule'
            ? p.rule.exclusions
            : [],
      )
    )
      return INDICATOR_EXCLUSION;
    if (subjectsOf(p).some((x) => this.isBlockedSubject(x)))
      return p.kind === 'retire' ? STILL_CATCHES_THREAT : BLOCKED_EXCLUSION;
    const added =
      p.kind === 'tuning'
        ? p.rule.exclusions.slice(-1)
        : p.kind === 'new_rule'
          ? p.rule.exclusions
          : [];
    if (added.some((c) => this.excludesBlockedHash(c))) return BLOCKED_EXCLUSION;
    if (p.kind === 'new_rule') return undefined;
    if ((p.hides ?? []).some((h) => this.isBlockedHash(h)))
      return p.kind === 'tuning' ? HIDES_THREAT : STILL_CATCHES_THREAT;
    if (!replay || !base) return undefined;
    if (p.kind === 'tuning') {
      const before = this.replay(base);
      const after = this.replay({ ...base, exclusions: [...base.exclusions, ...added] });
      const removed = [...before.hitEventIds].filter((id) => !after.hitEventIds.has(id));
      if (this.countConfirmedThreats(removed, before.report.windowStart, before.report.windowEnd))
        return HIDES_THREAT;
    } else {
      const before = this.replay(base);
      const hits = [...before.hitEventIds];
      if (this.countConfirmedThreats(hits, before.report.windowStart, before.report.windowEnd))
        return STILL_CATCHES_THREAT;
    }
    return undefined;
  }

  /**
   * Quietly withdraw every waiting proposal that what is known now rules out:
   * a program it would hide or exclude was blocked by the user or listed by a
   * threat feed. Call after the threat lists change; list() also runs it.
   * Returns how many were withdrawn.
   */
  withdrawAffected(): number {
    let n = 0;
    for (const p of this.store.list()) {
      if (p.status !== 'awaiting_review') continue;
      const problem = this.problemNow(p, false);
      if (!problem) continue;
      this.withdraw(p, problem);
      n++;
    }
    return n;
  }

  private withdraw(p: Proposal, why: string): void {
    this.store.put({
      ...p,
      status: 'withdrawn',
      decidedAt: this.opts.now(),
      decidedVia: VIGIL_PROVIDER,
      decisionNote: why,
    });
  }

  private countConfirmedThreats(eventIds: string[], from: number, to: number): number {
    if (eventIds.length === 0) return 0;
    const ids = new Set(eventIds);
    let n = 0;
    for (const e of this.history.range(from, to)) {
      if (!ids.has(e.id)) continue;
      const h = 'process' in e ? e.process?.sha256 : undefined;
      if (h && this.isBlockedHash(h)) n++;
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
    // What is known about threats may have changed since it was checked: check again.
    const problem = this.problemNow(p, true);
    if (problem) {
      this.withdraw(p, problem);
      throw new Error(problem);
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
