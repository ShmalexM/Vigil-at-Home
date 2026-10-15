import type { RuleMode } from '@vigil/core';
import {
  aiMayNotChange,
  BLOCKED_EXCLUSION,
  exclusionFor,
  type ProposalSubject,
  type Detection,
  type Proposal,
  type SubmitResult,
} from '@vigil/detection';
import type { ExcludeScope, RuleSuggestionView, RuleSuggestionsView } from '../shared/ipc.js';
import type { RuleDraft } from '../shared/pack.js';
import type { Detector, HelperSyncOutcome } from './detection.js';
import { describeCondition } from './rule-editing.js';

const BOOKKEEPING = ['version', 'createdAt', 'updatedAt', 'origin', 'provenance', 'mode'];
const RECENT = 10;

/**
 * A rule change the Lead dog asks for in chat, to quiet an alert. Vigil, not
 * the model, builds the change: an exclusion comes from the alert's own event
 * (the same one "Stop alerting on this" adds), and a turn-down only goes to
 * Shadow.
 */
export interface RuleDraftRequest {
  kind: 'exclude' | 'turn-down';
  alertId?: string;
  ruleId?: string;
  /** For exclude: what to stop matching. Default the program itself. */
  scope?: ExcludeScope;
  why: string;
}

/**
 * The Rules screen's list of AI suggestions. The AI proposes; the detection
 * pipeline checks and replays; only the user's click here changes a rule.
 */
export class RuleSuggestions {
  constructor(
    private readonly detector: Detector,
    /** Whether a cloud AI is set up to run reviews at all. */
    private readonly available: () => boolean,
    /** The detection behind an alert, for drafts made from one. */
    private readonly detectionOf: (alertId: string) => unknown = () => undefined,
  ) {}

  view(): RuleSuggestionsView {
    const all = this.detector.pipeline.list();
    const pending = all.filter((p) => p.status === 'awaiting_review').map((p) => this.one(p));
    const recent = all
      .filter((p) => p.status !== 'awaiting_review')
      .slice(0, RECENT)
      .map((p) => ({
        id: p.id,
        kind: p.kind,
        ruleName: p.rule.name,
        status: p.status as RuleSuggestionsView['recent'][number]['status'],
        at: p.decidedAt ?? p.createdAt,
      }));
    const s = this.detector.reviewStatus();
    const review: RuleSuggestionsView['review'] = { available: this.available() };
    if (s) {
      for (const k of ['lastRunAt', 'lastOkAt', 'lastError', 'lastSummary'] as const)
        if (s[k] !== undefined) (review as Record<string, unknown>)[k] = s[k];
      if (s.nextDueAt) review.nextDueAt = s.nextDueAt;
    }
    return { pending, recent, review };
  }

  /** Resolves once the helper has the change, or the user cancelled its password. */
  accept(id: string, mode?: RuleMode): Promise<HelperSyncOutcome> {
    return this.detector.approveProposal(id, mode);
  }

  /** accept, with the helper's reason when it refused the change. */
  async acceptWithReason(
    id: string,
    mode?: RuleMode,
  ): Promise<{ helper: HelperSyncOutcome; helperReason?: string }> {
    const { helper, reason } = await this.detector.acceptProposal(id, mode);
    return reason === undefined ? { helper } : { helper, helperReason: reason };
  }

  dismiss(id: string, note?: string): void {
    this.detector.rejectProposal(id, note);
  }

  /**
   * The Lead dog drafts a change. It goes through the pipeline exactly like
   * the rule reviewer's (schema, guards, replay, impact, budget) and only
   * ever waits for the user: nothing here changes a live rule.
   */
  draft(req: RuleDraftRequest, by: { provider: string; name: string }): Omit<RuleDraft, 'id'> {
    const { kind } = req;
    const d = req.alertId ? (this.detectionOf(req.alertId) as Detection | undefined) : undefined;
    if (req.alertId && !d)
      return { kind, status: 'failed', note: 'That alert didn’t come from a detection rule' };
    const ruleId = d?.match.ruleId ?? req.ruleId;
    if (!ruleId || (kind === 'exclude' && !d))
      return {
        kind,
        status: 'failed',
        note: kind === 'exclude' ? 'An exclusion needs the alert it’s about' : 'It needs a rule',
      };
    const rule = this.detector.engine.getRule(ruleId);
    if (!rule) return { kind, ruleId, status: 'failed', note: `There’s no rule called ${ruleId}` };
    const why = req.why.trim();
    const rationale =
      why.length >= 10 ? why : `You asked ${by.name} to stop this alert from repeating.`;
    const evidence = [
      req.alertId
        ? `Drafted by ${by.name} in chat, from an alert`
        : `Drafted by ${by.name} in chat`,
    ];
    const base = { kind, ruleId, ruleName: rule.name };
    const { pipeline } = this.detector;
    // What an AI may touch at all: never an agent rule, a blocking rule or a blocklist rule.
    const outOfScope = aiMayNotChange(rule, this.detector.engine.modeOf(rule));
    if (outOfScope) return { ...base, status: 'failed', note: outOfScope };
    // The alert's program goes with the draft, so it is checked against the
    // blocklists until it is decided, however old the alert.
    const proc = d && 'process' in d.event ? d.event.process : undefined;
    const subject: ProposalSubject = {};
    if (proc?.sha256) subject.sha256 = proc.sha256;
    if (proc?.teamId) subject.teamId = proc.teamId;
    if (proc?.signingId) subject.signingId = proc.signingId;
    // An alert about a program the user blocked, or a feed lists as bad, is never quieted.
    if (d && pipeline.isBlockedSubject(subject))
      return { ...base, status: 'failed', note: BLOCKED_EXCLUSION };
    if (kind === 'exclude' && !subject.sha256)
      return {
        ...base,
        status: 'failed',
        note: 'The alert doesn’t say which program it was, so Vigil can’t check it against your blocked list',
      };
    const about = d ? subject : undefined;
    let res: SubmitResult;
    let change: string;
    if (kind === 'exclude') {
      const c = exclusionFor(d!.event, req.scope ?? 'this_binary');
      if (!c)
        return { ...base, status: 'failed', note: 'The alert doesn’t say enough to exclude that' };
      change = `Stop "${rule.name}" matching when ${describeCondition(c)}`;
      res = pipeline.submitTuning(
        { ruleId, addExclusion: c, rationale, evidence },
        by.provider,
        by.name,
        about,
      );
    } else {
      change = `Move "${rule.name}" to Shadow: it keeps recording matches but stops alerting`;
      res = pipeline.submitRetirement(
        { ruleId, toMode: 'shadow', rationale, evidence },
        by.provider,
        by.name,
        about,
      );
    }
    if (res.duplicateOf) return { ...base, change, status: 'already', proposalId: res.duplicateOf };
    if (!res.ok || !res.proposalId)
      return { ...base, change, status: 'failed', note: res.errors.join(' ') || 'Refused' };
    const out: Omit<RuleDraft, 'id'> = {
      ...base,
      change,
      status: 'waiting',
      proposalId: res.proposalId,
    };
    if (res.warnings.length) out.warnings = res.warnings;
    const t = pipeline.get(res.proposalId)?.tuning;
    if (t) out.hits = { before: t.hitsBefore, after: t.hitsAfter };
    return out;
  }

  async reviewNow(): Promise<RuleSuggestionsView> {
    await this.detector.reviewRules({ force: true });
    return this.view();
  }

  private one(p: Proposal): RuleSuggestionView {
    const v: RuleSuggestionView = {
      id: p.id,
      kind: p.kind,
      createdAt: p.createdAt,
      provider: p.provider,
      rationale: p.rationale,
      evidence: p.evidence,
      ruleId: p.rule.id,
      ruleName: p.rule.name,
      description: p.rule.description,
      severity: p.rule.severity,
      warnings: p.lint.warnings,
    };
    if (p.by) v.by = p.by;
    if (p.replay) v.replay = p.replay;
    if (p.impact) v.impact = p.impact;
    if (p.kind === 'new_rule') {
      v.condition = describeCondition(p.rule.condition);
      const editable = Object.fromEntries(
        Object.entries(p.rule).filter(([k]) => !BOOKKEEPING.includes(k)),
      );
      v.ruleJson = JSON.stringify(editable, null, 2);
    }
    if (p.kind === 'tuning') {
      const added = p.rule.exclusions.at(-1);
      if (added) v.exclusion = describeCondition(added);
      if (p.tuning)
        v.tuning = {
          hitsBefore: p.tuning.hitsBefore,
          hitsAfter: p.tuning.hitsAfter,
          removed: p.tuning.removed,
        };
    }
    if (p.kind === 'retire' && p.retireTo) v.retireTo = p.retireTo;
    return v;
  }
}
