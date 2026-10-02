import type { RuleMode } from '@vigil/core';
import type { Proposal } from '@vigil/detection';
import type { RuleSuggestionView, RuleSuggestionsView } from '../shared/ipc.js';
import type { Detector } from './detection.js';
import { describeCondition } from './rule-editing.js';

const BOOKKEEPING = ['version', 'createdAt', 'updatedAt', 'origin', 'provenance', 'mode'];
const RECENT = 10;

/**
 * The Rules screen's list of AI suggestions. The AI proposes; the detection
 * pipeline checks and replays; only the user's click here changes a rule.
 */
export class RuleSuggestions {
  constructor(
    private readonly detector: Detector,
    /** Whether a cloud AI is set up to run reviews at all. */
    private readonly available: () => boolean,
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

  accept(id: string, mode?: RuleMode): void {
    void this.detector.approveProposal(id, mode);
  }

  dismiss(id: string, note?: string): void {
    this.detector.rejectProposal(id, note);
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
