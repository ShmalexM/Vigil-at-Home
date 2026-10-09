import type { Condition as CoreCondition } from '@vigil/core';
import {
  KNOWN_FIELDS,
  type Condition,
  type Detection,
  type DetectionRule,
  type EditResult,
} from '@vigil/detection';
import { userOrigin } from '@vigil/detection/user';
import type { ExcludeScope, ExclusionInput, RuleCheck, RuleEditorView } from '../shared/ipc.js';
import { notChangedText } from '../shared/helper-outcome.js';
import type { Store } from './db/store.js';
import { notApplied, type Detector } from './detection.js';

/** Fields the editor manages itself; left out of the JSON the user edits. */
const BOOKKEEPING = ['version', 'createdAt', 'updatedAt', 'origin', 'provenance', 'editedFrom'];

/**
 * The Rules screen's editor, on top of the detection engine's RuleEditor.
 * Every change here comes from the UI, so it carries a user origin; the
 * engine validates, lints and compiles it before anything runs. Each change
 * is made only once the helper takes it: one that weakens a blocking rule
 * waits on the admin password, and if that is cancelled (or the helper
 * refuses) nothing changes and the result says so.
 */
export class RuleEditing {
  constructor(
    private readonly detector: Detector,
    private readonly store: Store,
  ) {}

  view(id: string): RuleEditorView | null {
    const v = this.detector.editor.view(id);
    if (!v) return null;
    const editable = Object.fromEntries(
      Object.entries(v.rule).filter(([k]) => !BOOKKEEPING.includes(k)),
    );
    return {
      rule: v.rule as unknown as RuleEditorView['rule'],
      ruleJson: JSON.stringify({ ...editable, mode: v.mode }, null, 2),
      mode: v.mode,
      builtin: v.builtin !== undefined,
      edited: v.edited,
      builtinUpdateAvailable: v.builtinUpdateAvailable,
      exclusions: v.rule.exclusions.map(describeCondition),
      exceptions: v.exceptions.map((x) => ({
        id: x.id,
        summary: Object.entries(x.match)
          .map(([f, val]) => `${f} is ${val}`)
          .join(' and '),
        ...(x.note ? { note: x.note } : {}),
        createdAt: x.createdAt,
      })),
      fields: [...KNOWN_FIELDS],
    };
  }

  preview(ruleJson: string): RuleCheck {
    const parsed = parseJson(ruleJson);
    if ('error' in parsed) return { ok: false, errors: [parsed.error], warnings: [] };
    const r = this.detector.editor.preview(parsed.value);
    return {
      ...check(r),
      ...(r.replay ? { replay: r.replay } : {}),
      ...(r.impact ? { impact: r.impact } : {}),
    };
  }

  async save(ruleJson: string): Promise<RuleCheck> {
    const parsed = parseJson(ruleJson);
    if ('error' in parsed) return { ok: false, errors: [parsed.error], warnings: [] };
    return this.done(() => this.detector.editor.save(parsed.value, userOrigin('rules-screen')));
  }

  revert(id: string): Promise<RuleCheck> {
    return this.done(() => {
      this.detector.editor.revert(id, userOrigin('rules-screen'));
      return { ok: true, errors: [], warnings: [] };
    });
  }

  delete(id: string): Promise<RuleCheck> {
    return this.done(() => {
      this.detector.editor.delete(id, userOrigin('rules-screen'));
      return { ok: true, errors: [], warnings: [] };
    });
  }

  addExclusion(ruleId: string, input: ExclusionInput): Promise<RuleCheck> {
    const value =
      input.op === 'in'
        ? input.value
            .split(',')
            .map((v) => v.trim())
            .filter(Boolean)
        : input.value.trim();
    const condition = { field: input.field, op: input.op, value, nocase: true };
    return this.done(() =>
      this.detector.editor.addExclusion(ruleId, condition, userOrigin('rules-screen')),
    );
  }

  removeExclusion(ruleId: string, index: number): Promise<RuleCheck> {
    return this.done(() =>
      this.detector.editor.removeExclusion(ruleId, index, userOrigin('rules-screen')),
    );
  }

  removeException(id: string): Promise<RuleCheck> {
    return this.done(() => {
      this.detector.feedback.removeException(id, userOrigin('rules-screen'));
      return { ok: true, errors: [], warnings: [] };
    });
  }

  /** "Never alert on this again" from an alert, as an exclusion on its rule. */
  async excludeFromAlert(alertId: string, scope: ExcludeScope): Promise<RuleCheck> {
    const d = this.store.getAlertDetection(alertId) as Detection | undefined;
    if (!d) {
      return { ok: false, errors: ['This alert did not come from a detection rule'], warnings: [] };
    }
    return this.done(() =>
      this.detector.editor.excludeEvent(d.match.ruleId, d.event, scope, userOrigin('alert')),
    );
  }

  /** Make the change once the helper takes it; if it doesn't, nothing changed. */
  private async done(fn: () => EditResult): Promise<RuleCheck> {
    const { value: r, helper, reason } = await this.detector.userChange(fn);
    const out: RuleCheck = { ...check(r), helper };
    if (r.ok && notApplied(helper))
      return { ...out, ok: false, errors: [notChangedText(helper, reason)!] };
    return out;
  }
}

function check(r: EditResult): RuleCheck {
  return { ok: r.ok, errors: r.errors, warnings: r.warnings };
}

function parseJson(text: string): { value: unknown } | { error: string } {
  try {
    return { value: JSON.parse(text) as unknown };
  } catch (err) {
    return { error: `Not valid JSON: ${err instanceof Error ? err.message : String(err)}` };
  }
}

const OPS: Record<string, string> = {
  eq: 'is',
  neq: 'is not',
  in: 'is one of',
  notIn: 'is not one of',
  startsWith: 'starts with',
  endsWith: 'ends with',
  contains: 'contains',
  glob: 'matches',
  regex: 'matches pattern',
  exists: 'is present',
  cidr: 'is in network',
  gt: 'is more than',
  lt: 'is less than',
};

/** A condition in plain words, e.g. "process.teamId is ABC and process.signingId is com.x". */
export function describeCondition(c: Condition | CoreCondition): string {
  if ('all' in c) return c.all.map(describeCondition).join(' and ');
  if ('any' in c) return `(${c.any.map(describeCondition).join(' or ')})`;
  if ('not' in c) return `not (${describeCondition(c.not)})`;
  if ('firstSeen' in c) return `first time ${c.firstSeen.key.join(' + ')} is seen`;
  if ('inList' in c) return `${c.inList.field} is on the ${c.inList.list} list`;
  const v = Array.isArray(c.value) ? c.value.join(', ') : c.value;
  return `${c.field} ${OPS[c.op] ?? c.op}${v === undefined ? '' : ` ${String(v)}`}`;
}

export type { DetectionRule };
