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
import type { Store } from './db/store.js';
import type { Detector } from './detection.js';

/** Fields the editor manages itself; left out of the JSON the user edits. */
const BOOKKEEPING = ['version', 'createdAt', 'updatedAt', 'origin', 'provenance', 'editedFrom'];

/**
 * The Rules screen's editor, on top of the detection engine's RuleEditor.
 * Every change here comes from the UI, so it carries a user origin; the
 * engine validates, lints and compiles it before anything runs.
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
    return { ...check(r), ...(r.replay ? { replay: r.replay } : {}) };
  }

  save(ruleJson: string): RuleCheck {
    const parsed = parseJson(ruleJson);
    if ('error' in parsed) return { ok: false, errors: [parsed.error], warnings: [] };
    return this.done(this.detector.editor.save(parsed.value, userOrigin('rules-screen')));
  }

  revert(id: string): void {
    this.detector.editor.revert(id, userOrigin('rules-screen'));
    this.detector.rulesChanged();
  }

  delete(id: string): void {
    this.detector.editor.delete(id, userOrigin('rules-screen'));
    this.detector.rulesChanged();
  }

  addExclusion(ruleId: string, input: ExclusionInput): RuleCheck {
    const value =
      input.op === 'in'
        ? input.value
            .split(',')
            .map((v) => v.trim())
            .filter(Boolean)
        : input.value.trim();
    const condition = { field: input.field, op: input.op, value, nocase: true };
    return this.done(
      this.detector.editor.addExclusion(ruleId, condition, userOrigin('rules-screen')),
    );
  }

  removeExclusion(ruleId: string, index: number): RuleCheck {
    return this.done(
      this.detector.editor.removeExclusion(ruleId, index, userOrigin('rules-screen')),
    );
  }

  removeException(id: string): void {
    this.detector.feedback.removeException(id, userOrigin('rules-screen'));
  }

  /** "Never alert on this again" from an alert, as an exclusion on its rule. */
  excludeFromAlert(alertId: string, scope: ExcludeScope): RuleCheck {
    const d = this.store.getAlertDetection(alertId) as Detection | undefined;
    if (!d) {
      return { ok: false, errors: ['This alert did not come from a detection rule'], warnings: [] };
    }
    return this.done(
      this.detector.editor.excludeEvent(d.match.ruleId, d.event, scope, userOrigin('alert')),
    );
  }

  private done(r: EditResult): RuleCheck {
    if (r.ok) this.detector.rulesChanged();
    return check(r);
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
