import type { DetectionEngine } from './engine.js';
import { compileRule } from './engine.js';
import { assertUserOrigin, type UserOrigin } from './origin.js';
import { formatZod } from './proposals/pipeline.js';
import { proveChange, type ImpactReport } from './proposals/prover.js';
import { replayRule, type ReplayReport } from './proposals/replay.js';
import { lintRule } from './rules/lint.js';
import type { RuleRepository } from './state/sqlite.js';
import type { EventHistory, RuleException } from './state/stores.js';
import { Condition, DetectionRule, type DetectionEvent, type DetectionRuleInput } from './types.js';

const DAY = 86_400_000;

export interface EditResult {
  ok: boolean;
  rule?: DetectionRule;
  errors: string[];
  warnings: string[];
}

export interface RuleEditView {
  /** The rule as it runs now. */
  rule: DetectionRule;
  /** The mode it runs in (the user's or the engine's override, else the rule's own). */
  mode: DetectionRule['mode'];
  origin: 'builtin' | 'user' | 'ai' | 'feed';
  /** The shipped version, when this is a built-in. */
  builtin?: DetectionRule;
  /** True when the user changed a built-in; `revert` restores the shipped version. */
  edited: boolean;
  /** A pack update shipped a newer built-in than the one the user edited. */
  builtinUpdateAvailable: boolean;
  /** "Don't alert me about this again" answers from alerts, which also suppress the rule. */
  exceptions: RuleException[];
}

export interface PreviewResult extends EditResult {
  /** How the rule would have behaved on this Mac over the replay window. */
  replay?: ReplayReport;
  /** For an edit to an existing rule: what it would stop catching. */
  impact?: ImpactReport;
}

export type ExcludeScope = 'this_binary' | 'this_signer' | 'this_path' | 'this_host';

/**
 * What an exclusion for this event should match, narrowest first. Undefined
 * when the event lacks what the scope needs (a signer needs team ID and
 * signing ID together, since an ad-hoc signature can claim any signing ID).
 */
export function exclusionFor(e: DetectionEvent, scope: ExcludeScope): Condition | undefined {
  const p = 'process' in e ? e.process : undefined;
  const eq = (field: string, value: string) => ({ field, op: 'eq' as const, value });
  switch (scope) {
    case 'this_binary':
      if (p?.sha256) return eq('process.sha256', p.sha256);
      if (p?.cdhash) return eq('process.cdhash', p.cdhash);
      return p ? eq('process.path', p.path) : undefined;
    case 'this_signer':
      return p?.teamId && p.signingId
        ? { all: [eq('process.teamId', p.teamId), eq('process.signingId', p.signingId)] }
        : undefined;
    case 'this_path':
      if (p) return eq('process.path', p.path);
      return 'path' in e && e.path ? eq('path', e.path) : undefined;
    case 'this_host':
      if (e.kind !== 'network.connection') return undefined;
      return e.remoteHost ? eq('remoteHost', e.remoteHost) : eq('remoteAddress', e.remoteAddress);
  }
}

/**
 * The user's rule editor. Every change needs a UserOrigin, so none of this is
 * reachable from the AI tool surface, and every change is validated, linted
 * and compiled before it touches the running engine.
 *
 * Built-ins can be edited; the shipped version stays in the pack, so `revert`
 * brings it back. Rules the user wrote can be deleted; built-ins can only be
 * turned off.
 */
export class RuleEditor {
  private readonly builtins: Map<string, DetectionRule>;
  private readonly now: () => number;
  private readonly replayDays: number;

  constructor(
    private readonly engine: DetectionEngine,
    builtins: readonly DetectionRuleInput[],
    private readonly repository: RuleRepository,
    private readonly history: EventHistory,
    opts: { now?: () => number; replayDays?: number } = {},
  ) {
    this.builtins = new Map(builtins.map((b) => [b.id, DetectionRule.parse(b)]));
    this.now = opts.now ?? Date.now;
    this.replayDays = opts.replayDays ?? 14;
  }

  view(id: string): RuleEditView | undefined {
    const rule = this.engine.getRule(id);
    if (!rule) return undefined;
    const builtin = this.builtins.get(id);
    const out: RuleEditView = {
      rule,
      mode: this.engine.modeOf(rule),
      origin: builtin ? 'builtin' : rule.origin,
      edited: builtin !== undefined && rule.editedFrom !== undefined,
      builtinUpdateAvailable:
        builtin !== undefined && rule.editedFrom !== undefined && builtin.version > rule.editedFrom,
      exceptions: this.engine.stores.exceptions.forRule(id).filter((x) => x.ruleId === id),
    };
    if (builtin) out.builtin = builtin;
    return out;
  }

  list(): RuleEditView[] {
    return this.engine
      .allRules()
      .map((r) => this.view(r.id)!)
      .sort((a, b) => a.rule.name.localeCompare(b.rule.name));
  }

  /** Check a draft without saving it. */
  validate(raw: unknown): EditResult {
    const parsed = DetectionRule.safeParse(this.draft(raw));
    if (!parsed.success) return { ok: false, errors: formatZod(parsed.error), warnings: [] };
    const rule = parsed.data;
    const { errors, warnings } = lintRule(rule);
    try {
      compileRule(rule);
    } catch (err) {
      errors.push((err as Error).message);
    }
    return errors.length
      ? { ok: false, rule, errors, warnings }
      : { ok: true, rule, errors, warnings };
  }

  /** Validate, then replay the draft over recent history so the user sees how often it would fire. */
  preview(raw: unknown): PreviewResult {
    const v = this.validate(raw);
    if (!v.ok || !v.rule) return v;
    const to = this.now();
    const { report } = replayRule(
      v.rule,
      {
        history: this.history,
        lists: this.engine.stores.lists,
        userExceptions: this.engine.stores.exceptions,
        existingRules: this.engine.allRules(),
      },
      { from: to - this.replayDays * DAY, to },
    );
    const current = this.engine.getRule(v.rule.id);
    if (!current) return { ...v, replay: report };
    const impact = proveChange({
      before: current,
      beforeMode: this.engine.modeOf(current),
      after: v.rule,
      afterMode: v.rule.mode,
      history: this.history,
      lists: this.engine.stores.lists,
      from: to - this.replayDays * DAY,
      to,
    });
    return { ...v, replay: report, impact };
  }

  /** Save a new rule or an edit. The mode in the draft becomes the rule's running mode. */
  save(raw: unknown, origin: UserOrigin): EditResult {
    assertUserOrigin(origin);
    const v = this.validate(raw);
    if (!v.ok || !v.rule) return v;
    const rule = v.rule;
    this.engine.upsertRule(rule);
    this.repository.save(rule, this.now());
    this.engine._setMode(rule.id, rule.mode);
    return { ...v, rule };
  }

  /** Put a built-in back to the shipped version, including its mode. */
  revert(id: string, origin: UserOrigin): DetectionRule {
    assertUserOrigin(origin);
    const builtin = this.builtins.get(id);
    if (!builtin) throw new Error(`${id} is not a built-in rule`);
    this.repository.remove(id);
    this.engine.upsertRule(builtin);
    this.engine._setMode(id, builtin.mode);
    return builtin;
  }

  /** Delete a rule the user or an AI proposal added. Built-ins can only be turned off. */
  delete(id: string, origin: UserOrigin): void {
    assertUserOrigin(origin);
    if (this.builtins.has(id)) throw new Error('Built-in rules can be turned off, not deleted');
    if (!this.engine.getRule(id)) throw new Error(`No rule ${id}`);
    this.repository.remove(id);
    this.engine.removeRule(id);
  }

  addExclusion(ruleId: string, condition: unknown, origin: UserOrigin): EditResult {
    const c = Condition.safeParse(condition);
    if (!c.success) return { ok: false, errors: formatZod(c.error), warnings: [] };
    const rule = this.engine.getRule(ruleId);
    if (!rule) return { ok: false, errors: [`No rule ${ruleId}`], warnings: [] };
    const same = JSON.stringify(c.data);
    if (rule.exclusions.some((x) => JSON.stringify(x) === same)) {
      return { ok: true, rule, errors: [], warnings: ['That exclusion is already on the rule.'] };
    }
    // Keep the mode it runs in: the rule's own may be older than the user's choice.
    const mode = this.engine.modeOf(rule);
    return this.save({ ...rule, mode, exclusions: [...rule.exclusions, c.data] }, origin);
  }

  removeExclusion(ruleId: string, index: number, origin: UserOrigin): EditResult {
    const rule = this.engine.getRule(ruleId);
    if (!rule) return { ok: false, errors: [`No rule ${ruleId}`], warnings: [] };
    if (!Number.isInteger(index) || index < 0 || index >= rule.exclusions.length) {
      return { ok: false, errors: ['No exclusion at that position'], warnings: [] };
    }
    return this.save(
      {
        ...rule,
        mode: this.engine.modeOf(rule),
        exclusions: rule.exclusions.filter((_, i) => i !== index),
      },
      origin,
    );
  }

  /** Exclude what an alert was about from its rule, e.g. "never alert on this program again". */
  excludeEvent(
    ruleId: string,
    e: DetectionEvent,
    scope: ExcludeScope,
    origin: UserOrigin,
  ): EditResult {
    const c = exclusionFor(e, scope);
    if (!c)
      return { ok: false, errors: ['The alert does not say enough to exclude that'], warnings: [] };
    return this.addExclusion(ruleId, c, origin);
  }

  /** Fill in bookkeeping the user does not edit: version, dates, origin, the built-in marker. */
  private draft(raw: unknown): unknown {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return raw;
    const r = raw as Record<string, unknown>;
    const id = typeof r.id === 'string' ? r.id : undefined;
    const current = id ? this.engine.getRule(id) : undefined;
    const builtin = id ? this.builtins.get(id) : undefined;
    const now = this.now();
    const out: Record<string, unknown> = {
      description: '',
      fidelity: 'medium',
      ...r,
      version: Math.max(current?.version ?? 0, builtin?.version ?? 0) + 1,
      createdAt: current?.createdAt ?? now,
      updatedAt: now,
      origin: current?.origin ?? 'user',
    };
    if (builtin) out.editedFrom = current?.editedFrom ?? builtin.version;
    else delete out.editedFrom;
    if (current?.provenance) out.provenance = current.provenance;
    else delete out.provenance;
    return out;
  }
}
