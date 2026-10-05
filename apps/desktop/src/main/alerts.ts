import { EventEmitter } from 'node:events';
import {
  AiAssessment,
  authorizeAction,
  canPropose,
  compareSeverity,
  newId,
  undoOf,
  type Action,
  type ActionProposal,
  type ActionRecord,
  type Actor,
  type Alert,
  type NotifyLevel,
  type Rule,
  type SensorEvent,
  type UserDecision,
} from '@vigil/core';
import { AGENT_CATALOG } from '@vigil/detection';
import type { Store } from './db/store.js';
import type { ActionExecutor } from './executor.js';

/** What the detection engine hands over when a rule in alert or block mode matches. */
export interface Detection {
  rule: Rule;
  events: SensorEvent[];
  /** The rule's response with placeholders already resolved. */
  actions: Action[];
  title?: string;
  summary?: string;
  subject?: Alert['subject'];
  /** How loudly to tell the user, instead of what the rule's mode and fidelity call for. */
  notify?: NotifyLevel;
  /** Never fold into an earlier alert (a test alert must pop up every time). */
  standalone?: boolean;
}

export interface AlertEvents {
  /** Any alert was created or changed. */
  changed: [Alert];
  /** Show the always-on-top popup for this alert now. */
  popup: [Alert];
  /** A new alert, after its response ran. The AI explains it from here. */
  raised: [Alert];
}

/** The user's answer from the popup or the app. */
export interface DecisionInput {
  verdict: UserDecision['verdict'];
  /** Undo every containment action still in force for this alert. */
  release: boolean;
  remember?: boolean;
  scope?: UserDecision['scope'];
  note?: string;
}

/**
 * Turns detections into alerts, runs containment inline, and applies the
 * user's decisions. Blocks never wait on anything slow: the response runs
 * before the alert is even announced, and the AI only sees it afterwards.
 */
export class AlertService extends EventEmitter<AlertEvents> {
  constructor(
    private readonly store: Store,
    private readonly executor: ActionExecutor,
    private readonly now: () => number = Date.now,
  ) {
    super();
  }

  /** A shadow-mode rule matched: record it for review, tell nobody. */
  recordShadowMatch(rule: Rule, events: SensorEvent[]): void {
    this.store.tx(() => {
      for (const e of events) this.store.insertEvent(e);
      this.store.insertRuleMatch({
        id: newId(this.now()),
        ruleId: rule.id,
        ruleVersion: rule.version,
        mode: 'shadow',
        ts: this.now(),
        eventIds: events.map((e) => e.id),
      });
    });
  }

  async raise(d: Detection): Promise<Alert> {
    if (d.rule.mode !== 'alert' && d.rule.mode !== 'block') {
      throw new Error(`Rule ${d.rule.id} is in ${d.rule.mode} mode and cannot raise alerts`);
    }
    if (d.events.length === 0) throw new Error('A detection needs at least one event');
    const at = this.now();
    const key = repeatKey(d);
    const same = key ? this.openRepeatOf(key, at) : undefined;
    if (same) return this.foldRepeat(same, d, at);
    let alert: Alert = {
      id: newId(at),
      createdAt: at,
      updatedAt: at,
      ruleId: d.rule.id,
      ruleVersion: d.rule.version,
      title: d.title ?? d.rule.name,
      summary: d.summary ?? d.rule.description,
      severity: d.rule.severity,
      fidelity: d.rule.fidelity,
      notify: d.notify ?? notifyLevel(d.rule),
      status: 'open',
      containment: 'none',
      eventIds: d.events.map((e) => e.id),
      actionIds: [],
      ...(d.subject ? { subject: d.subject } : {}),
      ...(key ? { repeats: { key, count: 1, lastAt: at } } : {}),
    };
    const pile = pileOf(d);
    if (pile) {
      alert.pile = pile;
      // A burst interrupts once: the rest of a pile only adds to the badge.
      if (alert.notify === 'popup' && this.openPileOf(pile.key, at)) alert.notify = 'badge';
    }
    this.store.tx(() => {
      for (const e of d.events) this.store.insertEvent(e);
      this.store.saveAlert(alert);
      this.store.insertRuleMatch({
        id: newId(at),
        ruleId: d.rule.id,
        ruleVersion: d.rule.version,
        mode: d.rule.mode,
        ts: at,
        eventIds: alert.eventIds,
        alertId: alert.id,
      });
    });

    if (d.rule.mode === 'block') {
      for (const action of d.actions) {
        await this.run('rule', action, {
          alertId: alert.id,
          ruleId: d.rule.id,
          reason: d.rule.name,
        });
      }
    } else {
      for (const action of d.actions) {
        this.propose('rule', action, alert.id, `Suggested by rule: ${d.rule.name}`);
      }
    }

    alert = this.refresh(alert.id);
    if (alert.notify === 'popup') this.emit('popup', alert);
    this.emit('raised', alert);
    return alert;
  }

  /** An open, undecided alert of the same pile that started within the last {@link REPEAT_WINDOW_MS}. */
  private openPileOf(key: string, at: number): Alert | undefined {
    return this.store
      .listAlerts({ status: 'open' })
      .find((a) => a.pile?.key === key && !a.decision && at - a.createdAt <= REPEAT_WINDOW_MS);
  }

  /**
   * An open alert this detection repeats exactly, if one started within the
   * last {@link REPEAT_WINDOW_MS}. Anything the user or a rule has acted on, or
   * that carries a suggestion, stands alone.
   */
  private openRepeatOf(key: string, at: number): Alert | undefined {
    return this.store
      .listAlerts({ status: 'open' })
      .find(
        (a) =>
          a.repeats?.key === key &&
          !a.decision &&
          a.containment === 'none' &&
          a.actionIds.length === 0 &&
          at - a.createdAt <= REPEAT_WINDOW_MS &&
          !a.ai?.proposalIds.length &&
          this.store.listProposals({ alertId: a.id }).length === 0 &&
          this.store.listActions({ alertId: a.id }).length === 0,
      );
  }

  /**
   * Fold an identical repeat into its open alert: its events and rule match
   * are kept, the row's count goes up, and nobody is interrupted again (no
   * popup, and the AI isn't asked twice).
   */
  private foldRepeat(alert: Alert, d: Detection, at: number): Alert {
    const next: Alert = {
      ...alert,
      updatedAt: at,
      eventIds: [...alert.eventIds, ...d.events.map((e) => e.id)],
      repeats: { ...alert.repeats!, count: alert.repeats!.count + 1, lastAt: at },
    };
    this.store.tx(() => {
      for (const e of d.events) this.store.insertEvent(e);
      this.store.saveAlert(next);
      this.store.insertRuleMatch({
        id: newId(at),
        ruleId: d.rule.id,
        ruleVersion: d.rule.version,
        mode: d.rule.mode,
        ts: at,
        eventIds: d.events.map((e) => e.id),
        alertId: alert.id,
      });
    });
    this.emit('changed', next);
    return next;
  }

  /** Authorize, log and execute one action. Never throws for a denied or failed action. */
  async run(
    actor: Actor,
    action: Action,
    ctx: { alertId?: string; ruleId?: string; reason: string; undoes?: string },
  ): Promise<ActionRecord> {
    const base: ActionRecord = {
      id: newId(this.now()),
      action,
      actor,
      reason: ctx.reason,
      requestedAt: this.now(),
      status: 'pending',
      ...(ctx.alertId ? { alertId: ctx.alertId } : {}),
      ...(ctx.ruleId ? { ruleId: ctx.ruleId } : {}),
      ...(ctx.undoes ? { undoes: ctx.undoes } : {}),
    };
    const auth = authorizeAction(actor, action);
    if (!auth.ok) {
      return this.logAction({
        ...base,
        status: 'denied',
        result: { at: this.now(), error: auth.reason },
      });
    }
    this.logAction(base);
    try {
      const result = await this.executor.execute(action);
      return this.logAction({ ...base, status: result.error ? 'failed' : 'done', result });
    } catch (err) {
      const error = err instanceof Error ? err.message : String(err);
      return this.logAction({ ...base, status: 'failed', result: { at: this.now(), error } });
    }
  }

  /** The user undoes one action. */
  async undo(actionId: string): Promise<ActionRecord> {
    const record = this.store.getAction(actionId);
    if (!record) throw new Error(`No action ${actionId}`);
    if (record.status !== 'done') throw new Error(`Action ${actionId} is ${record.status}`);
    const reverse = undoOf(record.action, record.result);
    if (!reverse) throw new Error(`${record.action.kind} cannot be undone`);
    const out = await this.run('user', reverse, {
      reason: `Undo ${record.action.kind}`,
      undoes: record.id,
      ...(record.alertId ? { alertId: record.alertId } : {}),
    });
    if (out.status === 'done') this.store.saveAction({ ...record, status: 'undone' });
    if (record.alertId) this.refresh(record.alertId);
    return out;
  }

  /**
   * The user's verdict. Only this path releases containment. If any part of a
   * release fails, the alert stays open and undecided with whatever is still
   * in force shown as blocked: the user is never told something was released
   * when it wasn't. The failed undo is in the action log with its error.
   */
  async decide(alertId: string, input: DecisionInput): Promise<Alert> {
    const alert = this.store.getAlert(alertId);
    if (!alert) throw new Error(`No alert ${alertId}`);
    if (input.release) {
      const active = this.store
        .listActions({ alertId })
        .filter((r) => r.status === 'done' && !r.undoes && undoOf(r.action, r.result));
      let failed = 0;
      for (const r of active) {
        try {
          if ((await this.undo(r.id)).status !== 'done') failed++;
        } catch (err) {
          console.warn(`[alerts] could not undo ${r.id}:`, err);
          failed++;
        }
      }
      if (failed > 0) return this.refresh(alertId);
    }
    for (const p of this.store.listProposals({ alertId, status: 'pending' })) {
      this.store.saveProposal({ ...p, status: 'expired', decidedAt: this.now() });
    }
    const decision: UserDecision = {
      at: this.now(),
      verdict: input.verdict,
      remember: input.remember ?? false,
      ...(input.scope ? { scope: input.scope } : {}),
      ...(input.note ? { note: input.note } : {}),
    };
    return this.update(alertId, (a) => ({ ...a, decision, status: 'resolved' }));
  }

  /** Put a resolved alert back in the list. */
  reopen(alertId: string): Alert {
    return this.update(alertId, ({ decision: _d, ...a }) => ({ ...a, status: 'open' }));
  }

  // ---------------------------------------------------------------- proposals and AI

  propose(actor: Actor, action: Action, alertId: string, rationale: string): ActionProposal {
    const ok = canPropose(actor, action);
    if (!ok.ok) throw new Error(ok.reason);
    const proposal = this.store.saveProposal({
      id: newId(this.now()),
      action,
      proposedBy: actor,
      alertId,
      rationale,
      createdAt: this.now(),
      status: 'pending',
    });
    this.refresh(alertId);
    return proposal;
  }

  async approveProposal(id: string): Promise<ActionRecord> {
    const p = this.store.listProposals().find((x) => x.id === id);
    if (!p || p.status !== 'pending') throw new Error(`No pending proposal ${id}`);
    const record = await this.run('user', p.action, {
      reason: `Approved: ${p.rationale}`,
      ...(p.alertId ? { alertId: p.alertId } : {}),
    });
    this.store.saveProposal({
      ...p,
      status: 'approved',
      decidedAt: this.now(),
      actionId: record.id,
    });
    if (p.alertId) this.refresh(p.alertId);
    return record;
  }

  rejectProposal(id: string): void {
    const p = this.store.listProposals().find((x) => x.id === id);
    if (!p || p.status !== 'pending') throw new Error(`No pending proposal ${id}`);
    this.store.saveProposal({ ...p, status: 'rejected', decidedAt: this.now() });
    if (p.alertId) this.refresh(p.alertId);
  }

  /** The AI bridge reports its read on an alert. Advisory: containment is untouched. */
  recordAssessment(alertId: string, assessment: AiAssessment): Alert {
    const ai = AiAssessment.parse(assessment);
    return this.update(alertId, (a) => ({ ...a, ai }));
  }

  // ---------------------------------------------------------------- internals

  private logAction(record: ActionRecord): ActionRecord {
    const saved = this.store.saveAction(record);
    if (record.alertId) {
      const alert = this.store.getAlert(record.alertId);
      if (alert && !alert.actionIds.includes(record.id)) {
        this.store.saveAlert({ ...alert, actionIds: [...alert.actionIds, record.id] });
      }
    }
    return saved;
  }

  private update(alertId: string, fn: (a: Alert) => Alert): Alert {
    const alert = this.store.getAlert(alertId);
    if (!alert) throw new Error(`No alert ${alertId}`);
    this.store.saveAlert({ ...fn(alert), updatedAt: this.now() });
    return this.refresh(alertId);
  }

  /** Recompute containment from the action log, save, and announce. */
  private refresh(alertId: string): Alert {
    const alert = this.store.getAlert(alertId);
    if (!alert) throw new Error(`No alert ${alertId}`);
    const actions = this.store.listActions({ alertId });
    const containing = actions.filter(
      (r) => !r.undoes && r.status !== 'denied' && r.status !== 'failed',
    );
    const containment: Alert['containment'] = containing.some((r) => r.status === 'done')
      ? 'active'
      : containing.some((r) => r.status === 'undone')
        ? 'released'
        : 'none';
    const next = { ...alert, containment };
    if (next.containment !== alert.containment) {
      next.updatedAt = this.now();
      this.store.saveAlert(next);
    }
    this.emit('changed', next);
    return next;
  }
}

/** How long one row may keep folding in identical repeats, counted from its first detection. */
export const REPEAT_WINDOW_MS = 15 * 60_000;

/**
 * The evidence a repeat must match exactly to share a row: the rule and its
 * version, what the alert says, and every event with its process (executable
 * identity and signature, pid and start time, command line, working
 * directory, user, parent) and resource, with only the event's id, time and
 * raw sensor record left out. Detections that run or suggest an action,
 * critical ones, and ones marked standalone never share a row.
 */
export function repeatKey(d: Detection): string | undefined {
  if (d.standalone || d.actions.length > 0 || d.rule.severity === 'critical') return undefined;
  return JSON.stringify([
    d.rule.id,
    d.rule.version,
    d.title ?? null,
    d.summary ?? null,
    d.subject ?? null,
    d.events.map(({ id: _id, ts: _ts, raw: _raw, ...rest }) => sorted(rest)),
  ]);
}

/**
 * Which pile a detection joins: the same rule and version, in one agent run
 * (or, outside an agent, from one program). Detections that run or suggest an
 * action, critical ones, and ones marked standalone each stand alone, like
 * {@link repeatKey}.
 */
export function pileOf(d: Detection): Alert['pile'] | undefined {
  if (d.standalone || d.actions.length > 0 || d.rule.severity === 'critical') return undefined;
  const e = d.events[0]!;
  const proc = 'process' in e ? e.process : undefined;
  const agent = proc?.agent;
  const what = 'path' in e && typeof e.path === 'string' ? e.path : undefined;
  if (agent) {
    const name = AGENT_CATALOG.find((c) => c.id === agent.id)?.name ?? agent.id;
    return {
      key: JSON.stringify([d.rule.id, d.rule.version, 'agent', agent.session]),
      who: name,
      ...(what ? { what } : {}),
    };
  }
  if (!proc?.path) return undefined;
  return {
    key: JSON.stringify([d.rule.id, d.rule.version, 'program', proc.path]),
    who: proc.path.split('/').pop() || proc.path,
    ...(what ? { what } : {}),
  };
}

/** The same value with object keys in a fixed order, so equal evidence gives an equal key. */
function sorted(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sorted);
  if (v && typeof v === 'object') {
    return Object.fromEntries(
      Object.entries(v as Record<string, unknown>)
        .filter(([, x]) => x !== undefined)
        .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
        .map(([k, x]) => [k, sorted(x)]),
    );
  }
  return v;
}

/**
 * Popup when Vigil blocked something, or when a trustworthy rule sees something serious.
 * Noisier rules only raise the menu-bar badge, so a low-fidelity rule can't cry wolf.
 */
export function notifyLevel(rule: Rule): NotifyLevel {
  if (rule.mode === 'block') return 'popup';
  if (rule.fidelity === 'high' && compareSeverity(rule.severity, 'medium') >= 0) return 'popup';
  if (rule.fidelity === 'low' && compareSeverity(rule.severity, 'medium') < 0) return 'silent';
  return 'badge';
}
