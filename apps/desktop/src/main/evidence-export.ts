import {
  Action,
  SensorEvent,
  type ActionProposal,
  type ActionRecord,
  type Alert,
} from '@vigil/core';
import type { AlertDetail } from '../shared/ipc.js';

/**
 * What Copy as JSON exports, field by field. Each field is picked on purpose,
 * so one added to a record later (or an internal one such as a repeat's
 * match key, which holds the whole command line) stays out until someone
 * adds it here. Redaction runs on the result (evidence-redact.ts).
 */
export function evidenceOf(d: AlertDetail): unknown {
  const { alert, events, actions, proposals, rule } = d;
  return {
    alert: alertFields(alert),
    rule: rule
      ? { id: rule.id, name: rule.name, version: rule.version, mode: rule.mode }
      : undefined,
    events: events.map(eventFields),
    actions: actions.map(actionFields),
    proposals: proposals.map(proposalFields),
  };
}

function alertFields(a: Alert) {
  return {
    id: a.id,
    createdAt: a.createdAt,
    updatedAt: a.updatedAt,
    ruleId: a.ruleId,
    ruleVersion: a.ruleVersion,
    title: a.title,
    summary: a.summary,
    severity: a.severity,
    fidelity: a.fidelity,
    notify: a.notify,
    status: a.status,
    containment: a.containment,
    eventIds: a.eventIds,
    actionIds: a.actionIds,
    subject: a.subject && { kind: a.subject.kind, label: a.subject.label, path: a.subject.path },
    ai: a.ai && {
      provider: a.ai.provider,
      model: a.ai.model,
      at: a.ai.at,
      verdict: a.ai.verdict,
      confidence: a.ai.confidence,
      summary: a.ai.summary,
      details: a.ai.details,
    },
    decision: a.decision && {
      at: a.decision.at,
      verdict: a.decision.verdict,
      remember: a.decision.remember,
      scope: a.decision.scope,
      note: a.decision.note,
    },
    // Not the key: it is the matched evidence itself, serialized.
    repeats: a.repeats && { count: a.repeats.count, lastAt: a.repeats.lastAt },
    pile: a.pile && { who: a.pile.who, what: a.pile.what },
  };
}

/**
 * An event as its schema defines it, which drops any field the schema
 * doesn't name, without the raw sensor record the redaction can't vouch for.
 */
function eventFields(e: SensorEvent) {
  const { raw: _raw, ...rest } = e;
  const parsed = SensorEvent.safeParse(rest);
  if (parsed.success) {
    const { raw: _r, ...event } = parsed.data;
    return event;
  }
  return { id: e.id, ts: e.ts, source: e.source, kind: e.kind };
}

/** An action, checked against its schema the same way. */
function actionOf(a: Action) {
  const parsed = Action.safeParse(a);
  return parsed.success ? parsed.data : { kind: a.kind };
}

function actionFields(r: ActionRecord) {
  return {
    id: r.id,
    action: actionOf(r.action),
    actor: r.actor,
    alertId: r.alertId,
    ruleId: r.ruleId,
    reason: r.reason,
    requestedAt: r.requestedAt,
    status: r.status,
    result: r.result && {
      at: r.result.at,
      error: r.result.error,
      quarantineId: r.result.quarantineId,
      simulated: r.result.simulated,
    },
    undoes: r.undoes,
  };
}

function proposalFields(p: ActionProposal) {
  return {
    id: p.id,
    action: actionOf(p.action),
    proposedBy: p.proposedBy,
    alertId: p.alertId,
    rationale: p.rationale,
    createdAt: p.createdAt,
    status: p.status,
    decidedAt: p.decidedAt,
    actionId: p.actionId,
  };
}
