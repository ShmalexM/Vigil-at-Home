import type { Action, ActionRecord, ActionProposal, Alert } from '@vigil/core';
import { needsDecision } from '../../shared/attention';
import { pileMates } from '../../shared/piles';

/**
 * Words for the decision buttons, so each one says what it does ("Resume
 * app", "Unblock connection") instead of a generic "Allow". Shared by the
 * alert page and the popup. The release steps mirror undoOf in @vigil/core
 * and the "still in force" filter in AlertService.decide.
 */

const base = (p: string) => p.split('/').filter(Boolean).pop() ?? p;
const proc = (a: { pid: number; path?: string | undefined }) =>
  a.path ? base(a.path) : `process ${a.pid}`;

/** Containment from this alert that is still in force and can be undone. */
export function activeContainment(actions: readonly ActionRecord[]): ActionRecord[] {
  return actions.filter((r) => r.status === 'done' && !r.undoes && releaseStep(r) !== undefined);
}

/** What releasing one containment action does, in a few words. */
export function releaseStep(r: ActionRecord): string | undefined {
  const a = r.action;
  switch (a.kind) {
    case 'process.suspend':
      return `Resume ${proc(a)}`;
    case 'network.block':
      return `Unblock connections to ${a.address}${a.port ? `:${a.port}` : ''}`;
    case 'file.quarantine':
      return r.result?.quarantineId ? `Restore ${base(a.path)}` : undefined;
    case 'santa.rule.set':
      return a.policy === 'allow' ? undefined : 'Let this program run again';
    case 'persistence.disable':
      return `Turn startup item ${base(a.path)} back on`;
    default:
      return undefined;
  }
}

type Kind = Action['kind'];
const one = (records: readonly { action: Action }[]): Kind | undefined => {
  const kinds = new Set(records.map((r) => r.action.kind));
  return kinds.size === 1 ? [...kinds][0] : undefined;
};

/** "Keep paused", "Keep quarantined", or "Keep blocked" when it's a mix. */
export function keepLabel(active: readonly ActionRecord[]): string {
  switch (one(active)) {
    case 'process.suspend':
      return 'Keep paused';
    case 'file.quarantine':
      return 'Keep quarantined';
    case 'persistence.disable':
      return 'Keep turned off';
    default:
      return 'Keep blocked';
  }
}

/** "Resume app", "Unblock connections", or "Release both" when it's a mix. */
export function releaseLabel(active: readonly ActionRecord[]): string {
  const n = active.length;
  const s = n === 1 ? '' : 's';
  switch (one(active)) {
    case 'process.suspend':
      return `Resume app${s}`;
    case 'network.block':
      return `Unblock connection${s}`;
    case 'file.quarantine':
      return `Restore file${s}`;
    case 'persistence.disable':
      return n === 1 ? 'Turn it back on' : 'Turn them back on';
    case 'santa.rule.set':
      return 'Let it run';
    default:
      return n === 0 ? 'Mark as fine' : n === 2 ? 'Release both' : `Release all ${n}`;
  }
}

/** The button for a suggested response: "Pause app", "Block connection", or "Do all 2". */
export function containLabel(pending: readonly ActionProposal[]): string {
  if (pending.length > 1) return `Do all ${pending.length}`;
  const a = pending[0]?.action;
  switch (a?.kind) {
    case 'process.suspend':
      return 'Pause app';
    case 'process.kill':
      return 'Stop app';
    case 'network.block':
      return 'Block connection';
    case 'file.quarantine':
      return 'Quarantine file';
    case 'persistence.disable':
      return 'Turn off startup item';
    case 'santa.rule.set':
      return a.policy === 'allow' ? 'Always allow' : 'Block this program';
    default:
      return 'Block it';
  }
}

/**
 * Whether an action really changed something: `real` ran through the helper,
 * `simulated` was only logged (the helper wasn't connected), and `unknown`
 * was recorded by an older build that didn't say. Those builds left one
 * sign, the dry run's `dry-` quarantine id; anything else stays unknown,
 * never real.
 */
export type Provenance = 'real' | 'simulated' | 'unknown';

export function provenance(r: ActionRecord): Provenance {
  const s = r.result?.simulated;
  if (s === true) return 'simulated';
  if (s === false) return 'real';
  return r.result?.quarantineId?.startsWith('dry-') ? 'simulated' : 'unknown';
}

/** This action only ran as a simulation: the helper wasn't connected at the time. */
export function isSimulated(r: ActionRecord): boolean {
  return provenance(r) === 'simulated';
}

/**
 * The mark for an action that went through but may not have changed
 * anything, shown next to it in the popup and in History; undefined for a
 * real one, and for one that never went through.
 */
export function provenanceLabel(r: ActionRecord): string | undefined {
  if (r.status !== 'done' && r.status !== 'undone') return undefined;
  return { real: undefined, simulated: 'Simulated', unknown: 'Maybe simulated' }[provenance(r)];
}

/**
 * What Vigil's own response to an alert really did, over every action that
 * went through (one with no undo, like a kill, included): all `real`, all
 * `simulated`, a `mixed` bag, or `unknown` when any of them doesn't say.
 * Undefined when nothing went through. Decided from the alert's own records,
 * so a real block stays "blocked" through a dropped connection, and a
 * simulated one doesn't turn real when the helper is installed later.
 */
export type ResponseProvenance = Provenance | 'mixed';

export function responseProvenance(
  actions: readonly ActionRecord[],
): ResponseProvenance | undefined {
  const done = actions.filter((r) => r.status === 'done' && !r.undoes).map(provenance);
  if (done.length === 0) return undefined;
  if (done.includes('unknown')) return 'unknown';
  if (done.every((p) => p === 'real')) return 'real';
  if (done.every((p) => p === 'simulated')) return 'simulated';
  return 'mixed';
}

/**
 * How many other decisions wait besides this alert, counted like Needs you
 * (a pile is one). When this alert is in a pile, its siblings stay a row of
 * their own after it's decided, so the pile still counts.
 */
export function othersNeedingYou(
  alert: Alert,
  needsYou: number,
  openAlerts: readonly Alert[],
): number {
  if (!needsDecision(alert)) return needsYou;
  const inPile = pileMates(alert, openAlerts.filter(needsDecision)).length > 1;
  return Math.max(0, inPile ? needsYou : needsYou - 1);
}
