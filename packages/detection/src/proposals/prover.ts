import type { RuleMode } from '@vigil/core';
import { DetectionEngine } from '../engine.js';
import {
  MemoryBaselineStore,
  MemoryEventHistory,
  MemoryExceptionStore,
  MemoryRuleStateStore,
  type EventHistory,
  type ListStore,
} from '../state/stores.js';
import type { DetectionEvent, DetectionRule } from '../types.js';
import { toolRequestSubject } from './replay.js';

/**
 * What approving a change would cost in coverage, shown before the user
 * approves it. A replay says how often a rule fires; this says what it would
 * stop catching: the real events it goes quiet on, and look-alikes (an
 * unsigned copy, the same name elsewhere, any program to the same host) that
 * would now slip through too. Deterministic, no AI.
 */
export interface ImpactReport {
  /** Events in the window the current rule catches and the changed one would not. */
  lostEvents: number;
  /** Those events grouped by what they were about, most first. */
  stopsAlertingOn: Array<{ what: string; events: number; untrusted: boolean }>;
  /** Variants of the lost events an attacker could use that would slip through too. */
  lookAlikes: Array<{ what: string; how: string }>;
  /** Plain sentences for the approval card, most serious first. */
  findings: string[];
  /**
   * no_loss: loses nothing. narrow: goes quiet only on what it names.
   * broad: something an attacker controls would slip through too.
   */
  verdict: 'no_loss' | 'narrow' | 'broad';
}

export interface ProveInput {
  /** The rule as it runs now. Undefined for a brand new rule. */
  before?: DetectionRule;
  beforeMode?: RuleMode;
  /** The rule after the change. Undefined when the change turns the rule off. */
  after?: DetectionRule;
  afterMode?: RuleMode;
  history: EventHistory;
  lists: ListStore;
  from: number;
  to: number;
}

const UNTRUSTED = new Set(['unsigned', 'adhoc', 'invalid']);
const MODE_RANK: Record<RuleMode, number> = { disabled: 0, shadow: 1, alert: 2, block: 3 };
const MAX_GROUPS = 20;
const IMPOSTOR_SHA = 'f'.repeat(64);

function isolated(rule: DetectionRule, lists: ListStore): DetectionEngine {
  return new DetectionEngine(
    [{ ...rule, mode: 'block' }],
    {
      baseline: new MemoryBaselineStore(),
      lists,
      exceptions: new MemoryExceptionStore(),
      ruleState: new MemoryRuleStateStore(),
      history: new MemoryEventHistory(),
    },
    { recordHistory: false, learningUntil: 0 },
  );
}

function fires(rule: DetectionRule, lists: ListStore, e: DetectionEvent): boolean {
  return isolated(rule, lists)
    .evaluate(e)
    .some((d) => d.match.ruleId === rule.id);
}

function programOf(e: DetectionEvent): string | undefined {
  return 'process' in e ? e.process?.path : undefined;
}

function whatOf(e: DetectionEvent): string {
  if (e.kind === 'agent.tool_request') return `${e.tool}: ${toolRequestSubject(e)}`;
  const prog = programOf(e);
  if (e.kind === 'network.connection')
    return `${prog ?? 'a program'} -> ${e.remoteHost ?? e.remoteAddress}`;
  if (e.kind === 'browser.extension') return e.extensionId;
  if ((e.kind === 'persistence' || e.kind === 'file') && e.path) return e.path;
  return prog ?? e.kind;
}

function basename(p: string): string {
  return p.slice(p.lastIndexOf('/') + 1) || p;
}

/** Attacker-controlled variants of an event. Each keeps what the attacker can copy and drops what they can't. */
function impostors(e: DetectionEvent): Array<{ how: string; event: DetectionEvent }> {
  if (!('process' in e) || !e.process) return [];
  const p = e.process;
  const stripped = {
    ...p,
    signing: 'unsigned' as const,
    sha256: IMPOSTOR_SHA,
  } as typeof p & Record<string, unknown>;
  delete stripped.teamId;
  delete stripped.signingId;
  delete stripped.cdhash;
  const out: Array<{ how: string; event: DetectionEvent }> = [];
  const name = basename(p.path);
  out.push({
    how: `An unsigned program at ${p.path}`,
    event: { ...e, id: `${e.id}~copy`, process: stripped } as DetectionEvent,
  });
  out.push({
    how: `Any unsigned program named ${name}, in any folder`,
    event: {
      ...e,
      id: `${e.id}~renamed`,
      process: { ...stripped, path: `/Users/Shared/.cache/${name}` },
    } as DetectionEvent,
  });
  if (e.kind === 'network.connection') {
    const host = e.remoteHost ?? e.remoteAddress;
    out.push({
      how: `Any unsigned program talking to ${host}`,
      event: {
        ...e,
        id: `${e.id}~other`,
        process: { ...stripped, path: '/private/tmp/.x/agent' },
      } as DetectionEvent,
    });
  }
  return out;
}

export function proveChange(input: ProveInput): ImpactReport {
  const { before, after, lists } = input;
  const beforeMode = input.beforeMode ?? before?.mode ?? 'disabled';
  const afterMode = after ? (input.afterMode ?? after.mode) : 'disabled';

  if (!before) {
    return {
      lostEvents: 0,
      stopsAlertingOn: [],
      lookAlikes: [],
      findings: [
        'Adds a new rule. It can only raise alerts; it cannot allow, unblock or hide anything.',
      ],
      verdict: 'no_loss',
    };
  }

  // One pass over history with two single-rule engines, both in block mode.
  const eb = isolated(before, lists);
  const ea = after ? isolated(after, lists) : undefined;
  const groups = new Map<string, { events: number; untrusted: boolean; sample: DetectionEvent }>();
  let lost = 0;
  for (const e of input.history.range(input.from, input.to)) {
    const hitBefore = eb.evaluate(e).some((d) => d.match.ruleId === before.id);
    const hitAfter = ea ? ea.evaluate(e).some((d) => d.match.ruleId === after!.id) : false;
    if (!hitBefore || hitAfter) continue;
    lost++;
    const what = whatOf(e);
    const g = groups.get(what);
    const untrusted = 'process' in e && UNTRUSTED.has(e.process?.signing ?? '');
    if (g) {
      g.events++;
      g.untrusted ||= untrusted;
    } else groups.set(what, { events: 1, untrusted, sample: e });
  }
  const top = [...groups.entries()].sort((a, b) => b[1].events - a[1].events);
  const stopsAlertingOn = top
    .slice(0, MAX_GROUPS)
    .map(([what, g]) => ({ what, events: g.events, untrusted: g.untrusted }));

  // Look-alikes only make sense when the rule stays on but narrower.
  const lookAlikes: ImpactReport['lookAlikes'] = [];
  if (after && afterMode !== 'disabled') {
    const seen = new Set<string>();
    for (const [what, g] of top.slice(0, MAX_GROUPS)) {
      for (const imp of impostors(g.sample)) {
        if (seen.has(imp.how)) continue;
        if (fires(before, lists, imp.event) && !fires(after, lists, imp.event)) {
          seen.add(imp.how);
          lookAlikes.push({ what, how: imp.how });
        }
      }
    }
  }

  const findings: string[] = [];
  const days = Math.max(1, Math.round((input.to - input.from) / 86_400_000));
  if (MODE_RANK[afterMode] < MODE_RANK[beforeMode]) {
    if (afterMode === 'disabled')
      findings.push(
        'Turns the rule off: it would stop watching for everything it looks for, including attacks that have not happened yet.',
      );
    else if (afterMode === 'shadow' && MODE_RANK[beforeMode] >= MODE_RANK.alert)
      findings.push(
        'It would stop alerting on everything this rule looks for, including future attacks. Matches are still recorded.',
      );
    else if (beforeMode === 'block')
      findings.push('It would stop blocking. You would get an alert instead.');
  }
  for (const l of lookAlikes.slice(0, 5))
    findings.push(`${l.how} would also be skipped, not only ${l.what}.`);
  if (lost > 0) {
    const untrusted = top.filter(([, g]) => g.untrusted).length;
    findings.push(
      `It would have stayed quiet on ${lost} ${lost === 1 ? 'event' : 'events'} from ${groups.size} ${groups.size === 1 ? 'source' : 'sources'} in the last ${days} days.` +
        (untrusted > 0
          ? ` ${untrusted} of them ${untrusted === 1 ? 'is' : 'are'} unsigned or ad hoc signed.`
          : ''),
    );
  } else if (findings.length === 0) {
    findings.push(`It loses nothing on your last ${days} days, and no look-alike slips through.`);
  }

  const verdict: ImpactReport['verdict'] =
    lookAlikes.length > 0 || MODE_RANK[afterMode] < MODE_RANK[beforeMode]
      ? 'broad'
      : lost > 0
        ? 'narrow'
        : 'no_loss';
  return { lostEvents: lost, stopsAlertingOn, lookAlikes, findings, verdict };
}
