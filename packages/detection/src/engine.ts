import {
  Action,
  newId,
  type Alert,
  type NotifyLevel,
  type RuleMatch,
  type RuleMode,
} from '@vigil/core';
import {
  compileCondition,
  renderTemplate,
  resolveTemplateValue,
  type CompiledCondition,
  type EvalState,
  type FirstSeenSpec,
} from './rules/compile.js';
import { compileField, keyOf, type FieldGetter } from './rules/fields.js';
import { SafetyFloor, type SafetyConfig } from './safety.js';
import type { Stores } from './state/stores.js';
import {
  DetectionRule,
  type Detection,
  type DetectionEvent,
  type DetectionEventKind,
  type DetectionRuleInput,
} from './types.js';

export interface EngineConfig {
  /**
   * Until this time (ms), rules that depend on "first seen" only record. On a
   * fresh install everything is new, so alerting would be all noise.
   */
  learningUntil?: number;
  safety?: Partial<SafetyConfig>;
  /** Default window in which the same rule and subject alert only once. */
  defaultDedupeWindowSec?: number;
  /** Append every evaluated event to the history store (for replay). Default true. */
  recordHistory?: boolean;
  newId?: () => string;
}

interface CompiledRule {
  rule: DetectionRule;
  condition: CompiledCondition;
  exclusions: CompiledCondition[];
  usesBaseline: boolean;
  thresholdKey: FieldGetter[] | undefined;
  dedupeKey: FieldGetter[];
  dedupeWindowMs: number;
  santaFrom: FieldGetter | undefined;
  sequence:
    | {
        steps: { kinds: Set<string>; condition: CompiledCondition }[];
        key: FieldGetter[];
        windowMs: number;
      }
    | undefined;
}

/** Candidate dedupe keys when a rule names none: the first one present on the event wins. */
const DEFAULT_DEDUPE_KEYS = [
  ['process.sha256'],
  ['process.path'],
  ['remoteHost'],
  ['remoteAddress'],
  ['extensionId'],
  ['path'],
].map((k) => k.map(compileField));

const MAX_WINDOW_ENTRIES = 20_000;
const MODE_RANK: Record<RuleMode, number> = { disabled: 0, shadow: 1, alert: 2, block: 3 };

export class RuleCompileError extends Error {
  constructor(
    readonly ruleId: string,
    message: string,
  ) {
    super(`rule ${ruleId}: ${message}`);
  }
}

export function compileRule(
  input: DetectionRuleInput | DetectionRule,
  defaultDedupeWindowSec = 3600,
): CompiledRule {
  const rule = DetectionRule.parse(input);
  try {
    const scopePrefix = `${[...rule.eventKinds].sort().join('+')}:`;
    const condition = compileCondition(rule.condition, scopePrefix);
    const exclusions = rule.exclusions.map((x) => compileCondition(x, scopePrefix));
    return {
      rule,
      condition,
      exclusions,
      usesBaseline: condition.firstSeen.length > 0,
      thresholdKey: rule.threshold?.groupBy?.map(compileField) ?? (rule.threshold ? [] : undefined),
      dedupeKey: (rule.dedupe?.key ?? []).map(compileField),
      dedupeWindowMs: (rule.dedupe?.windowSec ?? defaultDedupeWindowSec) * 1000,
      santaFrom: rule.santa ? compileField(rule.santa.from) : undefined,
      sequence: rule.sequence
        ? {
            steps: rule.sequence.steps.map((st) => ({
              kinds: new Set<string>(st.eventKinds),
              condition: compileCondition(st.condition, scopePrefix),
            })),
            key: rule.sequence.key.map(compileField),
            windowMs: rule.sequence.windowSec * 1000,
          }
        : undefined,
    };
  } catch (err) {
    throw new RuleCompileError(rule.id, (err as Error).message);
  }
}

/** Bounded map of key -> timestamps, oldest keys evicted first. */
class WindowMap {
  private readonly m = new Map<string, number[]>();
  hits(key: string, ts: number, windowMs: number): number[] {
    const prev = this.m.get(key);
    if (prev) this.m.delete(key); // re-insert to keep recency order
    const arr = (prev ?? []).filter((t) => ts - t <= windowMs);
    this.m.set(key, arr);
    if (this.m.size > MAX_WINDOW_ENTRIES) this.m.delete(this.m.keys().next().value!);
    return arr;
  }
  reset(key: string): void {
    this.m.delete(key);
  }
}

function lastPart(p: string): string {
  return p.split('/').pop() || p;
}

function subjectOf(e: DetectionEvent): Alert['subject'] {
  switch (e.kind) {
    case 'network.connection':
      return { kind: 'network', label: e.remoteHost ?? e.remoteAddress };
    case 'network.listen':
      return { kind: 'network', label: `port ${e.localPort}` };
    case 'persistence':
      return { kind: 'persistence', label: lastPart(e.path), path: e.path };
    case 'browser.extension':
      return { kind: 'persistence', label: e.name ?? e.extensionId };
    case 'file':
      if (!e.process) return { kind: 'file', label: lastPart(e.path), path: e.path };
      break;
    case 'agent.tool_request':
      // Its process is only the shell the request would start.
      return { kind: 'process', label: `${e.tool} request` };
    default:
      break;
  }
  const p = 'process' in e ? e.process : undefined;
  if (!p) return undefined;
  return { kind: 'process', label: lastPart(p.path), path: p.path };
}

function notifyFor(rule: DetectionRule, mode: RuleMode): NotifyLevel {
  if (mode === 'block') return 'popup';
  if (rule.severity === 'critical' || rule.severity === 'high' || rule.fidelity === 'high') {
    return 'popup';
  }
  return 'badge';
}

/**
 * The inline detection engine. `evaluate` is synchronous and does no I/O
 * beyond the synchronous stores, so it can sit directly on the sensor stream.
 * No AI is involved anywhere in this file.
 */
export class DetectionEngine {
  private byKind = new Map<DetectionEventKind, CompiledRule[]>();
  private byId = new Map<string, CompiledRule>();
  private readonly revisions = new Map<string, number>();
  /** Baseline scopes to learn per event kind. */
  private learnByKind = new Map<DetectionEventKind, FirstSeenSpec[]>();
  private readonly safety: SafetyFloor;
  private readonly thresholds = new WindowMap();
  /** Chain progress per rule and key: how many steps are done, and when the first was. */
  private readonly chains = new Map<string, { done: number; start: number }>();
  private readonly dedupe = new Map<string, number>();
  private readonly learningUntil: number;
  private readonly defaultDedupeWindowSec: number;
  private readonly recordHistory: boolean;
  private readonly makeId: () => string;
  private readonly state: EvalState;

  constructor(
    rules: Array<DetectionRuleInput | DetectionRule>,
    readonly stores: Stores,
    cfg: EngineConfig = {},
  ) {
    this.learningUntil = cfg.learningUntil ?? 0;
    this.defaultDedupeWindowSec = cfg.defaultDedupeWindowSec ?? 3600;
    this.recordHistory = cfg.recordHistory ?? true;
    this.makeId = cfg.newId ?? (() => newId());
    this.safety = new SafetyFloor(cfg.safety);
    this.state = {
      baselineHas: (scope, key) => stores.baseline.has(scope, key),
      listHas: (list, value) => stores.lists.has(list, value),
    };
    this.loadRules(rules);
  }

  /** The sha256 of Vigil's own programs, which no rule may block (see SafetyConfig). */
  setSelfHashes(hashes: readonly string[]): void {
    this.safety.setSelfHashes(hashes);
  }

  /** Replace the whole rule set. Throws RuleCompileError before changing anything. */
  loadRules(rules: Array<DetectionRuleInput | DetectionRule>): void {
    const compiled = rules.map((r) => compileRule(r, this.defaultDedupeWindowSec));
    const ids = new Set<string>();
    for (const c of compiled) {
      if (ids.has(c.rule.id)) throw new RuleCompileError(c.rule.id, 'duplicate rule id');
      ids.add(c.rule.id);
    }
    this.byId = new Map(compiled.map((c) => [c.rule.id, c]));
    this.reindex();
    for (const id of ids) this.bump(id);
  }

  upsertRule(rule: DetectionRuleInput | DetectionRule): DetectionRule {
    const c = compileRule(rule, this.defaultDedupeWindowSec);
    this.byId.set(c.rule.id, c);
    this.reindex();
    this.bump(c.rule.id);
    return c.rule;
  }

  removeRule(ruleId: string): void {
    this.byId.delete(ruleId);
    this.reindex();
    this.bump(ruleId);
  }

  /**
   * How many times a rule or its mode has changed in this engine: any save,
   * removal, mode change or cleared override counts, even one to the same
   * value. An undo compares it to tell "nothing changed since" from "changed
   * and changed back".
   */
  revision(ruleId: string): number {
    return this.revisions.get(ruleId) ?? 0;
  }

  private bump(ruleId: string): void {
    this.revisions.set(ruleId, this.revision(ruleId) + 1);
  }

  getRule(ruleId: string): DetectionRule | undefined {
    return this.byId.get(ruleId)?.rule;
  }

  /** The rules as loaded (each with its own mode, not the user's override). */
  allRules(): DetectionRule[] {
    return [...this.byId.values()].map((c) => c.rule);
  }

  listRules(): Array<DetectionRule & { effectiveMode: RuleMode }> {
    return [...this.byId.values()].map((c) => ({ ...c.rule, effectiveMode: this.modeOf(c.rule) }));
  }

  /**
   * Until when a rule only records, whatever its mode, because it compares
   * against a baseline Vigil is still learning. Undefined once learned, or for
   * a rule that has no baseline.
   */
  learningEnds(ruleId: string, now: number): number | undefined {
    const c = this.byId.get(ruleId);
    return c?.usesBaseline && now < this.learningUntil ? this.learningUntil : undefined;
  }

  modeOf(rule: DetectionRule): RuleMode {
    return this.stores.ruleState.get(rule.id)?.mode ?? rule.mode;
  }

  /**
   * Set a rule's mode. Package-internal: the user path goes through
   * feedback.ts (which requires a user origin), the engine path through
   * automatic demotion.
   */
  _setMode(ruleId: string, mode: RuleMode): void {
    const prev = this.stores.ruleState.get(ruleId) ?? { ruleId, fired: 0 };
    this.stores.ruleState.put({ ...prev, mode });
    this.bump(ruleId);
  }

  /** The user's override of a rule's mode, or undefined when it runs in its own mode. */
  modeOverride(ruleId: string): RuleMode | undefined {
    return this.stores.ruleState.get(ruleId)?.mode;
  }

  /**
   * Drop a rule's override, so it runs in its own mode again (and follows a
   * pack update to it). Package-internal, like `_setMode`.
   */
  _clearMode(ruleId: string): void {
    const prev = this.stores.ruleState.get(ruleId);
    if (prev?.mode === undefined) return;
    const { mode: _mode, ...rest } = prev;
    this.stores.ruleState.put(rest);
    this.bump(ruleId);
  }

  private reindex(): void {
    this.byKind = new Map();
    this.learnByKind = new Map();
    for (const c of this.byId.values()) {
      const kinds = new Set(c.rule.eventKinds);
      for (const st of c.rule.sequence?.steps ?? []) for (const k of st.eventKinds) kinds.add(k);
      for (const k of kinds) {
        let list = this.byKind.get(k);
        if (!list) this.byKind.set(k, (list = []));
        list.push(c);
        let learn = this.learnByKind.get(k);
        if (!learn) this.learnByKind.set(k, (learn = []));
        for (const fs of c.condition.firstSeen) {
          if (!learn.some((l) => l.scope === fs.scope)) learn.push(fs);
        }
      }
    }
  }

  evaluate(e: DetectionEvent): Detection[] {
    if (this.recordHistory) this.stores.history.append(e);
    const out: Detection[] = [];
    for (const c of this.byKind.get(e.kind) ?? []) {
      const d = this.evaluateRule(c, e);
      if (d) out.push(d);
    }
    // Learn after evaluating, so every rule sees the same "first seen" answer.
    for (const fs of this.learnByKind.get(e.kind) ?? []) {
      const k = keyOf(fs.getters, e);
      if (k !== undefined && !this.stores.baseline.has(fs.scope, k)) {
        this.stores.baseline.add(fs.scope, k, e.ts);
      }
    }
    return out;
  }

  /**
   * Evaluate without leaving a trace: no history, no baseline learning, no
   * dedupe or threshold state, no rule statistics. The pre-flight path uses
   * it, so asking about a tool call many times changes nothing. Each mode is
   * the one `evaluate` would apply; threshold rules never match here, and a
   * chain rule matches only once its earlier steps are already done (the
   * check never advances a chain).
   */
  check(e: DetectionEvent): Detection[] {
    const out: Detection[] = [];
    for (const c of this.byKind.get(e.kind) ?? []) {
      const d = this.evaluateRule(c, e, true);
      if (d) out.push(d);
    }
    return out;
  }

  /**
   * Whether this rule, as it is now, lets the event off: its condition still
   * fits, but one of its exclusions or the user's exceptions covers it. For
   * an open alert raised before an exclusion existed. Only an exclusion
   * counts, never a condition that no longer fits: a chain or a threshold
   * can't be replayed from one event, so "doesn't match" would be a guess.
   * Touches no state.
   */
  excuses(ruleId: string, e: DetectionEvent): boolean {
    const c = this.byId.get(ruleId);
    if (!c || !c.rule.eventKinds.includes(e.kind)) return false;
    if (!c.condition.test(e, this.state)) return false;
    return c.exclusions.some((x) => x.test(e, this.state)) || this.isExcepted(ruleId, e);
  }

  /** Resolve the rule's response templates, dropping any the safety floor refuses. */
  private resolveResponse(rule: DetectionRule, e: DetectionEvent, downgrades: string[]): Action[] {
    const actions: Action[] = [];
    for (const tpl of rule.response) {
      // Values the event lacks are left out; the Action schema decides whether they were required.
      const resolved: Record<string, unknown> = {};
      for (const [k, v] of Object.entries(tpl)) {
        const r = k === 'kind' ? v : resolveTemplateValue(v, e);
        if (r !== undefined) resolved[k] = r;
      }
      const parsed = Action.safeParse(resolved);
      if (!parsed.success) {
        downgrades.push(`Skipped ${tpl.kind}: the event does not say what to act on.`);
        continue;
      }
      const why = this.safety.check(parsed.data, e);
      if (why) {
        downgrades.push(`Vigil will not run ${tpl.kind} here because ${why}.`);
        continue;
      }
      actions.push(parsed.data);
    }
    return actions;
  }

  /** @param dry for `check`: decide only, touching no state. */
  private evaluateRule(c: CompiledRule, e: DetectionEvent, dry = false): Detection | undefined {
    const { rule } = c;
    let mode = this.modeOf(rule);
    if (mode === 'disabled') return undefined;
    // A threshold needs counting, which is state.
    if (dry && rule.threshold) return undefined;
    if (dry) {
      // An event that only advances a chain's earlier steps can't match, and
      // a dry check reads the chain's progress without moving it.
      if (!rule.eventKinds.includes(e.kind)) return undefined;
      if (c.sequence && !this.chainDone(c, e)) return undefined;
    } else {
      if (c.sequence && !this.chainReady(c, e)) return undefined;
      if (!rule.eventKinds.includes(e.kind)) return undefined;
    }
    if (!c.condition.test(e, this.state)) return undefined;
    if (c.exclusions.some((x) => x.test(e, this.state))) return undefined;
    if (this.isExcepted(rule.id, e)) return undefined;

    if (rule.threshold && c.thresholdKey) {
      const g = c.thresholdKey.length ? keyOf(c.thresholdKey, e) : '';
      if (g === undefined) return undefined;
      const tkey = `${rule.id}␞${g}`;
      const hits = this.thresholds.hits(tkey, e.ts, rule.threshold.windowSec * 1000);
      hits.push(e.ts);
      if (hits.length < rule.threshold.count) return undefined;
      this.thresholds.reset(tkey);
    }

    const downgrades: string[] = [];
    if (c.usesBaseline && e.ts < this.learningUntil && MODE_RANK[mode] > MODE_RANK.shadow) {
      mode = 'shadow';
      downgrades.push('Vigil is still learning what is normal on this Mac.');
    }

    const actions =
      mode === 'alert' || mode === 'block' ? this.resolveResponse(rule, e, downgrades) : [];
    if (mode === 'block' && rule.response.length > 0 && actions.length === 0) {
      mode = 'alert';
      downgrades.push('Nothing safe was left to do, so Vigil only tells you.');
    }

    // A dry check is never a repeat and counts nothing.
    let deduped = false;
    if (!dry) {
      const dkeyVal = c.dedupeKey.length
        ? keyOf(c.dedupeKey, e)
        : DEFAULT_DEDUPE_KEYS.map((k) => keyOf(k, e)).find((k) => k !== undefined);
      const dkey = `${rule.id}␞${dkeyVal ?? e.id}`;
      const last = this.dedupe.get(dkey);
      deduped = last !== undefined && e.ts - last <= c.dedupeWindowMs;
      if (!deduped && MODE_RANK[mode] >= MODE_RANK.alert) {
        this.dedupe.set(dkey, e.ts);
        if (this.dedupe.size > MAX_WINDOW_ENTRIES) {
          this.dedupe.delete(this.dedupe.keys().next().value!);
        }
      }

      const st = this.stores.ruleState.get(rule.id) ?? { ruleId: rule.id, fired: 0 };
      this.stores.ruleState.put({ ...st, fired: st.fired + 1, lastFiredAt: e.ts });
    }

    const reasons = rule.reasons.map((r) => renderTemplate(r, e));
    const match: RuleMatch = {
      id: this.makeId(),
      ruleId: rule.id,
      ruleVersion: rule.version,
      mode,
      ts: e.ts,
      eventIds: [e.id],
    };
    const d: Detection = {
      match,
      execute: mode === 'block' ? actions : [],
      propose: mode === 'alert' ? actions : [],
      reasons,
      downgrades,
      ruleMode: rule.mode,
      mode,
      deduped,
      event: e,
    };

    if (!deduped && MODE_RANK[mode] >= MODE_RANK.alert) {
      const alert: Alert = {
        id: this.makeId(),
        createdAt: e.ts,
        updatedAt: e.ts,
        ruleId: rule.id,
        ruleVersion: rule.version,
        title: rule.name,
        summary: reasons.join(' '),
        severity: rule.severity,
        fidelity: rule.fidelity,
        notify: notifyFor(rule, mode),
        status: 'open',
        containment: mode === 'block' && actions.length > 0 ? 'active' : 'none',
        eventIds: [e.id],
        actionIds: [],
      };
      const subject = subjectOf(e);
      if (subject) alert.subject = subject;
      d.alert = alert;
      match.alertId = alert.id;
    }

    if (rule.santa && c.santaFrom) {
      const identifier = c.santaFrom(e);
      if (typeof identifier === 'string' && identifier.length > 0) {
        const santa = {
          kind: 'santa.rule.set' as const,
          ruleType: rule.santa.ruleType,
          identifier,
          policy: 'block' as const,
          message: rule.name,
        };
        if (!this.safety.check(santa, e)) d.santa = santa;
      }
    }
    return d;
  }

  /**
   * Advances a chain rule's earlier steps on this event. True when every step
   * is done for the event's key within the window, so the rule's own
   * condition may be checked.
   */
  private chainReady(c: CompiledRule, e: DetectionEvent): boolean {
    const seq = c.sequence!;
    const k = keyOf(seq.key, e);
    if (k === undefined) return false;
    const ckey = `${c.rule.id}␞${k}`;
    let st = this.chains.get(ckey);
    if (st && e.ts - st.start > seq.windowMs) {
      this.chains.delete(ckey);
      st = undefined;
    }
    const done = st?.done ?? 0;
    if (done >= seq.steps.length) return true;
    const step = seq.steps[done]!;
    if (step.kinds.has(e.kind) && step.condition.test(e, this.state)) {
      this.chains.delete(ckey); // re-insert to keep recency order
      this.chains.set(ckey, { done: done + 1, start: st?.start ?? e.ts });
      if (this.chains.size > MAX_WINDOW_ENTRIES)
        this.chains.delete(this.chains.keys().next().value!);
    }
    return false;
  }

  /**
   * `chainReady` without changing anything: true when every earlier step is
   * already done for the event's key within the window. It is what
   * `chainReady` would answer for this event, since the event itself can
   * only complete a step, never the rule.
   */
  private chainDone(c: CompiledRule, e: DetectionEvent): boolean {
    const seq = c.sequence!;
    const k = keyOf(seq.key, e);
    if (k === undefined) return false;
    const st = this.chains.get(`${c.rule.id}␞${k}`);
    return !!st && e.ts - st.start <= seq.windowMs && st.done >= seq.steps.length;
  }

  private isExcepted(ruleId: string, e: DetectionEvent): boolean {
    for (const ex of this.stores.exceptions.forRule(ruleId)) {
      const entries = Object.entries(ex.match);
      if (entries.length === 0) continue;
      const all = entries.every(([field, want]) => {
        const v = compileField(field)(e);
        if (v === undefined) return false;
        const vals = Array.isArray(v) ? v : [String(v)];
        return vals.some((x) => x.toLowerCase() === want.toLowerCase());
      });
      if (all) return true;
    }
    return false;
  }
}
