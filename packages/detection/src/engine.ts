import { randomUUID } from "node:crypto";
import { compileCondition, renderTemplate, type CompiledCondition, type EvalState, type FirstSeenSpec } from "./rules/compile.js";
import { compileField, keyOf, type FieldGetter } from "./rules/fields.js";
import { RuleSchema, type Rule, type RuleInput } from "./rules/schema.js";
import { SafetyFloor, type SafetyConfig } from "./safety.js";
import type { Stores } from "./state/stores.js";
import {
  minAction,
  type Action,
  type Detection,
  type EventKind,
  type ResponseSubject,
  type SensorEvent,
  type Stage,
} from "./types.js";

export interface EngineConfig {
  /**
   * Until this time (ms), rules that depend on "first seen" only record. On a
   * fresh install everything is new, so popping up would be all noise.
   */
  learningUntil?: number;
  safety?: Partial<SafetyConfig>;
  /** Default window in which the same rule and subject pop up only once. */
  defaultDedupeWindowSec?: number;
  /** Append every evaluated event to the history store (for replay). Default true. */
  recordHistory?: boolean;
  newId?: () => string;
}

interface CompiledRule {
  rule: Rule;
  condition: CompiledCondition;
  exclusions: CompiledCondition[];
  usesBaseline: boolean;
  thresholdKey?: FieldGetter[];
  dedupeKey: FieldGetter[];
  dedupeWindowMs: number;
  santaFrom?: FieldGetter;
}

const DEFAULT_DEDUPE_KEYS: Record<Rule["target"], string[][]> = {
  process: [["process.sha256"], ["process.path"]],
  network: [["network.domain"], ["network.remoteAddress"]],
  persistence: [["persistence.itemPath"]],
};

const MAX_WINDOW_ENTRIES = 20_000;

export class RuleCompileError extends Error {
  constructor(
    readonly ruleId: string,
    message: string,
  ) {
    super(`rule ${ruleId}: ${message}`);
  }
}

export function compileRule(input: RuleInput | Rule, defaultDedupeWindowSec = 3600): CompiledRule {
  const rule = RuleSchema.parse(input);
  try {
    const scopePrefix = `${[...rule.kinds].sort().join("+")}:`;
    const condition = compileCondition(rule.condition, scopePrefix);
    const exclusions = rule.exclusions.map((x) => compileCondition(x, scopePrefix));
    const dedupePaths = rule.dedupe?.key;
    return {
      rule,
      condition,
      exclusions,
      usesBaseline: condition.firstSeen.length > 0,
      thresholdKey: rule.threshold?.groupBy.map(compileField),
      dedupeKey: (dedupePaths ?? []).map(compileField),
      dedupeWindowMs: (rule.dedupe?.windowSec ?? defaultDedupeWindowSec) * 1000,
      santaFrom: rule.santa ? compileField(rule.santa.from) : undefined,
    };
  } catch (err) {
    throw new RuleCompileError(rule.id, (err as Error).message);
  }
}

/** First key from a list of candidate key tuples that has a value on this event. */
function defaultDedupeKey(rule: Rule, e: SensorEvent): string {
  for (const paths of DEFAULT_DEDUPE_KEYS[rule.target]) {
    const k = keyOf(paths.map(compileField), e);
    if (k !== undefined) return k;
  }
  return e.id;
}

function subjectOf(e: SensorEvent): ResponseSubject {
  const s: ResponseSubject = {};
  if (e.process) {
    s.pid = e.process.pid;
    s.processPath = e.process.path;
    if (e.process.sha256) s.sha256 = e.process.sha256;
  }
  if (e.network?.remoteAddress) s.remoteAddress = e.network.remoteAddress;
  if (e.network?.domain) s.domain = e.network.domain;
  if (e.persistence) {
    s.itemPath = e.persistence.itemPath;
    if (e.persistence.label) s.label = e.persistence.label;
  }
  return s;
}

/** Bounded map of key -> timestamps, oldest keys evicted first. */
class WindowMap {
  private readonly m = new Map<string, number[]>();
  hits(key: string, ts: number, windowMs: number): number[] {
    let arr = this.m.get(key);
    if (arr) this.m.delete(key); // re-insert to keep recency order
    arr = (arr ?? []).filter((t) => ts - t <= windowMs);
    this.m.set(key, arr);
    if (this.m.size > MAX_WINDOW_ENTRIES) this.m.delete(this.m.keys().next().value!);
    return arr;
  }
  reset(key: string): void {
    this.m.delete(key);
  }
}

/**
 * The inline detection engine. `evaluate` is synchronous and does no I/O
 * beyond the synchronous stores, so it can sit directly on the sensor stream.
 * No AI is involved anywhere in this file.
 */
export class DetectionEngine {
  private byKind = new Map<EventKind, CompiledRule[]>();
  private byId = new Map<string, CompiledRule>();
  /** Baseline scopes to learn per event kind. */
  private learnByKind = new Map<EventKind, FirstSeenSpec[]>();
  private readonly safety: SafetyFloor;
  private readonly thresholds = new WindowMap();
  private readonly dedupe = new Map<string, number>();
  private readonly cfg: Required<Omit<EngineConfig, "safety" | "learningUntil">> & { learningUntil: number };
  private readonly state: EvalState;

  constructor(
    rules: Array<RuleInput | Rule>,
    readonly stores: Stores,
    cfg: EngineConfig = {},
  ) {
    this.cfg = {
      learningUntil: cfg.learningUntil ?? 0,
      defaultDedupeWindowSec: cfg.defaultDedupeWindowSec ?? 3600,
      recordHistory: cfg.recordHistory ?? true,
      newId: cfg.newId ?? randomUUID,
    };
    this.safety = new SafetyFloor(cfg.safety);
    this.state = {
      baselineHas: (scope, key) => stores.baseline.has(scope, key),
      listHas: (list, value) => stores.lists.has(list, value),
    };
    this.loadRules(rules);
  }

  /** Replace the whole rule set. Throws RuleCompileError before changing anything. */
  loadRules(rules: Array<RuleInput | Rule>): void {
    const compiled = rules.map((r) => compileRule(r, this.cfg.defaultDedupeWindowSec));
    const ids = new Set<string>();
    for (const c of compiled) {
      if (ids.has(c.rule.id)) throw new RuleCompileError(c.rule.id, "duplicate rule id");
      ids.add(c.rule.id);
    }
    this.byId = new Map(compiled.map((c) => [c.rule.id, c]));
    this.reindex();
  }

  upsertRule(rule: RuleInput | Rule): Rule {
    const c = compileRule(rule, this.cfg.defaultDedupeWindowSec);
    this.byId.set(c.rule.id, c);
    this.reindex();
    return c.rule;
  }

  removeRule(ruleId: string): void {
    this.byId.delete(ruleId);
    this.reindex();
  }

  getRule(ruleId: string): Rule | undefined {
    return this.byId.get(ruleId)?.rule;
  }

  /** The rules as loaded (each with its own stage, not the user's override). */
  allRules(): Rule[] {
    return [...this.byId.values()].map((c) => c.rule);
  }

  listRules(): Array<Rule & { effectiveStage: Stage }> {
    return [...this.byId.values()].map((c) => ({ ...c.rule, effectiveStage: this.stageOf(c.rule) }));
  }

  stageOf(rule: Rule): Stage {
    return this.stores.ruleState.get(rule.id)?.stage ?? rule.stage;
  }

  /**
   * Set a rule's stage. Package-internal: the user path goes through
   * feedback.ts (which requires a user origin), the engine path through
   * automatic demotion.
   */
  _setStage(ruleId: string, stage: Stage): void {
    const prev = this.stores.ruleState.get(ruleId) ?? { ruleId, fired: 0 };
    this.stores.ruleState.put({ ...prev, stage });
  }

  private reindex(): void {
    this.byKind = new Map();
    this.learnByKind = new Map();
    for (const c of this.byId.values()) {
      for (const k of c.rule.kinds) {
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

  evaluate(e: SensorEvent): Detection[] {
    if (this.cfg.recordHistory) this.stores.history.append(e);
    const out: Detection[] = [];
    for (const c of this.byKind.get(e.kind) ?? []) {
      const d = this.evaluateRule(c, e);
      if (d) out.push(d);
    }
    // Learn after evaluating, so every rule sees the same "first seen" answer.
    for (const fs of this.learnByKind.get(e.kind) ?? []) {
      const k = keyOf(fs.getters, e);
      if (k !== undefined && !this.stores.baseline.has(fs.scope, k)) this.stores.baseline.add(fs.scope, k, e.ts);
    }
    return out;
  }

  /** Does the rule's logic match, ignoring stage, exceptions, thresholds and dedupe? Used by replay. */
  matches(ruleId: string, e: SensorEvent): boolean {
    const c = this.byId.get(ruleId);
    return !!c && c.condition.test(e, this.state) && !c.exclusions.some((x) => x.test(e, this.state));
  }

  private evaluateRule(c: CompiledRule, e: SensorEvent): Detection | undefined {
    const { rule } = c;
    if (!c.condition.test(e, this.state)) return undefined;
    if (c.exclusions.some((x) => x.test(e, this.state))) return undefined;
    if (this.isExcepted(rule.id, e)) return undefined;

    if (rule.threshold && c.thresholdKey) {
      const g = keyOf(c.thresholdKey, e);
      if (g === undefined) return undefined;
      const tkey = `${rule.id}␞${g}`;
      const hits = this.thresholds.hits(tkey, e.ts, rule.threshold.withinSec * 1000);
      hits.push(e.ts);
      if (hits.length < rule.threshold.count) return undefined;
      this.thresholds.reset(tkey);
    }

    const stage = this.stageOf(rule);
    const downgrades: string[] = [];
    let action: Action = rule.action;

    if (stage === "shadow" && action !== "record") {
      action = "record";
      downgrades.push("This rule is on trial, so it only records what it would have done.");
    } else if (stage === "alert" && (action === "suspend" || action === "block")) {
      action = "alert";
      downgrades.push("This rule may warn you but is not yet trusted to pause or block.");
    }
    if (c.usesBaseline && e.ts < this.cfg.learningUntil && action !== "record") {
      action = "record";
      downgrades.push("Vigil is still learning what is normal on this Mac.");
    }
    const floor = this.safety.apply(e, rule.target, action);
    if (floor.reason) downgrades.push(floor.reason);
    action = minAction(action, floor.action);

    const dkey = `${rule.id}␞${c.dedupeKey.length ? (keyOf(c.dedupeKey, e) ?? e.id) : defaultDedupeKey(rule, e)}`;
    const last = this.dedupe.get(dkey);
    const deduped = last !== undefined && e.ts - last <= c.dedupeWindowMs;
    if (!deduped) {
      this.dedupe.set(dkey, e.ts);
      if (this.dedupe.size > MAX_WINDOW_ENTRIES) this.dedupe.delete(this.dedupe.keys().next().value!);
    }
    if (deduped && action === "alert") {
      action = "record";
      downgrades.push("You were already told about this recently.");
    }

    const st = this.stores.ruleState.get(rule.id) ?? { ruleId: rule.id, fired: 0 };
    this.stores.ruleState.put({ ...st, fired: st.fired + 1, lastFiredAt: e.ts });

    const d: Detection = {
      id: this.cfg.newId(),
      ts: e.ts,
      ruleId: rule.id,
      ruleVersion: rule.version,
      title: rule.title,
      severity: rule.severity,
      requestedAction: rule.action,
      action,
      stage,
      target: rule.target,
      subject: subjectOf(e),
      reasons: rule.reasons.map((r) => renderTemplate(r, e)),
      downgrades,
      eventIds: [e.id],
      dedupeKey: dkey,
      deduped,
      tags: rule.tags,
    };
    if (rule.santa && c.santaFrom) {
      const v = c.santaFrom(e);
      if (typeof v === "string" && v.length > 0) {
        d.santaSuggestion = { policy: "BLOCKLIST", ruleType: rule.santa.ruleType, identifier: v, customMsg: rule.title };
      }
    }
    return d;
  }

  private isExcepted(ruleId: string, e: SensorEvent): boolean {
    for (const ex of this.stores.exceptions.forRule(ruleId)) {
      const v = compileField(ex.field)(e);
      if (v === undefined) continue;
      const vals = Array.isArray(v) ? v : [String(v)];
      if (vals.some((x) => x.toLowerCase() === ex.value.toLowerCase())) return true;
    }
    return false;
  }
}
