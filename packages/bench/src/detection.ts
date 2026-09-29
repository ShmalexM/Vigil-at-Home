import { compareSeverity, type SensorEvent } from '@vigil/core';
import {
  DetectionEngine,
  macosCoreRules,
  memoryStores,
  type Detection,
  type DetectionRule,
  type DetectionRuleInput,
  type Stores,
} from '@vigil/detection';
import { ATTACKS, fakeHash, type AttackScenario, type Tactic, type Variant } from './attacks.js';
import { HELDOUT_ATTACKS, HELDOUT_LOOKALIKES, type HeldoutLookalike } from './heldout.js';
import { rng } from './rng.js';
import { throughSensors, type SensorOptions } from './sensors.js';
import { workday, workdayRates, type Profile } from './workday.js';

const DAY = 86_400_000;
/** Vigil's "first seen" rules learn for this long after install (apps/desktop detection.ts). */
const LEARNING_DAYS = 7;
export const START = Date.UTC(2026, 8, 7, 7); // a Monday morning, Pacific

export type Telemetry = 'ideal' | 'sensors';
export type Notify = 'popup' | 'badge' | 'silent';

/** Same as the app's notifyLevel (apps/desktop/src/main/alerts.ts). */
export function notifyLevel(rule: DetectionRule, mode: string): Notify {
  if (mode === 'block') return 'popup';
  if (rule.fidelity === 'high' && compareSeverity(rule.severity, 'medium') >= 0) return 'popup';
  if (rule.fidelity === 'low' && compareSeverity(rule.severity, 'medium') < 0) return 'silent';
  return 'badge';
}

/** The rules under test: the built-in pack unless a caller passes others (e.g. AI proposals). */
export type RuleSet = readonly DetectionRuleInput[];

function engine(
  stores: Stores,
  learningUntil: number,
  rules: RuleSet = macosCoreRules,
): DetectionEngine {
  return new DetectionEngine([...rules], stores, {
    learningUntil,
    recordHistory: false,
    // Vigil's own app; nothing in the corpus lives there.
    safety: { selfPaths: ['/Applications/Vigil at Home.app'] },
  });
}

/** Threat lists about the size of the real abuse.ch feeds, so lookups aren't trivially fast. */
function seedLists(stores: Stores): void {
  const meta = { source: 'bench', updatedAt: START };
  stores.lists.replace(
    'known_bad_sha256',
    Array.from({ length: 1400 }, (_, i) => fakeHash(`mb-${i}`)),
    meta,
  );
  stores.lists.replace(
    'known_bad_domains',
    Array.from({ length: 400 }, (_, i) => `bad-${i}.example`),
    meta,
  );
  stores.lists.replace(
    'known_bad_ips',
    Array.from({ length: 50 }, (_, i) => `192.0.2.${i + 1}`),
    meta,
  );
}

// ------------------------------------------------------------------ attacks

export interface AttackResult {
  id: string;
  name: string;
  mimics: string;
  tactic: Tactic;
  variant: Variant;
  expect: string[];
  note?: string;
  telemetry: Telemetry;
  /** An expected rule raised an alert or blocked. */
  caught: boolean;
  /** Some other rule raised an alert. */
  caughtBy: string[];
  /** A rule ran containment (block mode). */
  blocked: boolean;
  notify: Notify | null;
  /** The sensors never report this activity at all. */
  unseen: boolean;
  /** Muted during the first week because its rule waits for a baseline. */
  mutedWhileLearning: boolean;
}

function runScenario(
  s: AttackScenario,
  telemetry: Telemetry,
  learning: boolean,
  sensorOpts: SensorOptions,
  rules: RuleSet,
) {
  const at = START + 10 * DAY + 3_600_000;
  const stores = memoryStores();
  seedLists(stores);
  for (const l of s.lists ?? [])
    stores.lists.add(l.list, l.value, { source: 'bench', updatedAt: at });
  const e = engine(stores, learning ? at + DAY : at - DAY, rules);
  const raw = s.events(at);
  const events: SensorEvent[] =
    telemetry === 'ideal' ? raw : raw.flatMap((ev) => throughSensors(ev, sensorOpts));
  const detections: Detection[] = [];
  for (const ev of events) detections.push(...e.evaluate(ev));
  const raised = detections.filter((d) => d.alert && (d.mode === 'alert' || d.mode === 'block'));
  const firing = [...new Set(raised.map((d) => d.match.ruleId))];
  // A held-out attack aims at no rule: any alert catches it.
  const caught = s.expect.length ? firing.some((r) => s.expect.includes(r)) : firing.length > 0;
  const notify = raised
    .map((d) => notifyLevel(e.getRule(d.match.ruleId)!, d.mode))
    .sort(
      (a, b) => ['popup', 'badge', 'silent'].indexOf(a) - ['popup', 'badge', 'silent'].indexOf(b),
    )[0];
  return {
    unseen: events.length === 0,
    caught,
    firing,
    blocked:
      detections.some((d) => d.mode === 'block' && d.execute.length > 0) ||
      events.some((ev) => ev.kind === 'santa.decision' && ev.decision === 'block'),
    notify: notify ?? null,
  };
}

export function runAttacks(
  sensorOpts: SensorOptions = {},
  rules: RuleSet = macosCoreRules,
  scenarios: readonly AttackScenario[] = ATTACKS,
): AttackResult[] {
  const out: AttackResult[] = [];
  for (const telemetry of ['ideal', 'sensors'] as const)
    for (const s of scenarios) {
      const after = runScenario(s, telemetry, false, sensorOpts, rules);
      const during = runScenario(s, telemetry, true, sensorOpts, rules);
      out.push({
        id: s.id,
        name: s.name,
        mimics: s.mimics,
        tactic: s.tactic,
        variant: s.variant,
        expect: s.expect,
        ...(s.note ? { note: s.note } : {}),
        telemetry,
        caught: after.caught,
        caughtBy: after.firing,
        blocked: after.blocked,
        notify: after.notify,
        unseen: after.unseen,
        mutedWhileLearning: after.firing.length > 0 && during.firing.length === 0,
      });
    }
  return out;
}

// ------------------------------------------------------------------ held-out

export interface LookalikeResult {
  id: string;
  name: string;
  who: string;
  telemetry: Telemetry;
  /** Rules that raised an alert: each one is a false alert. */
  alertedBy: string[];
  blocked: boolean;
  notify: Notify | null;
}

function runLookalike(l: HeldoutLookalike, telemetry: Telemetry, rules: RuleSet): LookalikeResult {
  const at = START + 10 * DAY + 3_600_000;
  const stores = memoryStores();
  seedLists(stores);
  const e = engine(stores, at - DAY, rules);
  const raw = l.events(at);
  const events = telemetry === 'ideal' ? raw : raw.flatMap((ev) => throughSensors(ev));
  const raised = events
    .flatMap((ev) => e.evaluate(ev))
    .filter((d) => d.alert && (d.mode === 'alert' || d.mode === 'block'));
  const notify = raised
    .map((d) => notifyLevel(e.getRule(d.match.ruleId)!, d.mode))
    .sort(
      (a, b) => ['popup', 'badge', 'silent'].indexOf(a) - ['popup', 'badge', 'silent'].indexOf(b),
    )[0];
  return {
    id: l.id,
    name: l.name,
    who: l.who,
    telemetry,
    alertedBy: [...new Set(raised.map((d) => d.match.ruleId))],
    blocked: raised.some((d) => d.mode === 'block' && d.execute.length > 0),
    notify: notify ?? null,
  };
}

export interface HeldoutResult {
  attacks: AttackResult[];
  lookalikes: LookalikeResult[];
}

/** The held-out set (heldout.ts): the score that counts, never used for tuning. */
export function runHeldout(rules: RuleSet = macosCoreRules): HeldoutResult {
  return {
    attacks: runAttacks({}, rules, HELDOUT_ATTACKS),
    lookalikes: (['ideal', 'sensors'] as const).flatMap((t) =>
      HELDOUT_LOOKALIKES.map((l) => runLookalike(l, t, rules)),
    ),
  };
}

export interface HeldoutSummary {
  attacks: number;
  caughtIdeal: number;
  caughtSensors: number;
  /** Caught through today's sensors with a popup or badge, not just a silent entry. */
  caughtSensorsNoticed: number;
  lookalikes: number;
  /** Look-alikes that raise a popup or badge (a silent log entry doesn't count). */
  falseAlertsIdeal: number;
  falseAlertsSensors: number;
  /** Look-alikes that only leave a silent entry in Activity. */
  silentSensors: number;
  falseBlocksSensors: number;
}

const noticed = (n: Notify | null) => n === 'popup' || n === 'badge';

export function summarizeHeldout(h: HeldoutResult): HeldoutSummary {
  const a = (t: Telemetry) => h.attacks.filter((r) => r.telemetry === t);
  const l = (t: Telemetry) => h.lookalikes.filter((r) => r.telemetry === t);
  return {
    attacks: a('ideal').length,
    caughtIdeal: a('ideal').filter((r) => r.caught).length,
    caughtSensors: a('sensors').filter((r) => r.caught).length,
    caughtSensorsNoticed: a('sensors').filter((r) => r.caught && noticed(r.notify)).length,
    lookalikes: l('ideal').length,
    falseAlertsIdeal: l('ideal').filter((r) => noticed(r.notify)).length,
    falseAlertsSensors: l('sensors').filter((r) => noticed(r.notify)).length,
    silentSensors: l('sensors').filter((r) => r.notify === 'silent').length,
    falseBlocksSensors: l('sensors').filter((r) => r.blocked).length,
  };
}

// ------------------------------------------------------------------ workload

export interface FalseAlert {
  day: number;
  ruleId: string;
  mode: string;
  notify: Notify;
  lookalike: string | null;
}

export interface WorkloadResult {
  profile: Profile;
  telemetry: Telemetry;
  days: number;
  learningDays: number;
  events: number;
  eventsPerDay: number;
  /** After the learning week. */
  perDay: { alerts: number; popups: number; badges: number; silent: number; blocks: number };
  learningWeek: { alerts: number; popups: number; blocks: number };
  byRule: Record<string, { alerts: number; blocks: number; notify: Notify; lookalikes: string[] }>;
  byDay: Array<{ day: number; alerts: number; popups: number; blocks: number }>;
  rates: Readonly<Record<string, number>>;
  /** Inline cost of evaluating one event (µs). */
  latencyUs: { p50: number; p95: number; p99: number; max: number; mean: number };
  eventsPerSecond: number;
}

function percentile(sorted: Float64Array, p: number): number {
  if (sorted.length === 0) return 0;
  return sorted[Math.min(sorted.length - 1, Math.floor(p * sorted.length))]!;
}

export function runWorkload(
  profile: Profile,
  telemetry: Telemetry,
  opts: { days?: number; seed?: number; sensorOpts?: SensorOptions; rules?: RuleSet } = {},
): WorkloadResult {
  const days = opts.days ?? 14;
  const r = rng(opts.seed ?? 20260928);
  const stores = memoryStores();
  seedLists(stores);
  const e = engine(stores, START + LEARNING_DAYS * DAY, opts.rules);
  const alerts: FalseAlert[] = [];
  const blocks: Array<{ day: number; ruleId: string }> = [];
  const timings: number[] = [];
  let events = 0;
  let evalMs = 0;

  for (let day = 0; day < days; day++) {
    const dayStart = START + day * DAY;
    for (const w of workday(profile, dayStart, r)) {
      const batch =
        telemetry === 'ideal' ? [w.event] : throughSensors(w.event, opts.sensorOpts ?? {});
      for (const ev of batch) {
        events++;
        const t0 = performance.now();
        const ds = e.evaluate(ev);
        const dt = performance.now() - t0;
        evalMs += dt;
        timings.push(dt * 1000);
        // Santa itself refused the file read (file-access policy enforced).
        if (ev.kind === 'santa.decision' && ev.decision === 'block' && ev.target === 'file_access')
          blocks.push({ day, ruleId: 'santa-file-access' });
        for (const d of ds) {
          if (d.alert && (d.mode === 'alert' || d.mode === 'block')) {
            alerts.push({
              day,
              ruleId: d.match.ruleId,
              mode: d.mode,
              notify: notifyLevel(e.getRule(d.match.ruleId)!, d.mode),
              lookalike: w.lookalike ?? null,
            });
          }
          if (d.mode === 'block' && d.execute.length > 0)
            blocks.push({ day, ruleId: d.match.ruleId });
        }
      }
    }
  }

  const measured = alerts.filter((a) => a.day >= LEARNING_DAYS);
  const measuredDays = Math.max(1, days - LEARNING_DAYS);
  const byRule: WorkloadResult['byRule'] = {};
  for (const a of measured) {
    const x = (byRule[a.ruleId] ??= { alerts: 0, blocks: 0, notify: a.notify, lookalikes: [] });
    x.alerts++;
    if (a.lookalike && !x.lookalikes.includes(a.lookalike)) x.lookalikes.push(a.lookalike);
  }
  for (const b of blocks.filter((b) => b.day >= LEARNING_DAYS)) {
    const x = (byRule[b.ruleId] ??= { alerts: 0, blocks: 0, notify: 'popup', lookalikes: [] });
    x.blocks++;
  }
  const sorted = Float64Array.from(timings).sort();
  const perDay = (xs: FalseAlert[], n: number) => xs.length / n;
  return {
    profile,
    telemetry,
    days,
    learningDays: LEARNING_DAYS,
    events,
    eventsPerDay: Math.round(events / days),
    perDay: {
      alerts: perDay(measured, measuredDays),
      popups: perDay(
        measured.filter((a) => a.notify === 'popup'),
        measuredDays,
      ),
      badges: perDay(
        measured.filter((a) => a.notify === 'badge'),
        measuredDays,
      ),
      silent: perDay(
        measured.filter((a) => a.notify === 'silent'),
        measuredDays,
      ),
      blocks: blocks.filter((b) => b.day >= LEARNING_DAYS).length / measuredDays,
    },
    learningWeek: {
      alerts: alerts.filter((a) => a.day < LEARNING_DAYS).length,
      popups: alerts.filter((a) => a.day < LEARNING_DAYS && a.notify === 'popup').length,
      blocks: blocks.filter((b) => b.day < LEARNING_DAYS).length,
    },
    byRule,
    byDay: Array.from({ length: days }, (_, day) => ({
      day,
      alerts: alerts.filter((a) => a.day === day).length,
      popups: alerts.filter((a) => a.day === day && a.notify === 'popup').length,
      blocks: blocks.filter((b) => b.day === day).length,
    })),
    rates: workdayRates(profile),
    latencyUs: {
      p50: percentile(sorted, 0.5),
      p95: percentile(sorted, 0.95),
      p99: percentile(sorted, 0.99),
      max: sorted[sorted.length - 1] ?? 0,
      mean: (evalMs * 1000) / Math.max(1, events),
    },
    eventsPerSecond: events / Math.max(evalMs / 1000, 1e-9),
  };
}

// ------------------------------------------------------------------ summary

export interface DetectionSummary {
  rules: number;
  canonical: { total: number; caughtIdeal: number; caughtSensors: number };
  evasive: { total: number; caughtIdeal: number; caughtSensors: number };
  byRule: Array<{
    ruleId: string;
    mode: string;
    scenarios: number;
    caughtIdeal: number;
    caughtSensors: number;
  }>;
}

export function summarize(
  results: AttackResult[],
  rules: RuleSet = macosCoreRules,
): DetectionSummary {
  const count = (v: Variant, t: Telemetry) =>
    results.filter((r) => r.variant === v && r.telemetry === t);
  const caught = (xs: AttackResult[]) => xs.filter((r) => r.caught).length;
  const byRule = rules.map((rule) => {
    const ideal = results.filter(
      (r) => r.telemetry === 'ideal' && r.variant === 'canonical' && r.expect.includes(rule.id),
    );
    const sensors = results.filter(
      (r) => r.telemetry === 'sensors' && r.variant === 'canonical' && r.expect.includes(rule.id),
    );
    return {
      ruleId: rule.id,
      mode: rule.mode,
      scenarios: ideal.length,
      caughtIdeal: caught(ideal),
      caughtSensors: caught(sensors),
    };
  });
  return {
    rules: rules.length,
    canonical: {
      total: count('canonical', 'ideal').length,
      caughtIdeal: caught(count('canonical', 'ideal')),
      caughtSensors: caught(count('canonical', 'sensors')),
    },
    evasive: {
      total: count('evasive', 'ideal').length,
      caughtIdeal: caught(count('evasive', 'ideal')),
      caughtSensors: caught(count('evasive', 'sensors')),
    },
    byRule,
  };
}

// ------------------------------------------------------------------ rule quality

export type Grade = 'good' | 'gaps' | 'noisy' | 'blind' | 'untested';

export interface RuleScore {
  ruleId: string;
  name: string;
  mode: string;
  severity: string;
  fidelity: string;
  /** How the app tells the user when it fires. */
  notify: Notify;
  canonical: number;
  caughtIdeal: number;
  caughtSensors: number;
  /** Evasive variants aimed at this rule, and how many it still catches. */
  evasive: number;
  evasiveCaught: number;
  /** False alerts and blocks per day after the learning week, through today's sensors. */
  falsePerDay: Record<Profile, { alerts: number; blocks: number }>;
  /** Same with full telemetry (what the rule would do if the sensors gave it everything). */
  falsePerDayIdeal: Record<Profile, { alerts: number; blocks: number }>;
  grade: Grade;
  why: string;
}

/**
 * One line per rule: does it catch what it is for, does it still catch the
 * obvious variations, and what does it cost in false alerts.
 */
export function scoreRules(
  attacks: AttackResult[],
  workloads: WorkloadResult[],
  rules: RuleSet = macosCoreRules,
): RuleScore[] {
  const days = (w: WorkloadResult) => Math.max(1, w.days - w.learningDays);
  const falseFor = (id: string, telemetry: Telemetry) =>
    Object.fromEntries(
      (['everyday', 'developer'] as const).map((p) => {
        const w = workloads.find(
          (x) => x.profile === p && x.telemetry === telemetry && !('variant' in x),
        );
        const r = w?.byRule[id];
        return [
          p,
          { alerts: w && r ? r.alerts / days(w) : 0, blocks: w && r ? r.blocks / days(w) : 0 },
        ];
      }),
    ) as Record<Profile, { alerts: number; blocks: number }>;
  return rules.map((input) => {
    const rule = DetectionRuleSchemaless(input);
    const mine = (t: Telemetry, v: Variant) =>
      attacks.filter((a) => a.telemetry === t && a.variant === v && a.expect.includes(rule.id));
    const caughtBy = (xs: AttackResult[]) => xs.filter((a) => a.caughtBy.includes(rule.id)).length;
    const canonical = mine('ideal', 'canonical');
    const evasive = mine('ideal', 'evasive');
    const falseSensors = falseFor(rule.id, 'sensors');
    const falseIdeal = falseFor(rule.id, 'ideal');
    const score: Omit<RuleScore, 'grade' | 'why'> = {
      ruleId: rule.id,
      name: rule.name,
      mode: rule.mode,
      severity: rule.severity,
      fidelity: rule.fidelity,
      notify: notifyLevel(rule, rule.mode),
      canonical: canonical.length,
      caughtIdeal: caughtBy(canonical),
      caughtSensors: caughtBy(mine('sensors', 'canonical')),
      evasive: evasive.length,
      evasiveCaught: caughtBy(evasive),
      falsePerDay: falseSensors,
      falsePerDayIdeal: falseIdeal,
    };
    return { ...score, ...grade(score) };
  });
}

/** The fields scoring needs, from a rule input (no zod: inputs may be AI drafts). */
function DetectionRuleSchemaless(r: DetectionRuleInput): DetectionRule {
  return r as unknown as DetectionRule;
}

function grade(s: Omit<RuleScore, 'grade' | 'why'>): { grade: Grade; why: string } {
  const dev = s.falsePerDay.developer;
  const devIdeal = s.falsePerDayIdeal.developer;
  if (s.mode === 'shadow' || s.mode === 'disabled')
    return { grade: 'untested', why: `in ${s.mode} mode, so it never alerts` };
  if (s.canonical === 0 && s.evasive === 0)
    return { grade: 'untested', why: 'no simulated attack aims at it' };
  // Rules added for a variation (no canonical attack of their own) are graded on that variation.
  if (s.canonical > 0 && s.caughtSensors === 0)
    return {
      grade: 'blind',
      why: `catches ${s.caughtIdeal}/${s.canonical} with full telemetry but 0 through today's sensors`,
    };
  const falseBlocks = dev.blocks + devIdeal.blocks;
  const popupRate = s.notify === 'popup' ? dev.alerts : 0;
  if (falseBlocks > 0 || popupRate >= 0.1 || dev.alerts >= 0.5)
    return {
      grade: 'noisy',
      why:
        falseBlocks > 0
          ? `would block normal activity (${devIdeal.blocks.toFixed(2)}/day for a developer with full telemetry)`
          : `${dev.alerts.toFixed(2)} false alerts a day for a developer`,
    };
  if (s.evasive > 0 && s.evasiveCaught < s.evasive)
    return {
      grade: 'gaps',
      why: `misses ${s.evasive - s.evasiveCaught} of ${s.evasive} simple variations`,
    };
  if (s.caughtSensors < s.canonical)
    return {
      grade: 'gaps',
      why: `today's sensors only let it catch ${s.caughtSensors} of ${s.canonical}`,
    };
  return { grade: 'good', why: 'catches its attacks with few false alerts' };
}

/**
 * Scores candidate rules (drafted by the AI or the user) against the same
 * attacks and workload, as if they were switched to alert. Shows what each
 * newly catches on top of the built-in pack and what it costs.
 */
export function scoreCandidates(
  candidates: RuleSet,
  opts: { days?: number; telemetry?: Telemetry[] } = {},
) {
  const promoted = candidates.map((r) => ({ ...r, mode: 'alert' as const }));
  const rules = [...macosCoreRules, ...promoted];
  const base = runAttacks();
  const withThem = runAttacks({}, rules);
  const workloads = (['everyday', 'developer'] as const).flatMap((p) =>
    (opts.telemetry ?? (['ideal', 'sensors'] as const)).map((t) =>
      runWorkload(p, t, { days: opts.days ?? 28, rules }),
    ),
  );
  const scores = scoreRules(withThem, workloads, promoted);
  return promoted.map((r, i) => ({
    ...scores[i]!,
    newlyCaught: withThem
      .filter(
        (a) =>
          a.caughtBy.includes(r.id) &&
          !base.find((b) => b.id === a.id && b.telemetry === a.telemetry)?.caughtBy.length,
      )
      .map((a) => `${a.id} (${a.telemetry})`),
  }));
}

/**
 * The held-out grade for a set of candidate rules: held-out attacks they catch
 * that the built-in pack doesn't, and look-alikes they alert on. Tuning loops
 * use this only to accept or reject a change; its cases never go back to the AI.
 */
export function scoreCandidatesHeldout(candidates: RuleSet) {
  const promoted = candidates.map((r) => ({ ...r, mode: 'alert' as const }));
  const base = runHeldout();
  const withThem = runHeldout([...macosCoreRules, ...promoted]);
  const ids = new Set(promoted.map((r) => r.id));
  const baseCaught = (id: string, t: Telemetry) =>
    base.attacks.find((b) => b.id === id && b.telemetry === t)?.caught ?? false;
  return {
    summary: summarizeHeldout(withThem),
    baseline: summarizeHeldout(base),
    newlyCaught: withThem.attacks
      .filter((a) => a.caughtBy.some((r) => ids.has(r)) && !baseCaught(a.id, a.telemetry))
      .map((a) => `${a.id} (${a.telemetry})`),
    // Candidates run as alerts, so any hit on a look-alike counts, silent or not.
    falseAlerts: withThem.lookalikes
      .filter((l) => l.alertedBy.some((r) => ids.has(r)))
      .map((l) => `${l.id} (${l.telemetry})`),
  };
}
