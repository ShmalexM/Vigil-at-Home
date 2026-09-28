import { compareSeverity, type SensorEvent } from '@vigil/core';
import {
  DetectionEngine,
  macosCoreRules,
  memoryStores,
  type Detection,
  type DetectionRule,
  type Stores,
} from '@vigil/detection';
import { ATTACKS, fakeHash, type AttackScenario, type Tactic, type Variant } from './attacks.js';
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

function engine(stores: Stores, learningUntil: number): DetectionEngine {
  return new DetectionEngine(macosCoreRules, stores, {
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
) {
  const at = START + 10 * DAY + 3_600_000;
  const stores = memoryStores();
  seedLists(stores);
  for (const l of s.lists ?? [])
    stores.lists.add(l.list, l.value, { source: 'bench', updatedAt: at });
  const e = engine(stores, learning ? at + DAY : at - DAY);
  const raw = s.events(at);
  const events: SensorEvent[] =
    telemetry === 'ideal' ? raw : raw.flatMap((ev) => throughSensors(ev, sensorOpts));
  const detections: Detection[] = [];
  for (const ev of events) detections.push(...e.evaluate(ev));
  const raised = detections.filter((d) => d.alert && (d.mode === 'alert' || d.mode === 'block'));
  const firing = [...new Set(raised.map((d) => d.match.ruleId))];
  const caught = firing.some((r) => s.expect.includes(r));
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

export function runAttacks(sensorOpts: SensorOptions = {}): AttackResult[] {
  const out: AttackResult[] = [];
  for (const telemetry of ['ideal', 'sensors'] as const)
    for (const s of ATTACKS) {
      const after = runScenario(s, telemetry, false, sensorOpts);
      const during = runScenario(s, telemetry, true, sensorOpts);
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
  opts: { days?: number; seed?: number; sensorOpts?: SensorOptions } = {},
): WorkloadResult {
  const days = opts.days ?? 14;
  const r = rng(opts.seed ?? 20260928);
  const stores = memoryStores();
  seedLists(stores);
  const e = engine(stores, START + LEARNING_DAYS * DAY);
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

export function summarize(results: AttackResult[]): DetectionSummary {
  const count = (v: Variant, t: Telemetry) =>
    results.filter((r) => r.variant === v && r.telemetry === t);
  const caught = (xs: AttackResult[]) => xs.filter((r) => r.caught).length;
  const byRule = macosCoreRules.map((rule) => {
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
    rules: macosCoreRules.length,
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
