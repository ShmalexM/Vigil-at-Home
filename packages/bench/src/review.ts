import type { SensorEvent } from '@vigil/core';
import {
  DetectionEngine,
  RulePipeline,
  macosCoreRules,
  memoryStores,
  type DetectionRuleInput,
  type DetectionToolContext,
  type FlaggedEvent,
  type Proposal,
} from '@vigil/detection';
import { ATTACKS, type AttackScenario } from './attacks.js';
import { START, runAttacks, runHeldout, runWorkload, type RuleSet } from './detection.js';
import { HELDOUT_ATTACKS } from './heldout.js';
import { labelKey } from './labels.js';
import { rng } from './rng.js';
import { throughSensors } from './sensors.js';
import { workday } from './workday.js';

/**
 * An eval for the AI rule review (#42): a developer's Mac with attacks the
 * built-in rules miss hidden in its history, one review run, and a grade for
 * the rules it queues. Run it on the train set to see why a prompt fails, and
 * on the held-out set to decide whether a prompt change is kept.
 *
 * The AI sees what it sees in the app: the redacted telemetry summary and the
 * leads from a classifier. The classifier here is simulated at roughly the
 * measured quality of the local models: it sees what the app's label filter
 * sends (once per distinct event), flags a third of the missed attack events
 * and 12% of ordinary ones, so runs don't depend on Ollama.
 */
export type Split = 'train' | 'heldout';

const DAY = 86_400_000;
const LEARNING_DAYS = 7;
/** Enough history for the 14-day replay the pipeline runs on each proposal. */
const HISTORY_DAYS = 15;
/** Seed of the workload the grade uses; the episode's history uses others. */
const GRADE_DAYS = 10;

export function scenariosFor(split: Split): readonly AttackScenario[] {
  return split === 'train' ? ATTACKS : HELDOUT_ATTACKS;
}

/** Attacks the built-in rules miss through today's sensors: what a review should find. */
export function missedBySensors(split: Split): string[] {
  const results = split === 'train' ? runAttacks() : runHeldout().attacks;
  return results.filter((r) => r.telemetry === 'sensors' && !r.caught).map((r) => r.id);
}

export interface ReviewEpisode {
  ctx: DetectionToolContext;
  pipeline: RulePipeline;
  split: Split;
  /** Missed attacks hidden in the history. */
  hidden: string[];
  end: number;
}

export function reviewEpisode(split: Split, seed: number): ReviewEpisode {
  const r = rng(1000 + seed);
  const stores = memoryStores();
  const engine = new DetectionEngine([...macosCoreRules], stores, {
    learningUntil: START + LEARNING_DAYS * DAY,
    recordHistory: true,
    safety: { selfPaths: ['/Applications/Vigil at Home.app'] },
  });
  const end = START + HISTORY_DAYS * DAY;
  const missed = new Set(missedBySensors(split));
  const hidden = scenariosFor(split).filter((s) => missed.has(s.id));

  // Attacks land at random times in the last week, among ordinary activity.
  const attackAt = new Map(
    hidden.map((s) => [s.id, end - r.int(1, 6 * 24) * 3_600_000 - r.int(0, 3_599_999)]),
  );
  const timeline: Array<{ ev: SensorEvent; attack: boolean }> = [];
  for (let day = 0; day < HISTORY_DAYS; day++)
    for (const w of workday('developer', START + day * DAY, r))
      for (const ev of throughSensors(w.event)) timeline.push({ ev, attack: false });
  for (const s of hidden)
    for (const ev of s.events(attackAt.get(s.id)!).flatMap((e) => throughSensors(e)))
      timeline.push({ ev, attack: true });
  timeline.sort((a, b) => a.ev.ts - b.ev.ts);

  const flagged: Array<FlaggedEvent & { ts: number }> = [];
  const sent = new Set<string>();
  for (const { ev, attack } of timeline) {
    const ds = engine.evaluate(ev);
    if (ds.length > 0) continue;
    const key = labelKey(ev);
    if (key === undefined || sent.has(key)) continue;
    sent.add(key);
    if (r.next() >= (attack ? 0.33 : 0.12)) continue;
    // A third of the false flags come back as suspicious too, like the real models.
    const f = flaggedFrom(ev, attack || r.next() < 0.3 ? 'suspicious' : 'unusual');
    if (f) flagged.push(f);
  }

  const pipeline = new RulePipeline(engine, stores.history, undefined, { now: () => end });
  return {
    split,
    hidden: hidden.map((s) => s.id),
    end,
    pipeline,
    ctx: {
      engine,
      pipeline,
      history: stores.history,
      flagged: (from, to) => flagged.filter((f) => f.ts >= from && f.ts <= to),
      now: () => end,
    },
  };
}

function flaggedFrom(
  ev: SensorEvent,
  label: 'unusual' | 'suspicious',
): (FlaggedEvent & { ts: number }) | undefined {
  const p = 'process' in ev ? ev.process : undefined;
  const subject =
    ev.kind === 'network.connection'
      ? `${p?.path ?? 'unknown'} -> ${ev.remoteAddress}`
      : ev.kind === 'persistence' || ev.kind === 'file' || ev.kind === 'system.alert'
        ? (ev.path ?? p?.path)
        : ev.kind === 'browser.extension'
          ? ev.extensionId
          : p?.path;
  if (!subject) return undefined;
  const commandLine =
    ev.kind === 'persistence'
      ? ev.programArgs?.join(' ')
      : p?.args && p.args.length > 1
        ? p.args.join(' ')
        : undefined;
  return {
    ts: ev.ts,
    kind: ev.kind,
    subject,
    label,
    ...(commandLine ? { commandLine } : {}),
  };
}

/** New rules the review queued for the user (the only kind this eval grades). */
export function queuedRules(pipeline: RulePipeline): Proposal[] {
  return pipeline.list().filter((p) => p.kind === 'new_rule' && p.status === 'awaiting_review');
}

export interface ReviewGrade {
  split: Split;
  /** Missed attacks (through today's sensors) the queued rules now catch. */
  caught: string[];
  missed: number;
  recall: number;
  /** Alerts a day the queued rules raise on ordinary use (developer and everyday, averaged). */
  falseAlertsPerDay: number;
  /** Held-out look-alikes the queued rules alert on. */
  lookalikeHits: number;
  /** recall - 0.1 per false alert a day - 0.05 per look-alike hit. */
  score: number;
}

/**
 * Grades rules as if the user switched them to alert: which of the missed
 * attacks they catch through today's sensors, and what they cost on a
 * workload the review never saw (a different seed from the episode).
 */
export function gradeRules(split: Split, rules: RuleSet): ReviewGrade {
  const missed = missedBySensors(split);
  const promoted = rules.map((r) => ({ ...r, mode: 'alert' as const }));
  const ids = new Set(promoted.map((r) => r.id));
  const all = [...macosCoreRules, ...promoted] as DetectionRuleInput[];
  const results = split === 'train' ? runAttacks({}, all) : runHeldout(all).attacks;
  const caught = results
    .filter((a) => a.telemetry === 'sensors' && missed.includes(a.id))
    .filter((a) => a.caughtBy.some((r) => ids.has(r)))
    .map((a) => a.id);
  let falsePerDay = 0;
  if (promoted.length > 0)
    for (const profile of ['developer', 'everyday'] as const) {
      const w = runWorkload(profile, 'sensors', { days: GRADE_DAYS, rules: all });
      const days = Math.max(1, w.days - w.learningDays);
      for (const id of ids) falsePerDay += (w.byRule[id]?.alerts ?? 0) / days / 2;
    }
  const lookalikeHits =
    split === 'heldout' && promoted.length > 0
      ? runHeldout(all).lookalikes.filter(
          (l) => l.telemetry === 'sensors' && l.alertedBy.some((r) => ids.has(r)),
        ).length
      : 0;
  const recall = missed.length ? caught.length / missed.length : 0;
  return {
    split,
    caught,
    missed: missed.length,
    recall,
    falseAlertsPerDay: falsePerDay,
    lookalikeHits,
    score: recall - 0.1 * falsePerDay - 0.05 * lookalikeHits,
  };
}

/** Mean and a 95% interval (Student's t), for comparing prompts over a few runs. */
export function meanInterval(xs: number[]): { mean: number; lo: number; hi: number; n: number } {
  const n = xs.length;
  const mean = xs.reduce((a, b) => a + b, 0) / Math.max(1, n);
  if (n < 2) return { mean, lo: mean, hi: mean, n };
  const sd = Math.sqrt(xs.reduce((a, b) => a + (b - mean) ** 2, 0) / (n - 1));
  const t = [0, 12.71, 4.3, 3.18, 2.78, 2.57, 2.45, 2.36, 2.31, 2.26][n - 1] ?? 2.0;
  const half = (t * sd) / Math.sqrt(n);
  return { mean, lo: mean - half, hi: mean + half, n };
}
