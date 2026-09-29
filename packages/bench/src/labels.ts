import type { SensorEvent } from '@vigil/core';
import { DetectionEngine, macosCoreRules, memoryStores } from '@vigil/detection';
import { ATTACKS, type AttackScenario } from './attacks.js';
import { START, type Telemetry } from './detection.js';
import { rng } from './rng.js';
import { throughSensors } from './sensors.js';
import { workday, type Profile } from './workday.js';
import { labelKey as appLabelKey } from '../../../apps/desktop/src/main/label-filter.js';

const DAY = 86_400_000;

/** Which events the app sends to the labeller: the app's own filter. */
export function labelKey(e: SensorEvent): string | undefined {
  return appLabelKey(e)?.key;
}

export interface LabelCase {
  event: SensorEvent;
  truth: 'attack' | 'benign';
  /** Scenario id for attacks, the look-alike or event kind for benign ones. */
  source: string;
  /** Whether the app would send this event to the model today (labelKey). */
  appSends: boolean;
}

export interface LabelCoverage {
  id: string;
  variant: string;
  telemetry: Telemetry;
  /** A rule alerted, so the event never needs a label. */
  caughtByRules: boolean;
  /** Some event of this attack would be queued for labelling. */
  reachesLabeller: boolean;
  /** Why not, when it doesn't. */
  why?: string;
}

export interface LabelSet {
  /**
   * The model test: events the rules let through, attacks and normal use,
   * in a fixed shuffled order. It includes events the app's filter skips
   * today (Apple-signed tools), so it measures the model rather than the filter.
   */
  cases: LabelCase[];
  /** For every simulated attack: does it reach the labeller today? */
  coverage: LabelCoverage[];
}

function genericKey(e: SensorEvent): string {
  const p = 'process' in e ? e.process : undefined;
  // File events collapse per folder: a search opening 100 files is one thing to look at.
  const path = ('path' in e ? e.path : undefined) ?? '';
  return `${e.kind}:${p?.path ?? ''}:${p?.args?.join(' ') ?? ''}:${
    e.kind === 'file' ? path.slice(0, path.lastIndexOf('/')) : path
  }:${
    'remoteAddress' in e ? e.remoteAddress : ''
  }:${'localPort' in e ? e.localPort : ''}:${'extensionId' in e ? e.extensionId : ''}`;
}

function whyNotLabelled(e: SensorEvent): string {
  const p = 'process' in e ? e.process : undefined;
  if (p?.signing === 'apple') return 'Apple-signed programs are skipped';
  if (e.kind === 'file' || e.kind === 'santa.decision' || e.kind === 'system.alert')
    return `${e.kind} events are skipped`;
  return 'skipped';
}

function engineAt(at: number, learning: boolean, lists: AttackScenario['lists'] = []) {
  const stores = memoryStores();
  for (const l of lists) stores.lists.add(l.list, l.value, { source: 'b', updatedAt: at });
  return new DetectionEngine(macosCoreRules, stores, {
    learningUntil: learning ? at + DAY : at - DAY,
    recordHistory: false,
  });
}

/** Builds the model test set and the coverage table. */
export function labelSet(opts: { benign?: number; seed?: number } = {}): LabelSet {
  const r = rng(opts.seed ?? 7);
  const cases: LabelCase[] = [];
  const coverage: LabelCoverage[] = [];
  const at = START + 10 * DAY;

  for (const telemetry of ['ideal', 'sensors'] as const)
    for (const s of ATTACKS) {
      const engine = engineAt(at, false, s.lists);
      const raw = s.events(at);
      const events = telemetry === 'ideal' ? raw : raw.flatMap((e) => throughSensors(e));
      const results = events.map((e) => ({ e, ds: engine.evaluate(e) }));
      const caught = results.some(({ ds }) =>
        ds.some((d) => d.alert && (d.mode === 'alert' || d.mode === 'block')),
      );
      const unmatched = results.filter(({ ds }) => ds.length === 0).map(({ e }) => e);
      const sent = unmatched.filter((e) => labelKey(e) !== undefined);
      coverage.push({
        id: s.id,
        variant: s.variant,
        telemetry,
        caughtByRules: caught,
        reachesLabeller: !caught && sent.length > 0,
        ...(!caught && sent.length === 0
          ? {
              why:
                events.length === 0
                  ? 'no sensor reports it'
                  : whyNotLabelled(unmatched[0] ?? events[0]!),
            }
          : {}),
      });
      if (telemetry === 'ideal' && !caught && unmatched.length > 0)
        cases.push({
          event: sent[0] ?? unmatched[0]!,
          truth: 'attack',
          source: s.id,
          appSends: sent.length > 0,
        });
    }

  const want = opts.benign ?? 180;
  const seen = new Set<string>();
  const engine = engineAt(START + 7 * DAY, false);
  const pool: LabelCase[] = [];
  for (let day = 0; day < 14; day++)
    for (const profile of ['developer', 'everyday'] as Profile[])
      for (const w of workday(profile, START + day * DAY, r)) {
        if (engine.evaluate(w.event).length > 0) continue;
        const key = genericKey(w.event);
        if (seen.has(key)) continue;
        seen.add(key);
        pool.push({
          event: w.event,
          truth: 'benign',
          source: w.lookalike ?? w.event.kind,
          appSends: labelKey(w.event) !== undefined,
        });
      }
  // A spread of kinds, not just the first N (connections far outnumber the rest).
  const groups = new Map<string, LabelCase[]>();
  for (const c of pool) {
    const k = `${c.source}:${c.appSends}`;
    const g = groups.get(k) ?? [];
    g.push(c);
    groups.set(k, g);
  }
  const benign: LabelCase[] = [];
  while (benign.length < want && [...groups.values()].some((g) => g.length > 0))
    for (const g of groups.values()) {
      const c = g.splice(r.int(0, Math.max(0, g.length - 1)), 1)[0];
      if (c && benign.length < want) benign.push(c);
    }
  cases.push(...benign);
  for (let i = cases.length - 1; i > 0; i--) {
    const j = r.int(0, i);
    [cases[i], cases[j]] = [cases[j]!, cases[i]!];
  }
  return { cases, coverage };
}
