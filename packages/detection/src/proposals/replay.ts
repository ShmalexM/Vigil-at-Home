import { DetectionEngine } from '../engine.js';
import { compileField } from '../rules/fields.js';
import {
  MemoryBaselineStore,
  MemoryEventHistory,
  MemoryExceptionStore,
  MemoryRuleStateStore,
  type EventHistory,
  type ExceptionStore,
  type ListStore,
} from '../state/stores.js';
import type { DetectionEvent, DetectionRule } from '../types.js';

export interface ReplaySample {
  ts: number;
  program?: string;
  subject: string;
  reasons: string[];
  /** Actions it would have run in block mode, or "alert" when it would only have told you. */
  wouldDo: string[];
}

export interface ReplayReport {
  windowStart: number;
  windowEnd: number;
  /** Hits before this time were used to learn the baseline and are not counted. */
  countedFrom: number;
  eventsScanned: number;
  hits: number;
  /** Hits that would have raised an alert (not repeats inside the dedupe window). */
  popups: number;
  hitsPerDay: number;
  popupsPerDay: number;
  /** Hits where the safety floor would have stopped a suspend or block. */
  cappedBySafetyFloor: number;
  distinctPrograms: number;
  topPrograms: Array<{ program: string; hits: number }>;
  /** Hits on things the user already marked as fine for some rule. Likely false positives. */
  hitsOnUserAllowed: number;
  /** Hits on Apple-signed programs. */
  hitsOnAppleSigned: number;
  /** Hits some existing rule also caught on the same event. */
  alreadyCaughtByOtherRules: number;
  samples: ReplaySample[];
  verdict: 'never_fired' | 'quiet' | 'ok' | 'noisy';
  notes: string[];
}

export interface ReplayContext {
  history: EventHistory;
  lists: ListStore;
  /** The user's real exceptions, used only to count overlap. */
  userExceptions: ExceptionStore;
  /** Current rules, to measure overlap. Omit to skip. */
  existingRules?: DetectionRule[];
}

export interface ReplayOptions {
  from: number;
  to: number;
  /** Defaults to the first quarter of the window, at most 3 days, for rules that use "first seen". */
  warmupUntil?: number;
  maxSamples?: number;
}

const DAY = 86_400_000;

function programOf(e: DetectionEvent): string | undefined {
  return 'process' in e ? e.process?.path : undefined;
}

function subjectOf(e: DetectionEvent): string {
  if ('path' in e && e.path) return e.path;
  if (e.kind === 'network.connection') return e.remoteHost ?? e.remoteAddress;
  if (e.kind === 'browser.extension') return e.extensionId;
  return programOf(e) ?? e.id;
}

function matchesAnyException(e: DetectionEvent, exs: ExceptionStore): boolean {
  return exs.all().some((ex) => {
    const entries = Object.entries(ex.match);
    return (
      entries.length > 0 &&
      entries.every(([field, want]) => {
        const v = compileField(field)(e);
        if (v === undefined) return false;
        const vals = Array.isArray(v) ? v : [String(v)];
        return vals.some((x) => x.toLowerCase() === want.toLowerCase());
      })
    );
  });
}

export interface ReplayRun {
  report: ReplayReport;
  /** Event ids the candidate hit (counted window only). */
  hitEventIds: Set<string>;
}

/**
 * Run a candidate rule over recorded history in an isolated engine: fresh
 * baseline, no real state touched, candidate forced to block mode so the
 * report shows what it would really have done.
 */
export function replayRule(
  candidate: DetectionRule,
  ctx: ReplayContext,
  opts: ReplayOptions,
): ReplayRun {
  const span = Math.max(1, opts.to - opts.from);
  const uses = JSON.stringify(candidate.condition).includes('"firstSeen"');
  const warmupUntil =
    opts.warmupUntil ?? (uses ? opts.from + Math.min(3 * DAY, Math.floor(span / 4)) : opts.from);
  const maxSamples = opts.maxSamples ?? 10;

  const probe: DetectionRule = { ...candidate, mode: 'block' };
  const others = (ctx.existingRules ?? []).filter((r) => r.id !== candidate.id);
  const engine = new DetectionEngine(
    [probe, ...others.map((r) => ({ ...r, mode: 'shadow' as const }))],
    {
      baseline: new MemoryBaselineStore(),
      lists: ctx.lists,
      exceptions: new MemoryExceptionStore(),
      ruleState: new MemoryRuleStateStore(),
      history: new MemoryEventHistory(),
    },
    { recordHistory: false, learningUntil: 0 },
  );

  let eventsScanned = 0;
  let hits = 0;
  let popups = 0;
  let capped = 0;
  let onAllowed = 0;
  let onApple = 0;
  let overlap = 0;
  const programs = new Map<string, number>();
  const samples: ReplaySample[] = [];
  const hitEventIds = new Set<string>();

  for (const e of ctx.history.range(opts.from, opts.to)) {
    eventsScanned++;
    const ds = engine.evaluate(e);
    const mine = ds.find((d) => d.match.ruleId === candidate.id);
    if (!mine || e.ts < warmupUntil) continue;
    hits++;
    hitEventIds.add(e.id);
    if (mine.alert) popups++;
    if (mine.downgrades.some((r) => r.startsWith('Vigil will not'))) capped++;
    if (matchesAnyException(e, ctx.userExceptions)) onAllowed++;
    if ('process' in e && e.process?.signing === 'apple') onApple++;
    if (ds.some((d) => d.match.ruleId !== candidate.id)) overlap++;
    const prog = programOf(e);
    if (prog) programs.set(prog, (programs.get(prog) ?? 0) + 1);
    if (samples.length < maxSamples) {
      const sample: ReplaySample = {
        ts: e.ts,
        subject: subjectOf(e),
        reasons: mine.reasons,
        wouldDo: mine.execute.length ? mine.execute.map((a) => a.kind) : ['alert'],
      };
      if (prog) sample.program = prog;
      samples.push(sample);
    }
  }

  const countedDays = Math.max((opts.to - warmupUntil) / DAY, 1 / 24);
  const hitsPerDay = hits / countedDays;
  const popupsPerDay = popups / countedDays;
  const notes: string[] = [];
  let verdict: ReplayReport['verdict'];
  if (hits === 0) {
    verdict = 'never_fired';
    notes.push(
      'It would not have fired at all in this window. That is fine for a rule about rare attacks, but check it is not misspelled.',
    );
  } else if (popupsPerDay > 1 || onAllowed / hits >= 0.2) {
    verdict = 'noisy';
  } else if (popupsPerDay <= 0.2) {
    verdict = 'quiet';
  } else {
    verdict = 'ok';
  }
  if (popupsPerDay > 1)
    notes.push(`It would have interrupted you about ${popupsPerDay.toFixed(1)} times a day.`);
  if (onAllowed > 0)
    notes.push(`${onAllowed} of its hits were on things you already marked as fine.`);
  if (onApple > 0) notes.push(`${onApple} hits were on programs that are part of macOS.`);
  if (capped > 0)
    notes.push(`The safety floor would have stopped it pausing or blocking ${capped} times.`);
  if (overlap > 0 && overlap === hits)
    notes.push('Every hit was already caught by an existing rule.');
  if (eventsScanned === 0)
    notes.push('There is no recorded history for this window, so this replay says nothing yet.');

  const topPrograms = [...programs.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([program, n]) => ({ program, hits: n }));

  return {
    hitEventIds,
    report: {
      windowStart: opts.from,
      windowEnd: opts.to,
      countedFrom: warmupUntil,
      eventsScanned,
      hits,
      popups,
      hitsPerDay: Math.round(hitsPerDay * 100) / 100,
      popupsPerDay: Math.round(popupsPerDay * 100) / 100,
      cappedBySafetyFloor: capped,
      distinctPrograms: programs.size,
      topPrograms,
      hitsOnUserAllowed: onAllowed,
      hitsOnAppleSigned: onApple,
      alreadyCaughtByOtherRules: overlap,
      samples,
      verdict,
      notes,
    },
  };
}
