import type { Store } from './db/store.js';
import {
  BILLED_PROVIDERS,
  USAGE_PROVIDERS,
  type KeySpendView,
  type LimitWindowView,
  type ModelTotals,
  type PeriodTotals,
  type PlanLimitsView,
  type ProviderTotals,
  type PurposeTotals,
  type UsageDays,
  type UsageLimitsView,
  type UsageProvider,
  type UsagePurpose,
  type UsageReport,
  type UsageRun,
  type UsageTotals,
} from '../shared/usage.js';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;
/** A little past the longest period the page offers (90 days). */
export const USAGE_RETENTION_DAYS = 100;
/** Plan limits are read at most this often unless the user presses refresh. */
const LIMITS_TTL_MS = 60_000;

/**
 * A prompt log entry as @vigil/ai records it (`PromptLogEntry`), plus the
 * model when the caller knows it. Only the fields the Usage page needs.
 */
export interface PromptLogLike {
  readonly id: string;
  readonly at: number;
  readonly purpose: UsagePurpose;
  readonly provider: UsageProvider | null;
  readonly outcome: string;
  readonly model?: string;
  readonly usage?: {
    readonly inputTokens: number;
    readonly cachedInputTokens: number;
    readonly outputTokens: number;
    readonly costUsd: number | null;
  };
}

/** A plan as `ai.spending()` returns it: `SpendingPlan` from @vigil/ai fits as is. */
export type PlanSource = Omit<PlanLimitsView, 'windows'> & {
  readonly windows: readonly Omit<LimitWindowView, 'durationMins'>[];
};

/** Where plan limits and key caps come from. The app wires this to @vigil/ai. */
export type LimitsSource = () => Promise<{
  readonly plans: readonly PlanSource[];
  /** Monthly caps on the user's own keys, in US dollars. */
  readonly caps?: Partial<Record<UsageProvider, number>>;
  readonly backgroundSharePercent?: number;
}>;

/** Window lengths the vendors use, for the even-pace mark. */
const DURATION_MINS: Record<LimitWindowView['kind'], number | undefined> = {
  session: 5 * 60,
  weekly: 7 * 24 * 60,
  other: undefined,
};

/**
 * Vigil's AI usage for the Usage page: runs from the prompt log, stored for
 * 100 days, and plan limits read from the vendors' own CLIs.
 */
export class UsageService {
  private source: LimitsSource | undefined;
  private cached: { at: number; view: UsageLimitsView } | undefined;

  constructor(
    private readonly store: Store,
    private readonly now: () => number = Date.now,
  ) {}

  /** Pass every prompt log entry here. Entries that never reached a provider are skipped. */
  record(entry: PromptLogLike): void {
    const run = toRun(entry);
    if (run) this.store.addAiRun(run);
  }

  setLimitsSource(source: LimitsSource | undefined): void {
    this.source = source;
    this.cached = undefined;
  }

  report(days: UsageDays): UsageReport {
    const window = usageWindow(days, this.now());
    return buildReport(this.store.listAiRuns(window.since, window.until), days, window);
  }

  async limits(refresh = false): Promise<UsageLimitsView> {
    const at = this.now();
    if (!refresh && this.cached && at - this.cached.at < LIMITS_TTL_MS) return this.cached.view;
    let read: Awaited<ReturnType<LimitsSource>> = { plans: [] };
    try {
      if (this.source) read = await this.source();
    } catch (err) {
      console.error('[usage] reading plan limits failed:', err);
    }
    const view: UsageLimitsView = {
      checkedAt: at,
      plans: read.plans
        .filter((p) => p.available && p.windows.length > 0)
        .map((p) => ({
          ...p,
          windows: p.windows.map((w) => {
            const durationMins = DURATION_MINS[w.kind];
            return durationMins === undefined ? { ...w } : { ...w, durationMins };
          }),
        })),
      keys: keySpend(this.store.listAiRuns(monthStart(at)), read.caps ?? {}),
      ...(read.backgroundSharePercent !== undefined
        ? { backgroundSharePercent: read.backgroundSharePercent }
        : {}),
    };
    this.cached = { at, view };
    return view;
  }

  prune(): number {
    return this.store.pruneAiRuns(this.now() - USAGE_RETENTION_DAYS * DAY);
  }
}

export function toRun(e: PromptLogLike): UsageRun | undefined {
  if (e.provider === null) return undefined;
  const u = e.usage;
  const whole = (n: number | undefined) => Math.max(0, Math.round(n ?? 0));
  return {
    id: e.id,
    at: e.at,
    provider: e.provider,
    purpose: e.purpose,
    ok: e.outcome === 'ok',
    ...(e.model ? { model: e.model.slice(0, 200) } : {}),
    inputTokens: whole(u?.inputTokens),
    cachedInputTokens: whole(u?.cachedInputTokens),
    outputTokens: whole(u?.outputTokens),
    // A local model costs nothing; anything else without a price stays unpriced.
    costUsd:
      e.provider === 'ollama'
        ? 0
        : typeof u?.costUsd === 'number' && u.costUsd >= 0
          ? u.costUsd
          : null,
  };
}

/** Local day starts for 7 to 90 days (today included), or the past 24 hour starts. */
export function usageWindow(
  days: UsageDays,
  now: number,
): { since: number; until: number; starts: number[] } {
  const starts: number[] = [];
  if (days === 1) {
    const hour = new Date(now);
    hour.setMinutes(0, 0, 0);
    for (let i = 23; i >= 0; i--) starts.push(hour.getTime() - i * HOUR);
    return { since: starts[0]!, until: now + 1, starts };
  }
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  d.setDate(d.getDate() - (days - 1));
  for (let i = 0; i < days; i++) {
    starts.push(d.getTime());
    d.setDate(d.getDate() + 1);
  }
  return { since: starts[0]!, until: now + 1, starts };
}

function emptyTotals(): UsageTotals {
  return {
    runs: 0,
    failed: 0,
    inputTokens: 0,
    cachedInputTokens: 0,
    outputTokens: 0,
    totalTokens: 0,
    costUsd: 0,
    billedUsd: 0,
    unpricedRuns: 0,
  };
}

function add(t: UsageTotals, r: UsageRun): void {
  t.runs += 1;
  if (!r.ok) t.failed += 1;
  t.inputTokens += r.inputTokens;
  t.cachedInputTokens += r.cachedInputTokens;
  t.outputTokens += r.outputTokens;
  t.totalTokens += r.inputTokens + r.cachedInputTokens + r.outputTokens;
  if (r.costUsd === null) t.unpricedRuns += 1;
  else {
    t.costUsd += r.costUsd;
    if (BILLED_PROVIDERS.includes(r.provider)) t.billedUsd += r.costUsd;
  }
}

const share = (part: number, whole: number) => (whole > 0 ? part / whole : 0);

export function buildReport(
  runs: readonly UsageRun[],
  days: UsageDays,
  window: { since: number; until: number; starts: number[] },
): UsageReport {
  const totals = emptyTotals();
  const providers = new Map<UsageProvider, UsageTotals>();
  const models = new Map<string, UsageTotals & { provider: UsageProvider; model: string }>();
  const purposes = new Map<UsagePurpose, UsageTotals>();
  const periods: PeriodTotals[] = window.starts.map((start) => ({
    start,
    costUsd: 0,
    totalTokens: 0,
    byProvider: {},
  }));

  for (const r of runs) {
    if (r.at < window.since || r.at >= window.until) continue;
    add(totals, r);

    let p = providers.get(r.provider);
    if (!p) providers.set(r.provider, (p = emptyTotals()));
    add(p, r);

    const model = r.model ?? '';
    const key = `${r.provider}\u0000${model}`;
    let m = models.get(key);
    if (!m) models.set(key, (m = { ...emptyTotals(), provider: r.provider, model }));
    add(m, r);

    let u = purposes.get(r.purpose);
    if (!u) purposes.set(r.purpose, (u = emptyTotals()));
    add(u, r);

    const period = periods[periodIndex(window.starts, r.at)];
    if (period) {
      const tokens = r.inputTokens + r.cachedInputTokens + r.outputTokens;
      const cost = r.costUsd ?? 0;
      period.costUsd += cost;
      period.totalTokens += tokens;
      const slot = (period.byProvider[r.provider] ??= { costUsd: 0, totalTokens: 0 });
      slot.costUsd += cost;
      slot.totalTokens += tokens;
    }
  }

  const providerRows: ProviderTotals[] = USAGE_PROVIDERS.flatMap((provider) => {
    const t = providers.get(provider);
    return t
      ? [
          {
            ...t,
            provider,
            costShare: share(t.costUsd, totals.costUsd),
            tokenShare: share(t.totalTokens, totals.totalTokens),
          },
        ]
      : [];
  });
  const modelRows: ModelTotals[] = [...models.values()]
    .map((m) => ({
      ...m,
      priced: m.unpricedRuns < m.runs,
      costShare: share(m.costUsd, totals.costUsd),
    }))
    .sort((a, b) => b.costUsd - a.costUsd || b.totalTokens - a.totalTokens);
  const purposeRows: PurposeTotals[] = [...purposes.entries()]
    .map(([purpose, t]) => ({ ...t, purpose, costShare: share(t.costUsd, totals.costUsd) }))
    .sort((a, b) => b.costUsd - a.costUsd || b.totalTokens - a.totalTokens);

  return {
    days,
    resolution: days === 1 ? 'hour' : 'day',
    since: window.since,
    until: window.until,
    periods,
    totals: { ...totals, unpricedShare: share(totals.unpricedRuns, totals.runs) },
    providers: providerRows,
    models: modelRows,
    purposes: purposeRows,
  };
}

/** The last period starting at or before `at`. */
function periodIndex(starts: readonly number[], at: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid]! <= at) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

export function monthStart(now: number): number {
  const d = new Date(now);
  return new Date(d.getFullYear(), d.getMonth(), 1).getTime();
}

/** This month's spend on each key-billed provider that was used or has a cap. */
export function keySpend(
  monthRuns: readonly UsageRun[],
  caps: Partial<Record<UsageProvider, number>>,
): KeySpendView[] {
  return BILLED_PROVIDERS.flatMap((provider) => {
    const runs = monthRuns.filter((r) => r.provider === provider);
    const cap = caps[provider];
    if (runs.length === 0 && cap === undefined) return [];
    return [
      {
        provider,
        runs: runs.length,
        spentUsd: runs.reduce((sum, r) => sum + (r.costUsd ?? 0), 0),
        ...(cap !== undefined ? { capUsd: cap } : {}),
      },
    ];
  });
}
