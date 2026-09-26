import type { QuotaTracker } from './quota.js';
import type { AiSettings } from './settings.js';
import type { ProviderId, PromptLogEntry, Purpose, UsageWindow } from './types.js';

/** The settings the spending page shows and changes. */
export interface SpendingLimits {
  /** Vigil's share of each plan window for background work, in percent. */
  readonly backgroundSharePercent: number;
  /** Only when Claude runs on the user's own API key. */
  readonly apiKeyMonthlyCapUsd?: number;
}

export interface SpendingWindow {
  readonly id: string;
  readonly label: string;
  readonly kind: 'session' | 'weekly' | 'other';
  /** How full the window is, counting everything on the account. */
  readonly usedPercent: number;
  /** The part of it Vigil used, as far as Vigil has seen since it started. */
  readonly vigilPercent: number;
  readonly resetsAt?: number;
}

export interface SpendingPlan {
  readonly provider: 'claude' | 'codex';
  /** As the vendor names it (pro, max, plus...). */
  readonly plan?: string;
  /** False when the vendor reports no windows, such as on an API key. */
  readonly available: boolean;
  readonly windows: readonly SpendingWindow[];
}

export interface SpendingDay {
  /** Local calendar day, `YYYY-MM-DD`. */
  readonly day: string;
  readonly provider: ProviderId;
  readonly purpose: Purpose;
  readonly runs: number;
  readonly failed: number;
  readonly inputTokens: number;
  readonly cachedInputTokens: number;
  readonly outputTokens: number;
  /** Claude Code's estimate at API list price; null when nothing had a price. */
  readonly costUsd: number | null;
}

export interface SpendingSnapshot {
  readonly asOf: number;
  readonly plans: readonly SpendingPlan[];
  readonly days: readonly SpendingDay[];
  readonly limits: SpendingLimits;
}

const LABELS: Record<string, { label: string; kind: SpendingWindow['kind'] }> = {
  five_hour: { label: '5-hour limit', kind: 'session' },
  seven_day: { label: 'Weekly limit', kind: 'weekly' },
  seven_day_opus: { label: 'Weekly Opus limit', kind: 'weekly' },
  seven_day_sonnet: { label: 'Weekly Sonnet limit', kind: 'weekly' },
};

function describe(w: UsageWindow): Pick<SpendingWindow, 'label' | 'kind'> {
  const known = LABELS[w.windowId];
  if (known) return known;
  if (w.windowId.startsWith('model:'))
    return { label: `Weekly ${w.windowId.slice(6)} limit`, kind: 'weekly' };
  if (w.windowId.endsWith(':primary')) return { label: 'Short-term limit', kind: 'session' };
  if (w.windowId.endsWith(':secondary')) return { label: 'Weekly limit', kind: 'weekly' };
  return { label: w.windowId, kind: 'other' };
}

function localDay(at: number): string {
  const d = new Date(at);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

/**
 * Adds up Vigil's own runs from the prompt log. Only Vigil's runs: the user's
 * other conversations with these tools are never read.
 */
export function spendingDays(entries: Iterable<PromptLogEntry>, since: number): SpendingDay[] {
  const rows = new Map<string, SpendingDay & { priced: boolean }>();
  for (const e of entries) {
    if (e.at < since || e.provider === null) continue;
    const day = localDay(e.at);
    const k = `${day}\u0000${e.provider}\u0000${e.purpose}`;
    const row = rows.get(k) ?? {
      day,
      provider: e.provider,
      purpose: e.purpose,
      runs: 0,
      failed: 0,
      inputTokens: 0,
      cachedInputTokens: 0,
      outputTokens: 0,
      costUsd: 0,
      priced: false,
    };
    const cost = e.usage?.costUsd;
    rows.set(k, {
      ...row,
      runs: row.runs + 1,
      failed: row.failed + (e.outcome === 'ok' ? 0 : 1),
      inputTokens: row.inputTokens + (e.usage?.inputTokens ?? 0),
      cachedInputTokens: row.cachedInputTokens + (e.usage?.cachedInputTokens ?? 0),
      outputTokens: row.outputTokens + (e.usage?.outputTokens ?? 0),
      costUsd: (row.costUsd ?? 0) + (cost ?? 0),
      priced: row.priced || typeof cost === 'number',
    });
  }
  return [...rows.values()]
    .map(({ priced, ...row }) => (priced ? row : { ...row, costUsd: null }))
    .sort((a, b) => b.day.localeCompare(a.day) || a.provider.localeCompare(b.provider));
}

export function spendingPlans(
  quota: QuotaTracker,
  planNames: ReadonlyMap<ProviderId, string>,
  now: number,
): SpendingPlan[] {
  const plans: SpendingPlan[] = [];
  for (const provider of ['claude', 'codex'] as const) {
    const windows = [...quota.snapshot(provider).values()]
      .filter((w) => w.resetsAt === undefined || w.resetsAt > now)
      .map((w) => ({
        id: w.windowId,
        ...describe(w),
        usedPercent: w.usedPercent,
        vigilPercent: Math.min(w.usedPercent, quota.vigilShare(provider, w.windowId)),
        ...(w.resetsAt !== undefined ? { resetsAt: w.resetsAt } : {}),
      }));
    const plan = planNames.get(provider);
    plans.push({ provider, ...(plan ? { plan } : {}), available: windows.length > 0, windows });
  }
  return plans;
}

export function spendingLimits(settings: AiSettings): SpendingLimits {
  return {
    backgroundSharePercent: settings.quota.backgroundSharePercent,
    ...(settings.quota.apiKeyMonthlyCapUsd !== undefined
      ? { apiKeyMonthlyCapUsd: settings.quota.apiKeyMonthlyCapUsd }
      : {}),
  };
}
