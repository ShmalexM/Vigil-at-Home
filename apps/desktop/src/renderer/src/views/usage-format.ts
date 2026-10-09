import type { UsageProvider, UsageTotals } from '../../../shared/usage';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const CURRENCY = new Intl.NumberFormat('en-US', {
  style: 'currency',
  currency: 'USD',
  minimumFractionDigits: 2,
  maximumFractionDigits: 2,
});
const INTEGER = new Intl.NumberFormat('en-US');

/** Jev bills fractions of a cent, so tiny amounts read as "<$0.01" rather than "$0.00". */
export function formatUsd(value: number): string {
  if (value > 0 && value < 0.005) return '<$0.01';
  return CURRENCY.format(value);
}

export function formatCount(value: number): string {
  return INTEGER.format(Math.round(value));
}

function trim(value: number): string {
  return value >= 100 ? value.toFixed(0) : value >= 10 ? value.toFixed(1) : value.toFixed(2);
}

export function formatTokens(value: number): string {
  const abs = Math.abs(value);
  if (abs >= 1e9) return `${trim(value / 1e9)}B`;
  if (abs >= 1e6) return `${trim(value / 1e6)}M`;
  if (abs >= 1e3) return `${trim(value / 1e3)}K`;
  return formatCount(value);
}

export function formatPercent(share: number, digits = 1): string {
  return `${(share * 100).toFixed(digits)}%`;
}

export function formatDuration(ms: number): string {
  const left = Math.max(0, ms);
  const days = Math.floor(left / DAY);
  const hours = Math.floor((left % DAY) / HOUR);
  const minutes = Math.floor((left % HOUR) / MINUTE);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

export function formatDay(start: number): string {
  return new Date(start).toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

export function formatHour(start: number): string {
  return new Date(start).toLocaleTimeString('en-US', { hour: 'numeric' });
}

export function formatDateTime(at: number): string {
  return new Date(at).toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

/** Series colours, shared by the chart, the summary rows and the limit bars. */
export const PROVIDER_COLOR: Record<UsageProvider, string> = {
  claude: '#d97757',
  codex: 'var(--tx0)',
  jev: '#2fb58a',
  api: '#5b9bbd',
  ollama: '#8c7bd1',
};

export type LimitPace = 'ahead' | 'on' | 'under';

/** How far into the window the clock is, 0 to 1, when the window's length is known. */
export function elapsedShare(
  w: { resetsAt?: number; durationMins?: number },
  now: number,
): number | null {
  if (w.resetsAt === undefined || w.durationMins === undefined || w.durationMins <= 0) return null;
  const length = w.durationMins * MINUTE;
  return Math.max(0, Math.min(1, (length - (w.resetsAt - now)) / length));
}

/** Ahead when more than 5 points of quota are spent beyond even spending. */
export function paceOf(
  w: { usedPercent: number; resetsAt?: number; durationMins?: number },
  now: number,
): LimitPace | null {
  const elapsed = elapsedShare(w, now);
  if (elapsed === null) return null;
  const gap = w.usedPercent - elapsed * 100;
  return gap > 5 ? 'ahead' : gap < -5 ? 'under' : 'on';
}

export function remainingPercent(w: { usedPercent: number }): number {
  return Math.round(100 - Math.max(0, Math.min(100, w.usedPercent)));
}

export function formatResetsIn(w: { resetsAt?: number }, now: number): string | null {
  if (w.resetsAt === undefined) return null;
  return w.resetsAt <= now ? 'resets now' : `resets in ${formatDuration(w.resetsAt - now)}`;
}

/**
 * The top of the axis: a readable 1/2/5 × 10^n step at or above the peak, so
 * the tallest period is never drawn past the top of the plot. Adapted from
 * T3 Code (MIT, Copyright (c) 2026 T3 Tools Inc.; see NOTICE).
 */
export function niceScale(peak: number, count: number): { max: number; ticks: number[] } {
  if (peak <= 0) return { max: 0, ticks: [0] };
  const rawStep = peak / count;
  const magnitude = 10 ** Math.floor(Math.log10(rawStep));
  const normalized = rawStep / magnitude;
  const step = (normalized > 5 ? 10 : normalized > 2 ? 5 : normalized > 1 ? 2 : 1) * magnitude;
  const max = Math.ceil(peak / step) * step;
  const ticks: number[] = [];
  for (let value = 0; value <= max + step * 1e-6; value += step) ticks.push(value);
  return { max, ticks };
}

type CostTotals = Pick<UsageTotals, 'costUsd' | 'billedUsd' | 'billedUnpricedRuns' | 'loginUsd'>;

/**
 * The headline's note on what the total is: what was billed to the user's
 * keys (and whether some of it has no price), and that the rest is Claude
 * Code's estimate at API prices. A run Vigil knows went to a plan says so,
 * with no claim about cost: paid extra usage can charge a plan run.
 */
export function costNote(t: CostTotals): string {
  const parts: string[] = [];
  if (t.billedUsd > 0) parts.push(`${formatUsd(t.billedUsd)} billed to your keys`);
  if (t.billedUnpricedRuns > 0)
    parts.push(
      `${formatCount(t.billedUnpricedRuns)} billed ${t.billedUnpricedRuns === 1 ? 'run' : 'runs'} at a cost Vigil can’t see`,
    );
  const rest = t.costUsd - t.billedUsd;
  if (rest > 0)
    parts.push(
      t.loginUsd > 0
        ? `${parts.length ? 'the rest ' : ''}at API prices, on your Claude login`
        : `${parts.length ? 'the rest ' : ''}at API prices, on your plan`,
    );
  if (parts.length === 0) return t.costUsd > 0 ? 'API estimate' : 'nothing billed';
  return parts.join(', ');
}

/** A provider's note when its price is only an estimate: on a plan, or on a login Vigil can't tell. */
export function estimateNote(p: CostTotals): string | undefined {
  if (!(p.costUsd > 0 && p.billedUsd === 0)) return undefined;
  return p.loginUsd > 0 ? 'at API prices, on your Claude login' : 'at API prices, on your plan';
}
