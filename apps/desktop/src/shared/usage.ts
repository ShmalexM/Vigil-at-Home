/**
 * The Usage page's data, shared by main and the renderer. Types and labels
 * only, with no runtime imports, so the renderer stays free of zod.
 *
 * Everything here counts Vigil's own AI runs from its prompt log. The user's
 * other conversations with Claude Code or Codex are never read.
 */

/** Same ids as `ProviderId` in @vigil/ai. */
export type UsageProvider = 'claude' | 'codex' | 'jev' | 'api' | 'ollama';
/** Same ids as `Purpose` in @vigil/ai. */
export type UsagePurpose = 'explain' | 'analyze' | 'classify' | 'chat';
export type UsageDays = 1 | 7 | 30 | 90;

/** Reading order for every chart, row and table. */
export const USAGE_PROVIDERS: readonly UsageProvider[] = [
  'claude',
  'codex',
  'jev',
  'api',
  'ollama',
];

export const PROVIDER_LABEL: Record<UsageProvider, string> = {
  claude: 'Claude Code',
  codex: 'Codex',
  jev: 'Jev',
  api: 'Cloud API',
  ollama: 'Ollama',
};

export const PURPOSE_LABEL: Record<UsagePurpose, string> = {
  explain: 'Explaining alerts',
  analyze: 'Rule reviews and pack jobs',
  classify: 'Labelling events',
  chat: 'Talking with the Lead dog',
};

/**
 * Providers that can charge the user's own API key per call, so their cost is
 * a bill, not an estimate. Claude bills on an Anthropic key and Codex on an
 * OpenAI key; their plan runs don't.
 */
export const BILLED_PROVIDERS: readonly UsageProvider[] = ['claude', 'codex', 'jev', 'api'];

/** Whether this run was charged to one of the user's keys. */
export function isKeyBilled(run: {
  provider: UsageProvider;
  costUsd: number | null;
  billed?: boolean | undefined;
}): boolean {
  if (run.costUsd === null) return false;
  return chargedToKey(run);
}

/** Whether this run went to one of the user's keys, priced or not. */
export function chargedToKey(run: {
  provider: UsageProvider;
  billed?: boolean | undefined;
}): boolean {
  if (run.billed !== undefined) return run.billed;
  // Runs logged before `billed` existed.
  if (run.provider === 'codex') return true;
  return run.provider === 'jev' || run.provider === 'api';
}

/** One AI run as the prompt log recorded it. */
export interface UsageRun {
  id: string;
  at: number;
  provider: UsageProvider;
  purpose: UsagePurpose;
  ok: boolean;
  /** The model that answered, when the log knows it. */
  model?: string | undefined;
  /** Input not served from cache. */
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
  /**
   * US dollars: Claude Code's estimate at API list price, or what OpenRouter
   * and Jev billed. Null when the vendor gives no price (a ChatGPT plan).
   */
  costUsd: number | null;
  /** Charged to one of the user's keys, as the runner decided. Absent on older runs. */
  billed?: boolean | undefined;
}

export interface UsageTotals {
  runs: number;
  failed: number;
  inputTokens: number;
  cachedInputTokens: number;
  outputTokens: number;
  /** Uncached input + cached input + output. */
  totalTokens: number;
  /** Priced runs only. */
  costUsd: number;
  /** The part of `costUsd` charged to the user's own API keys. */
  billedUsd: number;
  /** Runs with no price at all (Codex on a ChatGPT plan). Local runs are free, not unpriced. */
  unpricedRuns: number;
  /** Of those, runs charged to one of the user's keys: billed, but at a price Vigil doesn't know. */
  billedUnpricedRuns: number;
  /**
   * The part of `costUsd` from Claude Code's own login when Vigil can't tell
   * whether that login is a plan or pays per token (billed unknown).
   */
  loginUsd: number;
}

export interface ProviderTotals extends UsageTotals {
  provider: UsageProvider;
  costShare: number;
  tokenShare: number;
}

export interface ModelTotals extends UsageTotals {
  provider: UsageProvider;
  model: string;
  /** False when none of its runs had a price. */
  priced: boolean;
  costShare: number;
}

export interface PurposeTotals extends UsageTotals {
  purpose: UsagePurpose;
  costShare: number;
}

export interface PeriodTotals {
  /** Start of the local day or hour, epoch ms. */
  start: number;
  costUsd: number;
  totalTokens: number;
  byProvider: Partial<Record<UsageProvider, { costUsd: number; totalTokens: number }>>;
}

export interface UsageReport {
  days: UsageDays;
  resolution: 'day' | 'hour';
  since: number;
  until: number;
  /** Every day or hour in the window, oldest first, including empty ones. */
  periods: PeriodTotals[];
  totals: UsageTotals & { unpricedShare: number };
  /** Only providers with activity, in reading order. */
  providers: ProviderTotals[];
  models: ModelTotals[];
  purposes: PurposeTotals[];
}

/** One limit window of a subscription plan, as its vendor reports it. */
export interface LimitWindowView {
  id: string;
  label: string;
  kind: 'session' | 'weekly' | 'other';
  /** 0 to 100, everything on the account. */
  usedPercent: number;
  /** The part of it Vigil used, as far as Vigil has seen. */
  vigilPercent: number;
  resetsAt?: number;
  /** The window's length, when known, for the even-pace mark. */
  durationMins?: number;
}

/** Same shape as `SpendingPlan` in @vigil/ai, plus optional window lengths. */
export interface PlanLimitsView {
  provider: 'claude' | 'codex';
  plan?: string;
  available: boolean;
  windows: LimitWindowView[];
}

/** What one provider charged to the user's key this calendar month. */
export interface KeySpendView {
  provider: UsageProvider;
  spentUsd: number;
  runs: number;
}

/** The one monthly cap on everything Vigil charges to the user's keys. */
export interface KeyCapView {
  capUsd: number;
  spentUsd: number;
}

export interface UsageLimitsView {
  checkedAt: number;
  plans: PlanLimitsView[];
  keys: KeySpendView[];
  /** Present when the user set a monthly cap. */
  cap?: KeyCapView;
  /** Vigil's share of each plan window for background work, in percent. */
  backgroundSharePercent?: number;
}
