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
export type UsagePurpose = 'explain' | 'analyze' | 'classify';
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
  analyze: 'Proposing rules',
  classify: 'Labelling events',
};

/** Providers that charge the user's own API key per call, so their cost is a bill, not an estimate. */
export const BILLED_PROVIDERS: readonly UsageProvider[] = ['jev', 'api'];

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

/** What an API key spent this calendar month, against its cap if the user set one. */
export interface KeySpendView {
  provider: UsageProvider;
  spentUsd: number;
  runs: number;
  capUsd?: number;
}

export interface UsageLimitsView {
  checkedAt: number;
  plans: PlanLimitsView[];
  keys: KeySpendView[];
  /** Vigil's share of each plan window for background work, in percent. */
  backgroundSharePercent?: number;
}
