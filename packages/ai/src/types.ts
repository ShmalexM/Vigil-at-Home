import type { z } from 'zod';

/** `api` is any OpenAI-style API (OpenRouter, OpenAI, a self-hosted gateway) with the user's own key. */
export type ProviderId = 'claude' | 'codex' | 'ollama' | 'api' | 'jev';

/** Local providers run on this Mac; cloud ones send the (redacted) data off it. */
export const LOCAL_PROVIDERS: readonly ProviderId[] = ['ollama'];

/**
 * "explain": the text behind a popup. "analyze": out-of-band work such as proposing rules.
 * "classify": labelling a batch of events a rule didn't already explain.
 * "chat": the user talking with Vigil's Lead dog (the Pack page).
 */
export type Purpose = 'explain' | 'analyze' | 'classify' | 'chat';

/** "now" runs immediately. "background" waits for quota headroom and may be skipped. */
export type Urgency = 'now' | 'background';

/**
 * A read-only tool the agent may call. Vigil runs it in its own process; the
 * agent only ever sees the (redacted) JSON it returns.
 */
export interface ReadTool<Shape extends z.ZodRawShape = z.ZodRawShape> {
  readonly name: string;
  readonly description: string;
  readonly input: Shape;
  run(args: z.infer<z.ZodObject<Shape>>): Promise<unknown>;
}

export interface RunRequest<T> {
  readonly purpose: Purpose;
  readonly urgency: Urgency;
  /** What to do. Written by Vigil, never by the data. */
  readonly instructions: string;
  /** Evidence or telemetry. Treated as untrusted, redacted and size-capped before it leaves the Mac. */
  readonly data: unknown;
  /** Shape of the answer. The result is validated against it. */
  readonly output: z.ZodType<T>;
  /** Optional read-only tools. None by default. */
  readonly tools?: readonly ReadTool[];
  readonly deadlineMs: number;
  /** Only these providers, in the usual order. Default: all the settings allow. */
  readonly providers?: readonly ProviderId[];
  /**
   * The user asked for this run themselves (an "Explain with my Claude plan"
   * button, a message to the Lead dog). Only such an explanation or chat may
   * use a Claude plan; see `mayUsePlan`.
   */
  readonly requestedByUser?: boolean;
}

/**
 * Anthropic's terms bar apps from running their own work through a user's
 * Claude plan (Free, Pro or Max). So a plan serves only an explanation the user
 * asked for, or the user's own message to the Lead dog; automatic
 * explanations, labelling, rule reviews and pack dogs' jobs never reach it.
 */
export function mayUsePlan(
  request: Pick<RunRequest<unknown>, 'purpose' | 'requestedByUser'>,
): boolean {
  return (
    request.requestedByUser === true &&
    (request.purpose === 'explain' || request.purpose === 'chat')
  );
}

export type RunFailureReason = 'quota' | 'timeout' | 'invalid_output' | 'no_provider' | 'error';

export type RunResult<T> =
  | { readonly ok: true; readonly value: T; readonly provider: ProviderId; readonly logId: string }
  | {
      readonly ok: false;
      readonly reason: RunFailureReason;
      readonly detail?: string;
      readonly logId: string;
    };

export type ProviderState =
  | 'ready'
  | 'needs_sign_in'
  | 'not_installed'
  | 'binary_changed'
  | 'needs_setup'
  | 'disabled'
  | 'paused_by_vigil'
  | 'error';

export interface ProviderStatus {
  readonly provider: ProviderId;
  readonly state: ProviderState;
  readonly version?: string;
  /** The account the vendor reports, for display only. */
  readonly account?: string;
  readonly detail?: string;
  /** True when Vigil can start the vendor's sign-in itself (see `AiRunner.signIn`). */
  readonly canSignIn?: boolean;
  /**
   * Codex only: the user's own Codex has a sign-in Vigil's folder can link to
   * (`shareCodexSignIn`), so no second sign-in is needed.
   */
  readonly canShareSignIn?: boolean;
}

/** One usage window as the vendor reports it (for example Claude's five_hour, Codex's primary). */
export interface UsageWindow {
  readonly provider: ProviderId;
  readonly windowId: string;
  /** 0 to 100. */
  readonly usedPercent: number;
  /** Epoch milliseconds. */
  readonly resetsAt?: number;
  readonly rejected?: boolean;
}

/** What Vigil hands an adapter for one run. Everything in it is already redacted. */
export interface AdapterRunInput {
  readonly systemPrompt: string;
  readonly userPrompt: string;
  readonly jsonSchema: Record<string, unknown>;
  readonly tools: readonly ReadTool[];
  readonly signal: AbortSignal;
  readonly onUsage: (window: UsageWindow) => void;
  /** Set by the runner from `mayUsePlan(request)`. A Claude plan runs only when true. */
  readonly mayUsePlan?: boolean;
}

export interface ToolAudit {
  /** Vigil tools the agent called. */
  readonly called: string[];
  /** Anything else the agent tried to use (shell, file, web...). Always denied. */
  readonly denied: string[];
}

/** What one run cost, as the vendor reported it. */
export interface RunUsage {
  readonly inputTokens: number;
  readonly cachedInputTokens: number;
  readonly outputTokens: number;
  /**
   * Claude Code's own estimate in US dollars (API list price, not a bill). Null
   * where there is no per-token price: a ChatGPT plan, or a local model.
   */
  readonly costUsd: number | null;
  /** The model that answered, as the vendor names it, when the adapter knows it. */
  readonly model?: string;
}

export type AdapterRunOutput = (
  | { readonly kind: 'ok'; readonly json: unknown; readonly audit: ToolAudit }
  | { readonly kind: 'quota'; readonly resetsAt?: number; readonly audit: ToolAudit }
  | { readonly kind: 'error'; readonly message: string; readonly audit: ToolAudit }
) & { readonly usage?: RunUsage };

/** A provider's plan and limit windows, read from its own CLI. */
export interface PlanUsage {
  /** The plan name as the vendor reports it (pro, max, plus...). */
  readonly plan?: string;
  readonly windows: readonly UsageWindow[];
}

export interface ProviderAdapter {
  readonly id: ProviderId;
  /** Cheap and side-effect free. Never opens a session, runs hooks or opens a browser. */
  probe(): Promise<ProviderStatus>;
  run(input: AdapterRunInput): Promise<AdapterRunOutput>;
  /**
   * Starts the vendor's own sign-in in the user's browser, for providers where
   * Vigil can do that without seeing the login. Absent when the user signs in
   * with the vendor's app instead.
   */
  signIn?(): Promise<SignInFlow>;
  /**
   * The plan's limit windows, asked of the vendor's own CLI (which uses its
   * own login). Undefined when the account has none, such as an API key.
   */
  readUsage?(): Promise<PlanUsage | undefined>;
  /**
   * Whether this adapter can take a run with the given plan permission. The
   * runner skips it when false. Absent means always (it has no plan rule).
   */
  canServe?(mayUsePlan: boolean): Promise<boolean>;
}

/** A sign-in the vendor runs. Vigil only opens the URL; the login stays with the vendor's CLI. */
export interface SignInFlow {
  /** The vendor's own sign-in page, to open in the user's browser. */
  readonly url: string;
  /** Resolves true once the vendor reports the sign-in finished. */
  readonly completed: Promise<boolean>;
  cancel(): void;
}

/** Where every prompt that leaves the Mac is recorded, so the user can see it. */
export interface PromptLog {
  record(entry: PromptLogEntry): void;
}

export interface PromptLogEntry {
  readonly id: string;
  readonly at: number;
  readonly purpose: Purpose;
  readonly urgency: Urgency;
  readonly provider: ProviderId | null;
  readonly systemPrompt: string;
  readonly userPrompt: string;
  readonly outcome: 'ok' | RunFailureReason;
  readonly audit?: ToolAudit;
  readonly detail?: string;
  readonly usage?: RunUsage;
  /** Same as usage.model, kept at the top so the usage page can group runs by model. */
  readonly model?: string;
}
