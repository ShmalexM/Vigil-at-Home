import { join } from 'node:path';
import { JEV_DEFAULT_BASE_URL, JEV_DEFAULT_MODEL } from './providers/jev.js';
import type { ProviderId } from './types.js';

/**
 * Where AI runs. "local": only on this Mac (Ollama), nothing leaves it.
 * "cloud": the user's subscriptions and API keys. "both": local first for
 * high-volume labelling, cloud for explanations and rule proposals, each
 * falling back to the other.
 */
export type AiMode = 'local' | 'cloud' | 'both';

/** Ready-made OpenAI-style endpoints. "custom" takes any base URL. */
export const API_PRESETS = {
  openrouter: { label: 'OpenRouter', baseUrl: 'https://openrouter.ai/api/v1' },
  openai: { label: 'OpenAI', baseUrl: 'https://api.openai.com/v1' },
  custom: { label: 'Other OpenAI-compatible API', baseUrl: '' },
} as const;
export type ApiPreset = keyof typeof API_PRESETS;

export interface AiSettings {
  readonly mode: AiMode;
  /** Tried in this order. The first ready provider with headroom runs the task. */
  readonly order: readonly ProviderId[];
  readonly claude: {
    readonly enabled: boolean;
    /**
     * "apiKey" (the default) uses a key from the Keychain. "subscription" means
     * no key, only the user's own signed-in plan (and implies `allowPlan`).
     */
    readonly mode: 'subscription' | 'apiKey';
    /**
     * The user opted in to their Claude plan (off by default). Even then it
     * serves only explanations the user asks for (`mayUsePlan`); automatic
     * explanations, labelling and rule reviews need the API key.
     */
    readonly allowPlan?: boolean;
    readonly executablePath?: string;
  };
  readonly codex: {
    readonly enabled: boolean;
    /**
     * "subscription" uses a ChatGPT sign-in (Vigil's own, or the user's shared one).
     * "apiKey" uses an OpenAI API key from the Keychain, sent only to api.openai.com.
     */
    readonly mode?: 'subscription' | 'apiKey';
    readonly executablePath?: string;
    /**
     * Vigil's own Codex home, so the user's config, MCP servers and plugins never
     * apply. The user signs it in once with ChatGPT from Vigil (`signIn('codex')`).
     */
    readonly codexHome: string;
  };
  readonly ollama: {
    readonly enabled: boolean;
    readonly baseUrl: string;
    /** Unset means Vigil picks the largest installed model that supports tools. */
    readonly model?: string;
  };
  /** An OpenAI-style API with the user's own key, which the app keeps in the Keychain. */
  readonly api: {
    readonly enabled: boolean;
    readonly preset: ApiPreset;
    readonly baseUrl: string;
    /** The model id as the API names it. Chosen in setup from the API's own list. */
    readonly model?: string;
  };
  /**
   * TypeSafe's Jev, a cloud model built for fast typed decisions. With a key it
   * labels events instead of the local model (outside local mode), and the
   * local model takes over whenever Jev can't answer.
   */
  readonly jev: {
    readonly enabled: boolean;
    readonly baseUrl: string;
    readonly model: string;
  };
  /** The small local model that labels events rules didn't already explain. */
  readonly classifier: {
    readonly enabled: boolean;
    /** Unset means Vigil picks a small installed model that fits this Mac's memory. */
    readonly model?: string;
    /** Most events sent in one request. */
    readonly maxEventsPerBatch: number;
    /** Most requests per hour, local or cloud. */
    readonly maxBatchesPerHour: number;
    /**
     * CPU seconds per hour the local model may use: 72 is 2% of one core, the
     * speed budget in docs/performance.md. A slow Mac simply does fewer batches.
     */
    readonly maxCpuSecondsPerHour: number;
  };
  readonly quota: {
    /** Vigil's share of each subscription usage window for background work, in percent. */
    readonly backgroundSharePercent: number;
    /** Claude in apiKey mode stops for the month once Vigil's runs have cost this much. */
    readonly apiKeyMonthlyCapUsd?: number;
  };
  /** Providers turned off remotely by a Vigil update, for example after a change in terms. */
  readonly pausedByVigil: readonly ProviderId[];
  readonly redaction: {
    readonly username?: string;
    readonly hostname?: string;
    readonly maxDataBytes: number;
  };
}

/**
 * Shown in setup next to the Claude option. Claude runs on an API key by
 * default; using a Claude plan is opt-in and covers alert explanations only.
 */
export const CLAUDE_SUBSCRIPTION_NOTE =
  'Vigil runs your own Claude Code, signed in with your own account, and never sees your login. ' +
  "Anthropic's terms say apps built on Claude Code should use an API key, so your plan only explains " +
  'alerts you ask about. Automatic explanations, event labelling and rule reviews need an API key. ' +
  'Sign in yourself with `claude auth login`. You can turn this off at any time.';

/**
 * Everything is on by default: Vigil uses whichever of these it finds installed
 * and signed in, in this order, and the settings screen can switch any off.
 */
export function defaultAiSettings(appSupportDir: string): AiSettings {
  return {
    mode: 'both',
    order: ['claude', 'codex', 'api', 'ollama'],
    claude: { enabled: true, mode: 'apiKey', allowPlan: false },
    codex: { enabled: true, codexHome: join(appSupportDir, 'codex') },
    ollama: { enabled: true, baseUrl: 'http://127.0.0.1:11434' },
    api: { enabled: true, preset: 'openrouter', baseUrl: API_PRESETS.openrouter.baseUrl },
    jev: { enabled: true, baseUrl: JEV_DEFAULT_BASE_URL, model: JEV_DEFAULT_MODEL },
    classifier: {
      enabled: true,
      maxEventsPerBatch: 20,
      maxBatchesPerHour: 60,
      maxCpuSecondsPerHour: 72,
    },
    quota: { backgroundSharePercent: 10 },
    pausedByVigil: [],
    redaction: { maxDataBytes: 48_000 },
  };
}
