import { z } from 'zod';
import type { SetupMode } from './setup.js';

/**
 * The AI card in Settings, shared by main and the renderer. The AI only
 * explains alerts; it never blocks, releases or allows anything.
 */
export const AiProvider = z.enum(['claude', 'codex', 'api', 'ollama', 'jev']);
export type AiProvider = z.infer<typeof AiProvider>;

/** What the user can switch in Settings. Everything else comes from setup and saved keys. */
export const AiPrefs = z.object({
  claude: z.boolean(),
  codex: z.boolean(),
  api: z.boolean(),
  ollama: z.boolean(),
  jev: z.boolean(),
  /** Claude through the user's own Claude Code sign-in, or a saved Anthropic API key. */
  claudeUses: z.enum(['subscription', 'apiKey']),
  /** Vigil stops using paid keys (API, Jev, Claude on a key) for the month past this. */
  monthlyCapUsd: z.number().min(0).max(10_000).optional(),
});
export type AiPrefs = z.infer<typeof AiPrefs>;

export const DEFAULT_AI_PREFS: AiPrefs = {
  claude: true,
  codex: true,
  api: true,
  ollama: true,
  jev: true,
  claudeUses: 'subscription',
};

/** A change to some prefs. A null cap removes it. */
export const AiPrefsPatch = AiPrefs.omit({ monthlyCapUsd: true })
  .partial()
  .extend({ monthlyCapUsd: z.number().min(0).max(10_000).nullable().optional() });
export type AiPrefsPatch = z.input<typeof AiPrefsPatch>;

export type AiProviderState =
  | 'ready'
  | 'needs_sign_in'
  | 'not_installed'
  | 'binary_changed'
  | 'needs_setup'
  | 'disabled'
  | 'paused_by_vigil'
  | 'error';

export interface AiProviderView {
  provider: AiProvider;
  name: string;
  /** Local runs on this Mac; everything else sends redacted data off it. */
  local: boolean;
  state: AiProviderState;
  version?: string;
  /** The account the vendor reports, for display only. */
  account?: string;
  detail?: string;
  /** Vigil can open the vendor's own sign-in page (Codex with ChatGPT). */
  canSignIn: boolean;
  /** Codex: the user's own Codex has a sign-in Vigil can use instead. */
  canShareSignIn: boolean;
  /** Codex: Vigil is using the user's own Codex sign-in right now. */
  signInShared: boolean;
}

export interface AiView {
  /** Where AI runs, as chosen in setup. Unset until setup picks one. */
  mode?: SetupMode;
  prefs: AiPrefs;
  providers: AiProviderView[];
  /** The OpenAI-style API Vigil uses, from the saved keys. */
  api?: { name: string; last4: string };
  /** How Jev is reached: the OpenRouter key, its own TypeSafe key, or not at all. */
  jevVia: 'openrouter' | 'typesafe' | null;
  checkedAt: number;
}

export interface AiActionResult {
  ok: boolean;
  error?: string;
}
