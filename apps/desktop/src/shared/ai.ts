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
  /** A model labels events no rule matched, as hints in Activity. */
  labelling: z.boolean(),
  /**
   * Opt-in, off by default: the user's own Claude plan (through their Claude
   * Code sign-in) may explain an alert, but only when they ask for it. All
   * automatic Claude work (explaining new alerts, labelling, rule review)
   * uses a saved Anthropic API key.
   */
  claudePlan: z.boolean(),
  /** Codex through the user's ChatGPT plan sign-in, or a saved OpenAI API key. */
  codexUses: z.enum(['subscription', 'apiKey']),
  /**
   * One limit on everything Vigil charges to the user's keys this month, all
   * together (Cloud API, Jev, Claude on an Anthropic key, Codex on an OpenAI key).
   */
  monthlyCapUsd: z.number().min(0).max(10_000).optional(),
});
export type AiPrefs = z.infer<typeof AiPrefs>;

export const DEFAULT_AI_PREFS: AiPrefs = {
  claude: true,
  codex: true,
  api: true,
  ollama: true,
  jev: true,
  labelling: true,
  claudePlan: false,
  codexUses: 'subscription',
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
  /** Not set up, and nothing needs it: other apps already explain alerts. */
  | 'optional'
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
  /** An Anthropic API key is saved, so Claude can work on its own (and label with Haiku). */
  anthropicKey: boolean;
  /** How Jev is reached: the OpenRouter key, its own TypeSafe key, or not at all. */
  jevVia: 'openrouter' | 'typesafe' | null;
  /** Set when the switches leave the AI unable to work (AiBridge.offNotice). */
  off?: string;
  checkedAt: number;
}

export interface AiActionResult {
  ok: boolean;
  error?: string;
}
