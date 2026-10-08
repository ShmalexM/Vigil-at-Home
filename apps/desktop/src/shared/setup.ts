import { z } from 'zod';

/**
 * First-run setup, shared by main and the renderer. Protection (Santa,
 * osquery, the helper) always runs on the Mac; the mode picks where the AI
 * that explains alerts and drafts rules runs.
 */
export const SetupMode = z.enum(['local', 'cloud', 'both']);
export type SetupMode = z.infer<typeof SetupMode>;

export type StepGroup = 'protection' | 'ai';

export type CheckId =
  | 'homebrew'
  | 'santa.installed'
  | 'santa.running'
  | 'santa.profile'
  | 'osquery'
  | 'fapolicyd'
  | 'helper'
  | 'ollama'
  | 'ollama.model'
  | 'claude'
  | 'codex';

/**
 * - done: Vigil saw it working.
 * - todo: not there yet; run the commands.
 * - waiting: a step it depends on isn't done.
 * - unavailable: can't be done on this build or computer yet (detail says why).
 */
export type StepState = 'done' | 'todo' | 'waiting' | 'unavailable';

export const SettingsPane = z.enum(['extensions', 'fullDiskAccess', 'profiles', 'terminal']);
export type SettingsPane = z.infer<typeof SettingsPane>;

export const ApiKeyProvider = z.enum(['openrouter', 'anthropic', 'openai', 'custom', 'typesafe']);
export type ApiKeyProvider = z.infer<typeof ApiKeyProvider>;

export const ApiKeyInput = z.object({
  provider: ApiKeyProvider,
  key: z
    .string()
    .trim()
    .min(16, 'That looks too short for an API key')
    .max(512)
    .regex(/^\S+$/, 'API keys have no spaces'),
  baseUrl: z
    .url({ protocol: /^https?$/ })
    .max(300)
    .optional(),
});
export type ApiKeyInput = z.input<typeof ApiKeyInput>;

/** A one-click fix a step offers besides its commands. */
export const SetupAction = z.enum(['codex-share']);
export type SetupAction = z.infer<typeof SetupAction>;

export interface SetupStepView {
  id: string;
  group: StepGroup;
  title: string;
  why: string;
  optional: boolean;
  commands: { label: string; cmd: string }[];
  manual: { text: string; pane?: SettingsPane }[];
  /** What Vigil looked at. */
  checks: string;
  state: StepState;
  /** What Vigil found, e.g. "Santa 2026.9, monitor mode". */
  detail?: string;
  skipped: boolean;
  /** Shown as a button on the step, e.g. "Use my Codex sign-in". */
  action?: { id: SetupAction; label: string };
  /**
   * Set when a step that was done needs doing again (e.g. reinstalling
   * Santa's profile). Shown once as a calm banner outside Setup until the
   * user dismisses it; the step itself stays here.
   */
  banner?: string;
}

export interface ApiKeyView {
  provider: ApiKeyProvider;
  name: string;
  url?: string;
  use: string;
  needsBaseUrl: boolean;
  /** Listed under "More options" rather than as the main key. */
  more: boolean;
  /** Last four characters of the saved key. The key itself never leaves main. */
  saved?: string;
  baseUrl?: string;
}

export interface SetupView {
  mode?: SetupMode;
  finished: boolean;
  /** False when not on macOS: steps show but can't be checked. */
  supported: boolean;
  steps: SetupStepView[];
  keys: ApiKeyView[];
  /** Keys are encrypted with the macOS Keychain; false means they can't be saved. */
  canSaveKeys: boolean;
  checkedAt: number;
}
