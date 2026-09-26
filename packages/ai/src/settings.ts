import { join } from 'node:path';
import type { ProviderId } from './types.js';

export interface AiSettings {
  /** Tried in this order. The first ready provider with headroom runs the task. */
  readonly order: readonly ProviderId[];
  readonly claude: {
    readonly enabled: boolean;
    /** "subscription" uses the user's own signed-in Claude Code. "apiKey" uses a key from the Keychain. */
    readonly mode: 'subscription' | 'apiKey';
    readonly executablePath?: string;
  };
  readonly codex: {
    readonly enabled: boolean;
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
 * Shown in setup next to the Claude option. Claude subscription mode is on by
 * default and can be switched to an API key or turned off.
 */
export const CLAUDE_SUBSCRIPTION_NOTE =
  'Vigil runs your own Claude Code, signed in with your own account, and never sees your login. ' +
  "Anthropic's terms allow using your subscription with the unmodified Claude Code app, but they also say apps " +
  'built on it should use an API key, so this could change. Sign in yourself with `claude auth login`. ' +
  'You can switch to an API key or turn Claude off at any time.';

/**
 * Everything is on by default: Vigil uses whichever of these it finds installed
 * and signed in, in this order, and the settings screen can switch any off.
 */
export function defaultAiSettings(appSupportDir: string): AiSettings {
  return {
    order: ['claude', 'codex', 'ollama'],
    claude: { enabled: true, mode: 'subscription' },
    codex: { enabled: true, codexHome: join(appSupportDir, 'codex') },
    ollama: { enabled: true, baseUrl: 'http://127.0.0.1:11434' },
    quota: { backgroundSharePercent: 10 },
    pausedByVigil: [],
    redaction: { maxDataBytes: 48_000 },
  };
}
