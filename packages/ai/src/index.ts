import type { PinStore } from './executable.js';
import { createClaudeAdapter } from './providers/claude.js';
import { createCodexAdapter } from './providers/codex.js';
import { createOllamaAdapter } from './providers/ollama.js';
import { createAiRunner, type AiRunner } from './runner.js';
import type { AiSettings } from './settings.js';
import type { PromptLog, ProviderAdapter, ProviderId } from './types.js';

export * from './types.js';
export { CLAUDE_SUBSCRIPTION_NOTE, defaultAiSettings, type AiSettings } from './settings.js';
export { createAiRunner, jsonSchemaFor, type AiRunner, type AiRunnerDeps } from './runner.js';
export { readTool } from './tools.js';
export type {
  SpendingDay,
  SpendingLimits,
  SpendingPlan,
  SpendingSnapshot,
  SpendingWindow,
} from './spending.js';
export {
  detectAiApps,
  watchAiApps,
  type AiAppsSnapshot,
  type WatchAiAppsOptions,
} from './watch.js';
export { memoryPinStore, type ExecutablePin, type PinStore } from './executable.js';
export { QuotaTracker } from './quota.js';
export { createClaudeAdapter } from './providers/claude.js';
export { createCodexAdapter } from './providers/codex.js';
export {
  canShareCodexSignIn,
  DEFAULT_USER_CODEX_HOME,
  isCodexSignInLinkBroken,
  isCodexSignInShared,
  shareCodexSignIn,
  stopSharingCodexSignIn,
  type ShareCodexSignInResult,
} from './providers/codexSignIn.js';
export { createOllamaAdapter } from './providers/ollama.js';

export interface VigilAiOptions {
  readonly settings: AiSettings;
  readonly log: PromptLog;
  /** Where the binaries recorded at setup are kept (the app's database). */
  readonly pins: PinStore;
  /** Reads the Anthropic API key from the Keychain. Only used in apiKey mode. */
  readonly getAnthropicApiKey?: () => Promise<string | undefined>;
  /** What Vigil's runs on this provider cost this calendar month (for the API-key cap). */
  readonly spentThisMonthUsd?: (provider: ProviderId) => Promise<number>;
}

/** The runner with the three built-in adapters, configured from settings. */
export function createVigilAi(options: VigilAiOptions): AiRunner {
  const { settings } = options;
  const adapters: ProviderAdapter[] = [
    createClaudeAdapter({
      mode: settings.claude.mode,
      pins: options.pins,
      ...(settings.claude.executablePath ? { executablePath: settings.claude.executablePath } : {}),
      ...(options.getAnthropicApiKey ? { getApiKey: options.getAnthropicApiKey } : {}),
    }),
    createCodexAdapter({
      codexHome: settings.codex.codexHome,
      pins: options.pins,
      ...(settings.codex.executablePath ? { executablePath: settings.codex.executablePath } : {}),
    }),
    createOllamaAdapter({
      baseUrl: settings.ollama.baseUrl,
      ...(settings.ollama.model ? { model: settings.ollama.model } : {}),
    }),
  ];
  return createAiRunner({
    settings,
    adapters,
    log: options.log,
    ...(options.spentThisMonthUsd ? { spentThisMonthUsd: options.spentThisMonthUsd } : {}),
  });
}
