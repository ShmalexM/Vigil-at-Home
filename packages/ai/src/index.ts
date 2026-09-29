import type { PinStore } from './executable.js';
import { createClaudeAdapter } from './providers/claude.js';
import { createCodexAdapter } from './providers/codex.js';
import {
  classifierRuntime,
  createEventClassifier,
  pickClassifierModel,
  recommendedClassifierModel,
  type EventClassifier,
} from './classifier.js';
import { createJevClient } from './providers/jev.js';
import { createOllamaAdapter } from './providers/ollama.js';
import { createApiAdapter, type ApiModel } from './providers/openaiCompatible.js';
import { allowedByMode, createAiRunner, type AiRunner } from './runner.js';
import type { AiSettings } from './settings.js';
import type { PromptLog, ProviderAdapter, ProviderId } from './types.js';

export * from './types.js';
export {
  API_PRESETS,
  CLAUDE_SUBSCRIPTION_NOTE,
  defaultAiSettings,
  type AiMode,
  type AiSettings,
  type ApiPreset,
} from './settings.js';
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
export {
  createApiAdapter,
  isSafeBaseUrl,
  type ApiAdapterOptions,
  type ApiModel,
} from './providers/openaiCompatible.js';
export {
  createJevClient,
  JEV_DEFAULT_BASE_URL,
  JEV_DEFAULT_MODEL,
  JEV_LABELS,
  type JevAnswer,
  type JevClient,
  type JevOptions,
  JEV_OPENROUTER_MODEL,
  JEV_OPENROUTER_URL,
} from './providers/jev.js';
export {
  CLASSIFIER_MODELS,
  classifierRuntime,
  createEventClassifier,
  eventLine,
  LABEL_INSTRUCTIONS,
  pickClassifierModel,
  recommendedClassifierModel,
  type ClassifyResult,
  type EventClassifier,
  type EventLabel,
  type LabelledEvent,
} from './classifier.js';

/** The Claude model that labels events when Claude is signed in. */
export const CLASSIFIER_CLAUDE_MODEL = 'claude-haiku-4-5-20251001';

export interface VigilAiOptions {
  readonly settings: AiSettings;
  readonly log: PromptLog;
  /** Where the binaries recorded at setup are kept (the app's database). */
  readonly pins: PinStore;
  /** Reads the OpenAI API key from the Keychain. Only used when Codex is in apiKey mode. */
  readonly getOpenAiApiKey?: () => Promise<string | undefined>;
  /** Reads the Anthropic API key from the Keychain. Only used in apiKey mode. */
  readonly getAnthropicApiKey?: () => Promise<string | undefined>;
  /** Reads the key for the OpenAI-style API (OpenRouter, OpenAI...) from the Keychain. */
  readonly getApiKey?: () => Promise<string | undefined>;
  /** Reads the TypeSafe key for Jev from the Keychain. No key means Jev isn't used. */
  readonly getJevApiKey?: () => Promise<string | undefined>;
  /** What Vigil's runs on this provider cost this calendar month (for the API-key cap). */
  readonly spentThisMonthUsd?: (provider: ProviderId) => Promise<number>;
  /** The app says when the Mac is busy or on low battery, so event labelling waits. */
  readonly isBusy?: () => boolean;
}

export interface VigilAi extends AiRunner {
  /** Labels events rules didn't explain. Absent when labelling is off. */
  readonly classifier?: EventClassifier;
  /** The models the configured API offers, for setup. */
  listApiModels(): Promise<ApiModel[]>;
}

/** The runner with the built-in adapters and the event labeller, configured from settings. */
export function createVigilAi(options: VigilAiOptions): VigilAi {
  const { settings } = options;
  const getApiKey = options.getApiKey ?? (async () => undefined);
  const api = createApiAdapter({
    baseUrl: settings.api.baseUrl,
    getApiKey,
    ...(settings.api.model ? { model: settings.api.model } : {}),
  });
  const adapters: ProviderAdapter[] = [
    createClaudeAdapter({
      mode: settings.claude.mode,
      ...(settings.claude.allowPlan !== undefined ? { allowPlan: settings.claude.allowPlan } : {}),
      pins: options.pins,
      ...(settings.claude.executablePath ? { executablePath: settings.claude.executablePath } : {}),
      ...(options.getAnthropicApiKey ? { getApiKey: options.getAnthropicApiKey } : {}),
    }),
    createCodexAdapter({
      codexHome: settings.codex.codexHome,
      pins: options.pins,
      ...(settings.codex.mode ? { mode: settings.codex.mode } : {}),
      ...(options.getOpenAiApiKey ? { getApiKey: options.getOpenAiApiKey } : {}),
      ...(settings.codex.executablePath ? { executablePath: settings.codex.executablePath } : {}),
    }),
    api,
    createOllamaAdapter({
      baseUrl: settings.ollama.baseUrl,
      ...(settings.ollama.model ? { model: settings.ollama.model } : {}),
    }),
  ];
  const runner = createAiRunner({
    settings,
    adapters,
    log: options.log,
    ...(options.spentThisMonthUsd ? { spentThisMonthUsd: options.spentThisMonthUsd } : {}),
  });

  let classifier: EventClassifier | undefined;
  if (settings.classifier.enabled) {
    // Local and both: a small model on this Mac, so high-volume labelling never
    // leaves it or uses a subscription. Cloud only: the cloud runner, inside its
    // background share.
    const runtime = classifierRuntime();
    const labelRunner =
      settings.mode === 'cloud'
        ? runner
        : createAiRunner({
            settings: { ...settings, order: ['ollama'] },
            adapters: [
              createOllamaAdapter({
                baseUrl: settings.ollama.baseUrl,
                ...(settings.classifier.model
                  ? { model: settings.classifier.model }
                  : {
                      pickModel: (installed) => pickClassifierModel(installed),
                      suggestedModel: recommendedClassifierModel(),
                    }),
                runtime,
              }),
            ],
            log: options.log,
          });
    // An OpenRouter key set up as the API connection can also reach Jev.
    const openRouterKey =
      settings.api.enabled &&
      !settings.pausedByVigil.includes('api') &&
      new URL(settings.api.baseUrl).hostname === 'openrouter.ai' &&
      options.getApiKey
        ? options.getApiKey
        : undefined;
    const useJev =
      settings.jev.enabled &&
      allowedByMode(settings, 'jev') &&
      !settings.pausedByVigil.includes('jev') &&
      (options.getJevApiKey !== undefined || openRouterKey !== undefined);
    const cap = settings.quota.apiKeyMonthlyCapUsd;
    const spent = options.spentThisMonthUsd;
    // Claude Haiku labels first when Claude runs on an API key: on a held-out
    // set it flagged 16 of 16 attacks with 1% of normal events flagged, where
    // the local models flagged 1 to 5 of 16 (packages/bench, #50). Never on a
    // Claude plan, which serves only explanations the user asks for (mayUsePlan).
    // It counts toward the monthly cap, and Jev then the local model take over
    // when it can't answer.
    const haiku =
      settings.claude.enabled &&
      settings.claude.mode === 'apiKey' &&
      options.getAnthropicApiKey !== undefined &&
      allowedByMode(settings, 'claude') &&
      !settings.pausedByVigil.includes('claude')
        ? createAiRunner({
            settings: { ...settings, order: ['claude'] },
            adapters: [
              createClaudeAdapter({
                mode: 'apiKey',
                allowPlan: false,
                pins: options.pins,
                model: CLASSIFIER_CLAUDE_MODEL,
                ...(settings.claude.executablePath
                  ? { executablePath: settings.claude.executablePath }
                  : {}),
                ...(options.getAnthropicApiKey ? { getApiKey: options.getAnthropicApiKey } : {}),
              }),
            ],
            log: options.log,
            quota: runner.quota,
            ...(options.spentThisMonthUsd ? { spentThisMonthUsd: options.spentThisMonthUsd } : {}),
          })
        : undefined;
    classifier = createEventClassifier({
      ...(haiku ? { first: haiku } : {}),
      runner: labelRunner,
      ...(useJev
        ? {
            jev: createJevClient({
              baseUrl: settings.jev.baseUrl,
              model: settings.jev.model,
              getApiKey: options.getJevApiKey ?? (async () => undefined),
              ...(openRouterKey ? { getOpenRouterApiKey: openRouterKey } : {}),
              log: options.log,
            }),
            ...(cap !== undefined && spent
              ? { jevAllowed: async () => (await spent('jev')) < cap }
              : {}),
          }
        : {}),
      maxEventsPerBatch: settings.classifier.maxEventsPerBatch,
      maxBatchesPerHour: settings.classifier.maxBatchesPerHour,
      maxCpuSecondsPerHour: settings.classifier.maxCpuSecondsPerHour,
      cpuThreads: runtime.numThread,
      ...(options.isBusy ? { isBusy: options.isBusy } : {}),
    });
  }

  return Object.assign(runner, {
    ...(classifier ? { classifier } : {}),
    listApiModels: () => api.listModels(),
  });
}
