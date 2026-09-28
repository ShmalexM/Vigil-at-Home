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
import { createOllamaAdapter } from './providers/ollama.js';
import { createApiAdapter, type ApiModel } from './providers/openaiCompatible.js';
import { createAiRunner, type AiRunner } from './runner.js';
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
export { createOllamaAdapter } from './providers/ollama.js';
export {
  createApiAdapter,
  isSafeBaseUrl,
  type ApiAdapterOptions,
  type ApiModel,
} from './providers/openaiCompatible.js';
export {
  CLASSIFIER_MODELS,
  classifierRuntime,
  createEventClassifier,
  eventLine,
  pickClassifierModel,
  recommendedClassifierModel,
  type ClassifyResult,
  type EventClassifier,
  type EventLabel,
  type LabelledEvent,
} from './classifier.js';

export interface VigilAiOptions {
  readonly settings: AiSettings;
  readonly log: PromptLog;
  /** Where the binaries recorded at setup are kept (the app's database). */
  readonly pins: PinStore;
  /** Reads the Anthropic API key from the Keychain. Only used in apiKey mode. */
  readonly getAnthropicApiKey?: () => Promise<string | undefined>;
  /** Reads the key for the OpenAI-style API (OpenRouter, OpenAI...) from the Keychain. */
  readonly getApiKey?: () => Promise<string | undefined>;
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
      pins: options.pins,
      ...(settings.claude.executablePath ? { executablePath: settings.claude.executablePath } : {}),
      ...(options.getAnthropicApiKey ? { getApiKey: options.getAnthropicApiKey } : {}),
    }),
    createCodexAdapter({
      codexHome: settings.codex.codexHome,
      pins: options.pins,
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
                runtime: classifierRuntime(),
              }),
            ],
            log: options.log,
          });
    classifier = createEventClassifier({
      runner: labelRunner,
      maxEventsPerBatch: settings.classifier.maxEventsPerBatch,
      maxBatchesPerHour: settings.classifier.maxBatchesPerHour,
      ...(options.isBusy ? { isBusy: options.isBusy } : {}),
    });
  }

  return Object.assign(runner, {
    ...(classifier ? { classifier } : {}),
    listApiModels: () => api.listModels(),
  });
}
