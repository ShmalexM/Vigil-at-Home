import { isSafeBaseUrl } from './providers/openaiCompatible.js';
import type { AiSettings } from './settings.js';
import { LOCAL_PROVIDERS, type ProviderId } from './types.js';

/**
 * Which keys and connections the user saved, without the keys themselves.
 * `api` is a key for the API connection at `settings.api.baseUrl`.
 */
export interface AiKeysSaved {
  readonly anthropic: boolean;
  readonly openai: boolean;
  readonly api: boolean;
  readonly typesafe: boolean;
}

/** "explain": an alert explanation (the user's plan counts). "label": event labelling. */
export type AiPurpose = 'explain' | 'label';

/** Why a provider wouldn't run: switched off, missing a key or connection, or outside the mode. */
export type AiNotRunning = 'off' | 'needs_setup' | 'not_allowed_by_mode';

export type AiReach =
  | { readonly provider: ProviderId; readonly why?: undefined }
  | { readonly provider?: undefined; readonly why: AiNotRunning };

/** Whether the user's local, cloud or both choice lets this provider run at all. */
export function allowedByMode(settings: AiSettings, id: ProviderId): boolean {
  const local = LOCAL_PROVIDERS.includes(id);
  return settings.mode === 'both' || (settings.mode === 'local') === local;
}

/** The switch, the mode and Vigil's own pause: what the runner checks before any probe. */
export function switchedOn(settings: AiSettings, id: ProviderId): AiNotRunning | undefined {
  if (!settings[id].enabled || settings.pausedByVigil.includes(id)) return 'off';
  return allowedByMode(settings, id) ? undefined : 'not_allowed_by_mode';
}

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname;
  } catch {
    return undefined;
  }
}

/** Claude runs on its own only with an Anthropic API key; the plan takes explanations the user asks for. */
function claudeKey(settings: AiSettings, keys: AiKeysSaved): boolean {
  return settings.claude.mode === 'apiKey' && keys.anthropic;
}

function claudePlan(settings: AiSettings): boolean {
  return settings.claude.allowPlan ?? settings.claude.mode === 'subscription';
}

/**
 * How Jev is reached: its own TypeSafe key, an OpenRouter key set up as the
 * API connection, or both. Undefined when neither is there.
 */
export function jevRoute(
  settings: AiSettings,
  keys: AiKeysSaved,
): { readonly typesafe: boolean; readonly openrouter: boolean } | undefined {
  const openrouter =
    keys.api &&
    switchedOn(settings, 'api') === undefined &&
    hostOf(settings.api.baseUrl) === 'openrouter.ai';
  return keys.typesafe || openrouter ? { typesafe: keys.typesafe, openrouter } : undefined;
}

/**
 * Whether this provider would serve this purpose, from settings and saved
 * keys alone: no network, no probes. A provider that passes can still fail
 * at run time (not installed, not signed in, refused); one that fails here
 * never runs.
 */
export function canRun(
  settings: AiSettings,
  keys: AiKeysSaved,
  id: ProviderId,
  purpose: AiPurpose,
): true | AiNotRunning {
  // Jev only ever picks labels.
  if (id === 'jev' && purpose === 'explain') return 'off';
  if (purpose === 'label' && !settings.classifier.enabled) return 'off';
  const gate = switchedOn(settings, id);
  if (gate) return gate;
  // Labelling runs on this Mac outside cloud mode, and through the cloud
  // runner in it; Claude Haiku and Jev label in both of the modes that allow them.
  if (purpose === 'label' && (id === 'codex' || id === 'api') && settings.mode !== 'cloud')
    return 'not_allowed_by_mode';
  switch (id) {
    case 'claude':
      // Labelling never uses a plan (mayUsePlan): only the key.
      return claudeKey(settings, keys) || (purpose === 'explain' && claudePlan(settings))
        ? true
        : 'needs_setup';
    case 'codex':
      return settings.codex.mode !== 'apiKey' || keys.openai ? true : 'needs_setup';
    case 'api':
      return keys.api && isSafeBaseUrl(settings.api.baseUrl) ? true : 'needs_setup';
    case 'jev':
      return jevRoute(settings, keys) ? true : 'needs_setup';
    case 'ollama':
      return true;
  }
}

/** Every provider that may serve this purpose, in the order Vigil tries them. */
export function candidatesFor(settings: AiSettings, purpose: AiPurpose): ProviderId[] {
  if (purpose === 'explain') return [...settings.order];
  // The event classifier: Claude Haiku first, then Jev, then the cloud
  // runner (cloud mode) or the small model on this Mac.
  const rest = settings.mode === 'cloud' ? settings.order : ['ollama' as const];
  return [...new Set<ProviderId>(['claude', 'jev', ...rest])];
}

/** The most useful reason to show: a missing key, then the mode, then a switch. */
const WHY_RANK: Record<AiNotRunning, number> = {
  needs_setup: 2,
  not_allowed_by_mode: 1,
  off: 0,
};

/**
 * Which provider would run first for this purpose, or why none would. The
 * runner, the classifier and the app's "AI is off" notice all read this, so
 * they can't disagree.
 */
export function whoRuns(settings: AiSettings, keys: AiKeysSaved, purpose: AiPurpose): AiReach {
  if (purpose === 'label' && !settings.classifier.enabled) return { why: 'off' };
  let why: AiNotRunning = 'off';
  for (const id of candidatesFor(settings, purpose)) {
    const r = canRun(settings, keys, id, purpose);
    if (r === true) return { provider: id };
    if (WHY_RANK[r] > WHY_RANK[why]) why = r;
  }
  return { why };
}
