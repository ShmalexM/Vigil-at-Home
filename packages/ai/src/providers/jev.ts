import { randomUUID } from 'node:crypto';
import type { PromptLog } from '../types.js';
import { isSafeBaseUrl } from './openaiCompatible.js';

/**
 * TypeSafe's Jev, a "System One" model that answers typed questions about some
 * state with calibrated probabilities instead of generated text. It only runs
 * in TypeSafe's cloud (POST /v1/systemone); there are no weights to run
 * locally. Vigil uses it for one job: labelling events its rules didn't
 * explain. It gets no tools and can't act; it only returns probabilities.
 */
export const JEV_DEFAULT_BASE_URL = 'https://api.typesafe.ai/v1';
export const JEV_DEFAULT_MODEL = 'jev-latest';
/** Input tokens only; TypeSafe doesn't charge for output (docs, 2026-09-28). */
export const JEV_USD_PER_INPUT_TOKEN = 0.042 / 1_000_000;

export const JEV_LABELS = {
  benign: 'Normal activity for a personal Mac: known apps, system services, developer tools.',
  unusual:
    'Not clearly bad, but a careful person would want to glance at it: rare locations, new startup items, unfamiliar hosts.',
  suspicious:
    'Looks like malware or an attacker: hidden or unsigned programs in odd places, reading browser or keychain data, persistence, strange connections.',
} as const;

export type JevLabel = keyof typeof JEV_LABELS;

export interface JevOptions {
  readonly baseUrl?: string;
  readonly model?: string;
  /** Reads the TypeSafe key from the Keychain for each call. Vigil keeps no copy. */
  readonly getApiKey: () => Promise<string | undefined>;
  readonly log: PromptLog;
  readonly fetch?: typeof fetch;
  readonly timeoutMs?: number;
}

export interface JevAnswer {
  readonly id: string;
  readonly label: JevLabel;
  readonly probabilities: Readonly<Record<JevLabel, number>>;
  readonly confidence: number;
}

export type JevResult =
  | { readonly ok: true; readonly answers: JevAnswer[] }
  | { readonly ok: false; readonly detail: string };

interface ChoiceAnswer {
  type?: string;
  choice?: string;
  probabilities?: Record<string, number>;
  confidence?: number;
}

interface SystemOneResponse {
  model?: string;
  answers?: Record<string, ChoiceAnswer>;
  usage?: { input_tokens?: number; output_tokens?: number };
}

const INSTRUCTIONS =
  "The state lists events from one person's Mac that Vigil's security rules did not match, keyed by event key. " +
  'How should Vigil treat the event with key %KEY%?';

export function createJevClient(options: JevOptions) {
  const baseUrl = (options.baseUrl ?? JEV_DEFAULT_BASE_URL).replace(/\/+$/, '');
  const model = options.model ?? JEV_DEFAULT_MODEL;
  const doFetch = options.fetch ?? fetch;

  return {
    /** Labels one batch: one Choice question per event, all asked of the same state in one call. */
    async label(events: ReadonlyArray<{ id: string; line: string }>): Promise<JevResult> {
      if (!isSafeBaseUrl(baseUrl))
        return { ok: false, detail: 'The TypeSafe address must use https.' };
      const key = await options.getApiKey();
      if (!key) return { ok: false, detail: 'Add a TypeSafe API key.' };

      // Keys are Vigil's own (e1, e2...), so an event id never becomes part of the request shape.
      const keyOf = new Map(events.map((e, i) => [`e${i + 1}`, e.id]));
      const state = Object.fromEntries(events.map((e, i) => [`e${i + 1}`, e.line]));
      const questions = Object.fromEntries(
        [...keyOf.keys()].map((k) => [
          k,
          { type: 'choice', instructions: INSTRUCTIONS.replace('%KEY%', k), criteria: JEV_LABELS },
        ]),
      );
      const body = JSON.stringify({ model, state, questions });

      const started = Date.now();
      let outcome: 'ok' | 'quota' | 'timeout' | 'error' | 'invalid_output' = 'error';
      let detail: string | undefined;
      let usage: SystemOneResponse['usage'];
      try {
        const res = await doFetch(`${baseUrl}/systemone`, {
          method: 'POST',
          headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
          body,
          signal: AbortSignal.timeout(options.timeoutMs ?? 15_000),
        });
        if (!res.ok) {
          outcome = res.status === 429 || res.status === 529 ? 'quota' : 'error';
          detail =
            res.status === 401 || res.status === 403
              ? 'TypeSafe refused the API key.'
              : `TypeSafe answered ${res.status}.`;
          return { ok: false, detail };
        }
        const json = (await res.json()) as SystemOneResponse;
        usage = json.usage;
        const answers: JevAnswer[] = [];
        for (const [k, id] of keyOf) {
          const a = json.answers?.[k];
          if (!a || !isLabel(a.choice)) continue;
          const p = a.probabilities ?? {};
          answers.push({
            id,
            label: a.choice,
            probabilities: {
              benign: num(p.benign),
              unusual: num(p.unusual),
              suspicious: num(p.suspicious),
            },
            confidence: num(a.confidence),
          });
        }
        outcome = answers.length > 0 || events.length === 0 ? 'ok' : 'invalid_output';
        if (outcome !== 'ok') detail = 'TypeSafe returned no usable answers.';
        return outcome === 'ok' ? { ok: true, answers } : { ok: false, detail: detail! };
      } catch (err) {
        outcome = err instanceof Error && err.name === 'TimeoutError' ? 'timeout' : 'error';
        detail = outcome === 'timeout' ? 'TypeSafe took too long.' : 'Could not reach TypeSafe.';
        return { ok: false, detail };
      } finally {
        // Same prompt log as every other AI call, so the activity feed shows what left the Mac.
        const input = usage?.input_tokens ?? 0;
        options.log.record({
          id: randomUUID(),
          at: started,
          purpose: 'classify',
          urgency: 'background',
          provider: 'jev',
          systemPrompt: INSTRUCTIONS,
          userPrompt: JSON.stringify(state),
          outcome,
          ...(detail ? { detail } : {}),
          ...(usage
            ? {
                usage: {
                  inputTokens: input,
                  cachedInputTokens: 0,
                  outputTokens: usage.output_tokens ?? 0,
                  costUsd: input * JEV_USD_PER_INPUT_TOKEN,
                },
              }
            : {}),
        });
      }
    },
  };
}

export type JevClient = ReturnType<typeof createJevClient>;

function isLabel(x: unknown): x is JevLabel {
  return typeof x === 'string' && Object.hasOwn(JEV_LABELS, x);
}

function num(x: unknown): number {
  return typeof x === 'number' && Number.isFinite(x) ? Math.min(1, Math.max(0, x)) : 0;
}
