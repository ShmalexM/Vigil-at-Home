import { redactValue } from '@vigil/ai/redact';

/** What a value becomes when the redactor itself fails on it. */
export const WITHHELD_TEXT = '[withheld: may contain a secret]';

/**
 * The longest string handed to the redactor in one piece. The redactor slows
 * sharply on a very long unbroken word, so a longer string is first cut back
 * (see cutBefore). Callers keep far less than this, cut after redaction.
 */
export const REDACT_LIMIT = 64_000;

/**
 * The pack's one call into Vigil's redactor (@vigil/ai/redact): the notebook
 * and the connector hub both go through it, and nothing here redacts on its
 * own. A string is redacted as one field. An object or array is redacted as
 * data, before it is ever written out as text, so the redactor sees each
 * value under its key. Callers cut the result to size only after this.
 */
export function redactForPack(value: unknown, limit = REDACT_LIMIT): unknown {
  try {
    return redactValue(bounded(value, limit, 0), {});
  } catch {
    // A cycle, or a value that throws when read: none of it is kept.
    return WITHHELD_TEXT;
  }
}

/** redactForPack for one text field. */
export function redactTextForPack(text: string, limit = REDACT_LIMIT): string {
  const out = redactForPack(text, limit);
  return typeof out === 'string' ? out : WITHHELD_TEXT;
}

/** Data as JSON text, redacted as data first. Text stays text. */
export function redactDataForPack(value: unknown, limit = REDACT_LIMIT): string {
  if (typeof value === 'string') return redactTextForPack(value, limit);
  try {
    return JSON.stringify(redactForPack(value, limit)) ?? '';
  } catch {
    return WITHHELD_TEXT;
  }
}

/** Every string in a value kept within `limit`. Deeper than this is left to the redactor. */
function bounded(value: unknown, limit: number, depth: number): unknown {
  if (typeof value === 'string') return value.length > limit ? cutBefore(value, limit) : value;
  if (depth > 32 || !value || typeof value !== 'object') return value;
  if (Array.isArray(value)) return value.map((v) => bounded(v, limit, depth + 1));
  return Object.fromEntries(
    Object.entries(value).map(([k, v]) => [k, bounded(v, limit, depth + 1)]),
  );
}

/**
 * The text before `limit`, back to the last space or line break, so the word
 * the cut fell in goes whole and no piece of a cut-off secret is left at the
 * edge. A private key block the cut leaves open goes too.
 */
export function cutBefore(text: string, limit: number): string {
  let kept = text.slice(0, limit + 1);
  const space = kept.search(/\s\S*$/);
  kept = space > 0 ? kept.slice(0, space) : '';
  const begin = kept.lastIndexOf('-----BEGIN');
  if (begin >= 0 && !kept.includes('-----END', begin)) kept = kept.slice(0, begin);
  return `${kept}…`;
}
