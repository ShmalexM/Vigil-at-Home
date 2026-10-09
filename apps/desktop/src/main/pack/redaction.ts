import { localNames, redactValue, WITHHELD } from '@vigil/ai/redact';

/** What a value becomes when it can't be redacted: the redactor's own marker. */
export const WITHHELD_TEXT = WITHHELD;

let names: ReturnType<typeof localNames> | undefined;

/**
 * The pack's one call into Vigil's redactor (@vigil/ai/redact): the notebook,
 * the connector hub and the tool gate all go through it, and nothing here
 * redacts on its own. A string is redacted as one field. An object or array
 * is redacted as data, before it is ever written out as text, so a value
 * under a credential-named key goes whatever it looks like. This Mac's user
 * and host names are hidden too. Callers cut the result to size only after
 * this; a field too long to read is withheld whole by the redactor.
 */
export function redactForPack(value: unknown): unknown {
  try {
    names ??= localNames();
    return redactValue(value, names);
  } catch {
    // A value that throws when read: none of it is kept.
    return WITHHELD_TEXT;
  }
}

/** redactForPack for one text field. */
export function redactTextForPack(text: string): string {
  const out = redactForPack(text);
  return typeof out === 'string' ? out : WITHHELD_TEXT;
}

/** Data as JSON text, redacted as data first. Text stays text. */
export function redactDataForPack(value: unknown): string {
  if (typeof value === 'string') return redactJsonText(value);
  try {
    return JSON.stringify(redactDeep(value)) ?? '';
  } catch {
    return WITHHELD_TEXT;
  }
}

const MAX_DEPTH = 32;

/**
 * redactForPack, keys included. The shared redactor keeps an object's keys
 * as they are, so each key is redacted here as one field too, and a string
 * that is itself JSON (a tool's result, stored as text) is read as data the
 * same way rather than as one opaque field.
 */
export function redactDeep(value: unknown, depth = 0): unknown {
  return withKeys(redactForPack(value), depth);
}

function withKeys(value: unknown, depth: number): unknown {
  if (typeof value === 'string') return redactJsonText(value, depth);
  if (!value || typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH) return WITHHELD_TEXT;
  if (Array.isArray(value)) return value.map((v) => withKeys(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [key, v] of Object.entries(value)) {
    let name = redactTextForPack(key);
    for (let n = 2; Object.hasOwn(out, name); n++) name = `${redactTextForPack(key)} (${n})`;
    // defineProperty, so a key named __proto__ stays a key.
    Object.defineProperty(out, name, {
      value: withKeys(v, depth + 1),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/** Text that is a JSON object or array is redacted as data, keys included; other text as one field. */
export function redactJsonText(text: string, depth = 0): string {
  const t = text.trim();
  if ((t.startsWith('{') || t.startsWith('[')) && depth < MAX_DEPTH) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(t);
    } catch {
      parsed = undefined;
    }
    if (parsed && typeof parsed === 'object') return JSON.stringify(redactDeep(parsed, depth + 1));
  }
  return redactTextForPack(text);
}

/**
 * The text that is stored or handed out for one value: redacted as data,
 * keys included, then the whole serialized text through the redactor. Where
 * that last pass changes something and the result is no longer JSON, the
 * same check runs one level down, so only the part it objects to becomes
 * WITHHELD_TEXT and the rest stays readable.
 */
export function redactSerialized(value: unknown, space?: number): string {
  return JSON.stringify(settle(redactDeep(value), 0), null, space) ?? 'null';
}

function settle(value: unknown, depth: number): unknown {
  const text = JSON.stringify(value);
  if (text === undefined) return value;
  const whole = redactTextForPack(text);
  if (whole === text) return value;
  try {
    return JSON.parse(whole) as unknown;
  } catch {
    // Not JSON any more: find the part it objects to.
  }
  if (!value || typeof value !== 'object' || depth >= MAX_DEPTH) return WITHHELD_TEXT;
  if (Array.isArray(value)) return value.map((v) => settle(v, depth + 1));
  return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, settle(v, depth + 1)]));
}

/**
 * Rendered Markdown, redacted as a whole. When the whole would be withheld,
 * each line is redacted on its own instead, so one bad line doesn't blank
 * the export; a line that is JSON is read as data, keys included.
 */
export function redactMarkdown(text: string): string {
  const whole = redactTextForPack(text);
  if (whole !== WITHHELD_TEXT) return whole;
  return text
    .split('\n')
    .map((line) => {
      // A heading or list marker stays, so a withheld line keeps its place.
      const [, lead = '', rest = ''] = /^(\s*(?:#{1,6} |[-*] |\d+\. )?)([\s\S]*)$/.exec(line) ?? [];
      return rest ? lead + redactJsonText(rest) : line;
    })
    .join('\n');
}
