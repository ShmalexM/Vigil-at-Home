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
  if (typeof value === 'string') return redactTextForPack(value);
  try {
    return JSON.stringify(redactForPack(value)) ?? '';
  } catch {
    return WITHHELD_TEXT;
  }
}
