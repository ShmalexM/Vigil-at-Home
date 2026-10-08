// Plain string checks for the Lead dog's two paths (docs/pack.md, "Who sees
// outside text"). None of them reads a model's output or outside text, and
// none can make a change go ahead that would otherwise wait. No word in the
// person's message routes a turn: only the acting path's own request for a
// read sends it down the reading path.
//
// - `citesReference` only turns a change into a card: the person's message,
//   or what the acting path wrote, names a reference to outside text.
// - `typedNames` and `typedKeys` map what the person typed to a dog's id or a
//   tool's id, by exact match, so the acting path can name them without
//   seeing their text, and a change to a dog the person did not name waits.
// - `namesFact` is the one check that lets a change through: a memory
//   `replaces` goes ahead without a card only when the person's own message
//   names the fact it replaces, word for word.

/** Pointers the acting path is given in place of outside text. */
export const REFERENCE = /\b(answer-\d+|report:[a-z0-9-]+|job:[a-z0-9-]+|memory:[A-Za-z0-9-]+)\b/;

/** Whether any of these strings holds a reference. */
export function citesReference(values: readonly string[]): boolean {
  return values.some((v) => REFERENCE.test(v));
}

/**
 * The names the person typed, each as they typed it: a whole name, ignoring
 * case, between non-letters. The whole name has to be there, so typing part
 * of a longer name matches nothing. Longer names are matched first, and a
 * name that only appears inside a longer name already matched there does not
 * count: with dogs "Pip" and "Pip Two", "Retire Pip Two" names Pip Two only.
 */
export function typedNames(
  text: string,
  dogs: readonly { id: string; name: string }[],
): { typed: string; dogId: string }[] {
  const order = dogs
    .map((d, i) => ({ id: d.id, name: d.name.trim(), i }))
    .filter((d) => d.name)
    .sort((a, b) => b.name.length - a.name.length || a.i - b.i);
  const taken: { start: number; end: number; length: number }[] = [];
  const found: { typed: string; dogId: string; i: number }[] = [];
  for (const d of order) {
    const r = new RegExp(`(?<=^|[^\\p{L}\\p{N}])${escape(d.name)}(?=$|[^\\p{L}\\p{N}])`, 'giu');
    // Two dogs with the same name both match; resolveDog then picks neither.
    const longer = taken.filter((t) => t.length > d.name.length);
    for (const m of text.matchAll(r)) {
      const start = m.index;
      const end = start + m[0].length;
      if (longer.some((t) => start < t.end && end > t.start)) continue;
      taken.push({ start, end, length: d.name.length });
      found.push({ typed: m[0], dogId: d.id, i: d.i });
      break;
    }
  }
  return found.sort((a, b) => a.i - b.i).map(({ typed, dogId }) => ({ typed, dogId }));
}

/**
 * Tool keys the person typed, exactly: same case, and not part of a longer
 * key (`github.create_issue_preview` does not contain `github.create_issue`).
 * A full stop right after a key ends the sentence, not the key.
 */
export function typedKeys(text: string, keys: readonly string[]): string[] {
  return [...new Set(keys)].filter((k) => {
    const r = new RegExp(`(?:^|[^A-Za-z0-9_.-])${escape(k)}(?=$|[^A-Za-z0-9_.-]|\\.(?:$|\\s))`);
    return r.test(text);
  });
}

/**
 * The person's message names this fact word for word (case and runs of
 * spaces aside, and a full stop at its end), between non-letters.
 */
export function namesFact(text: string, fact: string): boolean {
  const f = fact
    .trim()
    .replace(/[.!?]+$/, '')
    .replace(/\s+/g, ' ');
  if (f.length < 3) return false;
  const t = text.replace(/\s+/g, ' ');
  return new RegExp(`(?:^|[^\\p{L}\\p{N}])${escape(f)}(?=$|[^\\p{L}\\p{N}])`, 'iu').test(t);
}

/** The message and the text share a word that means something (four letters or more). */
export function sharesWords(message: string, text: string): boolean {
  const mine = new Set(keyWords(message));
  return keyWords(text).some((w) => mine.has(w));
}

/** Too common to tie a fact to a dog's job. */
const STOP = new Set(
  'that this with from have what when where which about your yours mine they them there their then than been were will would should could into just like also only some more most very much make want know does dont doesn please thanks remember forget prefer prefers always never every each other here those these the and for are was not you can its it’s'.split(
    ' ',
  ),
);

function keyWords(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((w) => w.length >= 4 && !STOP.has(w))
    .map((w) => (w.length > 4 && w.endsWith('s') ? w.slice(0, -1) : w));
}

function escape(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
