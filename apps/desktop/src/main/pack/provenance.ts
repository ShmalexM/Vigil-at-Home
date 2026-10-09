// Plain string checks for the Lead dog's two paths (docs/pack.md, "Who sees
// outside text"). None of them reads a model's output or outside text, and
// none can make a change go ahead that would otherwise wait:
//
// - `asksToRead` only routes a message to the reading path, which has no way
//   to change anything.
// - `leansOn` only turns a change into a card.
// - `typedNames` and `typedKeys` map what the person typed to a dog's id or a
//   tool's id, by exact match, so the acting path can name them without
//   seeing their text.
// - `namesFact` is the one check that lets a change through: a memory
//   `replaces` goes ahead without a card only when the person's own message
//   names the fact it replaces, word for word.

/** Pointers the acting path is given in place of outside text. */
export const REFERENCE = /\b(answer-\d+|report:[a-z0-9-]+|job:[a-z0-9-]+|memory:[A-Za-z0-9-]+)\b/;

/** Questions about what a dog found, or what the pack remembers. Routing only. */
const READ_WORDS = [
  /\bwhat (did|does|has|have|had)\b.{0,60}\b(find|found|report|reported|say|said|see|saw|flag|flagged|spot|spotted|turn up|come back with)\b/i,
  /\b(reports?|findings?|results?|last run|latest run)\b/i,
  /\bwhat do you (know|remember)\b|\b(your|the pack'?s?) memory\b/i,
];

/** Words that defer to someone else's text: "do what Pip suggested". */
const DEFER = [
  /\b(suggest\w*|recommend\w*|advice|advis\w*|propos\w*|said|says|told)\b/i,
  /\b(do|follow|carry out|apply|implement|act on|go with|go ahead with)\b.{0,24}\b(it|that|this|those|these|them|what|its|their|the (report|plan|idea|finding|findings|result|results|answer|fix|steps?))\b/i,
];

/** The only words a short "yes, do it" to the last answer is made of. */
const FOLLOW_UP = new Set(
  "ok okay k yes yeah yep yup y sure fine great perfect good sounds alright right please pls thanks thank you do it that this go ahead for on proceed lets let's make so approve approved confirm confirmed same one agreed".split(
    ' ',
  ),
);

/** The message asks about a report, a finding or the memory. Only routes it to the reading path. */
export function asksToRead(text: string): boolean {
  return READ_WORDS.some((r) => r.test(text));
}

/** The person's message is a short "yes, do it" to the answer before it. */
export function isFollowUp(text: string): boolean {
  const words = text
    .toLowerCase()
    .replace(/[’]/g, "'")
    .split(/[^a-z']+/)
    .filter(Boolean);
  return words.length > 0 && words.length <= 8 && words.every((w) => FOLLOW_UP.has(w));
}

/**
 * The message leans on text the acting path never saw: it names a reference,
 * defers to what someone suggested or said, or is a short "yes" right after
 * an answer that read outside text. Only ever turns changes into cards.
 */
export function leansOn(text: string, afterOutsideText: boolean): boolean {
  if (REFERENCE.test(text)) return true;
  if (DEFER.some((r) => r.test(text))) return true;
  return afterOutsideText && isFollowUp(text);
}

/** Whether any of these strings holds a reference. */
export function citesReference(values: readonly string[]): boolean {
  return values.some((v) => REFERENCE.test(v));
}

/**
 * The names the person typed, each as they typed it: a whole name, ignoring
 * case, between non-letters. The whole name has to be there, so typing part
 * of a longer name matches nothing.
 */
export function typedNames(
  text: string,
  dogs: readonly { id: string; name: string }[],
): { typed: string; dogId: string }[] {
  const out: { typed: string; dogId: string }[] = [];
  for (const d of dogs) {
    const n = d.name.trim();
    if (!n) continue;
    const m = new RegExp(`(?:^|[^\\p{L}\\p{N}])(${escape(n)})(?=$|[^\\p{L}\\p{N}])`, 'iu').exec(
      text,
    );
    if (m?.[1]) out.push({ typed: m[1], dogId: d.id });
  }
  return out;
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
