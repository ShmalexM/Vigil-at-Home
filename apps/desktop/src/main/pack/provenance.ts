// Which outside text a Lead dog turn may carry. Provenance travels with the
// text: a dog's report, a job or a memory fact the person didn't type counts
// as someone else's text, and so does a connector's tool title or
// description. A turn is tainted only by what actually goes into its prompt,
// so the Lead dog's prompt leaves such text out unless the person's message
// is about it. The checks are plain word matches, never an AI call, so the
// same message always gets the same answer.

/** Words that ask about what a dog found. */
const REPORT_WORDS =
  /\b(reports?|reported|find|finds|found|findings?|latest|last run|results?|summary|says|said|saw|seen|spotted|flagged|discovered|turned up|came back|what did)\b/i;

/** Words that ask about what a dog is told to do. */
const JOB_WORDS = /\b(jobs?|tasks?|instructions?|what does|what do|doing|purpose|supposed to)\b/i;

/** Words that ask about the memory as a whole. */
const MEMORY_WORDS = /\b(memory|memories|remembered)\b|\bwhat do you (know|remember)\b/i;

/** The only words a short "yes, do it" to the last answer is made of. */
const FOLLOW_UP = new Set(
  "ok okay k yes yeah yep yup y sure fine great perfect good sounds alright right please pls thanks thank you do it that this go ahead for on proceed lets let's make so approve approved confirm confirmed same one agreed".split(
    ' ',
  ),
);

/** Too common to tie a fact to a message. */
const STOP = new Set(
  'that this with from have what when where which about your yours mine they them there their then than been were will would should could into just like also only some more most very much make want know does dont doesn please thanks remember forget prefer prefers always never every each other here those these the and for are was not you can its it’s'.split(
    ' ',
  ),
);

/** The person's message is a short "yes, do it" to the answer before it. */
export function isFollowUp(text: string): boolean {
  const words = text
    .toLowerCase()
    .replace(/[’]/g, "'")
    .split(/[^a-z']+/)
    .filter(Boolean);
  return words.length > 0 && words.length <= 8 && words.every((w) => FOLLOW_UP.has(w));
}

export function asksAboutReports(text: string): boolean {
  return REPORT_WORDS.test(text);
}

export function asksAboutJobs(text: string): boolean {
  return JOB_WORDS.test(text);
}

export function asksAboutMemory(text: string): boolean {
  return MEMORY_WORDS.test(text);
}

/** Whether the message names this dog, as a whole word. */
export function names(text: string, name: string): boolean {
  const n = name.trim().toLowerCase();
  if (!n) return false;
  const esc = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^\\p{L}\\p{N}])${esc}($|[^\\p{L}\\p{N}])`, 'iu').test(text);
}

/** The message and the text share a word that means something (four letters or more). */
export function sharesWords(message: string, text: string): boolean {
  const mine = new Set(keyWords(message));
  return keyWords(text).some((w) => mine.has(w));
}

function keyWords(s: string): string[] {
  return s
    .toLowerCase()
    .split(/[^\p{L}\p{N}]+/u)
    .filter((w) => w.length >= 4 && !STOP.has(w))
    .map((w) => (w.length > 4 && w.endsWith('s') ? w.slice(0, -1) : w));
}
