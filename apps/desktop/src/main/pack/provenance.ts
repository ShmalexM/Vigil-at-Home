// Provenance for the Lead dog and pack jobs, in two parts.
//
// What goes into a prompt: the word checks here (a report word, a job word,
// a short "yes, do it") only choose which outside text a prompt carries.
// They never decide taint. The prompt builders in service.ts count a prompt
// as tainted when anything they put in it is, item by item.
//
// Where an action's arguments came from: `typed` and `asksTo` check a
// proposed change against the person's own message for the turn, so a change
// they spelled out stays theirs even when the prompt carried outside text.
// All plain string checks, never an AI call, so the same message always gets
// the same answer.

/** Words that ask about what a named dog found. */
const REPORT_WORDS =
  /\b(reports?|reported|find|finds|found|findings?|latest|last run|results?|summary|says|said|saw|seen|spotted|flagged|discovered|turned up|came back|what did)\b/i;

/**
 * Words that ask about what the dogs found without naming one. Narrower than
 * REPORT_WORDS: "find" alone is too often a job ("a dog to find duplicates").
 */
const ANY_REPORT_WORDS =
  /\b(reports?|reported|findings?|latest|last run|results?|summary|what did|what have|what has)\b/i;

/** Words that point back at the answer before. */
const BACK_WORDS =
  /\b(it|that|this|those|these|them|your|recommend\w*|suggest\w*|said|above|previous|earlier|again|same|plan|idea|proposal|proposed)\b/i;

/** Words that ask to send a dog off, retire one, or forget a fact. */
const VERBS = {
  run: /\b(run|start|send|launch|kick off)\b/i,
  retire: /\b(retire|delete|remove|stop|fire|dismiss|get rid of)\b/i,
  forget: /\b(forget|delete|remove|drop|wrong|cross out|no longer|not true)\b/i,
};

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

/**
 * The newest message may lean on the answer before it: a short message, a
 * "yes, do it", or one that points back ("your recommendation", "that").
 * Only chooses whether that answer goes into the prompt.
 */
export function refersBack(text: string): boolean {
  const words = text.split(/\s+/).filter(Boolean);
  return isFollowUp(text) || words.length <= 6 || BACK_WORDS.test(text);
}

/** `named`: the message names the dog the report is from. */
export function asksAboutReports(text: string, named = true): boolean {
  return (named ? REPORT_WORDS : ANY_REPORT_WORDS).test(text);
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

/**
 * The value appears in the person's message, ignoring case, spacing and a
 * trailing full stop: so it is their text, not someone else's.
 */
export function typed(message: string, value: string): boolean {
  const v = norm(value);
  return v.length > 0 && norm(message).includes(v);
}

/** The message asks for this kind of change in so many words. */
export function asksTo(message: string, kind: keyof typeof VERBS): boolean {
  return VERBS[kind].test(message);
}

function norm(s: string): string {
  return s
    .toLowerCase()
    .replace(/[‘’]/g, "'")
    .replace(/[“”]/g, '"')
    .replace(/\s+/g, ' ')
    .trim()
    .replace(/[.!?]+$/, '')
    .trim();
}

/**
 * A connector tool name plain enough to show a model as it is: lower case,
 * up to three words joined by underscores, 32 characters at most. Servers
 * choose their tools' names; anything else is shown by a Vigil-made id.
 */
export function plainToolName(name: string): boolean {
  return name.length <= 32 && /^[a-z][a-z0-9]*(?:_[a-z0-9]+){0,2}$/.test(name);
}
