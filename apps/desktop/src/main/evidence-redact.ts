import { redactString } from '@vigil/ai/redact';

/**
 * Redaction for copied evidence. Command lines get no piecemeal redaction:
 * secrets hide in them in too many shapes (`mysql -phunter2`, quoted
 * `PGPASSWORD=…`, a value after `;` or a newline) for a pattern to cut out
 * the secret and nothing else. A command-line field that might hold one is
 * withheld whole, and otherwise only this computer's user and host names are
 * replaced. Every other string goes through the shared redaction
 * (@vigil/ai/redact) after the same name pass.
 *
 * This is a best-effort safety net, not a guarantee. A secret written so no
 * pattern can see it gets through: split by quotes (`PGPASS""WORD=…`),
 * percent-encoded (`%74%6f%6b%65%6e=`), or decoded at run time
 * (`$(… | base64 -d)`). The app asks the user to review the copy before
 * sharing it.
 */
export interface EvidenceNames {
  /** This computer's short user name, hidden at any length. */
  username?: string | undefined;
  /** Its host name, hidden with and without `.local`. */
  hostname?: string | undefined;
}

export const WITHHELD = '[withheld: may contain a secret]';

/**
 * The fields that carry a command line, by key, wherever they appear:
 * - lists: a process's argv (`args`) and a persistence item's `programArgs`;
 * - strings: a tool request's `command`, a persistence item's `program` (a
 *   cron job's whole command line), and the alert text rules fill from
 *   commands: `title`, `summary`, a subject's `label`, an AI read's
 *   `details`, an action's `reason` and a proposal's `rationale`;
 * - URLs (`url`, `originUrl`), which can carry `user:password@`, and are
 *   withheld if they hold a newline or other control character.
 */
const COMMAND_LISTS = new Set(['args', 'programArgs']);
const COMMAND_STRINGS = new Set([
  'command',
  'commandLine',
  'program',
  'title',
  'summary',
  'label',
  'details',
  'reason',
  'rationale',
]);
const URL_FIELDS = new Set(['url', 'originUrl']);

/**
 * Anything that might be a secret, matched anywhere: no word boundaries and
 * any case, so it over-withholds (`PWD=`, "author") rather than miss one.
 * The value shapes follow @vigil/ai/redact's SECRET_PATTERNS, loosened.
 */
const SECRET_HINTS: readonly RegExp[] = [
  /pass|pwd|secret|token|api_key|apikey|api-key|auth|credential|--key/i,
  /sshpass/i,
  /-----BEGIN/i,
  /AKIA[0-9A-Z]{16}/i,
  /gh[pousr]_|github_pat_/i,
  /sk-[A-Za-z0-9_-]{8,}/i,
  /xox[abprs]-/i,
  /eyJ[A-Za-z0-9_-]+\./i,
  /\b(?:bearer|basic)\s+\S/i,
  /:\/\/[^\s/]*@/, // URL user info
];

/** Whether a command line might hold a secret. */
function mightHoldSecret(text: string): boolean {
  if (SECRET_HINTS.some((p) => p.test(text))) return true;
  if (/mysql|mariadb/i.test(text) && /-p/i.test(text)) return true;
  if (/redis-cli/i.test(text) && /-a/i.test(text)) return true;
  if (/curl/i.test(text) && /\s-[a-z]*[uK]|--user|--config/.test(text)) return true;
  if (/unzip/i.test(text) && /-P/.test(text)) return true;
  if (/7z|7za|rar/i.test(text) && /-p\S/.test(text)) return true;
  return false;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * This computer's names as whole tokens: any character other than a letter
 * or digit ends one, so `al_backup`, `my-pc` and `<al;` give the name away
 * and `alpha` doesn't. One pass, and only the name's own characters change.
 */
function redactNames(text: string, names: EvidenceNames): string {
  const host = names.hostname?.replace(/\.local$/i, '');
  const words = [host && `${host}.local`, host, names.username].filter((w): w is string => !!w);
  if (words.length === 0) return text;
  const pattern = new RegExp(
    `(?<![A-Za-z0-9])(?:${words.map(escapeRegExp).join('|')})(?![A-Za-z0-9])`,
    'gi',
  );
  return text.replace(pattern, (match) =>
    names.username && match.toLowerCase() === names.username.toLowerCase() ? '<user>' : '<host>',
  );
}

/** A command string: withheld whole, or the same apart from the names. */
function commandString(text: string, names: EvidenceNames): string {
  return mightHoldSecret(text) ? WITHHELD : redactNames(text, names);
}

/** An argv list: withheld whole (one marker) if any arg, or the args together, might hold a secret. */
function commandList(args: string[], names: EvidenceNames): string[] {
  if (args.some(mightHoldSecret) || mightHoldSecret(args.join(' '))) return [WITHHELD];
  return args.map((a) => redactNames(a, names));
}

/** Any other string: the names, then the shared redaction. */
function freeText(text: string, names: EvidenceNames): string {
  return redactString(redactNames(text, names), {
    ...(names.username ? { username: names.username } : {}),
    ...(names.hostname ? { hostname: names.hostname } : {}),
  });
}

/** A URL: like a command string, and withheld if it holds a newline or control character. */
function urlString(text: string, names: EvidenceNames): string {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f]/.test(text) ? WITHHELD : commandString(text, names);
}

/** What one pass withheld: the command strings and argv lists, as they were. */
type Withheld = string[];

function walk(value: unknown, names: EvidenceNames, withheld: Withheld, key?: string): unknown {
  if (typeof value === 'string') {
    if (key === undefined) return freeText(value, names);
    const out = URL_FIELDS.has(key)
      ? urlString(value, names)
      : COMMAND_STRINGS.has(key)
        ? commandString(value, names)
        : freeText(value, names);
    if (out === WITHHELD) withheld.push(value);
    return out;
  }
  if (Array.isArray(value)) {
    if (key !== undefined && COMMAND_LISTS.has(key) && value.every((v) => typeof v === 'string')) {
      const out = commandList(value as string[], names);
      if (out[0] === WITHHELD) withheld.push(...(value as string[]));
      return out;
    }
    return value.map((v) => walk(v, names, withheld));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, item] of Object.entries(value)) out[k] = walk(item, names, withheld, k);
    return out;
  }
  return value;
}

/** Whether a line of alert text repeats something withheld: a whole command, or one of its args. */
function carries(text: unknown, withheld: Withheld): boolean {
  return typeof text === 'string' && withheld.some((w) => w.length >= 4 && text.includes(w));
}

/**
 * Evidence ready to copy. Keys are kept. When any command line in it was
 * withheld, so is the alert's summary, which rules fill from the command,
 * and its title and subject when they repeat the command or one of its args.
 */
export function redactEvidence(value: unknown, names: EvidenceNames): unknown {
  const withheld: Withheld = [];
  const out = walk(value, names, withheld);
  const alert = isRecord(value) && isRecord(value['alert']) ? value['alert'] : undefined;
  const copied = isRecord(out) && isRecord(out['alert']) ? out['alert'] : undefined;
  if (withheld.length > 0 && alert && copied) {
    if (copied['summary'] !== undefined) copied['summary'] = WITHHELD;
    if (carries(alert['title'], withheld)) copied['title'] = WITHHELD;
    const subject = alert['subject'];
    const copiedSubject = copied['subject'];
    if (isRecord(subject) && isRecord(copiedSubject) && carries(subject['label'], withheld)) {
      copiedSubject['label'] = WITHHELD;
    }
  }
  return out;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
