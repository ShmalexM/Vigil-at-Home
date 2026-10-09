import {
  redactArgv,
  redactField,
  REDACTED as SHARED_REDACTED,
  WITHHELD as SHARED_WITHHELD,
} from '@vigil/ai/redact';

/**
 * Redaction for copied evidence. Command lines get no piecemeal redaction:
 * secrets hide in them in too many shapes (`mysql -phunter2`, quoted
 * `PGPASSWORD=…`, a value after `;` or a newline) for a pattern to cut out
 * the secret and nothing else. A command-line field that might hold one is
 * withheld whole, and otherwise only this computer's user and host names are
 * replaced. Every other string, a decision note or an error included, is
 * treated the same way, since any of them can quote a command. Only titles
 * are rule text and skip the scan. The
 * shared redaction (@vigil/ai/redact) only adds to the scan: a string it
 * finds a secret in, or would cut a secret out of, is withheld too (see
 * `sharedFindsSecret`). Its output is never copied, since its home-path rule can eat text after a path
 * (`/Users/al;curl` loses `;curl`), and it is given no names, so a user or
 * host name alone never makes it withhold anything.
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
 * Every string is read as a possible command line, since a note, an error or
 * a summary can quote one as easily as `args` can. Argv lists (a process's
 * `args`, a persistence item's `programArgs`) are withheld as one list. URLs
 * (`url`, `originUrl`) can carry `user:password@` and are also withheld when
 * they hold a newline or other control character. Titles are rule text: they
 * are not scanned (a rule titled "Credentials file read" stays readable) and
 * are withheld only when they repeat a withheld command (see
 * `redactEvidence`). Subject labels are names that whoever made the thing
 * chose (a file's name, a launchd label), so they are scanned like any other
 * string, and withheld as well when they repeat a withheld command or the
 * last part of a withheld path.
 */
const COMMAND_LISTS = new Set(['args', 'programArgs']);
const URL_FIELDS = new Set(['url', 'originUrl']);
/** Rule text: only the names change, unless it repeats a withheld command. */
const FIXED_TEXT = new Set(['title']);
/** Text withheld when it repeats a withheld command: rule text and subject labels. */
const REPEATS = new Set(['title', 'label']);

/** A name that may label a secret, as in `PGPASSWORD`, `api_key` or `x-auth`. */
const SECRET_NAME =
  '[A-Za-z0-9_.-]*(?:(?:pass|pwd|secret|token|key|cred)[A-Za-z0-9_.-]*|auth(?:oriz[a-z]*|entic[a-z]*)?(?![A-Za-z])[A-Za-z0-9_.-]*)';

/**
 * What a secret looks like in a command line: an assignment or flag whose
 * name says so, a tool's own password flag, or a value shaped like a known
 * kind of key. Plain words and paths (`cat /etc/passwd`, `ls /opt/compass`)
 * pass, since a name only counts when a value is given to it, and `auth`
 * counts only as its own word (`x-auth`, `authorization`, not `--author`).
 * Any value counts, whatever its first character (`PASSWORD=:x`, `--password -x`). The value
 * shapes follow @vigil/ai/redact's SECRET_PATTERNS, loosened.
 */
const SECRET_HINTS: readonly RegExp[] = [
  // NAME=value or NAME: value, also inside quotes, `$(…)` or a URL query.
  new RegExp(`(?:^|[^A-Za-z0-9_])${SECRET_NAME}\\s*[=:]\\s*\\S`, 'i'),
  // --password hunter2, -pass x, --token=x (the = form is caught above).
  new RegExp(`(?:^|\\s)--?${SECRET_NAME}\\s+\\S`, 'i'),
  /\bpass:\S/i,
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

/**
 * Whether the shared redaction finds a secret in the text: read as a one-word
 * argv or as a field, it withholds the text or cuts a secret out of it (one
 * more {@link SHARED_REDACTED} than the text had). It is given no names, so
 * only secrets count: a home folder or email address changes its output but
 * never adds a secret marker.
 */
function sharedFindsSecret(text: string): boolean {
  if (text === SHARED_WITHHELD) return false;
  const markers = (t: string) => t.split(SHARED_REDACTED).length;
  const before = markers(text);
  return [redactArgv([text])[0] ?? SHARED_WITHHELD, redactField(text)].some(
    (out) => out === SHARED_WITHHELD || markers(out) > before,
  );
}

/** Whether a command line might hold a secret, by this file's scan or the shared redaction's. */
function mightHoldSecret(text: string): boolean {
  if (SECRET_HINTS.some((p) => p.test(text))) return true;
  if (/mysql|mariadb/i.test(text) && /-p/i.test(text)) return true;
  if (/redis-cli/i.test(text) && /-a|\bauth\b/i.test(text)) return true;
  if (/curl/i.test(text) && /\s-[a-z]*[uK]|--user(?![-\w])|--config/.test(text)) return true;
  if (/unzip/i.test(text) && /-P/.test(text)) return true;
  if (/7z|7za|rar/i.test(text) && /-p\S/.test(text)) return true;
  return sharedFindsSecret(text);
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Home folder names (`/Users/<name>/`, whoever's), then this computer's
 * names as whole tokens: any character other than a letter
 * or digit ends one, so `al_backup`, `my-pc` and `<al;` give the name away
 * and `alpha` doesn't. One pass, and only the name's own characters change.
 */
function redactNames(text: string, names: EvidenceNames): string {
  // Any user's home folder name, up to the next / or the end of the path.
  text = text.replace(/(\/(?:Users|home)\/)[A-Za-z0-9._-]+(?=\/|$|\s|['"])/g, '$1<user>');
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

/** A URL: like a command string, and withheld if it holds a newline or control character. */
function urlString(text: string, names: EvidenceNames): string {
  // eslint-disable-next-line no-control-regex
  return /[\u0000-\u001f\u007f]/.test(text) ? WITHHELD : commandString(text, names);
}

/** What one pass withheld: the command strings and argv lists, as they were. */
type Withheld = string[];

function walk(value: unknown, names: EvidenceNames, withheld: Withheld, key?: string): unknown {
  if (typeof value === 'string') {
    if (key !== undefined && FIXED_TEXT.has(key)) return redactNames(value, names);
    const out =
      key !== undefined && URL_FIELDS.has(key)
        ? urlString(value, names)
        : commandString(value, names);
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

/**
 * Whether a line of alert text repeats something withheld: a whole command,
 * one of its args, or the last part of a withheld path (a file's label is
 * its name).
 */
function carries(text: unknown, withheld: Withheld): boolean {
  if (typeof text !== 'string') return false;
  return withheld.some((w) => {
    const last = w.slice(w.lastIndexOf('/') + 1);
    return (w.length >= 4 && text.includes(w)) || (last.length >= 4 && text.includes(last));
  });
}

/**
 * Evidence ready to copy. Keys are kept. When any command line in it was
 * withheld, so is the alert's summary, which rules fill from the command,
 * and any title or label, anywhere, that repeats the command, one of its args
 * or the last part of a withheld path.
 */
export function redactEvidence(value: unknown, names: EvidenceNames): unknown {
  const withheld: Withheld = [];
  return finish(value, walk(value, names, withheld), withheld);
}

/** How long {@link redactEvidenceInSlices} works before letting other work run. */
export const SLICE_MS = 50;

const nextTurn = () => new Promise<void>((resolve) => setImmediate(resolve));

/**
 * {@link redactEvidence}, with the same result, for evidence that can be
 * large: an alert keeps every repeat's events, so it can hold thousands, and
 * the scan of each string is not cheap. The events are scanned a few at a
 * time, letting other work (the window) run every {@link SLICE_MS}.
 */
export async function redactEvidenceInSlices(
  value: unknown,
  names: EvidenceNames,
  yieldTo: () => Promise<void> = nextTurn,
  now: () => number = () => performance.now(),
): Promise<unknown> {
  if (!isRecord(value) || !Array.isArray(value['events'])) return redactEvidence(value, names);
  const withheld: Withheld = [];
  const { events, ...rest } = value;
  const out = walk(rest, names, withheld) as Record<string, unknown>;
  const scanned: unknown[] = [];
  let since = now();
  for (const event of events) {
    if (now() - since >= SLICE_MS) {
      await yieldTo();
      since = now();
    }
    scanned.push(walk(event, names, withheld));
  }
  // The same keys in the same order as redactEvidence gives.
  const whole: Record<string, unknown> = {};
  for (const k of Object.keys(value)) whole[k] = k === 'events' ? scanned : out[k];
  return finish(value, whole, withheld);
}

/** The alert summary and repeated titles and labels, once every string has been scanned. */
function finish(value: unknown, out: unknown, withheld: Withheld): unknown {
  if (withheld.length === 0) return out;
  const alert = isRecord(value) && isRecord(value['alert']) ? value['alert'] : undefined;
  const copied = isRecord(out) && isRecord(out['alert']) ? out['alert'] : undefined;
  if (alert && copied && copied['summary'] !== undefined) copied['summary'] = WITHHELD;
  withholdRepeats(value, out, withheld);
  return out;
}

/** Withhold each title or label in `out` whose original in `value` repeats something withheld. */
function withholdRepeats(value: unknown, out: unknown, withheld: Withheld): void {
  if (Array.isArray(value) && Array.isArray(out)) {
    value.forEach((v, i) => withholdRepeats(v, out[i], withheld));
  } else if (isRecord(value) && isRecord(out)) {
    for (const [k, v] of Object.entries(value)) {
      if (REPEATS.has(k) && carries(v, withheld)) out[k] = WITHHELD;
      else withholdRepeats(v, out[k], withheld);
    }
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}
