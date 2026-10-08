/**
 * Redaction for copied evidence. Command lines get no piecemeal redaction:
 * secrets hide in them in too many shapes (`mysql -phunter2`, quoted
 * `PGPASSWORD=…`, a value after `;` or a newline) for a pattern to cut out
 * the secret and nothing else. A command-line field that might hold one is
 * withheld whole, and otherwise only this computer's user and host names are
 * replaced. Every other string, a decision note or an error included, is
 * treated the same way, since any of them can quote a command. Only titles
 * and subject labels, which are rule text or names, skip the scan. The
 * shared redaction (@vigil/ai/redact) is not used here: its home-path rule
 * can eat text after a path (`/Users/al;curl` loses `;curl`).
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
 * they hold a newline or other control character. Titles and subject labels
 * are rule text or names: they are not scanned (a rule titled "Credentials
 * file read" stays readable) and are withheld only when they repeat a
 * withheld command (see `redactEvidence`).
 */
const COMMAND_LISTS = new Set(['args', 'programArgs']);
const URL_FIELDS = new Set(['url', 'originUrl']);
/** Rule text and names: only the names change, unless they repeat a withheld command. */
const FIXED_TEXT = new Set(['title', 'label']);

/** A name that may label a secret, as in `PGPASSWORD`, `api_key` or `x-auth`. */
const SECRET_NAME = '[A-Za-z0-9_.-]*(?:pass|pwd|secret|token|key|auth|cred)[A-Za-z0-9_.-]*';

/**
 * What a secret looks like in a command line: an assignment or flag whose
 * name says so, a tool's own password flag, or a value shaped like a known
 * kind of key. Plain words and paths (`cat /etc/passwd`, `ls /opt/compass`)
 * pass, since a name only counts when a value is given to it. The value
 * shapes follow @vigil/ai/redact's SECRET_PATTERNS, loosened.
 */
const SECRET_HINTS: readonly RegExp[] = [
  // NAME=value or NAME: value, also inside quotes, `$(…)` or a URL query.
  new RegExp(`(?:^|[^A-Za-z0-9_])${SECRET_NAME}\\s*[=:]\\s*[^\\s=:]`, 'i'),
  // --password hunter2, -pass x, --token=x (the = form is caught above).
  new RegExp(`(?:^|\\s)--?${SECRET_NAME}\\s+[^\\s-]`, 'i'),
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

/** Whether a command line might hold a secret. */
function mightHoldSecret(text: string): boolean {
  if (SECRET_HINTS.some((p) => p.test(text))) return true;
  if (/mysql|mariadb/i.test(text) && /-p/i.test(text)) return true;
  if (/redis-cli/i.test(text) && /-a|\bauth\b/i.test(text)) return true;
  if (/curl/i.test(text) && /\s-[a-z]*[uK]|--user|--config/.test(text)) return true;
  if (/unzip/i.test(text) && /-P/.test(text)) return true;
  if (/7z|7za|rar/i.test(text) && /-p\S/.test(text)) return true;
  return false;
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
