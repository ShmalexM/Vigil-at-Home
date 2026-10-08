import { redactString } from '@vigil/ai/redact';

/**
 * The extra pass copied evidence gets before the shared redaction
 * (@vigil/ai/redact), which looks at one string at a time and only catches a
 * generic secret written `name=value` under a few names. Command lines also
 * pass secrets as `--token value` (often as two separate args), as a tool's
 * own short flag (`mysql -phunter2`, `sshpass -p hunter2`, `redis-cli AUTH
 * hunter2`), in a URL's user info or in an environment variable, and this
 * computer's user and host names can be shorter than the shared pass's
 * length guard.
 *
 * Nothing here parses shell. A field (one arg, or one command string) that
 * holds a credential is redacted precisely only when it has no shell
 * metacharacters at all, so every secret in it is one plain word; otherwise
 * the whole field is withheld, so a redaction can never hide (or seem to
 * hide) the command after a `|` or `;`.
 */
export interface EvidenceNames {
  /** This computer's short user name, hidden at any length. */
  username?: string | undefined;
  /** Its host name, hidden with and without `.local`. */
  hostname?: string | undefined;
}

const REDACTED = '<redacted>';
export const WITHHELD = '[withheld: may contain a secret]';

/** Characters a shell treats specially. A field with any of them is never redacted piecemeal. */
const SHELL_META = /["'`$;&|<>(){}#\\]/;
/** A secret that can be cut out on its own: one word of ordinary characters. */
const SAFE_SECRET = /^[^\s"'`$;&|<>(){}#\\]+$/;

/** Flags whose value is a secret. Exact names only, so `--keyboard` keeps its value. */
const SECRET_FLAG = /^--(?:token|access-token|password|passwd|secret|api-key|apikey|auth|key)$/i;
/**
 * `NAME=value` where the name says it holds a credential: PGPASSWORD=,
 * AWS_SECRET_ACCESS_KEY=, --token= and the like.
 */
const SECRET_ASSIGNMENT =
  /^([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|key|auth)[A-Za-z0-9_.-]*=)(.+)$/i;
/** A URL's user info (`scheme://user:password@`), all of it, before the email pass sees an `@`. */
const URL_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)[^/\s@]+@/gi;
/** What the shared pass redacts as `name: value`; here only to decide whether a field holds a secret. */
const SHARED_GENERIC = /\b(?:pass(?:word|wd)?|secret|token|api[_-]?key)\s*[=:]/i;

/** Short flags a tool takes a password with: its value, attached or the next word. */
const PASSWORD_FLAG: Record<string, string> = {
  mysql: '-p',
  mysqldump: '-p',
  mysqladmin: '-p',
  mariadb: '-p',
  'mariadb-dump': '-p',
  sshpass: '-p',
  'redis-cli': '-a',
};

/**
 * Which words in order (args, or a command line split at spaces) are
 * secrets, each with the part of the word to keep in front of it: the value
 * after a secret long flag or a tool's password flag (or attached to it), a
 * credential `NAME=value`, and every word after redis-cli's AUTH.
 */
function secretWords(words: string[]): Map<number, string> {
  const found = new Map<number, string>();
  let tool: string | undefined;
  let hide = 0;
  words.forEach((w, i) => {
    if (w === '') return;
    if (hide > 0 && !w.startsWith('--')) {
      hide--;
      found.set(i, '');
      // What follows sshpass's password is the command it runs, with flags of its own.
      if (tool === 'sshpass') tool = undefined;
      return;
    }
    const name = w.split('/').pop()!.toLowerCase();
    if (Object.hasOwn(PASSWORD_FLAG, name)) tool = name;
    if (SECRET_FLAG.test(w)) hide = 1;
    const assigned = SECRET_ASSIGNMENT.exec(w);
    if (assigned) found.set(i, assigned[1]!);
    const flag = tool && PASSWORD_FLAG[tool];
    if (flag && w === flag) hide = 1;
    else if (flag && w.startsWith(flag) && w.length > flag.length && !w.startsWith('--')) {
      found.set(i, flag);
      if (tool === 'sshpass') tool = undefined;
    }
    if (tool === 'redis-cli' && w.toUpperCase() === 'AUTH') hide = Infinity;
  });
  return found;
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * This computer's names as whole tokens: any character other than a letter
 * or digit ends one, so `al_backup`, `my-pc` and `<al;` give the name away
 * and `alpha` doesn't. One pass, skipping the placeholders already put in.
 */
function redactNames(text: string, names: EvidenceNames): string {
  const host = names.hostname?.replace(/\.local$/i, '');
  const words = [host && `${host}.local`, host, names.username].filter((w): w is string => !!w);
  if (words.length === 0) return text;
  const pattern = new RegExp(
    `(<user>|<host>|<redacted>)|(?<![A-Za-z0-9])(${words.map(escapeRegExp).join('|')})(?![A-Za-z0-9])`,
    'gi',
  );
  return text.replace(pattern, (match, placeholder: string | undefined) => {
    if (placeholder) return match;
    return names.username && match.toLowerCase() === names.username.toLowerCase()
      ? '<user>'
      : '<host>';
  });
}

/** The shared redaction for one string, with the names it knows. */
function shared(text: string, names: EvidenceNames): string {
  return redactString(text, {
    ...(names.username ? { username: names.username } : {}),
    ...(names.hostname ? { hostname: names.hostname } : {}),
  });
}

/** One field: precise when it is plain words, withheld whole when a secret sits among shell syntax. */
function redactField(text: string, names: EvidenceNames): string {
  const parts = text.split(/(\s+)/);
  const words = parts.filter((_, i) => i % 2 === 0);
  const secrets = secretWords(words);
  URL_USERINFO.lastIndex = 0;
  const holdsSecret = secrets.size > 0 || URL_USERINFO.test(text) || SHARED_GENERIC.test(text);
  if (holdsSecret && SHELL_META.test(text)) return WITHHELD;
  let out = text;
  if (secrets.size > 0) {
    out = parts
      .map((p, i) => {
        const keep = i % 2 === 0 ? secrets.get(i / 2) : undefined;
        return keep === undefined ? p : `${keep}${REDACTED}`;
      })
      .join('');
  }
  out = out.replace(URL_USERINFO, `$1${REDACTED}@`);
  return shared(redactNames(out, names), names);
}

/**
 * An argument list, read in order like a command line: an arg that is a
 * secret's value is redacted if it is one plain word and withheld if not;
 * every other arg is a field of its own.
 */
function redactArgs(args: string[], names: EvidenceNames): string[] {
  const secrets = secretWords(args);
  return args.map((arg, i) => {
    const keep = secrets.get(i);
    if (keep === undefined) return redactField(arg, names);
    return SAFE_SECRET.test(arg.slice(keep.length)) && !SHELL_META.test(keep)
      ? `${keep}${REDACTED}`
      : WITHHELD;
  });
}

function walk(value: unknown, names: EvidenceNames): unknown {
  if (typeof value === 'string') return redactField(value, names);
  if (Array.isArray(value)) {
    if (value.every((v) => typeof v === 'string')) return redactArgs(value as string[], names);
    return value.map((v) => walk(v, names));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = walk(item, names);
    return out;
  }
  return value;
}

/**
 * Evidence ready to copy: secrets in command lines and this computer's names
 * first, then the shared redaction, string by string. Keys are kept.
 */
export function redactEvidence(value: unknown, names: EvidenceNames): unknown {
  return walk(value, names);
}
