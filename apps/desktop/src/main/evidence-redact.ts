import { redactValue } from '@vigil/ai/redact';

/**
 * The extra pass copied evidence gets before the shared redaction
 * (@vigil/ai/redact), which looks at one string at a time and only catches a
 * generic secret written `name=value` under a few names. Command lines also
 * pass secrets as `--token value` (often as two separate args), as a tool's
 * own short flag (`mysql -phunter2`, `sshpass -p hunter2`, `redis-cli AUTH
 * hunter2`), in a URL's user info or in an environment variable, and this
 * computer's user and host names can be shorter than the shared pass's
 * length guard.
 */
export interface EvidenceNames {
  /** This computer's short user name, hidden at any length. */
  username?: string | undefined;
  /** Its host name, hidden with and without `.local`. */
  hostname?: string | undefined;
}

const REDACTED = '<redacted>';
const LONG_FLAGS = 'token|access-token|password|passwd|secret|api-key|apikey|auth|key';
/** Flags whose value is a secret. Exact names only, so `--keyboard` keeps its value. */
const SECRET_FLAG = new RegExp(`^--(?:${LONG_FLAGS})$`, 'i');
/** The same flags inside one string, with the value after a space or `=`. */
const SECRET_FLAG_IN_TEXT = new RegExp(
  `(^|\\s)(--(?:${LONG_FLAGS}))(\\s+|=)("[^"]*"|'[^']*'|[^\\s"']+)`,
  'gi',
);
/** A URL's user info (`scheme://user:password@`), all of it, before the email pass sees an `@`. */
const URL_USERINFO = /\b([a-z][a-z0-9+.-]*:\/\/)[^/\s@"']+@/gi;
/** `NAME=value` where the name says it holds a credential: PGPASSWORD, AWS_SECRET_ACCESS_KEY... */
const SECRET_ASSIGNMENT =
  /(?<![A-Za-z0-9_])([A-Za-z0-9_.-]*(?:password|passwd|pwd|secret|token|key|auth)[A-Za-z0-9_.-]*=)("[^"]*"|'[^']*'|[^\s"'&;]+)/gi;

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
/** Shell words that end one command and start the next. */
const SEPARATOR = /^(?:;|\||\|\||&&)$/;

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * A whole token: any character other than a letter or digit ends it, so
 * `al_backup` and `my-pc` give the name away and `alpha` doesn't. Not a
 * placeholder already put in, either.
 */
function tokenPattern(word: string): RegExp {
  return new RegExp(`(?<![A-Za-z0-9<])${escapeRegExp(word)}(?![A-Za-z0-9>])`, 'gi');
}

/** A word without the quotes or brackets around it. */
function bare(word: string): string {
  return word.replace(/^["'(]+|["');]+$/g, '');
}

/**
 * Words in order, as args or a command line split at spaces: the value after
 * a secret long flag, after a tool's password flag (or attached to it), and
 * everything after redis-cli's AUTH up to the next command.
 */
function redactWords(words: string[]): string[] {
  let tool: string | undefined;
  let hide = 0;
  return words.map((word) => {
    const w = bare(word);
    if (SEPARATOR.test(w)) {
      tool = undefined;
      hide = 0;
      return word;
    }
    if (hide > 0 && w !== '' && !w.startsWith('--')) {
      hide--;
      // What follows sshpass's password is the command it runs, with flags of its own.
      if (tool === 'sshpass') tool = undefined;
      return word.replace(w, REDACTED); // keeps the quotes around it
    }
    const name = w.split('/').pop()!.toLowerCase();
    if (Object.hasOwn(PASSWORD_FLAG, name)) tool = name;
    if (SECRET_FLAG.test(w)) hide = 1;
    const flag = tool && PASSWORD_FLAG[tool];
    if (flag && w === flag) hide = 1;
    else if (flag && w.startsWith(flag) && w.length > flag.length && !w.startsWith('--')) {
      if (tool === 'sshpass') tool = undefined;
      return word.replace(w, `${flag}${REDACTED}`);
    }
    if (tool === 'redis-cli' && w.toUpperCase() === 'AUTH') hide = Infinity;
    return word;
  });
}

function redactText(text: string, names: EvidenceNames): string {
  let out = text.replace(URL_USERINFO, `$1${REDACTED}@`);
  out = out.replace(SECRET_FLAG_IN_TEXT, `$1$2$3${REDACTED}`);
  out = out.replace(SECRET_ASSIGNMENT, `$1${REDACTED}`);
  if (/\s/.test(out)) {
    const parts = out.split(/(\s+)/);
    const words = redactWords(parts.filter((_, i) => i % 2 === 0));
    out = parts.map((p, i) => (i % 2 === 0 ? words[i / 2]! : p)).join('');
  }
  const host = names.hostname?.replace(/\.local$/i, '');
  if (host) out = out.replace(tokenPattern(`${host}.local`), '<host>');
  if (host) out = out.replace(tokenPattern(host), '<host>');
  if (names.username) out = out.replace(tokenPattern(names.username), '<user>');
  return out;
}

/** An argument list, read in order like a command line, then each arg on its own. */
function redactArgs(args: string[], names: EvidenceNames): string[] {
  return redactWords(args).map((arg) => redactText(arg, names));
}

function walk(value: unknown, names: EvidenceNames): unknown {
  if (typeof value === 'string') return redactText(value, names);
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

/** Evidence ready to copy: secret flag values and this computer's names first, then the shared redaction. */
export function redactEvidence(value: unknown, names: EvidenceNames): unknown {
  return redactValue(walk(value, names), {
    ...(names.username ? { username: names.username } : {}),
    ...(names.hostname ? { hostname: names.hostname } : {}),
  });
}
