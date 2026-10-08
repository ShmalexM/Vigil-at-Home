import { redactString } from '@vigil/ai/redact';

/**
 * Redaction for copied evidence. Command lines get no piecemeal redaction:
 * secrets hide in them in too many shapes (`mysql -phunter2`, quoted
 * `PGPASSWORD=…`, a value after `;` or a newline) for a pattern to cut out
 * the secret and nothing else. A command-line field that might hold one is
 * withheld whole, and otherwise only this computer's user and host names are
 * replaced. Every other string goes through the shared redaction
 * (@vigil/ai/redact) after the same name pass.
 */
export interface EvidenceNames {
  /** This computer's short user name, hidden at any length. */
  username?: string | undefined;
  /** Its host name, hidden with and without `.local`. */
  hostname?: string | undefined;
}

export const WITHHELD = '[withheld: may contain a secret]';

/**
 * The fields that carry a command line, by key: a process's argv and a
 * persistence item's program arguments (lists), and an agent tool request's
 * command and URL (strings; a URL can carry `user:password@`).
 */
const COMMAND_LISTS = new Set(['args', 'programArgs']);
const COMMAND_STRINGS = new Set(['command', 'commandLine', 'url', 'originUrl']);

/**
 * Anything that might be a secret, matched anywhere: no word boundaries and
 * any case, so it over-withholds (`PWD=`, "author") rather than miss one.
 * The value shapes follow @vigil/ai/redact's SECRET_PATTERNS, loosened.
 */
const SECRET_HINTS: readonly RegExp[] = [
  /password|passwd|pwd|secret|token|api_key|apikey|api-key|auth|credential/i,
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

function walk(value: unknown, names: EvidenceNames, key?: string): unknown {
  if (typeof value === 'string') {
    return key !== undefined && COMMAND_STRINGS.has(key)
      ? commandString(value, names)
      : freeText(value, names);
  }
  if (Array.isArray(value)) {
    if (key !== undefined && COMMAND_LISTS.has(key) && value.every((v) => typeof v === 'string')) {
      return commandList(value as string[], names);
    }
    return value.map((v) => walk(v, names));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, item] of Object.entries(value)) out[k] = walk(item, names, k);
    return out;
  }
  return value;
}

/** Evidence ready to copy. Keys are kept. */
export function redactEvidence(value: unknown, names: EvidenceNames): unknown {
  return walk(value, names);
}
