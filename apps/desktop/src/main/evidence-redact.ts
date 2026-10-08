import { redactValue } from '@vigil/ai/redact';

/**
 * The extra pass copied evidence gets before the shared redaction
 * (@vigil/ai/redact), which looks at one string at a time and only catches a
 * generic secret written `name=value`. Command lines also pass secrets as
 * `--token value`, often as two separate args, and this computer's user and
 * host names can be shorter than the shared pass's length guard.
 */
export interface EvidenceNames {
  /** This computer's short user name, hidden at any length. */
  username?: string | undefined;
  /** Its host name, hidden with and without `.local`. */
  hostname?: string | undefined;
}

/** Flags whose value is a secret. Exact names only, so `--keyboard` keeps its value. */
const SECRET_FLAG = /^--(?:token|access-token|password|passwd|secret|api-key|apikey|auth|key)$/i;
/** The same flags inside one string, with the value after a space or `=`. */
const SECRET_FLAG_IN_TEXT =
  /(^|\s)(--(?:token|access-token|password|passwd|secret|api-key|apikey|auth|key))(\s+|=)("[^"]*"|'[^']*'|[^\s"']+)/gi;
const REDACTED = '<redacted>';

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** A whole token: not part of a longer word or host label, nor a placeholder already put in. */
function tokenPattern(word: string): RegExp {
  return new RegExp(`(?<![A-Za-z0-9_<-])${escapeRegExp(word)}(?![A-Za-z0-9_>-])`, 'gi');
}

function redactText(text: string, names: EvidenceNames): string {
  let out = text.replace(SECRET_FLAG_IN_TEXT, `$1$2$3${REDACTED}`);
  const host = names.hostname?.replace(/\.local$/i, '');
  if (host) out = out.replace(tokenPattern(`${host}.local`), '<host>');
  if (host) out = out.replace(tokenPattern(host), '<host>');
  if (names.username) out = out.replace(tokenPattern(names.username), '<user>');
  return out;
}

/** An argument list: the value after a secret flag is the secret. */
function redactArgs(args: string[], names: EvidenceNames): string[] {
  return args.map((arg, i) =>
    i > 0 && SECRET_FLAG.test(args[i - 1]!) && !arg.startsWith('--')
      ? REDACTED
      : redactText(arg, names),
  );
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
