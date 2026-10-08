import { hostname, userInfo } from 'node:os';

export interface RedactionOptions {
  /** The Mac's short user name, replaced wherever it appears. */
  readonly username?: string;
  /** The Mac's host name. */
  readonly hostname?: string;
  /** Upper bound for the serialized data sent to a model. */
  readonly maxBytes: number;
}

/** What a redacted value is replaced with. */
export const REDACTED = '<redacted>';

/**
 * The longest string redactString looks at. Anything past it is cut off before
 * redaction, so a hostile or runaway input can't make redaction slow.
 */
export const MAX_REDACT_CHARS = 512 * 1024;

// Every pattern here must run in time linear in its input: no unbounded
// repetition that can be retried from many start positions, and no lookahead
// that scans the rest of the string per match. redact.test.ts times each on
// adversarial input.
const SECRET_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  // An unterminated key runs to the end of the text: it may have been cut short.
  [
    /-----BEGIN [A-Z ]{0,40}PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]{0,40}PRIVATE KEY-----|$)/g,
    '<private-key>',
  ],
  [/\bAKIA[0-9A-Z]{16}\b/g, '<aws-key>'],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g, '<github-token>'],
  [/(?<![A-Za-z0-9_-])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])xox[abprs]-[A-Za-z0-9-]{10,}/g, '<slack-token>'],
  [/(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '<jwt>'],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}/g, '<api-key>'],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, '<npm-token>'],
  [/(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}/g, '<gitlab-token>'],
  // A long bearer token outside an Authorization header. In a header, any
  // length is redacted by redactKeyedValues.
  [/\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]{16,}/gi, '$1 <token>'],
  // user:password in a URL, such as postgres://me:hunter2@db.
  [
    /(?<![A-Za-z0-9+.-])([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s/?#@:]{1,256}:[^\s/?#]{1,256}@/gi,
    '$1<credentials>@',
  ],
];

const EMAIL = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}/g;

// ---------------------------------------------------------------------------
// Credential names: PGPASSWORD, x-api-key, githubToken, --db-password, ...

/** A name ending in one of these is about a secret, not the secret itself. */
const NON_SECRET_SUFFIXES = new Set([
  'count',
  'policy',
  'enabled',
  'disabled',
  'length',
  'min',
  'max',
  'required',
  'url',
  'uri',
  'file',
  'path',
  'dir',
  'type',
  'id',
  'name',
  'ttl',
  'expiry',
  'expires',
  'timeout',
  'limit',
]);

const CREDENTIAL_WORDS = new Set([
  'pwd',
  'pass',
  'auth',
  'authorization',
  'apikey',
  'accesskey',
  'privatekey',
]);
const KEY_QUALIFIERS = new Set(['api', 'access', 'private']);
const QUICK_CREDENTIAL = /pass|pwd|token|secret|key|auth|credential|cookie/i;

function nameParts(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

/** True for a name whose value is a secret, such as MYSQL_PWD or x-api-key. */
export function isCredentialName(name: string): boolean {
  if (!QUICK_CREDENTIAL.test(name)) return false;
  const parts = nameParts(name);
  if (parts.length === 0) return false;
  // The shell's working folder, not a password.
  if (parts.length === 1 && (parts[0] === 'pwd' || parts[0] === 'oldpwd')) return false;
  if (parts.length > 1 && NON_SECRET_SUFFIXES.has(parts[parts.length - 1]!)) return false;
  return parts.some((part, i) => {
    if (/password|passwd|passphrase|secret|credential|cookie/.test(part)) return true;
    // GITHUB_TOKEN, accessToken; not max_tokens.
    if (part.endsWith('token')) return true;
    if (CREDENTIAL_WORDS.has(part)) return true;
    if (/(?:api|access|private)key$/.test(part)) return true;
    return part === 'key' && i > 0 && KEY_QUALIFIERS.has(parts[i - 1]!);
  });
}

/** A password-like name, where even a short number is the secret (a PIN). */
function isPasswordName(name: string): boolean {
  return nameParts(name).some(
    (part) => /password|passwd|passphrase/.test(part) || part === 'pwd' || part === 'pass',
  );
}

/** Values that can't be a secret: flags and small counts. */
function isBenignValue(value: string, passwordName: boolean): boolean {
  if (value === '') return true;
  if (/^(?:true|false|null|undefined|none|yes|no|on|off)$/i.test(value)) return true;
  return !passwordName && /^-?\d{1,4}$/.test(value);
}

function isBenignNumber(value: number, passwordName: boolean): boolean {
  return !passwordName && Number.isInteger(value) && Math.abs(value) < 10_000;
}

/**
 * A name followed by its separator: NAME=, NAME: , "name": , --name=, or
 * --name followed by a space and a value that isn't another flag. The name is
 * bounded and must start a word, so the work at each position is bounded.
 */
const KEYED =
  /(?<![A-Za-z0-9_.-])(?:(["']?)-{0,2}([A-Za-z][A-Za-z0-9_.-]{0,63})(["']?)[ \t]*([=:])[ \t]*|--([A-Za-z][A-Za-z0-9_-]{0,63})[ \t]+(?=[^\s-]))/g;
// A quoted value, escapes included. An unclosed quote runs to the end of the
// line or text, so it can't be retried from later positions.
const DOUBLE_QUOTED = /"(?:[^"\\\n]|\\[\s\S])*(?:"|(?=\n)|$)/y;
const SINGLE_QUOTED = /'(?:[^'\\\n]|\\[\s\S])*(?:'|(?=\n)|$)/y;
const UNTIL_DOUBLE = /(?:[^"\\\n]|\\[\s\S])*/y;
const UNTIL_SINGLE = /[^'\n]*/y;
const BARE = /\S+/y;
const REST_OF_LINE = /[^\r\n]*/y;
const AUTH_SCHEME = /(?:Bearer|Basic|Token|Digest|Negotiate|NTLM)[ \t]+/iy;

function matchAt(pattern: RegExp, text: string, at: number): string {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0] ?? '';
}

/** The value that starts at `at`, by the rules for the name before it. */
function valueAt(text: string, at: number, argQuote: string, wholeLine: boolean): string {
  if (argQuote === '"') return matchAt(UNTIL_DOUBLE, text, at);
  if (argQuote === "'") return matchAt(UNTIL_SINGLE, text, at);
  if (text[at] === '"') return matchAt(DOUBLE_QUOTED, text, at);
  if (text[at] === "'") return matchAt(SINGLE_QUOTED, text, at);
  if (wholeLine) return matchAt(REST_OF_LINE, text, at).trimEnd();
  return matchAt(BARE, text, at);
}

function unquote(value: string): string {
  const q = value[0];
  return (q === '"' || q === "'") && value.length >= 2 && value.endsWith(q)
    ? value.slice(1, -1)
    : value;
}

/**
 * Redact the value of every credential-named setting, whatever its length:
 * PGPASSWORD=x, "password": "x", x-api-key: x, --token x, Authorization: Bearer x.
 * One pass, each value read once.
 */
function redactKeyedValues(text: string): string {
  let out = '';
  let last = 0;
  KEYED.lastIndex = 0;
  for (let m = KEYED.exec(text); m; m = KEYED.exec(text)) {
    const name = m[2] ?? m[5]!;
    if (!isCredentialName(name)) continue;
    const afterKey = m.index + m[0].length;
    const lead = m[1] ?? '';
    // 'x-api-key: abc' — the quote opens the shell argument, so the value runs
    // up to its closing quote and the quote stays.
    const argQuote = lead && !m[3] ? lead : '';
    const parts = nameParts(name);
    let at = afterKey;
    if (parts.includes('authorization')) at += matchAt(AUTH_SCHEME, text, at).length;
    // "auth": { ... } — the names inside are checked on their own.
    if (text[at] === '{' || text[at] === '[') continue;
    // Cookie: a=1; b=2 — a cookie header's value runs to the end of the line.
    const cookieHeader = m[4] === ':' && parts.some((p) => p.includes('cookie'));
    const value = valueAt(text, at, argQuote, cookieHeader);
    const bare = unquote(value);
    // Already replaced by a pattern above, such as <api-key>: keep the more telling marker.
    if (!value || /^<[a-z-]+>$/.test(bare) || isBenignValue(bare, isPasswordName(name))) continue;
    out += text.slice(last, at) + REDACTED;
    last = at + value.length;
    KEYED.lastIndex = last;
  }
  return last === 0 ? text : out + text.slice(last);
}

// ---------------------------------------------------------------------------
// mysql -phunter2. Only for the MySQL tools, which take the password glued to
// -p: elsewhere -p is a port (ssh -p 22) or a plain flag (mkdir -p). The
// command runs to the end of its line or pipeline stage, read once.
const MYSQL_COMMAND = /\b(?:mysql|mariadb)[a-z]*\b[^\n;|&]*/g;
const MYSQL_GLUED_PASSWORD = /(\s-p)[^\s-]\S*/g;

// ---------------------------------------------------------------------------
// Secrets hidden in base64, such as {"password":"hunter2"} encoded.
const BASE64_RUN = /(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_-]{16,}={0,2}/g;
const MAX_BASE64_RUN = 16 * 1024;
const DECODED_SECRET =
  /pass(?:word|wd)|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|"alg"\s*:/i;

function hidesSecret(run: string): boolean {
  if (run.length > MAX_BASE64_RUN) return false;
  const decoded = Buffer.from(run, 'base64').toString('latin1');
  if (decoded.length < 8) return false;
  let printable = 0;
  for (let i = 0; i < decoded.length; i++) {
    const c = decoded.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) printable++;
  }
  return printable / decoded.length >= 0.9 && DECODED_SECRET.test(decoded);
}

// ---------------------------------------------------------------------------
// The cut for over-long input.

function isBoundary(code: number): boolean {
  // Whitespace, quotes and the punctuation that ends a value in JSON or a shell.
  return (
    code <= 0x20 ||
    code === 0x22 || // "
    code === 0x27 || // '
    code === 0x60 || // `
    code === 0x2c || // ,
    code === 0x3b || // ;
    code === 0x28 || // (
    code === 0x29 || // )
    code === 0x5b || // [
    code === 0x5d || // ]
    code === 0x7b || // {
    code === 0x7d || // }
    code === 0x3c || // <
    code === 0x3e // >
  );
}

/**
 * Cut text past MAX_REDACT_CHARS, along with the word the cut runs through,
 * so no secret is left with its head on one side and only a tail to see.
 * A quoted value or private key left open by the cut is redacted to the end.
 */
function clip(input: string): { text: string; dropped: number } {
  if (input.length <= MAX_REDACT_CHARS) return { text: input, dropped: 0 };
  let end = MAX_REDACT_CHARS;
  while (end > 0 && !isBoundary(input.charCodeAt(end - 1))) end--;
  return { text: input.slice(0, end), dropped: input.length - end };
}

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** Names too short or too common to replace without mangling ordinary words. */
const GENERIC_NAMES = new Set(['root', 'user', 'admin', 'administrator', 'guest', 'localhost']);

function worthHiding(name: string | undefined): name is string {
  return !!name && name.length >= 3 && !GENERIC_NAMES.has(name.toLowerCase());
}

/** This Mac's user and host names, for the redaction of what leaves it. */
export function localNames(): { username?: string; hostname?: string } {
  let username: string | undefined;
  try {
    username = userInfo().username;
  } catch {
    // No account entry for this uid: there's no name to hide.
  }
  const host = hostname();
  return {
    ...(worthHiding(username) ? { username } : {}),
    ...(worthHiding(host) ? { hostname: host } : {}),
  };
}

export function redactString(input: string, options: Omit<RedactionOptions, 'maxBytes'>): string {
  const { text, dropped } = clip(input);
  let out = text.replace(/\/(Users|home)\/[^/\s"']+/g, '/$1/<user>');
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
  out = redactKeyedValues(out);
  out = out.replace(MYSQL_COMMAND, (command) =>
    command.replace(MYSQL_GLUED_PASSWORD, `$1${REDACTED}`),
  );
  out = out.replace(BASE64_RUN, (run) => (hidesSecret(run) ? '<base64-secret>' : run));
  out = out.replace(EMAIL, '<email>');
  if (worthHiding(options.hostname)) {
    out = out.replace(new RegExp(escapeRegExp(options.hostname), 'gi'), '<host>');
    // Alexs-MacBook-Pro.local is often written without its domain.
    const short = options.hostname.split('.')[0];
    if (short !== options.hostname && worthHiding(short)) {
      out = out.replace(
        new RegExp(`(?<![A-Za-z0-9_-])${escapeRegExp(short)}(?![A-Za-z0-9_-])`, 'gi'),
        '<host>',
      );
    }
  }
  if (worthHiding(options.username)) {
    out = out.replace(new RegExp(`\\b${escapeRegExp(options.username)}\\b`, 'gi'), '<user>');
  }
  return dropped ? `${out}…[truncated ${dropped} characters before redaction]` : out;
}

/**
 * Redact every string in a JSON-like value. Keys are kept. A value under a
 * credential-named key (password, x-api-key, authToken, ...) is replaced
 * whatever it looks like; when that value is an object or array, its shape is
 * kept and every string and number inside it is replaced, booleans and null
 * aside.
 */
export function redactValue(value: unknown, options: Omit<RedactionOptions, 'maxBytes'>): unknown {
  return redactWithin(value, options, undefined);
}

/** `secret` is set under a credential-named key: true when it names a password. */
function redactWithin(
  value: unknown,
  options: Omit<RedactionOptions, 'maxBytes'>,
  secret: { password: boolean } | undefined,
): unknown {
  if (secret) {
    if (typeof value === 'string') return isBenignValue(value, secret.password) ? value : REDACTED;
    if (typeof value === 'number') return isBenignNumber(value, secret.password) ? value : REDACTED;
    if (typeof value === 'bigint') return REDACTED;
  }
  if (typeof value === 'string') return redactString(value, options);
  if (Array.isArray(value)) return value.map((item) => redactWithin(item, options, secret));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      const keyed =
        secret || isCredentialName(key)
          ? { password: !!secret?.password || isPasswordName(key) }
          : undefined;
      out[key] = redactWithin(item, options, keyed);
    }
    return out;
  }
  return value;
}

/** Redact and serialize, cutting the text at maxBytes with a visible marker. */
export function redactAndSerialize(value: unknown, options: RedactionOptions): string {
  const text = JSON.stringify(redactValue(value, options), null, 1) ?? 'null';
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes <= options.maxBytes) return text;
  const cut = Buffer.from(text, 'utf8').subarray(0, options.maxBytes).toString('utf8');
  return `${cut}\n…[truncated ${bytes - options.maxBytes} bytes]`;
}
