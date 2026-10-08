import { hostname, userInfo } from 'node:os';

export interface RedactionOptions {
  /** The Mac's short user name, replaced wherever it appears. */
  readonly username?: string;
  /** The Mac's host name. */
  readonly hostname?: string;
  /** Upper bound for the serialized data sent to a model. */
  readonly maxBytes: number;
}

const SECRET_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, '<private-key>'],
  [/\bAKIA[0-9A-Z]{16}\b/g, '<aws-key>'],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g, '<github-token>'],
  [/\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}\b/g, '<api-key>'],
  [/\bxox[abprs]-[A-Za-z0-9-]{10,}\b/g, '<slack-token>'],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, '<jwt>'],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g, '<api-key>'],
  [/\bAIza[0-9A-Za-z_-]{35}/g, '<api-key>'],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, '<npm-token>'],
  [/\bglpat-[A-Za-z0-9_-]{20,}/g, '<gitlab-token>'],
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}/gi, '$1 <token>'],
  // user:password in a URL, such as postgres://me:hunter2@db.
  [/\b([a-z][a-z0-9+.-]*:\/\/)[^\s/?#@:]+:[^\s/?#]+@/gi, '$1<credentials>@'],
  // password=…, DB_PASSWORD=…, AWS_SECRET_ACCESS_KEY: …, "token": "…".
  [
    /(?<![A-Za-z0-9_])((?:[A-Za-z0-9]+[_-]){0,6}(?:pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key)(?:[_-][A-Za-z0-9]+){0,3}["']?\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi,
    '$1<redacted>',
  ],
  // --password hunter2, --github-token abc: the value after a space.
  [
    /(\s--(?:[a-z0-9]+-){0,4}(?:pass(?:word|wd|phrase)?|secret|token|api-?key|access-key)\s+)(?!-)("[^"]*"|'[^']*'|\S+)/gi,
    '$1<redacted>',
  ],
  // mysql -phunter2. Only for the MySQL tools, which take the password glued
  // to -p: elsewhere -p is a port (ssh -p 22) or a plain flag (mkdir -p).
  [
    /\b((?:mysql|mariadb|mysqldump|mysqladmin|mysqlimport|mysqlshow|mysqlcheck)(?:\s[^\n;|&]*?)?\s-p)(?=[^\s-])\S+/g,
    '$1<redacted>',
  ],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>'],
];

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
  let out = input.replace(/\/(Users|home)\/[^/\s"']+/g, '/$1/<user>');
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
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
  return out;
}

/** Redact every string in a JSON-like value. Keys are kept; values are rewritten. */
export function redactValue(value: unknown, options: Omit<RedactionOptions, 'maxBytes'>): unknown {
  if (typeof value === 'string') return redactString(value, options);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, options));
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) out[key] = redactValue(item, options);
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
