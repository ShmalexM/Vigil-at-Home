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
  [/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{16,}/gi, '$1 <token>'],
  [
    /\b((?:pass(?:word|wd)?|secret|token|api[_-]?key)\s*[=:]\s*)("[^"]*"|'[^']*'|\S+)/gi,
    '$1<redacted>',
  ],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '<email>'],
];

function escapeRegExp(text: string): string {
  return text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

export function redactString(input: string, options: Omit<RedactionOptions, 'maxBytes'>): string {
  let out = input.replace(/\/(Users|home)\/[^/\s"']+/g, '/$1/<user>');
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
  if (options.username && options.username.length >= 3) {
    out = out.replace(new RegExp(`\\b${escapeRegExp(options.username)}\\b`, 'gi'), '<user>');
  }
  if (options.hostname && options.hostname.length >= 3) {
    out = out.replace(new RegExp(escapeRegExp(options.hostname), 'gi'), '<host>');
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
