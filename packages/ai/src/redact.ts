import { hostname, userInfo } from 'node:os';

export interface RedactionOptions {
  /** The Mac's short user name, replaced wherever it appears. */
  readonly username?: string;
  /** The Mac's host name. */
  readonly hostname?: string;
  /** Upper bound for the serialized data sent to a model. */
  readonly maxBytes: number;
}

type NameOptions = Omit<RedactionOptions, 'maxBytes'>;

/** What a redacted value is replaced with. */
export const REDACTED = '<redacted>';

/**
 * The longest string redactString returns, give or take the redaction the
 * cut lands in. Text past it is dropped with a visible marker, so a hostile
 * or runaway input can't make redaction slow.
 */
export const MAX_REDACT_CHARS = 512 * 1024;

/**
 * How far past MAX_REDACT_CHARS redaction reads, so a secret the cut runs
 * through is recognized whole before the text is cut.
 */
const CUT_MARGIN = 64 * 1024;

// How redaction works. Every rule below finds spans of the text, each the
// extent of one secret value, and nothing is replaced until all are found.
// settle() then holds every span to one invariant before it is applied: a
// span never covers a shell metacharacter (; | & < > newline, backtick, $(
// or )) that the shell would act on. Redacted text is what an AI reviewer
// reads to judge an alert, so attacker-written text must not be able to
// hide the command that follows a secret. Where quoting is in doubt the
// span stops at the first metacharacter: the tail of an odd secret may
// show, a pipeline never hides.
//
// JSON is read as JSON: an object or array that parses is redacted by key
// and serialized again, never matched with a pattern.
//
// Every pattern here must run in time linear in its input: no unbounded
// repetition that can be retried from many start positions, and no nested
// quantifiers. redact.test.ts times each on adversarial input.

// ---------------------------------------------------------------------------
// The shell's view of the text.

function isMetaAt(text: string, i: number): boolean {
  switch (text.charCodeAt(i)) {
    case 0x0a: // \n
    case 0x0d: // \r
    case 0x3b: // ;
    case 0x7c: // |
    case 0x26: // &
    case 0x3c: // <
    case 0x3e: // >
    case 0x60: // `
    case 0x29: // )
      return true;
    case 0x24: // $(
      return text.charCodeAt(i + 1) === 0x28;
    default:
      return false;
  }
}

function isSpace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d || code === 0x0c;
}

function isAlnum(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a)
  );
}

/**
 * The index of the quote that closes the one at `open`, or -1. Single quotes
 * have no escapes in a shell; $'...' and double quotes do.
 */
function closingQuote(text: string, open: number): number {
  const q = text.charCodeAt(open);
  const escapes = q === 0x22 || (open > 0 && text.charCodeAt(open - 1) === 0x24);
  if (!escapes) return text.indexOf("'", open + 1);
  for (let i = open + 1; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x5c) i++;
    else if (c === q) return i;
  }
  return -1;
}

/**
 * Mark each metacharacter the shell would act on: those outside quotes, and
 * those inside quotes the scan can't vouch for. A quoted run is trusted only
 * when it closes on its own line, holds no command substitution, and isn't an
 * apostrophe in prose (a quote after a letter, with spaces inside). Quotes
 * pair as the shell pairs them, so what follows a doubtful run is read as
 * the shell reads it.
 */
function scanShell(text: string): Uint8Array {
  const n = text.length;
  const loose = new Uint8Array(n);
  let i = 0;
  while (i < n) {
    const c = text.charCodeAt(i);
    if (c === 0x5c) {
      // An escaped character is literal, but a line break stays one.
      const next = text[i + 1];
      if (next === '\n' || next === '\r') loose[i + 1] = 1;
      i += 2;
      continue;
    }
    if (c === 0x27 || c === 0x22) {
      const close = closingQuote(text, i);
      const end = close < 0 ? n : close;
      let sure = true;
      let spaced = false;
      let metas = false;
      // Escaped characters count too: an escaped line break still breaks the
      // line, and command substitution in double quotes still runs.
      for (let j = i + 1; j < end; j++) {
        const d = text.charCodeAt(j);
        if (d === 0x0a || d === 0x0d) sure = false;
        if (d === 0x20 || d === 0x09) spaced = true;
        if (isMetaAt(text, j)) {
          metas = true;
          if (c === 0x22 && (d === 0x60 || d === 0x24)) sure = false;
        }
      }
      // An apostrophe in prose: don't ... it's.
      if (spaced && i > 0 && isAlnum(text.charCodeAt(i - 1))) sure = false;
      // Left open to the end of the text: trusted only with nothing to hide.
      if (close < 0 && metas) sure = false;
      if (!sure) for (let j = i + 1; j < end; j++) if (isMetaAt(text, j)) loose[j] = 1;
      i = end + 1;
      continue;
    }
    if (isMetaAt(text, i)) loose[i] = 1;
    i++;
  }
  return loose;
}

// ---------------------------------------------------------------------------
// Spans, and the invariant every span is held to.

interface Span {
  readonly start: number;
  end: number;
  /** What the span is replaced with. */
  with: string;
  /** The higher wins where spans overlap. */
  rank: number;
  /** A YAML block or a private key, which may run over several lines. */
  readonly lines: boolean;
  /** Grown by joining another span: confined again. */
  joined: boolean;
}

/** User, host and email names: dropped where they overlap a secret. */
const RANK_NAME = 0;
const RANK_BASE64 = 1;
const RANK_KEYED = 2;
/** A known token format: its marker says more than <redacted>. */
const RANK_FORMAT = 3;
const RANK_KEY = 4;

function span(start: number, end: number, replacement: string, rank: number, lines = false): Span {
  return { start, end, with: replacement, rank, lines, joined: false };
}

const KEY_MARKER_LINE = /^-----(?:BEGIN|END) [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----$/;
const PEM_HEADER_LINE =
  /^(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset):[ \t][^;|&<>`$()'"]*$/;

/**
 * A line that may sit inside a multi-line value: one token of base64 or the
 * like, a `- item` of one, a PEM header, or a key's BEGIN or END line. A line
 * that could be a command never is.
 */
function isBlockLine(text: string, from: number, to: number): boolean {
  let line = text.slice(from, to).trim();
  if (!line) return true;
  for (let i = 0; i < line.length; i++) {
    const c = line.charCodeAt(i);
    if (isMetaAt(line, i) || c === 0x22 || c === 0x27) return false;
  }
  if (KEY_MARKER_LINE.test(line) || PEM_HEADER_LINE.test(line)) return true;
  if (line.startsWith('- ')) line = line.slice(2).trimStart();
  return !/\s/.test(line);
}

/**
 * Hold a span to the invariant: it ends before the first metacharacter the
 * shell would act on and, for a multi-line value, before the first line that
 * isn't one of its own. False when nothing is left of it.
 */
function confine(s: Span, text: string, loose: Uint8Array): boolean {
  let end = s.end;
  if (s.lines && /[\r\n]/.test(text.slice(s.start, end))) {
    let lineStart = s.start;
    for (let i = s.start; i <= end; i++) {
      if (i < end && text.charCodeAt(i) !== 0x0a) continue;
      if (!isBlockLine(text, lineStart, i)) {
        end = lineStart;
        break;
      }
      lineStart = i + 1;
    }
  } else {
    for (let i = s.start; i < end; i++) {
      if (loose[i]) {
        end = i;
        break;
      }
    }
  }
  while (end > s.start && isSpace(text.charCodeAt(end - 1))) end--;
  s.end = end;
  return end > s.start;
}

function byStart(a: Span, b: Span): number {
  return a.start - b.start || b.end - a.end;
}

/** Sort by start; the rules mostly find spans in order already. */
function sortSpans(spans: Span[]): Span[] {
  for (let i = 1; i < spans.length; i++) {
    if (byStart(spans[i - 1]!, spans[i]!) > 0) return spans.sort(byStart);
  }
  return spans;
}

/**
 * Join overlapping spans, given in order of their start; where secrets
 * overlap, the higher rank names the whole.
 */
function mergeOverlaps(spans: readonly Span[]): Span[] {
  const out: Span[] = [];
  for (const s of spans) {
    const last = out[out.length - 1];
    if (last && s.start < last.end) {
      if (s.end > last.end) {
        last.end = s.end;
        last.joined = true;
      }
      if (s.rank > last.rank) {
        last.rank = s.rank;
        last.with = s.with;
      }
    } else {
      out.push(s);
    }
  }
  return out;
}

/**
 * Settle the spans the rules found into the replacements to apply, in order:
 * each confined, none inside a JSON region (whose own replacement stands), and
 * none overlapping another.
 */
function settle(text: string, loose: Uint8Array, found: Span[], json: Span[]): Span[] {
  sortSpans(json);
  const secrets: Span[] = [];
  const names: Span[] = [];
  sortSpans(found);
  let r = 0;
  for (const s of found) {
    while (r < json.length && json[r]!.end <= s.start) r++;
    const region = json[r];
    if (region && region.start <= s.start) continue;
    if (region && region.start < s.end) s.end = region.start;
    if (!confine(s, text, loose)) continue;
    (s.rank === RANK_NAME ? names : secrets).push(s);
  }
  // Confining a union again only ever shortens it.
  const kept = mergeOverlaps(secrets).filter((s) => !s.joined || confine(s, text, loose));
  let k = 0;
  const shown = mergeOverlaps(names).filter((s) => {
    while (k < kept.length && kept[k]!.end <= s.start) k++;
    return !(k < kept.length && kept[k]!.start < s.end);
  });
  return shown.length || json.length ? sortSpans([...kept, ...shown, ...json]) : kept;
}

function render(text: string, spans: readonly Span[], end: number): string {
  let out = '';
  let last = 0;
  for (const s of spans) {
    if (s.start >= end) break;
    out += text.slice(last, s.start) + s.with;
    last = s.end;
  }
  return out + text.slice(last, end);
}

// ---------------------------------------------------------------------------
// Known token formats. Where a pattern has a group, only the group is the
// secret and the text around it stays.

const FORMATS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '<aws-key>'],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g, '<github-token>'],
  [/(?<![A-Za-z0-9_-])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])(?:xox[abeprs]|xapp)-[A-Za-z0-9-]{10,}/g, '<slack-token>'],
  [/\bhooks\.slack\.com\/(?:services|workflows|triggers)\/([A-Za-z0-9_/-]{8,})/g, REDACTED],
  // A JWT, or an unsigned one (alg "none") whose signature is empty.
  [
    /(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,}\.(?:eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]*|[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})/g,
    '<jwt>',
  ],
  [/\b[sr]k_(?:live|test)_[A-Za-z0-9]{10,}\b/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])AIza[0-9A-Za-z_-]{35}/g, '<api-key>'],
  [/\bnpm_[A-Za-z0-9]{36}\b/g, '<npm-token>'],
  [/(?<![A-Za-z0-9_-])glpat-[A-Za-z0-9_-]{20,}/g, '<gitlab-token>'],
  [/(?<![A-Za-z0-9_-])whsec_[A-Za-z0-9+/=]{20,}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])hf_[A-Za-z0-9]{30,}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_.-])SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])ya29\.[A-Za-z0-9_-]{20,}/g, '<oauth-token>'],
  [/(?<![A-Za-z0-9_-])shp(?:at|ss|ca|pa)_[A-Fa-f0-9]{32}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])do[opr]_v1_[a-f0-9]{64}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])pypi-[A-Za-z0-9_-]{50,}/g, '<api-key>'],
  // An AWS SigV4 signature, in an Authorization header or a presigned URL.
  [/\b(?:X-Amz-)?Signature=([0-9a-f]{64})\b/gi, REDACTED],
  // The signature of an Azure SAS URL.
  [/[?&;]sig=([A-Za-z0-9%+/=]{16,})/g, REDACTED],
  // A long bearer token outside an Authorization header. In a header, any
  // length is redacted by addKeyedValues.
  [/\b(?:Bearer|Basic)[ \t]+([A-Za-z0-9._~+/=-]{16,})/gi, '<token>'],
  // user:password in a URL, such as postgres://me:hunter2@db or redis://:pw@db.
  [
    /(?<![A-Za-z0-9+.-])[a-z][a-z0-9+.-]{0,30}:\/\/([^\s/?#@:]{0,256}:[^\s/?#]{1,256})(?=@)/gi,
    '<credentials>',
  ],
];

/**
 * The span of a match: its last group that took part, which every pattern
 * with groups ends on, or else the whole match.
 */
function matchSpan(m: RegExpExecArray, replacement: string, rank: number, offset = 0): Span {
  const end = offset + m.index + m[0].length;
  let g = m.length - 1;
  while (g > 0 && m[g] === undefined) g--;
  return span(end - m[g]!.length, end, replacement, rank);
}

/** Text without one of these holds none of the formats above. */
const FORMAT_HINT =
  /AKIA|ASIA|gh[pousr]_|github_pat_|sk-|xox|xapp-|hooks\.slack|eyJ|[sr]k_|AIza|npm_|glpat-|whsec_|hf_|SG\.|ya29\.|shp|do[opr]_v1|pypi-|signature=|sig=|bearer|basic|:\/\//i;

function addFormats(text: string, spans: Span[]): void {
  if (!FORMAT_HINT.test(text)) return;
  for (const [pattern, replacement] of FORMATS) {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
      spans.push(matchSpan(m, replacement, RANK_FORMAT));
    }
  }
}

// ---------------------------------------------------------------------------
// Private keys. A key is its BEGIN line, then lines of base64 (and the PEM or
// armor headers), then its END line. Only lines that can be part of a key are
// hidden, so a fake BEGIN line can't hide the commands written after it.

const KEY_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const KEY_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/y;
// Newlines, also as JSON escapes, and indentation.
const KEY_SEP = /(?:[ \t\r\n]|\\r|\\n){0,64}/y;
const KEY_HEADER =
  /(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset):[ \t]*[^\r\n\\|;&$`]{0,100}/y;
// A line of base64; a slash may be escaped in JSON.
const KEY_LINE = /(?:[A-Za-z0-9+=]|\\?\/){1,8192}/y;
const KEY_CHECKSUM = /=[A-Za-z0-9+/]{4}/y;
/** Key lines are 64 or 70 characters, but for the last. */
const MIN_FULL_KEY_LINE = 40;
const MAX_KEY_LINES = 512;

function stickyLength(pattern: RegExp, text: string, at: number): number {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0].length ?? 0;
}

/**
 * Where the key whose BEGIN line ends at `from` ends: at its END line when
 * only key lines lead there, else after its last line that is surely a key's.
 */
function keyBodyEnd(text: string, from: number): number {
  let pos = from;
  let body = false;
  for (let lines = 0; lines < MAX_KEY_LINES; lines++) {
    const at = pos + stickyLength(KEY_SEP, text, pos);
    const endLine = stickyLength(KEY_END, text, at);
    if (endLine) return at + endLine;
    const header = body ? 0 : stickyLength(KEY_HEADER, text, at);
    const line = header || stickyLength(KEY_LINE, text, at);
    if (!line) break;
    if (!header) body = true;
    pos = at + line;
  }
  // No END line: only full lines, and a short last one where a checksum or
  // the end of the text shows it is the last.
  let end = from;
  pos = from;
  body = false;
  for (let lines = 0; lines < MAX_KEY_LINES; lines++) {
    const at = pos + stickyLength(KEY_SEP, text, pos);
    if (!body) {
      const header = stickyLength(KEY_HEADER, text, at);
      if (header) {
        pos = end = at + header;
        continue;
      }
    }
    const line = stickyLength(KEY_LINE, text, at);
    if (!line) break;
    if (line < MIN_FULL_KEY_LINE) {
      const next = at + line + stickyLength(KEY_SEP, text, at + line);
      const last = stickyLength(KEY_CHECKSUM, text, next) > 0 || (body && next === text.length);
      if (!last) break;
    }
    body = true;
    pos = end = at + line;
  }
  return end;
}

function addPrivateKeys(text: string, spans: Span[]): void {
  if (!text.includes('PRIVATE KEY')) return;
  KEY_BEGIN.lastIndex = 0;
  for (let m = KEY_BEGIN.exec(text); m; m = KEY_BEGIN.exec(text)) {
    const end = keyBodyEnd(text, m.index + m[0].length);
    spans.push(span(m.index, end, '<private-key>', RANK_KEY, true));
    KEY_BEGIN.lastIndex = end;
  }
}

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
  'at',
  'time',
  'usage',
  'strength',
  'age',
  'rate',
  'used',
  'stdin',
]);

const CREDENTIAL_WORDS = new Set([
  'pwd',
  'auth',
  'authorization',
  'apikey',
  'accesskey',
  'privatekey',
]);
const KEY_QUALIFIER_LIST = [
  'api',
  'access',
  'private',
  'account',
  'signing',
  'encryption',
  'master',
  'session',
  'client',
  'secret',
  'shared',
];
const KEY_QUALIFIERS = new Set(KEY_QUALIFIER_LIST);
const QUALIFIED_KEY = new RegExp(`(?:${KEY_QUALIFIER_LIST.join('|')})key$`);
const QUICK_CREDENTIAL = /pass|pwd|token|secret|key|auth|credential|cookie/i;

// Names repeat, often thousands of times in one result: each is split once.
const MAX_CACHED_NAMES = 1024;
const partsCache = new Map<string, readonly string[]>();

function nameParts(name: string): readonly string[] {
  let parts = partsCache.get(name);
  if (!parts) {
    parts = name
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
    if (partsCache.size >= MAX_CACHED_NAMES) partsCache.clear();
    partsCache.set(name, parts);
  }
  return parts;
}

/** True for a name that describes a secret rather than holding one: token_count, expires_at. */
function hasNonSecretSuffix(name: string): boolean {
  const parts = nameParts(name);
  return parts.length > 0 && NON_SECRET_SUFFIXES.has(parts[parts.length - 1]!);
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
    // SMTP_PASS, pass; not pass_through.
    if (part === 'pass') return i === parts.length - 1;
    // GITHUB_TOKEN, accessToken; not max_tokens.
    if (part.endsWith('token')) return true;
    if (CREDENTIAL_WORDS.has(part)) return true;
    if (QUALIFIED_KEY.test(part)) return true;
    return part === 'key' && i > 0 && KEY_QUALIFIERS.has(parts[i - 1]!);
  });
}

/** A password-like name, where even a short number is the secret (a PIN). */
function isPasswordName(name: string): boolean {
  const parts = nameParts(name);
  return parts.some(
    (part, i) =>
      /password|passwd|passphrase/.test(part) ||
      part === 'pwd' ||
      (part === 'pass' && i === parts.length - 1),
  );
}

interface NameInfo {
  readonly credential: boolean;
  readonly password: boolean;
  readonly authorization: boolean;
  readonly cookie: boolean;
}
const nameCache = new Map<string, NameInfo>();

/** What addKeyedValues needs to know of a name, worked out once per name. */
function describeName(name: string): NameInfo {
  let info = nameCache.get(name);
  if (!info) {
    const credential = isCredentialName(name);
    const parts = credential ? nameParts(name) : [];
    info = {
      credential,
      password: credential && isPasswordName(name),
      authorization: parts.includes('authorization'),
      cookie: parts.some((p) => p.includes('cookie')),
    };
    if (nameCache.size >= MAX_CACHED_NAMES) nameCache.clear();
    nameCache.set(name, info);
  }
  return info;
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

// ---------------------------------------------------------------------------
// Values by name: PGPASSWORD=x, "password": "x", x-api-key: x, --token x.

/**
 * A name followed by its separator: NAME=, NAME: , "name": , name => , name := ,
 * --name=, or --name followed by a space and a value that isn't another flag.
 * The name must start a word, and backtracking within it fails at once, so
 * each name is read a bounded number of times whatever its length. npm's
 * _authToken starts with an underscore.
 */
const KEYED =
  /(?<![A-Za-z0-9_.-])(?:(["']?)-{0,2}(_*[A-Za-z][A-Za-z0-9_.-]*)(["']?)[ \t]*(===|==|=>|:=|[=:])[ \t]*|--([A-Za-z][A-Za-z0-9_-]*)[ \t]+(?=[^\s-]|-(?![-\s]|[A-Za-z](?:\s|$))))/g;
const AUTH_SCHEME = /(?:Bearer|Basic|Token|Digest|Negotiate|NTLM|AWS4-HMAC-SHA256)[ \t]+/iy;
// `hunter2`. A backtick value with spaces is a command, left to be read; the
// backticks of a one-word value stay in view.
const BACKTICK_WORD = /`[^`\s;|&<>$()'"]{1,256}`/y;
const MARKER = /^<[a-z-]+>$/;

function matchAt(pattern: RegExp, text: string, at: number): string {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0] ?? '';
}

/**
 * The end of the quoted string that opens at `at`: past its closing quote, or
 * at the end of the line when it has none there. Only double quotes escape.
 */
function quotedEnd(text: string, at: number): number {
  const q = text.charCodeAt(at);
  for (let i = at + 1; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === q) return i + 1;
    if (c === 0x0a || c === 0x0d) return i;
    if (c === 0x5c && q === 0x22) i++;
  }
  return text.length;
}

/** The end of a shell word from `at`: bare text and quoted strings, joined. */
function wordEnd(text: string, at: number, stops: string): number {
  let i = at;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === 0x27 || c === 0x22) {
      i = quotedEnd(text, i);
      continue;
    }
    if (isSpace(c) || isMetaAt(text, i) || stops.includes(text[i]!)) break;
    if (c === 0x5c) {
      if (i + 1 >= text.length || text[i + 1] === '\n' || text[i + 1] === '\r') break;
      i++;
    }
    i++;
  }
  return i;
}

/** The end of a bare value from `at`, which stops at a quote too. */
function bareEnd(text: string, at: number, stops: string): number {
  let i = at;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (isSpace(c) || isMetaAt(text, i) || c === 0x27 || c === 0x22 || stops.includes(text[i]!)) {
      break;
    }
    i++;
  }
  return i;
}

function unquote(value: string): string {
  const q = value[0];
  return (q === '"' || q === "'") && value.length >= 2 && value.endsWith(q)
    ? value.slice(1, -1)
    : value;
}

// ---------------------------------------------------------------------------
// YAML: `password:` with its value on the lines below, or a block scalar.
//
//   password:            private_key: |           tokens:
//     hunter2              LS0tLS1CRUdJTi...        - abc
//
// The value lines must each be one token: a line that could be a command
// ends the block.

const BLOCK_SCALAR = /[|>][-+]?[1-9]?[-+]?[ \t]*(?=\r?\n)/y;
const MAPPING_LINE = /["']?[A-Za-z0-9_.-]{1,64}["']?[ \t]*:(?:[ \t]|\r?$)/;
const MAX_BLOCK_LINES = 256;

/**
 * The value lines after the line break at `from`: lines indented past `column`,
 * or `- item` lines at `column`. Undefined when there are none, or when they
 * are a nested mapping, whose own names are checked as the scan reaches them.
 */
function indentedBlock(
  text: string,
  from: number,
  column: number,
  scalar: boolean,
): { start: number; end: number } | undefined {
  let pos = from;
  let start = -1;
  let end = -1;
  let list = false;
  for (let lines = 0; lines < MAX_BLOCK_LINES; lines++) {
    if (text[pos] === '\r') pos++;
    if (text[pos] !== '\n') break;
    const lineStart = ++pos;
    while (text[pos] === ' ' || text[pos] === '\t') pos++;
    const indent = pos - lineStart;
    const contentStart = pos;
    const newline = text.indexOf('\n', pos);
    let lineEnd = newline < 0 ? text.length : newline;
    if (lineEnd > contentStart && text[lineEnd - 1] === '\r') lineEnd--;
    if (lineEnd <= contentStart) {
      pos = lineEnd;
      continue; // A blank line inside the block.
    }
    const item = text[contentStart] === '-' && /[ \t\r\n]/.test(text[contentStart + 1] ?? '\n');
    if (start < 0) {
      if (indent > column) {
        if (!scalar && MAPPING_LINE.test(text.slice(contentStart, lineEnd))) return undefined;
      } else if (indent === column && item && !scalar) {
        list = true;
      } else {
        return undefined;
      }
    } else if (indent < column || (indent === column && !(list && item))) {
      break;
    }
    if (!isBlockLine(text, contentStart, lineEnd)) {
      if (start < 0) return undefined;
      break;
    }
    // `- item`: the dash stays.
    if (start < 0) {
      start = list ? contentStart + (text[contentStart + 1] === '\n' ? 1 : 2) : contentStart;
    }
    end = lineEnd;
    pos = lineEnd;
  }
  return start < 0 ? undefined : { start, end };
}

// ---------------------------------------------------------------------------
// Cookies: name=value pairs joined by "; ". Each value is its own span, so the
// separators stay in view and a pair list never runs into a command.

const COOKIE_ATTRIBUTES = new Set([
  'path',
  'domain',
  'expires',
  'max-age',
  'samesite',
  'secure',
  'httponly',
  'partitioned',
  'priority',
]);

function cookieNameEnd(text: string, at: number): number {
  let i = at;
  while (i < text.length && i - at < 256) {
    const c = text.charCodeAt(i);
    if (isSpace(c) || isMetaAt(text, i) || c === 0x3d || c === 0x2c || c === 0x22 || c === 0x27) {
      break;
    }
    i++;
  }
  return i;
}

/** Add the values of the cookie header whose value starts at `at`; returns where it ends. */
function addCookies(text: string, at: number, spans: Span[]): number {
  let pos = at;
  if (text[pos] === '"' || text[pos] === "'") pos++;
  for (let pairs = 0; ; pairs++) {
    const nameEnd = cookieNameEnd(text, pos);
    let valueStart = pos;
    let attribute = false;
    if (text[nameEnd] === '=') {
      valueStart = nameEnd + 1;
      attribute = pairs > 0 && COOKIE_ATTRIBUTES.has(text.slice(pos, nameEnd).toLowerCase());
    } else if (pairs > 0) {
      break;
    }
    const valueEnd = bareEnd(text, valueStart, ',\\');
    if (valueEnd > valueStart && !attribute) {
      spans.push(span(valueStart, valueEnd, REDACTED, RANK_KEYED));
    }
    pos = valueEnd;
    if (text[pos] !== ';') break;
    pos++;
    while (text[pos] === ' ' || text[pos] === '\t') pos++;
  }
  return pos;
}

/**
 * Add the value of every credential-named setting, whatever its length:
 * PGPASSWORD=x, "password": "x", x-api-key: x, --token x, Authorization: Bearer x.
 * One pass, each value read once.
 */
function addKeyedValues(text: string, spans: Span[]): void {
  KEYED.lastIndex = 0;
  for (let m = KEYED.exec(text); m; m = KEYED.exec(text)) {
    const name = describeName(m[2] ?? m[5]!);
    if (!name.credential) continue;
    const afterKey = m.index + m[0].length;
    const lead = m[1] ?? '';
    // 'x-api-key: abc' — the quote opens the shell argument, so the value runs
    // up to its closing quote and the quote stays.
    const argQuote = lead && !m[3] ? lead : '';
    const sep = m[4] ?? ' ';
    let at = afterKey;
    if (name.authorization) at += matchAt(AUTH_SCHEME, text, at).length;
    // "auth": { ... } — the names inside are checked on their own.
    if (text[at] === '{' || text[at] === '[') continue;
    if (sep === ':' && !argQuote) {
      const scalar = matchAt(BLOCK_SCALAR, text, at).length;
      if (scalar || text[at] === '\n' || text[at] === '\r') {
        const column = m.index - (text.lastIndexOf('\n', m.index - 1) + 1);
        const block = indentedBlock(text, at + scalar, column, scalar > 0);
        if (block) {
          spans.push(span(block.start, block.end, REDACTED, RANK_KEYED, true));
          KEYED.lastIndex = block.end;
        }
        continue;
      }
    }
    if (sep === ':' && name.cookie) {
      KEYED.lastIndex = Math.max(KEYED.lastIndex, addCookies(text, at, spans));
      continue;
    }
    let start = at;
    let end: number;
    if (argQuote) {
      end = at;
      while (end < text.length && text[end] !== argQuote && text[end] !== '\n') {
        if (argQuote === '"' && text[end] === '\\') end++;
        end++;
      }
      end = Math.min(end, text.length);
    } else if (text[at] === '`') {
      const word = matchAt(BACKTICK_WORD, text, at).length;
      start = at + 1;
      end = word ? at + word - 1 : start;
    } else if ((sep === '=' || sep === ' ') && !lead) {
      // A shell assignment or flag: the value is the whole shell word, so
      // 'abc'"def" and abc,def are one value.
      end = wordEnd(text, at, '}]');
    } else if (text[at] === '"' || text[at] === "'") {
      end = quotedEnd(text, at);
    } else {
      end = bareEnd(text, at, ',}]');
    }
    const bare = unquote(text.slice(start, end));
    if (end <= start || MARKER.test(bare) || isBenignValue(bare, name.password)) continue;
    spans.push(span(start, end, REDACTED, RANK_KEYED));
    KEYED.lastIndex = Math.max(KEYED.lastIndex, end);
  }
}

// ---------------------------------------------------------------------------
// `password hunter2`, as in .netrc, where the value follows a space. The words
// that follow "password" in a sentence are left alone.

// The value can't start like a separator (password => x) or a flag.
const PASSWORD_WORD =
  /(?<![A-Za-z0-9_./\\-])(?:pass(?:word|phrase))[ \t]+([^\s,;&|}\])"'`<>=:({[-][^\s,;&|}\])"'`<>]*)/gi;
const PROSE_AFTER_PASSWORD = new Set(
  (
    'a an the is are was were be been being for to and or of in on at by with from as it its this that ' +
    'these those not no must should will would can could cannot may might has have had does did do ' +
    'reset resets change changed changes expired expires expiry required prompt prompts manager ' +
    'managers field fields policy policies hash hashes hashed hashing file files protected protection ' +
    'authentication auth login please here again below above incorrect invalid wrong mismatch strength ' +
    'length set update updated entry entered input box dialog attempt attempts failed failure accepted ' +
    'rejected too if when then but so used use using based only via without store stored storage ' +
    'vault spraying spray guessing cracking brute dump dumping list lists recovery rotation history hint ' +
    'sync complexity requirements requirement rules rule protect matches match needed need sent '
  )
    .trim()
    .split(/\s+/),
);

function addPasswordWords(text: string, spans: Span[]): void {
  if (!/pass/i.test(text)) return;
  PASSWORD_WORD.lastIndex = 0;
  for (let m = PASSWORD_WORD.exec(text); m; m = PASSWORD_WORD.exec(text)) {
    const value = m[1]!;
    if (PROSE_AFTER_PASSWORD.has(value.toLowerCase()) || isBenignValue(value, true)) continue;
    spans.push(matchSpan(m, REDACTED, RANK_KEYED));
  }
}

// ---------------------------------------------------------------------------
// Passwords given as command-line flags by tools that take them that way.
// Each command runs to the end of its line or pipeline stage, read once.

const CURL_COMMAND = /\bcurl\b[^\n;|&]*/g;
const SSHPASS_COMMAND = /\bsshpass\b[^\n;|&]*/g;
const DOCKER_COMMAND = /\bdocker\b[^\n;|&]*/g;
const OPENSSL_COMMAND = /\bopenssl\b[^\n;|&]*/g;
const MYSQL_COMMAND = /\b(?:mysql|mariadb)[a-z]*\b[^\n;|&]*/g;
// curl -u user:pass, --user user:pass, -uuser:pass.
const CURL_USER =
  /\s(?:-u[ \t]*|--user(?:[ \t]+|=))(?:(["'])[^"'\n:]{0,256}:([^"'\n]{1,512})(?=\1)|[^\s"':]{0,256}:([^\s"']{1,512}))/g;
// sshpass -p pw, docker login -p pw: the first -p only, as later ones belong
// to the command sshpass runs.
const DASH_P = /\s-p[ \t]*("[^"\n]*"|'[^'\n]*'|[^\s"'-]\S*)/;
const OPENSSL_SECRET =
  /\s(?:-[kK][ \t]+|-pass(?:in|out)?[ \t]+pass:)("[^"\n]*"|'[^'\n]*'|[^\s"']+)/g;
// mysql -phunter2. For the MySQL tools, which take the password glued to -p:
// elsewhere -p is a port (ssh -p 22) or a plain flag (mkdir -p).
const MYSQL_GLUED_PASSWORD = /\s-p([^\s-]\S*)/g;

const COMMAND_HINT = /curl|sshpass|docker|openssl|mysql|mariadb/;

function addCommandSecrets(text: string, spans: Span[]): void {
  if (!COMMAND_HINT.test(text)) return;
  const each = (command: RegExp, flag: RegExp, when?: (c: string) => boolean) => {
    command.lastIndex = 0;
    for (let c = command.exec(text); c; c = command.exec(text)) {
      const line = c[0];
      if (when && !when(line)) continue;
      flag.lastIndex = 0;
      for (let m = flag.exec(line); m; m = flag.global ? flag.exec(line) : null) {
        spans.push(matchSpan(m, REDACTED, RANK_KEYED, c.index));
      }
    }
  };
  each(CURL_COMMAND, CURL_USER);
  each(SSHPASS_COMMAND, DASH_P);
  each(DOCKER_COMMAND, DASH_P, (c) => /\slogin\b/.test(c));
  each(OPENSSL_COMMAND, OPENSSL_SECRET);
  each(MYSQL_COMMAND, MYSQL_GLUED_PASSWORD);
}

// ---------------------------------------------------------------------------
// XML: <password>x</password>, and <add key="StripeApiKey" value="x" />.

const XML_ELEMENT =
  /<((?:[A-Za-z_][\w.-]{0,63}:)?([A-Za-z_][\w.-]{0,63}))(\s[^<>]*)?>([^<]*)<\/\1>/g;
const XML_KEYED_ATTRIBUTE =
  /\b(?:key|name)=(["'])([^"'\n<>]{1,128})\1\s+value=(["'])([^"'\n]*)(?=\3)/gi;

function addXml(text: string, spans: Span[]): void {
  if (!text.includes('<')) return;
  XML_ELEMENT.lastIndex = 0;
  for (let m = XML_ELEMENT.exec(text); m; m = XML_ELEMENT.exec(text)) {
    const [local, body] = [m[2]!, m[4]!];
    if (isCredentialName(local) && !isBenignValue(body.trim(), isPasswordName(local))) {
      const end = m.index + m[0].length - m[1]!.length - 3;
      spans.push(span(end - body.length, end, REDACTED, RANK_KEYED));
    }
  }
  XML_KEYED_ATTRIBUTE.lastIndex = 0;
  for (let m = XML_KEYED_ATTRIBUTE.exec(text); m; m = XML_KEYED_ATTRIBUTE.exec(text)) {
    const [key, value] = [m[2]!, m[4]!];
    if (isCredentialName(key) && !isBenignValue(value, isPasswordName(key))) {
      spans.push(matchSpan(m, REDACTED, RANK_KEYED));
    }
  }
}

// ---------------------------------------------------------------------------
// Secrets hidden in base64, such as {"password":"hunter2"} or MYSQL_PWD=x
// encoded. A run may follow an equals sign, as in data=eyJ... Runs of any
// length are decoded a bounded chunk at a time, each read with the tail of
// the one before, by the same rules as plain text.

const BASE64_RUN = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}/g;
/** Base64 characters decoded at a time: a multiple of 4. */
const BASE64_CHUNK = 4096;
/** Decoded characters carried into the next chunk, so a name split by a chunk is still read. */
const BASE64_CARRY = 256;
const DECODED_SECRET =
  /pass(?:word|wd)|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|credential|authorization|"alg"\s*:/i;

function mostlyPrintable(text: string): boolean {
  let printable = 0;
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7f) || c === 0x0a || c === 0x0d || c === 0x09) printable++;
  }
  return printable / text.length >= 0.9;
}

/** True when decoded text names a secret: a credential name with a value, or a known format. */
function namesSecret(text: string): boolean {
  if (DECODED_SECRET.test(text)) return true;
  const found: Span[] = [];
  addFormats(text, found);
  if (found.length) return true;
  addKeyedValues(text, found);
  return found.length > 0;
}

function hidesSecret(run: string): boolean {
  let carry = '';
  for (let at = 0; at < run.length; at += BASE64_CHUNK) {
    const piece = Buffer.from(run.slice(at, at + BASE64_CHUNK), 'base64').toString('latin1');
    if (piece.length && mostlyPrintable(piece)) {
      const decoded = carry + piece;
      if (decoded.length >= 8 && namesSecret(decoded)) return true;
      carry = decoded.slice(-BASE64_CARRY);
    } else {
      carry = '';
    }
  }
  return false;
}

function addBase64(text: string, spans: Span[]): void {
  BASE64_RUN.lastIndex = 0;
  for (let m = BASE64_RUN.exec(text); m; m = BASE64_RUN.exec(text)) {
    if (hidesSecret(m[0])) {
      spans.push(span(m.index, m.index + m[0].length, '<base64-secret>', RANK_BASE64));
    }
  }
}

// ---------------------------------------------------------------------------
// JSON. Each object or array in the text that parses is redacted by key with
// redactValue and serialized again, so a value under a credential key is
// replaced whatever its shape, and nothing beside it is touched. One that
// doesn't parse, has a key twice (which parsing would hide), nests too deep,
// or holds a metacharacter the shell would act on is left to the text rules,
// which are held to the shell's reading: '{"token":"x'; id; '"}' parses, but
// the shell runs the id.

/** How deep JSON found in a string, inside JSON found in a string, is read. */
const MAX_TEXT_DEPTH = 4;
/** Deeper than this, a value is replaced whole rather than walked. */
const MAX_DEPTH = 64;

interface Bracketed {
  /** Past the closing bracket, or -1 when the brackets don't balance. */
  readonly end: number;
  /** Where the scan stopped. */
  readonly stop: number;
  /** Object members, counted as keys followed by a colon. */
  readonly members: number;
  readonly strings: boolean;
}

const closers = new Uint8Array(MAX_DEPTH);

/**
 * Read the brackets that open at `open` to the one that closes them, minding
 * strings. Brackets nested deeper than redactValue walks are not JSON to it.
 */
function bracketed(text: string, open: number): Bracketed {
  let depth = 0;
  let members = 0;
  let strings = false;
  let key = false;
  for (let i = open; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) {
      strings = true;
      for (i++; i < text.length; i++) {
        const d = text.charCodeAt(i);
        if (d === 0x5c) i++;
        else if (d === 0x22) break;
        else if (d < 0x20) return { end: -1, stop: i, members, strings };
      }
      key = closers[depth - 1] === 0x7d;
      continue;
    }
    if (c === 0x7b || c === 0x5b) {
      if (depth >= MAX_DEPTH) return { end: -1, stop: i, members, strings };
      closers[depth++] = c + 2;
    } else if (c === 0x7d || c === 0x5d) {
      if (!depth || closers[--depth] !== c) return { end: -1, stop: i, members, strings };
      if (!depth) return { end: i + 1, stop: i + 1, members, strings };
    } else if (c === 0x3a && key) {
      members++;
    }
    if (!isSpace(c)) key = false;
  }
  return { end: -1, stop: text.length, members, strings };
}

/** The keys of every object in a parsed value, or -1 when it nests too deep. */
function countKeys(value: unknown, depth: number): number {
  if (!value || typeof value !== 'object') return 0;
  if (depth >= MAX_DEPTH) return -1;
  let count = 0;
  const items = Array.isArray(value) ? value : Object.values(value);
  if (!Array.isArray(value)) count += items.length;
  for (const item of items) {
    const inner = countKeys(item, depth + 1);
    if (inner < 0) return -1;
    count += inner;
  }
  return count;
}

/**
 * Serialize redacted JSON in the original's layout. A quote, backtick or
 * dollar sign the original only wrote escaped stays escaped, so the text
 * around it reads as it did.
 */
function reserialize(value: unknown, original: string): string {
  let space: string | number = 0;
  if (original.includes('\n')) {
    const indent = /\n([ \t]+)\S/.exec(original)?.[1];
    space = indent?.includes('\t') ? '\t' : indent ? Math.min(indent.length, 10) : 2;
  }
  let out = JSON.stringify(value, null, space);
  for (const [char, escape] of [
    ["'", '\\u0027'],
    ['`', '\\u0060'],
    ['$', '\\u0024'],
  ] as const) {
    if (!original.includes(char) && out.includes(char)) out = out.split(char).join(escape);
  }
  return out;
}

function redactJson(slice: string, members: number, options: NameOptions, depth: number) {
  // Nothing in it to redact: no need to parse it. Escapes are parsed, as
  // \u0070assword is password.
  if (!mayHoldSecret(slice, options)) return slice;
  let parsed: unknown;
  try {
    parsed = JSON.parse(slice);
  } catch {
    return undefined;
  }
  if (!parsed || typeof parsed !== 'object' || countKeys(parsed, 0) !== members) return undefined;
  const before = changes;
  const redacted = redactWithin(parsed, options, undefined, 0, new Set(), depth + 1);
  return changes === before ? slice : reserialize(redacted, slice);
}

/**
 * True when the shell would act on a metacharacter in text[from, to). A line
 * break doesn't count: in JSON that parses, it can only sit between values.
 */
function actsInShell(text: string, loose: Uint8Array, from: number, to: number): boolean {
  for (let i = from; i < to; i++) {
    if (loose[i] && text[i] !== '\n' && text[i] !== '\r') return true;
  }
  return false;
}

/**
 * Add a span for each JSON object or array in the text. A failed candidate is
 * retried one character on while the work stays within a few passes over the
 * text, then skipped whole, so brackets that never balance stay linear.
 */
function addJson(
  text: string,
  loose: () => Uint8Array,
  options: NameOptions,
  depth: number,
  spans: Span[],
): void {
  const budget = 2 * text.length + 64 * 1024;
  let work = 0;
  let i = 0;
  while (i < text.length) {
    let open = i;
    while (open < text.length && text[open] !== '{' && text[open] !== '[') open++;
    if (open >= text.length) return;
    const scan = bracketed(text, open);
    work += scan.stop - open;
    if (scan.end > 0 && scan.strings && !actsInShell(text, loose(), open, scan.end)) {
      work += scan.end - open;
      const replacement = redactJson(text.slice(open, scan.end), scan.members, options, depth);
      if (replacement !== undefined) {
        spans.push(span(open, scan.end, replacement, Infinity));
        i = scan.end;
        continue;
      }
    }
    i = work < budget ? open + 1 : Math.max(open + 1, scan.stop);
  }
}

// ---------------------------------------------------------------------------
// User, host and email names.

const HOME = /\/(?:Users|home)\/([^/\s"']+)/g;
const EMAIL = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}/g;

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

function addNames(text: string, options: NameOptions, spans: Span[]): void {
  const each = (pattern: RegExp, replacement: string) => {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
      const s = matchSpan(m, replacement, RANK_NAME);
      if (s.end > s.start) spans.push(s);
      else pattern.lastIndex++;
    }
  };
  each(HOME, '<user>');
  each(EMAIL, '<email>');
  if (worthHiding(options.hostname)) {
    each(new RegExp(escapeRegExp(options.hostname), 'gi'), '<host>');
    // Alexs-MacBook-Pro.local is often written without its domain.
    const short = options.hostname.split('.')[0];
    if (short !== options.hostname && worthHiding(short)) {
      each(new RegExp(`(?<![A-Za-z0-9_-])${escapeRegExp(short)}(?![A-Za-z0-9_-])`, 'gi'), '<host>');
    }
  }
  if (worthHiding(options.username)) {
    each(new RegExp(`\\b${escapeRegExp(options.username)}\\b`, 'gi'), '<user>');
  }
}

/**
 * Text that matches none of this holds nothing any rule above looks for: a
 * credential-like name, a token format's prefix, a command that takes a
 * password, an email, a home folder, a base64 run or a JSON escape.
 */
const SECRET_HINT = new RegExp(
  [
    QUICK_CREDENTIAL.source,
    FORMAT_HINT.source,
    COMMAND_HINT.source,
    '@',
    '\\/(?:Users|home)\\/',
    '[A-Za-z0-9+/_-]{16}',
    '\\\\',
  ].join('|'),
  'i',
);

function mayHoldSecret(text: string, options: NameOptions): boolean {
  if (SECRET_HINT.test(text)) return true;
  const lower = text.toLowerCase();
  return [options.username, options.hostname?.split('.')[0]].some(
    (name) => worthHiding(name) && lower.includes(name.toLowerCase()),
  );
}

// ---------------------------------------------------------------------------
// The cut for over-long input, made after redaction.

/** How far back the cut looks for whitespace before it settles for punctuation. */
const CUT_WINDOW = 1024;

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
 * Where redacted text is cut: at MAX_REDACT_CHARS, but never inside a
 * replacement (the cut moves past it) or a word (the cut goes back to
 * whitespace, or else to punctuation), so no secret the rules didn't know is
 * left with its head on one side and only a tail to see.
 */
function cutPoint(text: string, spans: readonly Span[]): number {
  const limit = MAX_REDACT_CHARS;
  let floor = 0;
  for (const s of spans) {
    if (s.start >= limit) break;
    if (s.end > limit) return s.end;
    floor = s.end;
  }
  if (floor === limit) return limit;
  for (let i = limit; i > Math.max(floor, limit - CUT_WINDOW); i--) {
    if (text.charCodeAt(i - 1) <= 0x20) return i;
  }
  for (let i = limit; i > floor; i--) if (isBoundary(text.charCodeAt(i - 1))) return i;
  return floor;
}

function redactText(input: string, options: NameOptions, depth: number): string {
  const clipped = input.length > MAX_REDACT_CHARS;
  if (!clipped && !mayHoldSecret(input, options)) return input;
  const text = clipped ? input.slice(0, MAX_REDACT_CHARS + CUT_MARGIN) : input;
  let shell: Uint8Array | undefined;
  const loose = () => (shell ??= scanShell(text));
  const json: Span[] = [];
  if (depth < MAX_TEXT_DEPTH) addJson(text, loose, options, depth, json);
  const found: Span[] = [];
  addPrivateKeys(text, found);
  addFormats(text, found);
  addCommandSecrets(text, found);
  addXml(text, found);
  addKeyedValues(text, found);
  addPasswordWords(text, found);
  addBase64(text, found);
  addNames(text, options, found);
  const spans = found.length || json.length ? settle(text, loose(), found, json) : found;
  const end = clipped ? cutPoint(text, spans) : text.length;
  const out = render(text, spans, end);
  return end < input.length ? `${out}…[truncated ${input.length - end} characters]` : out;
}

export function redactString(input: string, options: NameOptions): string {
  return redactText(input, options, 0);
}

/**
 * Redact every string in a JSON-like value. Keys are kept. A value under a
 * credential-named key (password, x-api-key, authToken, ...) is replaced
 * whatever it looks like; when that value is an object or array, its shape is
 * kept and every string and number inside it is replaced, booleans and null
 * aside, and numbers under names like expires_at. A value nested too deep, a
 * cycle, or one that throws when read is replaced whole.
 */
export function redactValue(value: unknown, options: NameOptions): unknown {
  return redactWithin(value, options, undefined, 0, new Set(), 0);
}

/** Counts the values redactWithin changes, so a caller can tell nothing was. */
let changes = 0;

function changed<T>(value: T): T {
  changes++;
  return value;
}

/** `secret` is set under a credential-named key: true when it names a password. */
function redactWithin(
  value: unknown,
  options: NameOptions,
  secret: { password: boolean } | undefined,
  depth: number,
  ancestors: Set<object>,
  textDepth: number,
): unknown {
  if (secret) {
    if (typeof value === 'string') {
      return isBenignValue(value, secret.password) ? value : changed(REDACTED);
    }
    if (typeof value === 'number') {
      return isBenignNumber(value, secret.password) ? value : changed(REDACTED);
    }
    if (typeof value === 'bigint') return changed(REDACTED);
  }
  if (typeof value === 'string') {
    const out = redactText(value, options, textDepth);
    return out === value ? value : changed(out);
  }
  if (!value || typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH || ancestors.has(value)) return changed(REDACTED);
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) =>
        redactWithin(item, options, secret, depth + 1, ancestors, textDepth),
      );
    }
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      let redacted: unknown;
      if (secret && typeof item === 'number' && hasNonSecretSuffix(key)) {
        redacted = item;
      } else {
        const name = describeName(key);
        const keyed =
          secret || name.credential
            ? { password: !!secret?.password || (secret ? isPasswordName(key) : name.password) }
            : undefined;
        redacted = redactWithin(item, options, keyed, depth + 1, ancestors, textDepth);
      }
      if (key === '__proto__') {
        // Kept as a key, not taken for the prototype.
        Object.defineProperty(out, key, {
          value: redacted,
          enumerable: true,
          writable: true,
          configurable: true,
        });
      } else {
        out[key] = redacted;
      }
    }
    return out;
  } catch {
    // A getter or proxy that throws: nothing of it is passed on.
    return changed(REDACTED);
  } finally {
    ancestors.delete(value);
  }
}

/**
 * Redact and serialize, cutting the text at maxBytes with a visible marker.
 * The cut never splits a character or leaves half a redaction marker.
 */
export function redactAndSerialize(value: unknown, options: RedactionOptions): string {
  const text = JSON.stringify(redactValue(value, options), null, 1) ?? 'null';
  const bytes = Buffer.byteLength(text, 'utf8');
  if (bytes <= options.maxBytes) return text;
  const buffer = Buffer.from(text, 'utf8');
  let end = Math.max(0, options.maxBytes);
  // Back up to the first byte of a character the cut runs through.
  while (end > 0 && (buffer[end]! & 0xc0) === 0x80) end--;
  const cut = buffer
    .subarray(0, end)
    .toString('utf8')
    .replace(/<[a-z-]{0,30}$/, '');
  return `${cut}\n…[truncated ${bytes - Buffer.byteLength(cut, 'utf8')} bytes]`;
}
