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
 * What a whole field is replaced with when a secret in it can't be cut out
 * exactly. Visible, so no one reads the field as harmless or empty.
 */
export const WITHHELD = '[withheld: may contain a secret]';

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

// How redaction works. Redacted text is what an AI reviewer reads to judge an
// alert, so attacker-written text must never be able to make a redaction hide
// a command. Every field has exactly one of two outcomes:
//
// - Precise: each secret is a single token in a plain value position
//   (NAME=value, a known flag's value, a header value, a JSON string from a
//   clean parse, a known token format), made only of characters no shell
//   acts on, not in command position, in a field with no comment, backtick
//   or heredoc. Only those tokens are replaced; every other character stays,
//   in order. A real private key's base64 lines are the one multi-line case.
// - Withheld: anything else a rule takes for a possible secret replaces the
//   whole field with WITHHELD. Dropping a field visibly can't make a command
//   look harmless.
//
// A field is the string being redacted; in structured data, each string.
//
// Every pattern here must run in time linear in its input: no unbounded
// repetition that can be retried from many start positions, and no nested
// quantifiers. redact.test.ts times each on adversarial input.

// ---------------------------------------------------------------------------
// Characters, tokens and fields.

/** A character a precise token may hold: printable ASCII that no shell acts on. */
function isSafeCode(code: number): boolean {
  if (code <= 0x20 || code >= 0x7f) return false;
  switch (code) {
    case 0x22: // "
    case 0x27: // '
    case 0x60: // `
    case 0x24: // $
    case 0x3b: // ;
    case 0x26: // &
    case 0x7c: // |
    case 0x3c: // <
    case 0x3e: // >
    case 0x28: // (
    case 0x29: // )
    case 0x7b: // {
    case 0x7d: // }
    case 0x23: // #
    case 0x5c: // \
      return false;
    default:
      return true;
  }
}

function isSafeToken(text: string, start: number, end: number): boolean {
  if (end <= start) return false;
  for (let i = start; i < end; i++) if (!isSafeCode(text.charCodeAt(i))) return false;
  return true;
}

function isSpace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d || code === 0x0c;
}

/**
 * True when a word starting at `start` could be a command the shell runs:
 * at the start of the field, a line or a pipeline stage, or right after a
 * substitution or group opener. Quotes and blanks before it don't count.
 */
function inCommandPosition(text: string, start: number): boolean {
  let i = start - 1;
  while (i >= 0) {
    const c = text.charCodeAt(i);
    if (c === 0x20 || c === 0x09 || c === 0x22 || c === 0x27) i--;
    else break;
  }
  if (i < 0) return true;
  switch (text.charCodeAt(i)) {
    case 0x0a: // \n
    case 0x0d: // \r
    case 0x3b: // ;
    case 0x7c: // |
    case 0x26: // &
    case 0x28: // (
    case 0x29: // )
    case 0x60: // `
    case 0x7b: // {
    case 0x7d: // }
    case 0x21: // !
      return true;
    default:
      return false;
  }
}

/** A comment, a backtick or a heredoc: text whose shell reading can't be vouched for. */
const HAZARD = /[#`]|<</;

/** What a rule found: a replacement, or a reason to withhold the field. */
interface Finding {
  readonly start: number;
  readonly end: number;
  /** What the span is replaced with. */
  readonly with: string;
  /** The higher wins where spans overlap. */
  readonly rank: number;
  /** The field can't be redacted precisely. */
  readonly withhold: boolean;
}

/** User, host and email names: privacy, not secrets, and dropped where they overlap one. */
const RANK_NAME = 0;
const RANK_BASE64 = 1;
const RANK_KEYED = 2;
/** A known token format: its marker says more than <redacted>. */
const RANK_FORMAT = 3;
const RANK_KEY = 4;

class Findings {
  readonly list: Finding[] = [];
  readonly text: string;

  constructor(text: string) {
    this.text = text;
  }

  /** A secret token: replaced when it can be cut out exactly, else the field is withheld. */
  token(start: number, end: number, replacement: string, rank: number): void {
    if (end <= start) return;
    const precise = isSafeToken(this.text, start, end) && !inCommandPosition(this.text, start);
    this.list.push({ start, end, with: replacement, rank, withhold: !precise });
  }

  /** A secret that can't be cut out exactly. */
  withhold(at: number): void {
    this.list.push({ start: at, end: at, with: '', rank: RANK_KEY, withhold: true });
  }

  /** A run its rule has already proven safe to replace, such as a private key's body. */
  block(start: number, end: number, replacement: string, rank: number): void {
    this.list.push({ start, end, with: replacement, rank, withhold: false });
  }

  /** A user, host or email name: replaced only where that can't hide anything. */
  name(start: number, end: number, replacement: string): void {
    if (isSafeToken(this.text, start, end)) {
      this.list.push({ start, end, with: replacement, rank: RANK_NAME, withhold: false });
    }
  }

  push(finding: Finding): void {
    this.list.push(finding);
  }
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
 * The extent of a match: its last group that took part, which every pattern
 * with groups ends on, or else the whole match.
 */
function matchRange(m: RegExpExecArray, offset = 0): readonly [number, number] {
  const end = offset + m.index + m[0].length;
  let g = m.length - 1;
  while (g > 0 && m[g] === undefined) g--;
  return [end - m[g]!.length, end];
}

/** Text without one of these holds none of the formats above. */
const FORMAT_HINT =
  /AKIA|ASIA|gh[pousr]_|github_pat_|sk-|xox|xapp-|hooks\.slack|eyJ|[sr]k_|AIza|npm_|glpat-|whsec_|hf_|SG\.|ya29\.|shp|do[opr]_v1|pypi-|signature=|sig=|bearer|basic|:\/\//i;

function addFormats(text: string, f: Findings): void {
  if (!FORMAT_HINT.test(text)) return;
  for (const [pattern, replacement] of FORMATS) {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
      const [start, end] = matchRange(m);
      f.token(start, end, replacement, RANK_FORMAT);
    }
  }
}

// ---------------------------------------------------------------------------
// Private keys. Only a real one is redacted in place: its BEGIN and END lines
// each alone on their line, and between them nothing but base64 lines of the
// standard 64 characters, the last shorter. Anything else that names a
// private key withholds the field, so a fake key can't hide the lines in it.

const KEY_BEGIN = /-----BEGIN ([A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?)-----/g;
const KEY_LINE = /^[A-Za-z0-9+/]{1,64}={0,2}$/;
const KEY_LINE_LENGTH = 64;
const MAX_KEY_LINES = 512;
/** DER (an ASN.1 SEQUENCE) or OpenSSH's own format. */
const KEY_BODY_START = /^(?:M|b3BlbnNzaC1rZXktdjE)/;

/** The bounds of the line holding `at`, trimmed of blanks and a carriage return. */
function trimmedLine(text: string, from: number): { start: number; end: number; next: number } {
  const newline = text.indexOf('\n', from);
  const next = newline < 0 ? text.length : newline;
  let start = from;
  let end = next;
  while (start < end && (text[start] === ' ' || text[start] === '\t')) start++;
  while (
    end > start &&
    (text[end - 1] === ' ' || text[end - 1] === '\t' || text[end - 1] === '\r')
  ) {
    end--;
  }
  return { start, end, next };
}

/** The body of the key whose BEGIN line `m` matched, when it is a real key. */
function keyBody(text: string, m: RegExpExecArray): { start: number; end: number } | undefined {
  let before = m.index - 1;
  while (before >= 0 && (text[before] === ' ' || text[before] === '\t')) before--;
  if (before >= 0 && text[before] !== '\n') return undefined;
  const header = trimmedLine(text, m.index);
  if (header.end !== m.index + m[0].length || header.next >= text.length) return undefined;
  const endLine = `-----END ${m[1]}-----`;
  let pos = header.next + 1;
  let start = -1;
  let end = -1;
  let total = 0;
  let short = false;
  for (let lines = 0; lines <= MAX_KEY_LINES; lines++) {
    const line = trimmedLine(text, pos);
    const length = line.end - line.start;
    if (length === endLine.length && text.startsWith(endLine, line.start)) {
      return start >= 0 && total % 4 === 0 ? { start, end } : undefined;
    }
    // Only the last line may be short or padded.
    if (short || length > KEY_LINE_LENGTH) return undefined;
    const content = text.slice(line.start, line.end);
    if (!KEY_LINE.test(content)) return undefined;
    if (start < 0 && !KEY_BODY_START.test(content)) return undefined;
    // A line with no capital and no padding could be a command or a path:
    // base64 almost never writes one.
    if (!/[A-Z=]/.test(content)) return undefined;
    short = length < KEY_LINE_LENGTH || content.endsWith('=');
    if (start < 0) start = line.start;
    end = line.end;
    total += length;
    if (line.next >= text.length) return undefined;
    pos = line.next + 1;
  }
  return undefined;
}

function addPrivateKeys(text: string, f: Findings): void {
  if (!text.includes('PRIVATE KEY')) return;
  KEY_BEGIN.lastIndex = 0;
  for (let m = KEY_BEGIN.exec(text); m; m = KEY_BEGIN.exec(text)) {
    const body = keyBody(text, m);
    if (!body) {
      f.withhold(m.index);
      return;
    }
    f.block(body.start, body.end, '<private-key>', RANK_KEY);
    KEY_BEGIN.lastIndex = body.end;
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

/** A value already redacted. */
const MARKER = /^<[a-z-]+>$/;

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

/** Where a bare value ends, whatever the context: the shell's own word breaks. */
const VALUE_STOPS = ';&|<>)';
/** What may follow a quoted value without joining more text to it. */
const QUOTE_FOLLOWERS = ',;&|)}]<>';

function matchAt(pattern: RegExp, text: string, at: number): string {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0] ?? '';
}

/** A value, unless it is empty, already redacted or can't be a secret. */
function addSecret(
  text: string,
  start: number,
  end: number,
  password: boolean,
  f: Findings,
  benign = true,
): void {
  const value = text.slice(start, end);
  if (MARKER.test(value) || (benign ? isBenignValue(value, password) : value === '')) return;
  f.token(start, end, REDACTED, RANK_KEYED);
}

/**
 * Add the value that starts at `at`: a quoted string closed on its line and
 * followed by nothing joined to it, or a bare run up to a blank, one of the
 * shell's word breaks, or one of `stops`. Returns where the value ends.
 */
function addValue(text: string, at: number, stops: string, password: boolean, f: Findings): number {
  const q = text[at];
  if (q === '"' || q === "'") {
    let close = at + 1;
    while (close < text.length && text[close] !== q && text[close] !== '\n') close++;
    if (text[close] !== q) {
      f.withhold(at);
      return close;
    }
    const after = close + 1;
    if (after < text.length && !isSpace(text.charCodeAt(after))) {
      if (!QUOTE_FOLLOWERS.includes(text[after]!)) {
        f.withhold(at);
        return after;
      }
    }
    addSecret(text, at + 1, close, password, f);
    return after;
  }
  let end = at;
  while (end < text.length) {
    const c = text[end]!;
    if (isSpace(text.charCodeAt(end)) || VALUE_STOPS.includes(c) || stops.includes(c)) break;
    end++;
  }
  addSecret(text, at, end, password, f);
  return end;
}

// ---------------------------------------------------------------------------
// YAML: `password:` with its value on the lines below, or a block scalar.
//
//   password:            private_key: |           tokens:
//     hunter2              LS0tLS1CRUdJTi...        - abc
//
// A value written over several lines can't be told from the commands after
// it, so it always withholds the field.

const BLOCK_SCALAR = /[|>][-+]?[1-9]?[-+]?[ \t]*(?=\r?\n)/y;
const MAPPING_LINE = /["']?[A-Za-z0-9_.-]{1,64}["']?[ \t]*:(?:[ \t]|\r?\n|\r?$)/y;
const MAX_BLOCK_LINES = 256;

/**
 * True when value lines follow the line break at `from`: lines indented past
 * `column`, or `- item` lines at `column`. A nested mapping is not a value:
 * its own names are checked as the scan reaches them.
 */
function hasValueBlock(text: string, from: number, column: number, scalar: boolean): boolean {
  let pos = from;
  for (let lines = 0; lines < MAX_BLOCK_LINES; lines++) {
    if (text[pos] === '\r') pos++;
    if (text[pos] !== '\n') return false;
    const lineStart = ++pos;
    while (text[pos] === ' ' || text[pos] === '\t') pos++;
    if (pos >= text.length) return false;
    if (text[pos] === '\n' || text[pos] === '\r') continue; // A blank line.
    const indent = pos - lineStart;
    if (indent > column) {
      MAPPING_LINE.lastIndex = pos;
      return scalar || !MAPPING_LINE.test(text);
    }
    const item = text[pos] === '-' && /[ \t\r\n]/.test(text[pos + 1] ?? '\n');
    return !scalar && indent === column && item;
  }
  return false;
}

// ---------------------------------------------------------------------------
// Cookies: name=value pairs joined by "; ". Each value is its own token, so
// the separators stay in view.

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
    if (!isSafeCode(c) || c === 0x3d || c === 0x2c) break;
    i++;
  }
  return i;
}

/** Add the values of the cookie header whose value starts at `at`; returns where it ends. */
function addCookies(text: string, at: number, argQuote: string, f: Findings): number {
  let pos = at;
  let quote = argQuote;
  if (!quote && (text[pos] === '"' || text[pos] === "'")) quote = text[pos++]!;
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
    let valueEnd = valueStart;
    while (valueEnd < text.length) {
      const c = text[valueEnd]!;
      if (isSpace(text.charCodeAt(valueEnd)) || c === ';' || c === ',' || c === quote) break;
      valueEnd++;
    }
    if (!attribute) addSecret(text, valueStart, valueEnd, false, f, false);
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
function addKeyedValues(text: string, f: Findings): void {
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
    // "auth": { ... } — JSON that parses is read by its keys; anything else
    // that shape can't be cut exactly.
    if (text[at] === '{' || text[at] === '[') {
      f.withhold(at);
      continue;
    }
    if (sep === ':' && !argQuote) {
      const scalar = matchAt(BLOCK_SCALAR, text, at).length;
      if (scalar || text[at] === '\n' || text[at] === '\r') {
        const column = m.index - (text.lastIndexOf('\n', m.index - 1) + 1);
        if (hasValueBlock(text, at + scalar, column, scalar > 0)) f.withhold(at);
        continue;
      }
    }
    let end: number;
    if (sep === ':' && name.cookie) {
      end = addCookies(text, at, argQuote, f);
    } else if (argQuote) {
      end = at;
      while (end < text.length && text[end] !== argQuote && text[end] !== '\n') end++;
      if (text[end] === argQuote) addSecret(text, at, end, name.password, f);
      else f.withhold(at);
    } else {
      // A shell assignment or flag ends where the shell word does, so
      // abc,def is one value.
      const shell = (sep === '=' || sep === ' ') && !lead;
      end = addValue(text, at, shell ? '}]' : ',}]', name.password, f);
    }
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

function addPasswordWords(text: string, f: Findings): void {
  if (!/pass/i.test(text)) return;
  PASSWORD_WORD.lastIndex = 0;
  for (let m = PASSWORD_WORD.exec(text); m; m = PASSWORD_WORD.exec(text)) {
    const value = m[1]!;
    if (PROSE_AFTER_PASSWORD.has(value.toLowerCase()) || isBenignValue(value, true)) continue;
    const [start, end] = matchRange(m);
    f.token(start, end, REDACTED, RANK_KEYED);
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

function addCommandSecrets(text: string, f: Findings): void {
  if (!COMMAND_HINT.test(text)) return;
  const each = (command: RegExp, flag: RegExp, when?: (c: string) => boolean) => {
    command.lastIndex = 0;
    for (let c = command.exec(text); c; c = command.exec(text)) {
      const line = c[0];
      if (when && !when(line)) continue;
      flag.lastIndex = 0;
      for (let m = flag.exec(line); m; m = flag.global ? flag.exec(line) : null) {
        let [start, end] = matchRange(m, c.index);
        // A quoted value: the quotes stay.
        const q = text[start];
        if ((q === '"' || q === "'") && end - start >= 2 && text[end - 1] === q) {
          start++;
          end--;
        }
        f.token(start, end, REDACTED, RANK_KEYED);
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

function addXml(text: string, f: Findings): void {
  if (!text.includes('<')) return;
  XML_ELEMENT.lastIndex = 0;
  for (let m = XML_ELEMENT.exec(text); m; m = XML_ELEMENT.exec(text)) {
    const [local, body] = [m[2]!, m[4]!];
    if (isCredentialName(local) && !isBenignValue(body.trim(), isPasswordName(local))) {
      const end = m.index + m[0].length - m[1]!.length - 3;
      f.token(end - body.length, end, REDACTED, RANK_KEYED);
    }
  }
  XML_KEYED_ATTRIBUTE.lastIndex = 0;
  for (let m = XML_KEYED_ATTRIBUTE.exec(text); m; m = XML_KEYED_ATTRIBUTE.exec(text)) {
    const [key, value] = [m[2]!, m[4]!];
    if (isCredentialName(key) && !isBenignValue(value, isPasswordName(key))) {
      const [start, end] = matchRange(m);
      f.token(start, end, REDACTED, RANK_KEYED);
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
  const found = new Findings(text);
  addFormats(text, found);
  if (found.list.length) return true;
  addKeyedValues(text, found);
  return found.list.length > 0;
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

function addBase64(text: string, f: Findings): void {
  BASE64_RUN.lastIndex = 0;
  for (let m = BASE64_RUN.exec(text); m; m = BASE64_RUN.exec(text)) {
    if (hidesSecret(m[0])) {
      f.token(m.index, m.index + m[0].length, '<base64-secret>', RANK_BASE64);
    }
  }
}

// ---------------------------------------------------------------------------
// JSON. Each object or array in the text that parses cleanly is read by its
// keys: a string or number under a credential key is a secret whatever the
// shape around it, and every other string is read as a field of its own, with
// what it finds mapped back to the text as written. Nothing is serialized
// again, so the text keeps its size and layout. JSON with a key twice (which
// a parser would hide) or nested past MAX_DEPTH withholds the field.

/** How deep JSON found in a string, inside JSON found in a string, is read. */
const MAX_TEXT_DEPTH = 4;
/** Deeper than this, a value is withheld rather than walked. */
const MAX_DEPTH = 64;

type Secret = { readonly password: boolean };

interface JsonString {
  /** The content, between the quotes. */
  readonly start: number;
  readonly end: number;
  readonly escaped: boolean;
  readonly secret: Secret | undefined;
}

interface JsonRead {
  /** Past the value, or -1 when it doesn't parse. */
  readonly end: number;
  /** Where the read stopped. */
  readonly stop: number;
  /** No key twice in an object, and nested no deeper than MAX_DEPTH. */
  readonly clean: boolean;
  readonly strings: JsonString[];
  /** Numbers under a credential key, as [start, end]. */
  readonly numbers: Array<readonly [number, number]>;
}

const JSON_NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const JSON_LITERAL = /true|false|null/y;
const JSON_ESCAPE = /\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4})/y;

function skipJsonSpace(text: string, i: number): number {
  for (; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c !== 0x20 && c !== 0x09 && c !== 0x0a && c !== 0x0d) break;
  }
  return i;
}

/** Past the closing quote of the JSON string that opens at `at`, or -1; and whether it escapes. */
function jsonStringEnd(text: string, at: number): { end: number; escaped: boolean } {
  let escaped = false;
  for (let i = at + 1; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 0x22) return { end: i + 1, escaped };
    if (c < 0x20) break;
    if (c === 0x5c) {
      JSON_ESCAPE.lastIndex = i;
      if (!JSON_ESCAPE.test(text)) break;
      escaped = true;
      i = JSON_ESCAPE.lastIndex - 1;
    }
  }
  return { end: -1, escaped };
}

interface Frame {
  readonly object: boolean;
  readonly secret: Secret | undefined;
  /** The object's first key, then all of them once there is a second. */
  first: string | undefined;
  keys: Set<string> | undefined;
}

/** Read the JSON value that opens at `open`, iteratively, so depth costs no stack. */
function readJson(text: string, open: number): JsonRead {
  const frames: Frame[] = [];
  const strings: JsonString[] = [];
  const numbers: Array<readonly [number, number]> = [];
  let clean = true;
  let i = open;
  // What is known of the value about to be read.
  let secret: Secret | undefined;
  let keepNumber = false;
  const fail = (stop: number): JsonRead => ({ end: -1, stop, clean, strings, numbers });

  /** Read an object's key and its colon; false when they don't parse. */
  const readKey = (frame: Frame): boolean => {
    i = skipJsonSpace(text, i);
    if (text.charCodeAt(i) !== 0x22) return false;
    const { end, escaped } = jsonStringEnd(text, i);
    if (end < 0) return false;
    const key = escaped ? (JSON.parse(text.slice(i, end)) as string) : text.slice(i + 1, end - 1);
    if (frame.first === undefined) {
      frame.first = key;
    } else {
      frame.keys ??= new Set([frame.first]);
      if (frame.keys.has(key)) clean = false;
      frame.keys.add(key);
    }
    i = skipJsonSpace(text, end);
    if (text.charCodeAt(i) !== 0x3a) return false;
    i++;
    const parent = frame.secret;
    const name = describeName(key);
    secret =
      parent || name.credential
        ? { password: !!parent?.password || (parent ? isPasswordName(key) : name.password) }
        : undefined;
    keepNumber = !!parent && hasNonSecretSuffix(key);
    return true;
  };

  for (;;) {
    // A value.
    i = skipJsonSpace(text, i);
    const c = text.charCodeAt(i);
    let opened = false;
    if (c === 0x7b || c === 0x5b) {
      const object = c === 0x7b;
      const frame: Frame = { object, secret, first: undefined, keys: undefined };
      frames.push(frame);
      if (frames.length > MAX_DEPTH) clean = false;
      i = skipJsonSpace(text, i + 1);
      if (text.charCodeAt(i) === (object ? 0x7d : 0x5d)) {
        frames.pop();
        i++;
      } else {
        opened = true;
        keepNumber = false;
        if (object && !readKey(frame)) return fail(i);
      }
    } else if (c === 0x22) {
      const { end, escaped } = jsonStringEnd(text, i);
      if (end < 0) return fail(i);
      strings.push({ start: i + 1, end: end - 1, escaped, secret });
      i = end;
    } else {
      const number = matchAt(JSON_NUMBER, text, i).length;
      const length = number || matchAt(JSON_LITERAL, text, i).length;
      if (!length) return fail(i);
      if (number && secret && !keepNumber) {
        if (!isBenignNumber(Number(text.slice(i, i + number)), secret.password)) {
          numbers.push([i, i + number]);
        }
      }
      i += length;
    }
    if (opened) continue;
    // After a value: a comma and the next, or the end of a container.
    for (;;) {
      const frame = frames[frames.length - 1];
      if (!frame) return { end: i, stop: i, clean, strings, numbers };
      i = skipJsonSpace(text, i);
      const d = text.charCodeAt(i);
      if (d === 0x2c) {
        i++;
        if (frame.object) {
          if (!readKey(frame)) return fail(i);
        } else {
          secret = frame.secret;
          keepNumber = false;
        }
        break;
      }
      if (d !== (frame.object ? 0x7d : 0x5d)) return fail(i);
      frames.pop();
      i++;
    }
  }
}

/**
 * Where in the text each unit of a JSON string's decoded content was written,
 * and where the content ends. The escapes were checked when it was read.
 */
function decodedPositions(text: string, start: number, end: number): Int32Array {
  const at = new Int32Array(end - start + 1);
  let k = 0;
  for (let i = start; i < end; k++) {
    at[k] = i;
    if (text.charCodeAt(i) !== 0x5c) i++;
    else i += text[i + 1] === 'u' ? 6 : 2;
  }
  at[k] = end;
  return at;
}

// JSON repeats its strings, often thousands of times in one field: within a
// field, each short string is read once.
const MAX_CACHED_STRINGS = 4096;
const MAX_CACHED_LENGTH = 256;
const stringCache = new Map<string, readonly Finding[]>();

function analyzeString(text: string, options: NameOptions, depth: number): readonly Finding[] {
  if (text.length > MAX_CACHED_LENGTH) return analyze(text, options, depth);
  const key = `${depth}\0${text}`;
  let found = stringCache.get(key);
  if (!found) {
    found = analyze(text, options, depth);
    if (stringCache.size >= MAX_CACHED_STRINGS) stringCache.clear();
    stringCache.set(key, found);
  }
  return found;
}

/** Add what each string of a clean read holds, as found in the text. */
function addJsonFindings(
  text: string,
  read: JsonRead,
  options: NameOptions,
  depth: number,
  f: Findings,
): void {
  for (const s of read.strings) {
    if (s.secret) {
      if (!s.escaped) {
        addSecret(text, s.start, s.end, s.secret.password, f);
      } else {
        const value = JSON.parse(text.slice(s.start - 1, s.end + 1)) as string;
        if (!MARKER.test(value) && !isBenignValue(value, s.secret.password)) f.withhold(s.start);
      }
      continue;
    }
    if (s.end === s.start) continue;
    if (!s.escaped) {
      const field = text.slice(s.start, s.end);
      if (!mayHoldSecret(field, options)) continue;
      for (const x of analyzeString(field, options, depth + 1)) {
        f.push({ ...x, start: x.start + s.start, end: x.end + s.start });
      }
      continue;
    }
    const value = JSON.parse(text.slice(s.start - 1, s.end + 1)) as string;
    if (!mayHoldSecret(value, options)) continue;
    const found = analyzeString(value, options, depth + 1);
    const at = found.length ? decodedPositions(text, s.start, s.end) : undefined;
    for (const x of found) {
      const start = at![x.start]!;
      const end = at![x.end]!;
      // Written with escapes: what the text shows isn't what was found.
      if (x.withhold || text.slice(start, end).includes('\\')) f.withhold(s.start);
      else f.push({ ...x, start, end });
    }
  }
  for (const [start, end] of read.numbers) f.token(start, end, REDACTED, RANK_KEYED);
}

/**
 * Read each JSON object or array in the text, adding what it holds and
 * recording where it is. A failed candidate is retried one character on
 * while the work stays within a few passes over the text, then skipped
 * whole, so brackets that never balance stay linear.
 */
function addJson(
  text: string,
  options: NameOptions,
  depth: number,
  f: Findings,
  regions: number[],
): void {
  const budget = 2 * text.length + 64 * 1024;
  let work = 0;
  let i = 0;
  while (i < text.length) {
    let open = i;
    while (open < text.length && text[open] !== '{' && text[open] !== '[') open++;
    if (open >= text.length) return;
    const read = readJson(text, open);
    if (read.end > 0) {
      if (!read.clean) {
        if (mayHoldSecret(text.slice(open, read.end), options)) {
          f.withhold(open);
          return;
        }
      } else {
        regions.push(open, read.end);
        addJsonFindings(text, read, options, depth, f);
      }
      i = read.end;
      continue;
    }
    work += read.stop - open;
    i = work < budget ? open + 1 : Math.max(open + 1, read.stop);
  }
}

// ---------------------------------------------------------------------------
// User, host and email names.

const HOME = /\/(?:Users|home)\/([^/\s"'`$;&|<>(){}#\\]+)/g;
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

function addNames(text: string, options: NameOptions, f: Findings): void {
  const each = (pattern: RegExp, replacement: string) => {
    pattern.lastIndex = 0;
    for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
      const [start, end] = matchRange(m);
      if (end > start) f.name(start, end, replacement);
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
// A field: every rule's findings, then one of the two outcomes.

function byStart(a: Finding, b: Finding): number {
  return a.start - b.start || b.end - a.end;
}

/** Drop findings that start inside a JSON region, given as start, end pairs in order. */
function outsideRegions(found: Finding[], regions: readonly number[]): Finding[] {
  found.sort(byStart);
  const out: Finding[] = [];
  let r = 0;
  for (const x of found) {
    while (r < regions.length && regions[r + 1]! <= x.start) r += 2;
    if (r < regions.length && regions[r]! <= x.start) continue;
    out.push(x);
  }
  return out;
}

/** What every rule finds in a field. */
function analyze(text: string, options: NameOptions, depth: number): Finding[] {
  if (!mayHoldSecret(text, options)) return [];
  const rules = new Findings(text);
  addPrivateKeys(text, rules);
  addFormats(text, rules);
  addCommandSecrets(text, rules);
  addXml(text, rules);
  addKeyedValues(text, rules);
  addPasswordWords(text, rules);
  addBase64(text, rules);
  addNames(text, options, rules);
  const json = new Findings(text);
  const regions: number[] = [];
  if (depth < MAX_TEXT_DEPTH && (text.includes('{') || text.includes('['))) {
    addJson(text, options, depth, json, regions);
  }
  // Inside JSON, the JSON reading stands.
  const found = regions.length ? outsideRegions(rules.list, regions) : rules.list;
  found.push(...json.list);
  if (found.some((x) => x.rank > RANK_NAME) && HAZARD.test(text)) {
    found.push({ start: 0, end: 0, with: '', rank: RANK_KEY, withhold: true });
  }
  return found;
}

/**
 * The replacements to apply, in order and none overlapping: where secrets
 * overlap, the higher rank names the whole, and names give way to secrets.
 */
function settle(found: Finding[]): Finding[] {
  found.sort(byStart);
  const secrets: Array<{ start: number; end: number; with: string; rank: number }> = [];
  const names: Finding[] = [];
  for (const x of found) {
    if (x.rank === RANK_NAME) {
      names.push(x);
      continue;
    }
    const last = secrets[secrets.length - 1];
    if (last && x.start < last.end) {
      last.end = Math.max(last.end, x.end);
      if (x.rank > last.rank) {
        last.rank = x.rank;
        last.with = x.with;
      }
    } else {
      secrets.push({ ...x });
    }
  }
  const out: Finding[] = [];
  let s = 0;
  let lastName = -1;
  for (const n of names) {
    while (s < secrets.length && secrets[s]!.end <= n.start) s++;
    if (s < secrets.length && secrets[s]!.start < n.end) continue;
    if (n.start < lastName) continue;
    out.push(n);
    lastName = n.end;
  }
  if (!out.length) return secrets.map((x) => ({ ...x, withhold: false }));
  return [...secrets.map((x) => ({ ...x, withhold: false })), ...out].sort(byStart);
}

function render(text: string, spans: readonly Finding[], end: number): string {
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
function cutPoint(text: string, spans: readonly Finding[]): number {
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

function redactText(input: string, options: NameOptions): string {
  const clipped = input.length > MAX_REDACT_CHARS;
  if (!clipped && !mayHoldSecret(input, options)) return input;
  const text = clipped ? input.slice(0, MAX_REDACT_CHARS + CUT_MARGIN) : input;
  stringCache.clear();
  const found = analyze(text, options, 0);
  if (found.some((x) => x.withhold)) return WITHHELD;
  const spans = found.length ? settle(found) : found;
  const end = clipped ? cutPoint(text, spans) : text.length;
  const out = render(text, spans, end);
  return end < input.length ? `${out}…[truncated ${input.length - end} characters]` : out;
}

/**
 * Redact one field: its secrets cut out exactly, or the whole field replaced
 * with WITHHELD when that can't be done without the risk of hiding a command.
 */
export function redactString(input: string, options: NameOptions): string {
  return redactText(input, options);
}

/** redactString for a field such as one line of evidence, by default with no local names. */
export function redactField(text: string, options: NameOptions = {}): string {
  return redactText(text, options);
}

/** A command's arguments, each its own field: one withheld argument leaves the rest in view. */
export function redactArgv(argv: readonly string[], options: NameOptions = {}): string[] {
  return argv.map((arg) => redactText(arg, options));
}

/**
 * Redact every string in a JSON-like value. Keys are kept. A value under a
 * credential-named key (password, x-api-key, authToken, ...) is replaced
 * whatever it looks like: with REDACTED when it is one plain token, else
 * WITHHELD. When that value is an object or array, its shape is kept and
 * every string and number inside it is replaced, booleans and null aside,
 * and numbers under names like expires_at. A value nested too deep, a cycle,
 * or one that throws when read is withheld whole.
 */
export function redactValue(value: unknown, options: NameOptions): unknown {
  return redactWithin(value, options, undefined, 0, new Set());
}

/** `secret` is set under a credential-named key: true when it names a password. */
function redactWithin(
  value: unknown,
  options: NameOptions,
  secret: Secret | undefined,
  depth: number,
  ancestors: Set<object>,
): unknown {
  if (secret) {
    if (typeof value === 'string') {
      if (isBenignValue(value, secret.password) || MARKER.test(value) || value === WITHHELD) {
        return value;
      }
      return isSafeToken(value, 0, value.length) ? REDACTED : WITHHELD;
    }
    if (typeof value === 'number') {
      return isBenignNumber(value, secret.password) ? value : REDACTED;
    }
    if (typeof value === 'bigint') return REDACTED;
  }
  if (typeof value === 'string') return redactText(value, options);
  if (!value || typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH || ancestors.has(value)) return WITHHELD;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => redactWithin(item, options, secret, depth + 1, ancestors));
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
        redacted = redactWithin(item, options, keyed, depth + 1, ancestors);
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
    return WITHHELD;
  } finally {
    ancestors.delete(value);
  }
}

// ---------------------------------------------------------------------------
// Serialization within a byte budget. The text is written as JSON.stringify
// with an indent of 1 writes it, and writing stops once the budget is spent,
// so a value that would serialize to far more than maxBytes is never written
// out in full.

class BoundedText {
  readonly parts: string[] = [];
  readonly max: number;
  bytes = 0;

  constructor(max: number) {
    this.max = max;
  }

  get full(): boolean {
    return this.bytes > this.max;
  }

  write(piece: string): void {
    if (this.full) return;
    this.parts.push(piece);
    this.bytes += Buffer.byteLength(piece, 'utf8');
  }

  /** A string, of which no more is escaped than could still fit. */
  string(value: string): void {
    const room = this.max - this.bytes + 1;
    this.write(JSON.stringify(value.length > room ? value.slice(0, room) : value));
  }
}

/** True for what JSON.stringify leaves out of an object, or writes as null in an array. */
function unwritable(value: unknown): boolean {
  return value === undefined || typeof value === 'function' || typeof value === 'symbol';
}

function writeJson(value: unknown, indent: string, out: BoundedText): void {
  if (out.full) return;
  switch (typeof value) {
    case 'string':
      out.string(value);
      return;
    case 'number':
      out.write(Number.isFinite(value) ? String(value) : 'null');
      return;
    case 'boolean':
    case 'bigint':
      out.write(String(value));
      return;
    default:
      break;
  }
  if (value === null || typeof value !== 'object') {
    out.write('null');
    return;
  }
  const inner = indent + ' ';
  if (Array.isArray(value)) {
    if (!value.length) return out.write('[]');
    out.write('[');
    value.forEach((item, i) => {
      if (out.full) return;
      out.write(`${i ? ',' : ''}\n${inner}`);
      writeJson(unwritable(item) ? null : item, inner, out);
    });
    out.write(`\n${indent}]`);
    return;
  }
  const entries = Object.entries(value).filter(([, item]) => !unwritable(item));
  if (!entries.length) return out.write('{}');
  out.write('{');
  entries.forEach(([key, item], i) => {
    if (out.full) return;
    out.write(`${i ? ',' : ''}\n${inner}${JSON.stringify(key)}: `);
    writeJson(item, inner, out);
  });
  out.write(`\n${indent}}`);
}

/**
 * Redact and serialize, stopping at maxBytes with a visible marker. The cut
 * never splits a character or leaves part of a redaction marker.
 */
export function redactAndSerialize(value: unknown, options: RedactionOptions): string {
  const max = Math.max(0, options.maxBytes);
  const redacted = redactValue(value, options);
  const out = new BoundedText(max);
  writeJson(unwritable(redacted) ? null : redacted, '', out);
  const text = out.parts.join('');
  if (!out.full) return text;
  const buffer = Buffer.from(text, 'utf8');
  let end = max;
  // Back up to the first byte of a character the cut runs through.
  while (end > 0 && (buffer[end]! & 0xc0) === 0x80) end--;
  let cut = buffer
    .subarray(0, end)
    .toString('utf8')
    .replace(/<[a-z-]{0,30}$/, '');
  const open = cut.lastIndexOf('[');
  if (open >= 0 && cut.length - open < WITHHELD.length && WITHHELD.startsWith(cut.slice(open))) {
    cut = cut.slice(0, open);
  }
  return `${cut}\n…[truncated after ${Buffer.byteLength(cut, 'utf8')} bytes]`;
}
