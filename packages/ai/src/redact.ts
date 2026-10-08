import { hostname, userInfo } from 'node:os';

export interface RedactionOptions {
  /** The Mac's short user name, replaced where it names a folder or an address. */
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
 * exactly. Visible, so no one reads the field as harmless or empty. Always
 * exactly this text, so callers can compare against it.
 */
export const WITHHELD = '[withheld: may contain a secret]';

/**
 * The longest field that is read. A longer one is withheld whole, unread, so
 * a hostile or runaway input can't make redaction slow, and nothing is ever
 * cut: a cut could leave part of a secret, or a hazard past it, unseen.
 */
export const MAX_REDACT_CHARS = 512 * 1024;

// How redaction works. Redacted text is what an AI reviewer reads to judge an
// alert, so attacker-written text must never be able to make a redaction hide
// a command. Every field has exactly one of two outcomes:
//
// - Precise: each secret is a single token in a plain value position, made
//   only of characters no shell acts on, not in command position, on one
//   line, in a field with no comment, backtick or heredoc. Only those tokens
//   are replaced; every other character stays, in order.
// - Withheld: anything else a rule takes for a possible secret replaces the
//   whole field with WITHHELD. Dropping a field visibly can't make a command
//   look harmless.
//
// The rules that hold this up:
//
// - A withhold from any rule wins. Nothing read later, such as JSON, undoes it.
// - A credential trigger (a name, a flag, a header, a .netrc keyword, an XML
//   element) names a value: the run up to the next whitespace or the end of
//   the field, or a quoted run closed at once. Unless that value is one clean
//   token, the field is withheld. No quoting, CDATA or other format is parsed
//   to find where a messier value ends.
// - A known token format (ghp_, sk-, AKIA, ...) and a base64 run that hides a
//   secret are replaced only in a value position: after `=` or `:`, alone in
//   quotes, or after a credential flag or an auth scheme. Anywhere else the
//   field is withheld, since a word there could be a command or its operand.
// - Nothing that spans lines is cut out: a private key withholds the field.
// - User, host and email names are replaced only where they can't be a
//   command: a folder in a path, an email or user@host, a host with its domain.
//
// A field is the string being redacted; in structured data, each string.
//
// Every pattern here must run in time linear in its input: no unbounded
// repetition that can be retried from many start positions, and no nested
// quantifiers. redact.test.ts times each on adversarial input.

// ---------------------------------------------------------------------------
// Characters, tokens and fields.

/**
 * A character a precise token may hold: printable ASCII that no shell acts
 * on, glob characters included.
 */
function isSafeCode(code: number): boolean {
  if (code <= 0x20 || code >= 0x7f) return false;
  switch (code) {
    case 0x2a: // *
    case 0x3f: // ?
    case 0x5b: // [
    case 0x5d: // ]
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

function isBlankOrQuote(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x22 || code === 0x27;
}

/** Where the shell starts a new command: a line, a list or pipeline stage, a group. */
function isCommandSeparator(code: number): boolean {
  switch (code) {
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

/** NAME=value, as the shell reads it before a command. */
const ASSIGNMENT_WORD = /^[A-Za-z_][A-Za-z0-9_]*=/;
/** How far back inCommandPosition reads before it assumes the worst. */
const MAX_COMMAND_LOOKBACK = 4096;

/**
 * Where the redirection that ends `word` starts, or -1: 2>x, >x, <x, >>x,
 * 2>&1, &>x, 2> (its target in the next word). Only a redirection that is
 * the whole word, or follows a command separator in it, counts.
 */
function redirectionStart(word: string): number {
  const op = Math.max(word.lastIndexOf('>'), word.lastIndexOf('<'));
  if (op < 0) return -1;
  let s = op;
  while (s > 0 && (word[s - 1] === '>' || word[s - 1] === '<')) s--;
  if (s > 0 && word[s - 1] === '&') s--;
  else while (s > 0 && word.charCodeAt(s - 1) >= 0x30 && word.charCodeAt(s - 1) <= 0x39) s--;
  return s === 0 || isCommandSeparator(word.charCodeAt(s - 1)) ? s : -1;
}

/**
 * Where the part of `word` that the shell reads before a command starts, or
 * -1: a redirection, or a NAME=value assignment after any separator.
 */
function prefixStart(word: string): number {
  const redirection = redirectionStart(word);
  if (redirection >= 0) return redirection;
  let segment = word.length;
  while (segment > 0 && !isCommandSeparator(word.charCodeAt(segment - 1))) segment--;
  return ASSIGNMENT_WORD.test(word.slice(segment)) ? segment : -1;
}

/**
 * True when a word starting at `start` could be a command the shell runs:
 * at the start of the field, a line or a pipeline stage, right after a
 * substitution or group opener, or after any number of NAME=value
 * assignments and redirections there (FLAG=1 2>/dev/null cmd). Quotes and
 * blanks before it don't count. Where the words before it can't be read
 * plainly, the answer is yes.
 */
function inCommandPosition(text: string, start: number): boolean {
  let i = start - 1;
  const floor = start - MAX_COMMAND_LOOKBACK;
  for (;;) {
    if (i < floor) return true;
    const from = i;
    while (i >= 0 && isBlankOrQuote(text.charCodeAt(i))) i--;
    if (i < 0) return true;
    if (isCommandSeparator(text.charCodeAt(i))) return true;
    // Glued to the text before it, with no blank between: not a new word.
    let blank = false;
    for (let j = i + 1; j <= from; j++) {
      const c = text.charCodeAt(j);
      if (c === 0x20 || c === 0x09) blank = true;
    }
    if (!blank) return false;
    // The word before ends in a quote the scan can't follow back: it might
    // end an assignment, as in NAME="a b" cmd, or a redirection's target.
    if (text[i + 1] === '"' || text[i + 1] === "'") return true;
    // The word before, back to the blank before it.
    let w = i;
    while (w >= 0 && !isSpace(text.charCodeAt(w))) {
      if (w < floor) return true;
      w--;
    }
    const prefix = prefixStart(text.slice(w + 1, i + 1));
    if (prefix >= 0) {
      i = w + prefix;
      continue;
    }
    // The target of a redirection written apart from it: 2> /dev/null cmd.
    let p = w;
    while (p >= 0 && (text[p] === ' ' || text[p] === '\t')) p--;
    if (p < 0 || p === w) return false;
    let q = p;
    while (q >= 0 && !isSpace(text.charCodeAt(q))) {
      if (q < floor) return true;
      q--;
    }
    const before = text.slice(q + 1, p + 1);
    const redirection = redirectionStart(before);
    if (redirection < 0 || !/[<>]&?$/.test(before)) return false;
    i = q + redirection;
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

const WITHHOLD: Finding = { start: 0, end: 0, with: '', rank: RANK_KEY, withhold: true };

class Findings {
  readonly list: Finding[] = [];
  readonly text: string;
  /**
   * The text is the content of a JSON string, read again as a field. A token
   * that is all of it stands alone in quotes in the text, where the rules
   * read on the whole text have already judged its position.
   */
  readonly quoted: boolean;
  /** Set once anything withholds the field: no rule needs to read further. */
  withheld = false;

  constructor(text: string, quoted = false) {
    this.text = text;
    this.quoted = quoted;
  }

  /** True for a token that is the whole of a quoted field. */
  alone(start: number, end: number): boolean {
    return this.quoted && start === 0 && end === this.text.length;
  }

  /** A secret token: replaced when it can be cut out exactly, else the field is withheld. */
  token(start: number, end: number, replacement: string, rank: number): void {
    if (end <= start) return;
    const precise =
      isSafeToken(this.text, start, end) &&
      (this.alone(start, end) || !inCommandPosition(this.text, start));
    if (!precise) this.withheld = true;
    this.list.push({ start, end, with: replacement, rank, withhold: !precise });
  }

  /** A secret that can't be cut out exactly. */
  withhold(at: number): void {
    this.withheld = true;
    this.list.push({ start: at, end: at, with: '', rank: RANK_KEY, withhold: true });
  }

  /** A user, host or email name, at a place its rule has checked. */
  name(start: number, end: number, replacement: string): void {
    if (isSafeToken(this.text, start, end)) {
      this.list.push({ start, end, with: replacement, rank: RANK_NAME, withhold: false });
    }
  }

  push(finding: Finding): void {
    if (finding.withhold) this.withheld = true;
    this.list.push(finding);
  }
}

// ---------------------------------------------------------------------------
// The value a credential trigger names. It is one clean token, or the field
// is withheld: there is no third reading.

/** What may follow a quoted value without joining more text to it. */
const QUOTE_FOLLOWERS = ',;&|)}]<>';
/** A marker from an earlier redaction. */
const MARKER = /^<[a-z-]+>$/;
const MARKER_AT = /<[a-z-]+>/y;

function matchAt(pattern: RegExp, text: string, at: number): string {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0] ?? '';
}

/**
 * Read the value that starts at `at`. Bare, it runs to the next whitespace
 * or the end of the field, and every character must be safe. Quoted (or
 * inside the quote `closer` that opened before its name), every character
 * up to the closing quote must be safe, the quote must come right after
 * them, and nothing may be joined on after it. Anything else withholds the
 * field and returns undefined; so does a clean value with nothing in it
 * worth replacing, such as an earlier marker. An empty value is returned
 * empty.
 */
function readValue(
  text: string,
  at: number,
  f: Findings,
  closer = '',
): { start: number; end: number } | undefined {
  let quote = closer;
  let start = at;
  if (!quote && (text[at] === '"' || text[at] === "'")) {
    quote = text[at]!;
    start++;
  }
  const marker = matchAt(MARKER_AT, text, start).length;
  let end = start + marker;
  if (!marker) while (end < text.length && isSafeCode(text.charCodeAt(end))) end++;
  let after = end;
  if (quote) {
    if (text[end] !== quote) {
      f.withhold(at);
      return undefined;
    }
    after = end + 1;
    if (after < text.length && !isSpace(text.charCodeAt(after))) {
      if (!QUOTE_FOLLOWERS.includes(text[after]!)) {
        f.withhold(at);
        return undefined;
      }
    }
  } else if (after < text.length && !isSpace(text.charCodeAt(after))) {
    f.withhold(at);
    return undefined;
  }
  return marker ? undefined : { start, end };
}

/**
 * Read a value with readValue, and add it unless it can't be a secret. A
 * value given to a credential flag is always a secret: `benign` is false.
 */
function addValue(
  text: string,
  at: number,
  password: boolean,
  f: Findings,
  closer = '',
  benign = true,
): number {
  const value = readValue(text, at, f, closer);
  if (!value) return at;
  if (!benign || !isBenignValue(text.slice(value.start, value.end), password)) {
    f.token(value.start, value.end, REDACTED, RANK_KEYED);
  }
  return value.end;
}

// ---------------------------------------------------------------------------
// Known token formats. Where a pattern has a group, only the group is the
// secret, it always follows the fixed text the pattern opens with, and that
// text stays.

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

/** An auth scheme, after which a token is a header's value: Bearer, Authorization:Bearer. */
const AUTH_WORD = /(?:^|[:="'])(?:Bearer|Basic|Token|Digest|Negotiate|NTLM)$/i;
const FLAG_WORD = /^--?[A-Za-z][A-Za-z0-9_-]*$/;
const MAX_FLAG_LENGTH = 128;

/**
 * True when the token at [start, end) sits where a value goes: right after
 * `=` or `:` (and blanks), alone between a pair of quotes, or after a
 * credential flag (--token) or an auth scheme (Bearer).
 */
function inValuePosition(text: string, start: number, end: number): boolean {
  const before = text[start - 1];
  if (before === '=') return true;
  if ((before === '"' || before === "'") && text[end] === before) return true;
  let i = start - 1;
  while (i >= 0 && (text[i] === ' ' || text[i] === '\t')) i--;
  if (i < 0) return false;
  if (text[i] === ':') return true;
  if (i === start - 1) return false;
  let w = i;
  while (w >= 0 && !isSpace(text.charCodeAt(w))) {
    if (i - w >= MAX_FLAG_LENGTH) return false;
    w--;
  }
  const word = text.slice(w + 1, i + 1);
  if (AUTH_WORD.test(word)) return true;
  return FLAG_WORD.test(word) && isCredentialName(word.replace(/^-+/, ''));
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
      if (m.length === 1 && !f.alone(start, end) && !inValuePosition(text, start, end)) {
        f.withhold(start);
        return;
      }
      f.token(start, end, replacement, RANK_FORMAT);
      if (f.withheld) return;
    }
  }
}

// ---------------------------------------------------------------------------
// Private keys. A key spans lines, and nothing that spans lines is cut out
// exactly: anything that marks the start or end of one withholds the field.

const PRIVATE_KEY = /-----(?:BEGIN|END) [A-Z0-9 ]{0,40}PRIVATE KEY/;

function addPrivateKeys(text: string, f: Findings): void {
  if (!text.includes('PRIVATE KEY')) return;
  const m = PRIVATE_KEY.exec(text);
  if (m) f.withhold(m.index);
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

const JSON_NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const JSON_LITERAL = /true|false|null/y;

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
    if (sep === ':' && !argQuote) {
      const scalar = matchAt(BLOCK_SCALAR, text, at).length;
      if (scalar || text[at] === '\n' || text[at] === '\r') {
        const column = m.index - (text.lastIndexOf('\n', m.index - 1) + 1);
        if (hasValueBlock(text, at + scalar, column, scalar > 0)) {
          f.withhold(at);
          return;
        }
        continue;
      }
    }
    // "token": null, "pin": 1234 — a JSON key's literal or number, ended
    // where JSON ends it. Any other value is read as one token.
    if (lead && m[3] === lead && sep === ':') {
      const number = matchAt(JSON_NUMBER, text, at).length;
      const length = number || matchAt(JSON_LITERAL, text, at).length;
      const next = text.charCodeAt(at + length);
      if (
        length &&
        (Number.isNaN(next) || isSpace(next) || next === 0x2c || next === 0x7d || next === 0x5d)
      ) {
        if (number && !isBenignNumber(Number(text.slice(at, at + number)), name.password)) {
          f.token(at, at + number, REDACTED, RANK_KEYED);
        }
        KEYED.lastIndex = Math.max(KEYED.lastIndex, at + length);
        continue;
      }
    }
    // --password x, --token=x: a flag's value is the secret, whatever it is.
    const flag = m[5] !== undefined || text[m.index + lead.length] === '-';
    const end = addValue(text, at, name.password, f, argQuote, !flag);
    if (f.withheld) return;
    KEYED.lastIndex = Math.max(KEYED.lastIndex, end);
  }
}

// ---------------------------------------------------------------------------
// `password hunter2` in .netrc, where the value follows a space. Only text
// with a .netrc's structure is read so, a machine or default entry with a
// login: elsewhere, as in `rm password x`, the word after it is any word.
// The words that follow "password" in a sentence are left alone.

const PASSWORD_WORD = /(?<![A-Za-z0-9_./\\-])password[ \t]+/gi;
const NETRC_ENTRY = /(?:^|\s)(?:machine[ \t]+\S|default(?:\s|$))/;
const NETRC_LOGIN = /(?:^|\s)login[ \t]+\S/;
/** What can't start a value after "password ": a separator, a flag or punctuation. */
const NOT_A_VALUE = '=:-,;&|)}]>(<{[';
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
  if (!/password/i.test(text) || !NETRC_ENTRY.test(text) || !NETRC_LOGIN.test(text)) return;
  PASSWORD_WORD.lastIndex = 0;
  for (let m = PASSWORD_WORD.exec(text); m; m = PASSWORD_WORD.exec(text)) {
    const at = m.index + m[0].length;
    const c = text[at];
    if (c === undefined || isSpace(text.charCodeAt(at)) || NOT_A_VALUE.includes(c)) continue;
    if (c !== '"' && c !== "'") {
      let end = at;
      while (end < text.length && !isSpace(text.charCodeAt(end))) end++;
      // A word from a sentence, with any punctuation after it.
      const word = text
        .slice(at, end)
        .replace(/[.,;:!?)]+$/, '')
        .toLowerCase();
      if (PROSE_AFTER_PASSWORD.has(word) || isBenignValue(word, true)) continue;
    }
    addValue(text, at, true, f);
    if (f.withheld) return;
  }
}

// ---------------------------------------------------------------------------
// Passwords given as command-line flags by tools that take them that way.
// Each command runs to the end of its line or pipeline stage, read once; the
// value after a flag is read from the field, past that end if it runs on.

const CURL_COMMAND = /\bcurl\b[^\n;|&]*/g;
const SSHPASS_COMMAND = /\bsshpass\b[^\n;|&]*/g;
const DOCKER_COMMAND = /\bdocker\b[^\n;|&]*/g;
const OPENSSL_COMMAND = /\bopenssl\b[^\n;|&]*/g;
const MYSQL_COMMAND = /\b(?:mysql|mariadb)[a-z]*\b[^\n;|&]*/g;
// curl -u user:pass, --user user:pass, -uuser:pass.
const CURL_USER = /\s(?:-u[ \t]*|--user(?:[ \t]+|=))(?=[^\s-])/g;
// sshpass -p pw, docker login -p pw: the first -p only, as later ones belong
// to the command sshpass runs.
const DASH_P = /\s-p[ \t]*(?=[^\s-])/;
const OPENSSL_SECRET = /\s(?:-[kK][ \t]+|-pass(?:in|out)?[ \t]+pass:)(?=\S)/g;
// mysql -phunter2. For the MySQL tools, which take the password glued to -p:
// elsewhere -p is a port (ssh -p 22) or a plain flag (mkdir -p).
const MYSQL_GLUED_PASSWORD = /\s-p(?=[^\s-])/g;

const COMMAND_HINT = /curl|sshpass|docker|openssl|mysql|mariadb/;

function addCommandSecrets(text: string, f: Findings): void {
  if (!COMMAND_HINT.test(text)) return;
  const each = (command: RegExp, flag: RegExp, when?: (c: string) => boolean, userPass = false) => {
    command.lastIndex = 0;
    for (let c = command.exec(text); c && !f.withheld; c = command.exec(text)) {
      const line = c[0];
      if (when && !when(line)) continue;
      flag.lastIndex = 0;
      for (let m = flag.exec(line); m; m = flag.global ? flag.exec(line) : null) {
        const at = c.index + m.index + m[0].length;
        if (!userPass) {
          addValue(text, at, true, f, '', false);
        } else {
          // user:password; with no colon, curl asks for the password.
          const value = readValue(text, at, f);
          const colon = value ? text.slice(value.start, value.end).indexOf(':') : -1;
          if (value && colon >= 0)
            f.token(value.start + colon + 1, value.end, REDACTED, RANK_KEYED);
        }
        if (f.withheld) return;
      }
    }
  };
  each(CURL_COMMAND, CURL_USER, undefined, true);
  each(SSHPASS_COMMAND, DASH_P);
  each(DOCKER_COMMAND, DASH_P, (c) => /\slogin\b/.test(c));
  each(OPENSSL_COMMAND, OPENSSL_SECRET);
  each(MYSQL_COMMAND, MYSQL_GLUED_PASSWORD);
}

// ---------------------------------------------------------------------------
// XML: <password>x</password>, and <add key="StripeApiKey" value="x" />. An
// element's content is one clean token closed at once by its end tag, or the
// field is withheld: CDATA, child elements and text over lines are not read.

const XML_OPEN = /<((?:[A-Za-z_][\w.-]{0,63}:)?([A-Za-z_][\w.-]{0,63}))(\s[^<>]*)?>/g;
const XML_CLOSE = /<\/((?:[A-Za-z_][\w.-]{0,63}:)?[A-Za-z_][\w.-]{0,63})>/g;
const XML_KEYED_ATTRIBUTE = /\b(?:key|name)=(["'])([^"'\n<>]{1,128})\1\s+value=/gi;

function addXml(text: string, f: Findings): void {
  if (!text.includes('<')) return;
  // Elements are the tags whose end tag the field holds. Any other tag, such
  // as a marker from an earlier redaction (<api-key>), is not one.
  const closed = new Set<string>();
  if (text.includes('</')) {
    XML_CLOSE.lastIndex = 0;
    for (let m = XML_CLOSE.exec(text); m; m = XML_CLOSE.exec(text)) closed.add(m[1]!);
  }
  XML_OPEN.lastIndex = 0;
  for (let m = closed.size ? XML_OPEN.exec(text) : null; m; m = XML_OPEN.exec(text)) {
    const local = m[2]!;
    if (!closed.has(m[1]!) || !isCredentialName(local) || m[0].endsWith('/>')) continue;
    const at = m.index + m[0].length;
    const close = `</${m[1]}>`;
    const marker = matchAt(MARKER_AT, text, at).length;
    let end = at + marker;
    if (!marker) while (end < text.length && isSafeCode(text.charCodeAt(end))) end++;
    if (text.startsWith(close, end)) {
      const body = text.slice(at, end);
      if (!marker && !isBenignValue(body, isPasswordName(local))) {
        f.token(at, end, REDACTED, RANK_KEYED);
      }
      XML_OPEN.lastIndex = end + close.length;
      continue;
    }
    // Only blanks, which hold nothing, may stand in for a token.
    let blank = at;
    while (blank < text.length && (text[blank] === ' ' || text[blank] === '\t')) blank++;
    if (end === at && text.startsWith(close, blank)) continue;
    f.withhold(at);
    return;
  }
  XML_KEYED_ATTRIBUTE.lastIndex = 0;
  for (let m = XML_KEYED_ATTRIBUTE.exec(text); m; m = XML_KEYED_ATTRIBUTE.exec(text)) {
    const key = m[2]!;
    if (!isCredentialName(key)) continue;
    addValue(text, m.index + m[0].length, isPasswordName(key), f);
    if (f.withheld) return;
  }
}

// ---------------------------------------------------------------------------
// Secrets hidden in base64, such as {"password":"hunter2"} or MYSQL_PWD=x
// encoded. A run may follow an equals sign, as in data=eyJ... Runs of any
// length are decoded a bounded chunk at a time, each read with the tail of
// the one before, by the same rules as plain text. Like a token format, a run
// is replaced only in a value position.

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
    if (!hidesSecret(m[0])) continue;
    const end = m.index + m[0].length;
    if (!f.alone(m.index, end) && !inValuePosition(text, m.index, end)) {
      f.withhold(m.index);
      return;
    }
    f.token(m.index, end, '<base64-secret>', RANK_BASE64);
    if (f.withheld) return;
  }
}

// ---------------------------------------------------------------------------
// JSON. Each object or array in the text that parses cleanly is read by its
// keys: a string or number under a credential key is a secret, and every
// other string is read as a field of its own, with what it finds mapped back
// to the text as written. Nothing is serialized again, so the text keeps its
// size and layout. JSON with a key twice (which a parser would hide), nested
// past MAX_DEPTH, or with an object or array under a credential key (not one
// token) withholds the field.

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
  /**
   * No key twice in an object, nested no deeper than MAX_DEPTH, and no object
   * or array under a credential key.
   */
  readonly clean: boolean;
  readonly strings: JsonString[];
  /** Numbers under a credential key, as [start, end]. */
  readonly numbers: Array<readonly [number, number]>;
}

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
    const name = describeName(key);
    secret = name.credential ? { password: name.password } : undefined;
    return true;
  };

  for (;;) {
    // A value.
    i = skipJsonSpace(text, i);
    const c = text.charCodeAt(i);
    let opened = false;
    if (c === 0x7b || c === 0x5b) {
      // An object or array under a credential key is not one token.
      if (secret) clean = false;
      const object = c === 0x7b;
      const frame: Frame = { object, first: undefined, keys: undefined };
      frames.push(frame);
      if (frames.length > MAX_DEPTH) clean = false;
      secret = undefined;
      i = skipJsonSpace(text, i + 1);
      if (text.charCodeAt(i) === (object ? 0x7d : 0x5d)) {
        frames.pop();
        i++;
      } else {
        opened = true;
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
      if (number && secret) {
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
          secret = undefined;
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
    if (f.withheld) return;
    if (s.secret) {
      if (!s.escaped) {
        const value = text.slice(s.start, s.end);
        if (!MARKER.test(value) && !isBenignValue(value, s.secret.password)) {
          f.token(s.start, s.end, REDACTED, RANK_KEYED);
        }
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
  while (i < text.length && !f.withheld) {
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
// User, host and email names. Each is replaced only where it can't be a
// command or a command's operand: a folder in a path (/Users/me/, /x/me/),
// an email, the user of user@host, the host after @ or //, or a host written
// with its domain. Anywhere else, such as a bare word equal to the user name,
// it stays as written. Apart from an email, none is replaced in command
// position.

const HOME = /\/(?:Users|home)\/([^/\s"'`$;&|<>(){}#\\]+)/g;
const EMAIL = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}/g;
const HOST_LABEL = /\.[A-Za-z0-9-]+/y;

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
  HOME.lastIndex = 0;
  for (let m = HOME.exec(text); m; m = HOME.exec(text)) {
    const [start, end] = matchRange(m);
    f.name(start, end, '<user>');
  }
  if (text.includes('@')) {
    EMAIL.lastIndex = 0;
    for (let m = EMAIL.exec(text); m; m = EMAIL.exec(text)) {
      f.name(m.index, m.index + m[0].length, '<email>');
    }
  }
  const word = (name: string) =>
    new RegExp(`(?<![A-Za-z0-9_.%+-])${escapeRegExp(name)}(?![A-Za-z0-9_-])`, 'gi');
  if (worthHiding(options.username)) {
    const pattern = word(options.username);
    for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
      const start = m.index;
      const end = start + m[0].length;
      const folder = text[start - 1] === '/' && text[end] === '/';
      const user = text[end] === '@' && !inCommandPosition(text, start);
      if (folder || user) f.name(start, end, '<user>');
    }
  }
  if (worthHiding(options.hostname)) {
    const full = options.hostname.toLowerCase();
    const short = full.split('.')[0]!;
    if (worthHiding(short)) {
      const pattern = word(short);
      for (let m = pattern.exec(text); m; m = pattern.exec(text)) {
        const start = m.index;
        const bare = start + m[0].length;
        let end = bare;
        // Its domain: the one it has, or .local.
        if (full !== short && text.slice(start, start + full.length).toLowerCase() === full) {
          end = start + full.length;
        } else if (text.slice(end, end + 6).toLowerCase() === '.local') {
          end += 6;
        }
        // Part of a longer name, such as another host in the same domain.
        if (/[A-Za-z0-9_-]/.test(text[end] ?? '') || matchAt(HOST_LABEL, text, end)) continue;
        const after = text[start - 1] === '@' || text.slice(start - 2, start) === '//';
        if ((after || end > bare) && !inCommandPosition(text, start)) f.name(start, end, '<host>');
        pattern.lastIndex = Math.max(pattern.lastIndex, end);
      }
    }
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

/**
 * What every rule finds in a field: a single withholding finding when any
 * rule withholds it, whatever another rule reads there, or else the spans to
 * replace.
 */
function analyze(text: string, options: NameOptions, depth: number): Finding[] {
  if (!mayHoldSecret(text, options)) return [];
  // Below the top, the text is a JSON string's content.
  const rules = new Findings(text, depth > 0);
  const steps = [
    addPrivateKeys,
    addFormats,
    addCommandSecrets,
    addXml,
    addKeyedValues,
    addPasswordWords,
    addBase64,
  ];
  for (const step of steps) {
    step(text, rules);
    if (rules.withheld) return [WITHHOLD];
  }
  addNames(text, options, rules);
  const json = new Findings(text);
  const regions: number[] = [];
  if (depth < MAX_TEXT_DEPTH && (text.includes('{') || text.includes('['))) {
    addJson(text, options, depth, json, regions);
    if (json.withheld) return [WITHHOLD];
  }
  // Inside JSON, the JSON reading of each precise span stands.
  const found = regions.length ? outsideRegions(rules.list, regions) : rules.list;
  found.push(...json.list);
  if (found.some((x) => x.rank > RANK_NAME) && HAZARD.test(text)) return [WITHHOLD];
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

function render(text: string, spans: readonly Finding[]): string {
  let out = '';
  let last = 0;
  for (const s of spans) {
    out += text.slice(last, s.start) + s.with;
    last = s.end;
  }
  return out + text.slice(last);
}

/**
 * Redact a field: WITHHELD, or the field with only its safe tokens replaced.
 * The length of a field withheld unread for its size is added to `oversized`.
 */
function redactText(input: string, options: NameOptions, oversized?: number[]): string {
  if (input.length > MAX_REDACT_CHARS) {
    oversized?.push(input.length);
    return WITHHELD;
  }
  if (!mayHoldSecret(input, options)) return input;
  stringCache.clear();
  const found = analyze(input, options, 0);
  if (found.some((x) => x.withhold)) return WITHHELD;
  return found.length ? render(input, settle(found)) : input;
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
  return redactWithin(value, options, undefined, 0, new Set(), undefined);
}

/** `secret` is set under a credential-named key: true when it names a password. */
function redactWithin(
  value: unknown,
  options: NameOptions,
  secret: Secret | undefined,
  depth: number,
  ancestors: Set<object>,
  oversized: number[] | undefined,
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
  if (typeof value === 'string') return redactText(value, options, oversized);
  if (!value || typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH || ancestors.has(value)) return WITHHELD;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) =>
        redactWithin(item, options, secret, depth + 1, ancestors, oversized),
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
        redacted = redactWithin(item, options, keyed, depth + 1, ancestors, oversized);
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
// with an indent of 1 writes it, but never cut inside a field: an object
// entry or array element that doesn't fit what is left of the budget is left
// out whole, and the rest is still tried, so the text is always valid JSON
// and every string in it is complete. What was left out is reported beside
// the text, never written into it. A string or key is measured by its length
// before it is escaped, so one far over the budget is never escaped whole.

/** What redactAndSerialize returns: the data, and what it leaves out. */
export interface SerializedData {
  /** Valid JSON, within maxBytes (at least `null` when nothing fits). */
  readonly text: string;
  /** Object entries and array elements left out whole to fit maxBytes. */
  readonly omitted: number;
  /** The length of each field withheld unread for its size. */
  readonly oversized: readonly number[];
}

interface Fitted {
  readonly text: string;
  readonly bytes: number;
}

/** True for what JSON.stringify leaves out of an object, or writes as null in an array. */
function unwritable(value: unknown): boolean {
  return value === undefined || typeof value === 'function' || typeof value === 'symbol';
}

/**
 * `value` as JSON in at most `room` bytes, or undefined when it can't fit.
 * A container fits as long as its brackets do, holding the entries that fit;
 * each one left out is counted in `omitted`.
 */
function fitJson(
  value: unknown,
  indent: string,
  room: number,
  omitted: { count: number },
): Fitted | undefined {
  if (room <= 0) return undefined;
  let scalar: string | undefined;
  switch (typeof value) {
    case 'string': {
      // Escaping never makes a string shorter.
      if (value.length + 2 > room) return undefined;
      const text = JSON.stringify(value);
      const bytes = Buffer.byteLength(text, 'utf8');
      return bytes <= room ? { text, bytes } : undefined;
    }
    case 'number':
      scalar = Number.isFinite(value) ? String(value) : 'null';
      break;
    case 'boolean':
    case 'bigint':
      scalar = String(value);
      break;
    default:
      if (value === null || typeof value !== 'object') scalar = 'null';
  }
  if (scalar !== undefined) {
    return scalar.length <= room ? { text: scalar, bytes: scalar.length } : undefined;
  }
  if (room < 2) return undefined;
  const array = Array.isArray(value);
  const empty = array ? '[]' : '{}';
  const entries: ReadonlyArray<readonly [string | undefined, unknown]> = array
    ? (value as unknown[]).map((item) => [undefined, unwritable(item) ? null : item] as const)
    : Object.entries(value as object).filter(([, item]) => !unwritable(item));
  if (!entries.length) return { text: empty, bytes: 2 };
  const inner = indent + ' ';
  const close = `\n${indent}${array ? ']' : '}'}`;
  let text = array ? '[' : '{';
  let bytes = 1;
  let written = 0;
  for (const [key, item] of entries) {
    const sep = `${written ? ',' : ''}\n${inner}`;
    let avail = room - bytes - sep.length - close.length;
    let head = '';
    let headBytes = 0;
    if (key !== undefined && avail > 0) {
      // "key": , measured before the key is escaped.
      if (key.length + 4 <= avail) {
        head = `${JSON.stringify(key)}: `;
        headBytes = Buffer.byteLength(head, 'utf8');
      }
      avail = head ? avail - headBytes : 0;
    }
    const piece = avail > 0 ? fitJson(item, inner, avail, omitted) : undefined;
    if (!piece) {
      omitted.count++;
      continue;
    }
    text += sep + head + piece.text;
    bytes += sep.length + headBytes + piece.bytes;
    written++;
  }
  if (!written) return { text: empty, bytes: 2 };
  return { text: text + close, bytes: bytes + close.length };
}

/**
 * Redact and serialize within maxBytes. Every field in the text is whole:
 * WITHHELD, or its precise redaction. Fields that don't fit are left out
 * whole and counted; fields withheld for their size are listed. Neither note
 * is written into the text.
 */
export function redactAndSerialize(value: unknown, options: RedactionOptions): SerializedData {
  const max = Math.max(0, options.maxBytes);
  const oversized: number[] = [];
  const redacted = redactWithin(value, options, undefined, 0, new Set(), oversized);
  const omitted = { count: 0 };
  const fitted = fitJson(unwritable(redacted) ? null : redacted, '', max, omitted);
  if (fitted) return { text: fitted.text, omitted: omitted.count, oversized };
  return { text: 'null', omitted: redacted == null || unwritable(redacted) ? 0 : 1, oversized };
}
