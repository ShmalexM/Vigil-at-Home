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
// - Precise: each secret is a single token, made only of characters no shell
//   acts on, in a place the field's structure makes a value that nothing
//   runs. Only those tokens are replaced; every other character stays.
// - Withheld: any other secret replaces the whole field with WITHHELD.
//   Dropping a field visibly can't make a command look harmless.
//
// Nothing here works out where a command starts inside shell text. A string
// may be a command line, a script or a word a wrapper runs, so a secret in
// free text withholds the field. A secret is cut out precisely only where
// the field's shape alone puts it in a value:
//
// - a field that is one NAME=value assignment, its value a single token;
// - a field that is one URL, with no blank or shell metacharacter in it: the
//   password of its userinfo, and the value of a credential-named query
//   parameter. A secret anywhere else in it withholds the field;
// - a field that is one JSON document, under a credential-named key, or in a
//   string that is itself one of these shapes (never an array's element,
//   which may be an argument list).
//
// An argument list (argv) is one field, and no secret in it is cut out: a
// secret in any argument, whatever the tool, withholds every argument.
//
// User, host and email names are privacy, not secrets: they are replaced
// wherever their rule finds them, each with a marker that says which name
// stood there.
//
// The rules that hold this up:
//
// - A withhold from any rule wins. Nothing read later, such as JSON, undoes it.
// - A credential trigger (a name, a flag, a header, an XML element) names a
//   value: the run up to the next whitespace or the end of the field, or a
//   quoted run closed at once. Unless that value is one clean token, the field
//   is withheld. No quoting, CDATA or other format is parsed to find where a
//   messier value ends.
// - Nothing that spans lines is cut out: a private key withholds the field,
//   and so does text shaped like a .netrc file.
//
// A field is the string being redacted; in structured data, each string, and
// each array of strings as a whole.
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
  /** Set once anything withholds the field: no rule needs to read further. */
  withheld = false;

  constructor(text: string) {
    this.text = text;
  }

  /**
   * A secret token: a candidate for replacement when it is one clean token,
   * else the field is withheld. Whether the field's shape lets it be
   * replaced is decided once every rule has read the field.
   */
  token(start: number, end: number, replacement: string, rank: number): void {
    if (end <= start) return;
    const precise = isSafeToken(this.text, start, end);
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
/**
 * A quote that opens a value, written as is or escaped (\" in JSON held in a
 * string, \\\" a level deeper). The value then ends at the same quote,
 * escaped the same way.
 */
const OPEN_QUOTE = /(?:\\{1,7})?["']/y;

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
  if (!quote) {
    quote = matchAt(OPEN_QUOTE, text, at);
    start += quote.length;
  }
  const marker = matchAt(MARKER_AT, text, start).length;
  let end = start + marker;
  if (!marker) while (end < text.length && isSafeCode(text.charCodeAt(end))) end++;
  let after = end;
  if (quote) {
    if (!text.startsWith(quote, end)) {
      f.withhold(at);
      return undefined;
    }
    after = end + quote.length;
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

/** What the user:password of a URL is replaced with. */
const URL_CREDENTIALS = '<credentials>';

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
    URL_CREDENTIALS,
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
  'algorithm',
  'algo',
]);

const CREDENTIAL_WORDS = new Set([
  'pwd',
  'auth',
  'authorization',
  'apikey',
  'accesskey',
  'privatekey',
  'jwt',
  'otp',
  'totp',
  'hotp',
  'mfacode',
  'bearer',
  'dsn',
  'hmac',
  'connectionstring',
  'connstr',
  'connstring',
  'connectionstrings',
]);
/** A word that makes a name a secret when the next word is one of its set: mfa_code, connection_string. */
const CREDENTIAL_PAIRS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['mfa', new Set(['code'])],
  ['2fa', new Set(['code'])],
  ['connection', new Set(['string', 'strings', 'str'])],
  ['conn', new Set(['string', 'strings', 'str'])],
]);
/** Password-like words, where even a short number is the secret (a PIN or a one-time code). */
const ONE_TIME_WORDS = new Set(['otp', 'totp', 'hotp', 'mfacode']);
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
  'priv',
  'ssh',
  'license',
];
const KEY_QUALIFIERS = new Set(KEY_QUALIFIER_LIST);
const QUALIFIED_KEY = new RegExp(`(?:${KEY_QUALIFIER_LIST.join('|')})key$`);
const QUICK_CREDENTIAL =
  /pass|pwd|token|secret|key|auth|credential|cookie|jwt|otp|mfa|2fa|bearer|dsn|hmac|conn/i;

// Names repeat, often thousands of times in one result: each is split once.
const MAX_CACHED_NAMES = 1024;
const partsCache = new Map<string, readonly string[]>();

function nameParts(name: string): readonly string[] {
  let parts = partsCache.get(name);
  if (!parts) {
    const split = name
      .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter(Boolean);
    // passWord and PassWord split into pass and word: join them again.
    const joined: string[] = [];
    for (const part of split) {
      const last = joined[joined.length - 1];
      if (last === 'pass' && (part === 'word' || part === 'wd' || part === 'phrase')) {
        joined[joined.length - 1] = last + part;
      } else {
        joined.push(part);
      }
    }
    parts = joined;
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
    if (CREDENTIAL_PAIRS.get(part)?.has(parts[i + 1] ?? '')) return true;
    if (QUALIFIED_KEY.test(part)) return true;
    return part === 'key' && i > 0 && KEY_QUALIFIERS.has(parts[i - 1]!);
  });
}

/** A password-like name, where even a short number is the secret (a PIN or a one-time code). */
function isPasswordName(name: string): boolean {
  const parts = nameParts(name);
  return parts.some(
    (part, i) =>
      /password|passwd|passphrase/.test(part) ||
      part === 'pwd' ||
      ONE_TIME_WORDS.has(part) ||
      ((part === 'mfa' || part === '2fa') && parts[i + 1] === 'code') ||
      (part === 'pass' && i === parts.length - 1),
  );
}

// ---------------------------------------------------------------------------
// Names whose value is a secret only when it looks like one: sig, signature,
// session, sessionid. Vigil's own data uses these names for what it must
// show: a binary's code signature (signing ID, team ID, CDHash) and agent,
// login and audit session IDs. Redaction sees a key's own name, never the
// path to it, so the value's shape alone decides. A value that doesn't look
// like a secret is read like any other field, and never withholds one.

type Conditional = 'signature' | 'session';

/** The last words of a name whose value is a signature. */
const SIGNATURE_WORDS = new Set(['sig', 'signature']);
/** The last words of a name whose value is a session. */
/** sid as in connect.sid; a process's session ID (sid in ps) is a small number. */
const SESSION_WORDS = new Set(['session', 'sessionid', 'sessid', 'phpsessid', 'jsessionid', 'sid']);

function conditionalKind(parts: readonly string[]): Conditional | undefined {
  const last = parts[parts.length - 1];
  if (last === undefined) return undefined;
  if (SIGNATURE_WORDS.has(last)) return 'signature';
  if (SESSION_WORDS.has(last)) return 'session';
  // session_id, sessionId, sess_id.
  const before = parts[parts.length - 2];
  if (last === 'id' && (before === 'session' || before === 'sess')) return 'session';
  return undefined;
}

/**
 * A signature blob: base64 (standard or URL-safe) of at least 32 characters,
 * padding aside, so 24 bytes or more, the size of a MAC or a signature and
 * not of an identifier. It must hold a character that isn't hex, a digit, and
 * both cases of letter: random base64 that long lacks one of these about once
 * in 200, while hex never passes. Hex is left alone however long it is:
 * CDHashes (40 hex), SHA-256 digests (64 hex) and other hashes are hex, and
 * not secrets. A signing ID (com.apple.ls, platform:com.apple.ls,
 * TEAMID:com.example.app) holds dots or a colon, and a team ID is 10
 * characters, so neither is ever a blob.
 */
const SIGNATURE_BLOB = /^[A-Za-z0-9+/_-]{32,}={0,2}$/;

/**
 * A session token: at least 20 characters, with a letter and a digit, of
 * characters a token is written with. A login or audit session ID is a small
 * number, Vigil's own agent session is 16 hex, and a host's session ID such
 * as Claude Code's is a UUID: none of these is redacted.
 */
const SESSION_TOKEN = /^[A-Za-z0-9._~+/=%-]{20,}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The characters a conditional value is read over, to its end. */
function isConditionalCode(code: number): boolean {
  return (
    (code >= 0x30 && code <= 0x39) ||
    (code >= 0x41 && code <= 0x5a) ||
    (code >= 0x61 && code <= 0x7a) ||
    code === 0x2b || // +
    code === 0x2f || // /
    code === 0x3d || // =
    code === 0x5f || // _
    code === 0x2d || // -
    code === 0x2e || // .
    code === 0x7e || // ~
    code === 0x25 // %
  );
}

/**
 * Where a value under a conditional name ends: at the first character a
 * token isn't written with, or after the = padding that ends base64. A value
 * with = inside it is cut there, and so is never taken for a secret: every
 * value is then read once, whatever names repeat in the text.
 */
function conditionalEnd(text: string, at: number): number {
  let end = at;
  while (
    end < text.length &&
    text.charCodeAt(end) !== 0x3d &&
    isConditionalCode(text.charCodeAt(end))
  ) {
    end++;
  }
  while (text.charCodeAt(end) === 0x3d) end++;
  return end;
}

/** True when a value under a conditional name looks like a secret. */
function isConditionalSecret(kind: Conditional, value: string): boolean {
  if (kind === 'signature') {
    if (!SIGNATURE_BLOB.test(value)) return false;
    const body = value.replace(/=+$/, '');
    return (
      /[^0-9A-Fa-f]/.test(body) && /[0-9]/.test(body) && /[A-Z]/.test(body) && /[a-z]/.test(body)
    );
  }
  return (
    SESSION_TOKEN.test(value) && /[A-Za-z]/.test(value) && /[0-9]/.test(value) && !UUID.test(value)
  );
}

interface NameInfo {
  readonly credential: boolean;
  readonly password: boolean;
  readonly authorization: boolean;
  /** Set for a name that isn't a credential's, whose value may still be one. */
  readonly conditional: Conditional | undefined;
}
const nameCache = new Map<string, NameInfo>();

/** What addKeyedValues needs to know of a name, worked out once per name. */
function describeName(name: string): NameInfo {
  let info = nameCache.get(name);
  if (!info) {
    const credential = isCredentialName(name);
    const parts = nameParts(name);
    info = {
      credential,
      password: credential && isPasswordName(name),
      authorization: credential && parts.includes('authorization'),
      conditional: credential ? undefined : conditionalKind(parts),
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
 * The quotes around a name may be escaped, as in \"password\": in JSON
 * written inside a string.
 * The name must start a word, and backtracking within it fails at once, so
 * each name is read a bounded number of times whatever its length. npm's
 * _authToken starts with an underscore.
 */
const KEYED =
  /(?<![A-Za-z0-9_.-])(?:((?:\\{1,7})?["']|)-{0,2}(_*[A-Za-z][A-Za-z0-9_.-]*)((?:\\{1,7})?["']|)[ \t]*(===|==|=>|:=|[=:])[ \t]*|--([A-Za-z][A-Za-z0-9_-]*)[ \t]+(?=[^\s-]|-(?![-\s]|[A-Za-z](?:\s|$))))/g;
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
    if (!name.credential && !name.conditional) continue;
    const afterKey = m.index + m[0].length;
    const lead = m[1] ?? '';
    // 'x-api-key: abc' — the quote opens the shell argument, so the value runs
    // up to its closing quote and the quote stays.
    const argQuote = lead && !m[3] ? lead : '';
    if (name.conditional) {
      // Read only when the value looks like a secret; anything else, such as
      // a signing ID or a session number, is left as it is.
      const start = afterKey + (argQuote ? 0 : matchAt(OPEN_QUOTE, text, afterKey).length);
      const end = conditionalEnd(text, start);
      const next = text.charCodeAt(end);
      const ended =
        Number.isNaN(next) ||
        isSpace(next) ||
        next === 0x22 ||
        next === 0x27 ||
        next === 0x5c ||
        QUOTE_FOLLOWERS.includes(text[end]!);
      if (!ended || !isConditionalSecret(name.conditional, text.slice(start, end))) continue;
      const valueEnd = addValue(text, afterKey, false, f, argQuote);
      if (f.withheld) return;
      KEYED.lastIndex = Math.max(KEYED.lastIndex, valueEnd);
      continue;
    }
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
// .netrc text: a machine or default entry with a login, and a password.
// Its values follow spaces, so none can be cut out as a token: the field is
// withheld.

const NETRC_ENTRY = /(?:^|\s)(?:machine[ \t]+\S|default(?:\s|$))/;
const NETRC_LOGIN = /(?:^|\s)login[ \t]+\S/;
const NETRC_SECRET = /(?:^|\s)(?:password|account)[ \t]+\S/;

function addNetrc(text: string, f: Findings): void {
  if (!/password|account/i.test(text)) return;
  if (NETRC_ENTRY.test(text) && NETRC_LOGIN.test(text) && NETRC_SECRET.test(text)) f.withhold(0);
}

// ---------------------------------------------------------------------------
// Passwords given as command-line flags by tools that take them that way:
// curl -u user:pw, sshpass -p pw, docker login -p pw, openssl -k pw, mysql
// -ppw, redis-cli -a pw, mongosh -p pw. In free text these only withhold the
// field, so each flag is looked for anywhere in a field that names its tool:
// no command is read out of the text. An argument list is read by its
// structure instead, in redactArgv.

/**
 * The words a field must hold, then the flag with a value. A value that
 * starts with < is a marker an argument list's redaction left there.
 */
const COMMAND_SECRETS: ReadonlyArray<readonly [readonly RegExp[], RegExp]> = [
  // curl -u user:pass, --user user:pass, -uuser:pass; with no colon, curl asks.
  [[/curl/], /\s(?:-[uU][ \t]*|--(?:proxy-)?user(?:[ \t]+|=))["']?[^\s"':]*:[^\s<]/],
  [[/curl/], /\s--oauth2-bearer[ \t=]+[^\s<]/],
  [[/sshpass/], /\s-p[ \t]*[^\s<-]/],
  [[/docker|podman/, /\slogin\b/], /\s(?:-p[ \t]*|--password(?:=|[ \t]+))[^\s<-]/],
  [[/openssl/], /\s(?:-[kK][ \t]+[^\s<]|-pass(?:in|out)?[ \t]+["']?pass:[^\s<])/],
  // mysql -phunter2. A bare -p prompts; elsewhere -p is a port or a plain flag.
  [[/mysql|mariadb/], /\s-p[^\s<-]/],
  [[/redis-cli/], /\s(?:-a|--pass)[ \t]+[^\s<-]/],
  [[/mongo/], /\s-p[ \t]*[^\s<-]/],
];

const COMMAND_HINT = /curl|sshpass|docker|podman|openssl|mysql|mariadb|redis-cli|mongo/;

function addCommandSecrets(text: string, f: Findings): void {
  if (!COMMAND_HINT.test(text)) return;
  for (const [tools, flag] of COMMAND_SECRETS) {
    if (tools.every((tool) => tool.test(text)) && flag.test(text)) {
      f.withhold(0);
      return;
    }
  }
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
    if (!closed.has(m[1]!) || m[0].endsWith('/>')) continue;
    const info = describeName(local);
    if (!info.credential && !info.conditional) continue;
    const at = m.index + m[0].length;
    const close = `</${m[1]}>`;
    if (info.conditional) {
      // <signature>, <session>: replaced when its content looks like a
      // secret, and else read like any other text.
      const end = conditionalEnd(text, at);
      if (
        text.startsWith(close, end) &&
        isConditionalSecret(info.conditional, text.slice(at, end))
      ) {
        f.token(at, end, REDACTED, RANK_KEYED);
        XML_OPEN.lastIndex = end + close.length;
      }
      continue;
    }
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
    if (!hidesSecret(m[0])) continue;
    f.token(m.index, m.index + m[0].length, '<base64-secret>', RANK_BASE64);
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
// token) withholds the field. What JSON holds is cut out precisely only when
// the field is one JSON document; JSON inside other text is free text.

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
  /** Under a name such as signature or session: a secret only if it looks like one. */
  readonly conditional: Conditional | undefined;
  /** An array's element: it may be an argument of a command list. */
  readonly element: boolean;
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
  let conditional: Conditional | undefined;
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
    conditional = name.conditional;
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
      conditional = undefined;
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
      const element = frames.length > 0 && !frames[frames.length - 1]!.object;
      strings.push({ start: i + 1, end: end - 1, escaped, secret, conditional, element });
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
          conditional = undefined;
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

function analyzeString(
  text: string,
  options: NameOptions,
  depth: number,
  shape: Shape,
): readonly Finding[] {
  if (text.length > MAX_CACHED_LENGTH) return analyze(text, options, depth, shape);
  const key = `${depth}\0${shape}\0${text}`;
  let found = stringCache.get(key);
  if (!found) {
    found = analyze(text, options, depth, shape);
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
    if (s.conditional) {
      // Its characters need no escape, so as written it is as read, unless
      // a / was written \/: then it can't be cut out as written.
      const value = s.escaped
        ? (JSON.parse(text.slice(s.start - 1, s.end + 1)) as string)
        : text.slice(s.start, s.end);
      if (isConditionalSecret(s.conditional, value)) {
        if (s.escaped) f.withhold(s.start);
        else f.token(s.start, s.end, REDACTED, RANK_KEYED);
        continue;
      }
    }
    // A string of an object is a field of its own; an array's element is
    // read as a word of a command, where no secret is cut out.
    const shape: Shape = s.element ? 'word' : 'field';
    if (!s.escaped) {
      const field = text.slice(s.start, s.end);
      if (!mayHoldSecret(field, options)) continue;
      for (const x of analyzeString(field, options, depth + 1, shape)) {
        f.push({ ...x, start: x.start + s.start, end: x.end + s.start });
      }
      continue;
    }
    const value = JSON.parse(text.slice(s.start - 1, s.end + 1)) as string;
    if (!mayHoldSecret(value, options)) continue;
    const found = analyzeString(value, options, depth + 1, shape);
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
  // A field that is, whole, one JSON string, such as JSON encoded again: its
  // content is read as a field of its own, mapped back to the text as
  // written. A secret whose text holds an escape withholds the field.
  const first = skipJsonSpace(text, 0);
  if (text.charCodeAt(first) === 0x22) {
    const { end, escaped } = jsonStringEnd(text, first);
    if (end > 0 && skipJsonSpace(text, end) === text.length) {
      regions.push(first, end);
      const literal: JsonString = {
        start: first + 1,
        end: end - 1,
        escaped,
        secret: undefined,
        conditional: undefined,
        element: false,
      };
      addJsonFindings(
        text,
        { end, stop: end, clean: true, strings: [literal], numbers: [] },
        options,
        depth,
        f,
      );
      return;
    }
  }
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
// User, host and email names: privacy, not secrets. Each is replaced only in
// a shape that marks it as a name: a folder in a path (/Users/me/, /x/me/),
// an email, the user of user@host, the host after @ or //, or a host written
// with its domain. A bare word equal to the user name stays as written. The
// marker says which name stood there, so a replaced name hides nothing a
// reviewer needs: <user> and <host> are this Mac's own names.

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
      if (folder || text[end] === '@') f.name(start, end, '<user>');
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
        if (after || end > bare) f.name(start, end, '<host>');
        pattern.lastIndex = Math.max(pattern.lastIndex, end);
      }
    }
  }
}

/**
 * Text that matches none of this holds nothing any rule above looks for: a
 * credential-like name, a signature or session name, a token format's prefix, a command that takes a
 * password, an email, a home folder, a base64 run or a JSON escape.
 */
const SECRET_HINT = new RegExp(
  [
    QUICK_CREDENTIAL.source,
    // Names whose value may be a secret: sig, signature, session, sid.
    'sig|sess|sid',
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
 * Where a field sits, which decides whether a secret in it may be cut out:
 *
 * - field: a string of its own. Only a field that is, whole, one NAME=value
 *   assignment, one URL (see analyzeUrl), or one JSON document, has a place
 *   for a secret that nothing runs. A field that is only a URL or only a JSON
 *   document is not a realistic command name, so its precise replacement is
 *   accepted as safe. Free text such as a command line is withheld whole
 *   when it holds a secret: losing precision there is the safe direction.
 * - word: a word that may be a command, such as an argument or an array's
 *   element. No secret in it is cut out.
 */
type Shape = 'field' | 'word';

const URL_START = /^[A-Za-z][A-Za-z0-9+.-]{0,30}:\/\//;
const ASSIGNMENT_START = /^[A-Za-z_][A-Za-z0-9_]*=/;

// ---------------------------------------------------------------------------
// A field that is one URL. Only two kinds of value in it are cut out: the
// password of its userinfo, and the value of a query parameter whose name is
// a credential's. A secret anywhere else (the host, the path, the fragment,
// the user name, a parameter's name or another parameter's value) withholds
// the field. The URL is parsed with the WHATWG parser, and read only when it
// serializes back to exactly the field, so each part's place in the field is
// known; the replacements are spliced into the field as written.

/** The last word of a query parameter name that makes its value a secret. */
const URL_KEY_WORDS = new Set(['key', 'sig', 'signature']);

function isUrlCredentialKey(key: string): boolean {
  if (isCredentialName(key)) return true;
  const parts = nameParts(key);
  return parts.length > 0 && URL_KEY_WORDS.has(parts[parts.length - 1]!);
}

/** A character a field read as one URL may hold: safe ones, and ? # [ ] &. */
function isUrlCode(code: number): boolean {
  return (
    isSafeCode(code) ||
    code === 0x3f ||
    code === 0x23 ||
    code === 0x5b ||
    code === 0x5d ||
    code === 0x26
  );
}

function decodeQueryPart(part: string): string {
  try {
    return decodeURIComponent(part.replace(/\+/g, ' '));
  } catch {
    return part;
  }
}

/**
 * The findings of a field that is one URL, or undefined when it isn't one
 * the parser serializes back to exactly the field.
 */
function analyzeUrl(text: string, options: NameOptions, depth: number): Finding[] | undefined {
  for (let i = 0; i < text.length; i++) if (!isUrlCode(text.charCodeAt(i))) return undefined;
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    return undefined;
  }
  const { protocol, username, password, host, pathname, search, hash } = url;
  const userinfo = username || password ? `${username}${password ? `:${password}` : ''}@` : '';
  // The parser writes an empty path of http://host as /: the one change
  // allowed, as it moves no part of the field.
  const paths = pathname === '/' ? ['/', ''] : [pathname];
  const href = url.href;
  if (
    !paths.some(
      (path) =>
        `${protocol}//${userinfo}${host}${path}${search}${hash}` === text &&
        href === `${protocol}//${userinfo}${host}${pathname}${search}${hash}`,
    )
  ) {
    return undefined;
  }
  // [start, end] of each value to replace, and of what to leave out when the
  // rest of the field is checked for secrets: the password with its colon,
  // and each credential parameter whole.
  const replace: Array<readonly [number, number]> = [];
  const drop: Array<readonly [number, number]> = [];
  if (password) {
    const start = protocol.length + 2 + username.length + 1;
    replace.push([start, start + password.length]);
    drop.push([start - 1, start + password.length]);
  }
  if (search.length > 1) {
    let at = text.length - hash.length - search.length + 1;
    for (const pair of search.slice(1).split('&')) {
      const eq = pair.indexOf('=');
      const key = eq < 0 ? pair : pair.slice(0, eq);
      if (eq >= 0 && isUrlCredentialKey(decodeQueryPart(key))) {
        const value = pair.slice(eq + 1);
        drop.push([at, at + pair.length]);
        if (!isBenignValue(decodeQueryPart(value), isPasswordName(decodeQueryPart(key)))) {
          replace.push([at + eq + 1, at + pair.length]);
        }
      }
      at += pair.length + 1;
    }
  }
  for (const [start, end] of replace) if (!isSafeToken(text, start, end)) return [WITHHOLD];
  // Every other part of the field must hold no secret.
  let rest = '';
  let last = 0;
  for (const [start, end] of drop) {
    rest += text.slice(last, start);
    last = end;
  }
  rest += text.slice(last);
  if (analyze(rest, options, depth, 'word').some((x) => x.withhold || x.rank > RANK_NAME)) {
    return [WITHHOLD];
  }
  const f = new Findings(text);
  addNames(text, options, f);
  for (const [start, end] of replace) {
    f.push({ start, end, with: REDACTED, rank: RANK_KEYED, withhold: false });
  }
  return f.list;
}

/** Where the value starts when the field is one NAME=value with a clean value, else -1. */
function assignmentValueStart(text: string): number {
  const name = ASSIGNMENT_START.exec(text);
  if (!name) return -1;
  const from = name[0].length;
  let start = from;
  let end = text.length;
  const quote = text[start];
  if (end - start >= 2 && (quote === '"' || quote === "'") && text[end - 1] === quote) {
    start++;
    end--;
  }
  return start === end || isSafeToken(text, start, end) ? from : -1;
}

/** True when the one JSON region read is the whole field, blanks aside. */
function isJsonDocument(text: string, regions: readonly number[]): boolean {
  if (regions.length !== 2) return false;
  for (let i = 0; i < regions[0]!; i++) if (!isSpace(text.charCodeAt(i))) return false;
  for (let i = regions[1]!; i < text.length; i++) if (!isSpace(text.charCodeAt(i))) return false;
  return true;
}

/** The rules that find secrets. Any of them may withhold the field. */
const DETECTORS = [
  addPrivateKeys,
  addNetrc,
  addFormats,
  addCommandSecrets,
  addXml,
  addKeyedValues,
  addBase64,
];

/**
 * What every rule finds in a field: a single withholding finding when any
 * rule withholds it, whatever another rule reads there, or when a secret is
 * anywhere but in a value the field's shape sets apart; else the spans to
 * replace.
 */
function analyze(text: string, options: NameOptions, depth: number, shape: Shape): Finding[] {
  if (!mayHoldSecret(text, options)) return [];
  if (shape === 'field' && URL_START.test(text)) {
    const url = analyzeUrl(text, options, depth);
    if (url) return url;
  }
  const rules = new Findings(text);
  for (const step of DETECTORS) {
    step(text, rules);
    if (rules.withheld) return [WITHHOLD];
  }
  addNames(text, options, rules);
  const json = new Findings(text);
  const regions: number[] = [];
  if (
    depth < MAX_TEXT_DEPTH &&
    (text.includes('{') || text.includes('[') || text.trimStart().startsWith('"'))
  ) {
    addJson(text, options, depth, json, regions);
    if (json.withheld) return [WITHHOLD];
  }
  // Inside JSON, the JSON reading of each precise span stands.
  const found = regions.length ? outsideRegions(rules.list, regions) : rules.list;
  found.push(...json.list);
  if (!found.some((x) => x.rank > RANK_NAME)) return found;
  // A secret. JSON's own reading placed each one it found, by key.
  if (shape === 'field' && isJsonDocument(text, regions)) return found;
  const from = shape === 'field' ? assignmentValueStart(text) : -1;
  if (from < 0) return [WITHHOLD];
  return found.every((x) => x.rank === RANK_NAME || x.start >= from) ? found : [WITHHOLD];
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
function redactText(
  input: string,
  options: NameOptions,
  oversized?: number[],
  shape: Shape = 'field',
): string {
  if (input.length > MAX_REDACT_CHARS) {
    oversized?.push(input.length);
    return WITHHELD;
  }
  if (!mayHoldSecret(input, options)) return input;
  stringCache.clear();
  const found = analyze(input, options, 0, shape);
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

// ---------------------------------------------------------------------------
// Argument lists. The list is one field, and nothing in it is cut out: no
// tool's flags are read, so an argument is never taken for a value it isn't.
// Any secret anywhere in the list, in one argument or across several read
// as a command line, withholds every argument. User, host and email names
// are still replaced, in any argument.

/**
 * Redact an argument list as one field: WITHHELD for every argument when any
 * secret is in it, else the list with only user, host and email names
 * replaced.
 */
function redactArgvWithin(
  argv: readonly string[],
  options: NameOptions,
  oversized?: number[],
): string[] {
  if (!argv.length) return [];
  const out: string[] = [];
  let withheld = false;
  for (const arg of argv) {
    // Too long to read: withheld unread, and the list with it.
    if (arg.length > MAX_REDACT_CHARS) {
      oversized?.push(arg.length);
      withheld = true;
      continue;
    }
    const redacted = redactText(arg, options, undefined, 'word');
    if (redacted === WITHHELD && arg !== WITHHELD) withheld = true;
    out.push(redacted);
  }
  // Read whole, as a command line, a list still holds no secret: a flag and
  // its value span two arguments.
  if (!withheld && holdsSecret(argv.join(' '))) withheld = true;
  return withheld ? argv.map(() => WITHHELD) : out;
}

/** True when any rule finds a secret in the text, or withholds it. */
function holdsSecret(text: string): boolean {
  if (text.length > MAX_REDACT_CHARS) return true;
  stringCache.clear();
  return analyze(text, {}, 0, 'word').some((x) => x.withhold || x.rank > RANK_NAME);
}

/**
 * Redact a command's arguments as one field: every argument WITHHELD when any
 * secret is in it, else only user, host and email names replaced.
 */
export function redactArgv(argv: readonly string[], options: NameOptions = {}): string[] {
  return redactArgvWithin(argv, options);
}

/**
 * Redact every string in a JSON-like value. Keys are kept. A value under a
 * credential-named key (password, x-api-key, authToken, ...) is replaced
 * whatever it looks like: with REDACTED when it is one plain token, else
 * WITHHELD. When that value is an object or array, its shape is kept and
 * every string and number inside it is replaced, booleans and null aside,
 * and numbers under names like expires_at. Elsewhere, an array of strings
 * is read as an argument list (see redactArgv), and a string of any other
 * array as a word that may be a command. A value nested too deep, a cycle,
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
      // A list of strings may be a command's arguments: it is one field.
      if (!secret && value.length && value.every((item) => typeof item === 'string')) {
        return redactArgvWithin(value as string[], options, oversized);
      }
      // Any other list's string may still be a word of a command.
      return value.map((item) =>
        typeof item === 'string' && !secret
          ? redactText(item, options, oversized, 'word')
          : redactWithin(item, options, secret, depth + 1, ancestors, oversized),
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
        redacted =
          !keyed &&
          name.conditional &&
          typeof item === 'string' &&
          isConditionalSecret(name.conditional, item)
            ? REDACTED
            : redactWithin(item, options, keyed, depth + 1, ancestors, oversized);
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
