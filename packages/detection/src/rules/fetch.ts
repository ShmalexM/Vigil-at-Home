// Which curl and wget calls in a command line fetch only from this Mac
// itself. Used by the `process.commandLineRemote` field (fields.ts), so the
// "downloaded script run directly" rules can leave out a local server's
// answer without a regex trying to read curl's arguments.
//
// The rule is strict: a call counts as local only when every target it
// fetches is a loopback address and nothing about the call can send the
// request elsewhere. An option this file doesn't know, a proxy, a config
// file, a URL that doesn't parse, or no target at all, and the call stays
// as it is. When in doubt, it is not local.

/** curl options that take a value; the value is not a target. */
const CURL_ARG_LONG = new Set([
  '--referer',
  '--header',
  '--data',
  '--data-raw',
  '--data-binary',
  '--data-ascii',
  '--data-urlencode',
  '--output',
  '--user',
  '--user-agent',
  '--cookie',
  '--cookie-jar',
  '--form',
  '--request',
  '--max-time',
  '--connect-timeout',
  '--write-out',
  '--retry',
  '--retry-delay',
  '--retry-max-time',
  '--limit-rate',
  '--range',
  '--output-dir',
  '--dump-header',
  '--max-filesize',
  '--json',
]);
/** curl options that take no value. */
const CURL_FLAG_LONG = new Set([
  '--silent',
  '--show-error',
  '--fail',
  '--fail-with-body',
  '--location',
  '--insecure',
  '--compressed',
  '--include',
  '--head',
  '--verbose',
  '--no-progress-meter',
  '--globoff',
  '--http1.1',
  '--http2',
  '--ipv4',
  '--ipv6',
  '--remote-name',
  '--create-dirs',
  '--no-buffer',
  '--get',
  '--progress-bar',
]);
/** Short curl options that take a value (the rest of the cluster, or the next word). */
const CURL_ARG_SHORT = new Set('eHdouAbcFXmwYyrDCz'.split(''));
/** Short curl options that take none. */
const CURL_FLAG_SHORT = new Set('sSfLkiIvOgGN#46Rq'.split(''));

const WGET_ARG_LONG = new Set([
  '--output-document',
  '--output-file',
  '--header',
  '--user-agent',
  '--post-data',
  '--directory-prefix',
  '--timeout',
  '--tries',
  '--wait',
  '--user',
  '--password',
  '--referer',
]);
const WGET_FLAG_LONG = new Set([
  '--quiet',
  '--no-verbose',
  '--verbose',
  '--no-check-certificate',
  '--server-response',
  '--spider',
  '--continue',
  '--no-clobber',
]);
const WGET_ARG_SHORT = new Set('OoUPTtw'.split(''));
const WGET_FLAG_SHORT = new Set('qvSncN'.split(''));

/**
 * Options that would send the request somewhere else or read more options
 * from a file: a call with one is never local, whatever its target says.
 * (`--url` is a target, handled apart.)
 */
const NEVER_LOCAL_LONG = new Set([
  '--proxy',
  '--preproxy',
  '--socks4',
  '--socks4a',
  '--socks5',
  '--socks5-hostname',
  '--connect-to',
  '--resolve',
  '--config',
  '--execute',
  '--input-file',
  '--unix-socket',
  '--abstract-unix-socket',
]);
const NEVER_LOCAL_SHORT = { curl: new Set(['x', 'K']), wget: new Set(['e', 'i']) };

type Tool = 'curl' | 'wget';

interface Spec {
  argLong: Set<string>;
  flagLong: Set<string>;
  argShort: Set<string>;
  flagShort: Set<string>;
  neverShort: Set<string>;
}
const SPEC: Record<Tool, Spec> = {
  curl: {
    argLong: CURL_ARG_LONG,
    flagLong: CURL_FLAG_LONG,
    argShort: CURL_ARG_SHORT,
    flagShort: CURL_FLAG_SHORT,
    neverShort: NEVER_LOCAL_SHORT.curl,
  },
  wget: {
    argLong: WGET_ARG_LONG,
    flagLong: WGET_FLAG_LONG,
    argShort: WGET_ARG_SHORT,
    flagShort: WGET_FLAG_SHORT,
    neverShort: NEVER_LOCAL_SHORT.wget,
  },
};

/** Words of one simple command, with quotes removed. Undefined if a quote is left open. */
function words(text: string): string[] | undefined {
  const out: string[] = [];
  let cur = '';
  let inWord = false;
  let quote: '"' | "'" | undefined;
  for (const ch of text) {
    if (quote) {
      if (ch === quote) quote = undefined;
      else cur += ch;
      continue;
    }
    if (ch === '"' || ch === "'") {
      quote = ch;
      inWord = true;
    } else if (/\s/.test(ch)) {
      if (inWord) out.push(cur);
      cur = '';
      inWord = false;
    } else {
      cur += ch;
      inWord = true;
    }
  }
  if (quote) return undefined;
  if (inWord) out.push(cur);
  return out;
}

/** A target that is this Mac itself: http(s) to 127.x.x.x, localhost or [::1], with no user part. */
export function isLoopbackTarget(target: string): boolean {
  // curl's URL globbing ({a,b}, [1-9]) could name anything.
  if (/[{}[\]]/.test(target.replace(/^\w+:\/\/\[::1\]/i, ''))) return false;
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(target) ? target : `http://${target}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return false;
  if (url.username || url.password) return false;
  const host = url.hostname.toLowerCase();
  if (host === 'localhost' || host === '[::1]') return true;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Whether one curl or wget call (its words after the program name) fetches
 * only from this Mac: at least one target, every target loopback, and only
 * options this file knows, none of which can send the request elsewhere.
 */
export function fetchesOnlyLoopback(tool: Tool, args: readonly string[]): boolean {
  const spec = SPEC[tool];
  const targets: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === '--') {
      targets.push(...args.slice(i + 1));
      break;
    }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const name = eq === -1 ? a : a.slice(0, eq);
      if (NEVER_LOCAL_LONG.has(name)) return false;
      if (name === '--url') {
        const v = eq === -1 ? args[++i] : a.slice(eq + 1);
        if (v === undefined) return false;
        targets.push(v);
      } else if (spec.argLong.has(name)) {
        if (eq === -1) i++;
      } else if (!spec.flagLong.has(name) || eq !== -1) {
        return false;
      }
      continue;
    }
    if (a.startsWith('-') && a.length > 1) {
      for (let j = 1; j < a.length; j++) {
        const c = a[j]!;
        if (spec.neverShort.has(c)) return false;
        if (spec.argShort.has(c)) {
          // The rest of the cluster is the value, or else the next word is.
          if (j === a.length - 1) i++;
          break;
        }
        if (!spec.flagShort.has(c)) return false;
      }
      continue;
    }
    targets.push(a);
  }
  return targets.length > 0 && targets.every(isLoopbackTarget);
}

/** Where a simple command ends: a pipe, a list operator, a subshell's close or a new line. */
const COMMAND_END = /[|;&)\n]/;

/**
 * The command line with every curl or wget call that fetches only from this
 * Mac renamed `local-fetch`, so a pattern looking for `curl …| sh` no longer
 * sees it. Every other call, and the rest of the line, is left as it is.
 */
export function blankLoopbackFetches(cmd: string): string {
  const re = /(^|[\s;&|($`'"])(curl|wget)(?=\s)/g;
  let out = '';
  let last = 0;
  for (let m = re.exec(cmd); m; m = re.exec(cmd)) {
    const start = m.index + m[1]!.length;
    const tool = m[2] as Tool;
    // The call's words run to the end of its simple command, ignoring ends inside quotes.
    let end = start + tool.length;
    let quote: string | undefined;
    for (; end < cmd.length; end++) {
      const ch = cmd[end]!;
      if (quote) {
        if (ch === quote) quote = undefined;
      } else if (ch === '"' || ch === "'") quote = ch;
      else if (COMMAND_END.test(ch)) break;
    }
    // A proxy set for this one command (`https_proxy=… curl …`) sends it elsewhere.
    const before = cmd.slice(0, start);
    const head = before.slice(Math.max(...[...'|;&(\n'].map((c) => before.lastIndexOf(c))) + 1);
    const args = words(cmd.slice(start + tool.length, end));
    if (args && !/proxy=/i.test(head) && fetchesOnlyLoopback(tool, args)) {
      out += `${cmd.slice(last, start)}local-fetch`;
      last = start + tool.length;
    }
  }
  return out + cmd.slice(last);
}
