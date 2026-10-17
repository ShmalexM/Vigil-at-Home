/**
 * A command line with its paths written one way, for rules that look for a
 * path (agent-guard-tamper and its pre-flight twin). The same file can be
 * named many ways: `"$HOME"/Library/…`, `/Users/alex//Library/./…`,
 * `Vigil\ at\ Home`, `/Library/PrivilegedHelperTools/{vigil-helper,x}`. Here:
 *
 * - backslash escapes are undone and quotes dropped;
 * - a home folder (`~`, `$HOME`, `${HOME}`, `/Users/<name>`, `/home/<name>`)
 *   becomes `~`;
 * - empty and `.` path parts go, `..` drops the part before it, and
 *   /private/var, /private/tmp and /private/etc lose `/private`;
 * - one level of `{a,b}` in a word becomes one word per choice (at most 16).
 *
 * Words keep their place and whitespace, so separators still split commands.
 * Linear in the length of the line, which is cut at MAX_CHARS.
 */
export function commandPaths(cmd: string | undefined): string | undefined {
  if (cmd === undefined) return undefined;
  const s = cmd.length > MAX_CHARS ? cmd.slice(0, MAX_CHARS) : cmd;
  let plain = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '\\' && i + 1 < s.length) plain += s[++i];
    else if (c !== '"' && c !== "'") plain += c;
  }
  return plain.replace(/\S+/g, (word) => expandBraces(word).map(normalizeWord).join(' '));
}

/** Longest command line normalized. */
export const MAX_CHARS = 16_384;
/** Most words one `{…}` turns into. */
const MAX_CHOICES = 16;

/** `a{b,c}d` as `abd` and `acd`; a word with no such group as itself. */
function expandBraces(word: string): string[] {
  const open = word.indexOf('{');
  if (open < 0) return [word];
  const close = word.indexOf('}', open);
  if (close < 0) return [word];
  const inner = word.slice(open + 1, close);
  if (!inner.includes(',') || inner.includes('{')) return [word];
  const head = word.slice(0, open);
  const tail = word.slice(close + 1);
  return inner
    .split(',')
    .slice(0, MAX_CHOICES)
    .map((choice) => head + choice + tail);
}

/** Home folder prefixes, as the first path parts. */
const HOME_ROOTS = new Set(['Users', 'home']);
const PRIVATE_LINKS = new Set(['var', 'tmp', 'etc']);

function normalizeWord(word: string): string {
  // What comes before the path: `--file=`, `>`, `file:`, `(`.
  let at = 0;
  while (at < word.length && word[at] !== '/' && word[at] !== '~' && word[at] !== '$') at++;
  const lead = word.slice(0, at);
  let path = word.slice(at);
  for (const home of ['${HOME}', '$HOME'])
    if (path === home || path.startsWith(`${home}/`)) path = `~${path.slice(home.length)}`;
  if (!path.includes('/')) return lead + path;
  const parts = path.split('/');
  const absolute = parts[0] === '';
  const out: string[] = [];
  for (let i = absolute ? 1 : 0; i < parts.length; i++) {
    const p = parts[i]!;
    if (p === '' || p === '.') continue;
    const last = out[out.length - 1];
    if (p === '..' && last !== undefined && last !== '..' && !(out.length === 1 && last === '~'))
      out.pop();
    else out.push(p);
  }
  const trailing = path.endsWith('/') ? '/' : '';
  if (absolute && out.length >= 2 && HOME_ROOTS.has(out[0]!)) out.splice(0, 2, '~');
  // macOS: /var, /tmp and /etc are links into /private.
  if (absolute && out[0] === 'private' && PRIVATE_LINKS.has(out[1] ?? '')) out.shift();
  const joined = out.join('/');
  if (absolute && out[0] !== '~') return `${lead}/${joined}${joined ? trailing : ''}`;
  return lead + joined + (joined ? trailing : '');
}
