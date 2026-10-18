/**
 * A command line with its paths written one way, for rules that look for a
 * path (agent-guard-tamper and its pre-flight twin). The same file can be
 * named many ways: `"$HOME"/Library/…`, `/Users/alex//Library/./…`,
 * `Vigil\ at\ Home`, `/Library/PrivilegedHelperTools/{vigil-helper,x}`. Here:
 *
 * - backslash escapes are undone and quotes dropped;
 * - a home folder (`~`, `~<name>`, `$HOME`, `${HOME}`, `/Users/<name>`,
 *   `/home/<name>`) becomes `~`;
 * - empty and `.` path parts go, `..` drops the part before it, and the
 *   firmlink /System/Volumes/Data and /private (before var, tmp, etc) go;
 * - up to three `{a,b}` groups in a word become one word per choice (at
 *   most 16).
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
/** Most words one word's `{…}` groups turn into. */
const MAX_CHOICES = 16;

/**
 * `a{b,c}d` as `abd` and `acd`, for up to MAX_GROUPS groups in a word, at
 * most MAX_CHOICES words in all; a word with no such group as itself.
 */
function expandBraces(word: string): string[] {
  let words = [word];
  for (let g = 0; g < MAX_GROUPS; g++) {
    const next: string[] = [];
    let grew = false;
    for (const w of words) {
      const open = w.indexOf('{');
      const close = open < 0 ? -1 : w.indexOf('}', open);
      const inner = close < 0 ? '' : w.slice(open + 1, close);
      if (close < 0 || !inner.includes(',') || inner.includes('{')) {
        next.push(w);
        continue;
      }
      grew = true;
      for (const choice of inner.split(','))
        next.push(w.slice(0, open) + choice + w.slice(close + 1));
    }
    words = next.slice(0, MAX_CHOICES);
    if (!grew) break;
  }
  return words;
}

/** Most `{…}` groups one word expands. */
const MAX_GROUPS = 3;

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
  // `~user/…`: another account's home, written as one.
  if (path.startsWith('~') && !path.startsWith('~/')) {
    const slash = path.indexOf('/');
    if (slash > 1 && /^~[\w.-]+$/.test(path.slice(0, slash))) path = `~${path.slice(slash)}`;
  }
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
  // macOS: everything on the data volume is also under /System/Volumes/Data.
  if (absolute && out[0] === 'System' && out[1] === 'Volumes' && out[2] === 'Data')
    out.splice(0, 3);
  if (absolute && out.length >= 2 && HOME_ROOTS.has(out[0]!)) out.splice(0, 2, '~');
  // macOS: /var, /tmp and /etc are links into /private.
  if (absolute && out[0] === 'private' && PRIVATE_LINKS.has(out[1] ?? '')) out.shift();
  const joined = out.join('/');
  if (absolute && out[0] !== '~') return `${lead}/${joined}${joined ? trailing : ''}`;
  return lead + joined + (joined ? trailing : '');
}
