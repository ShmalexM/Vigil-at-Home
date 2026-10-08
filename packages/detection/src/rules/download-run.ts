/**
 * A shell command line that downloads something and has any way to run code.
 *
 * The download-then-run rule (shadow) uses this. It does not try to work out
 * whether the downloaded bytes reach the code runner, or whether the code is
 * harmless. It asks two questions of the command and answers yes whenever it
 * is unsure:
 *
 * 1. Is a downloader (curl, wget, aria2c, http, fetch) the PROGRAM of some
 *    simple command, anywhere in the line, including inside command
 *    substitutions and the code arguments of eval, sh -c and xargs?
 * 2. Is there any execution vector anywhere: a simple command whose program
 *    is an interpreter or shell, python without `-m`, eval, source or `.`,
 *    xargs, find with -exec, tar with --to-command, awk with system( or -f,
 *    sed with an e flag or command, a git `!` alias, env -S, exec -a, or a
 *    command substitution used as the program name; or a process
 *    substitution `<(`/`>(` or a here-string `<<<`?
 *
 * Both questions are asked of a lightly cleaned copy (backslash-newlines
 * joined, ${IFS} spaced) tokenised into words, so a word is only read where
 * a program name sits, never inside a quoted argument or a package name. To
 * find a word someone broke up, quotes and backslashes are dropped while
 * tokenising, so `'cu''rl'`, `c"ur"l` and `c\url` are all the program `curl`.
 *
 * Only the recognised vectors above count; an unfamiliar program (bun, deno,
 * a saved file run as ./x) is not treated as a runner, so those are gaps for
 * the later on-switch, not matches here.
 *
 * Claude Code's harness wraps each command as `eval '<command>'`, optionally
 * after sourcing its shell snapshot. The wrapper only runs the quoted text,
 * so an exact wrapper is replaced by the text it runs before the questions
 * are asked; the snapshot form is unwrapped only when its home is the shell's
 * own user, so a foreign snapshot fails closed and the eval still counts.
 * Anything else that merely looks like a wrapper is left as is.
 *
 * Every scan is linear and the input is clipped to the engine's subject
 * limit, so a Shadow rule never slows detection.
 */

import { MAX_SUBJECT_LENGTH } from './compile.js';
import { harnessWrappers } from './quiet-lines.js';

/** Shells and interpreters that run code when they are the program. */
export const INTERPRETERS = new Set([
  'sh',
  'bash',
  'zsh',
  'dash',
  'ksh',
  'fish',
  'node',
  'perl',
  'ruby',
  'php',
  'osascript',
]);

const DOWNLOADERS = new Set(['curl', 'wget', 'aria2c', 'http', 'fetch']);

/** Programs that run the real command that follows them; skipped to reach it. */
const WRAPPERS = new Set([
  'sudo',
  'doas',
  'nohup',
  'command',
  'time',
  'nice',
  'stdbuf',
  'setsid',
  'builtin',
]);

const ASSIGN = /^[A-Za-z_][A-Za-z0-9_]*=/;
const MAX_DEPTH = 6;

interface Word {
  /** The word's text, with quotes and backslashes already removed. */
  text: string;
  /** Command substitutions found in the word (`$(…)` or backticks). */
  subs: string[];
  /** The word begins with a command substitution (a program-name vector). */
  progSub: boolean;
  /** The word is a redirection target, never a program. */
  redir: boolean;
}

interface Parsed {
  segments: Word[][];
  /** Command substitutions and process-substitution bodies to scan too. */
  subs: string[];
  /** A `<(`/`>(` process substitution or a `<<<` here-string was present. */
  spawnVector: boolean;
}

function newWord(): Word {
  return { text: '', subs: [], progSub: false, redir: false };
}

/** The balanced `(`…`)` body starting after an opening `$(`; returns it and the index past `)`. */
function captureParens(s: string, start: number): [string, number] {
  let depth = 1;
  let i = start;
  while (i < s.length && depth > 0) {
    const c = s[i]!;
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (c === "'") {
      const e = s.indexOf("'", i + 1);
      i = e === -1 ? s.length : e + 1;
      continue;
    }
    if (c === '(') depth++;
    else if (c === ')') {
      depth--;
      if (depth === 0) return [s.slice(start, i), i + 1];
    }
    i++;
  }
  return [s.slice(start, i), i];
}

/** Backslash-newlines joined, ${IFS}/$IFS turned into a space. */
function expandSeparators(text: string): string {
  return text.replace(/\\\r?\n/g, '').replace(/\$\{IFS\}|\$IFS\b/g, ' ');
}

/** Quotes and backslashes dropped, backslash-newlines joined, ${IFS} as a space. */
export function deobfuscate(text: string): string {
  return expandSeparators(text).replace(/['"\\]/g, '');
}

/**
 * Split a command into simple commands (words grouped between `|`, `;`, `&&`
 * and the like), collecting substitution bodies. Quotes are consumed so their
 * contents never read as words; `$(…)` and backticks are pulled out even
 * inside double quotes, as the shell expands them there.
 */
function tokenize(input: string): Parsed {
  const s = expandSeparators(input);
  const segments: Word[][] = [];
  const subs: string[] = [];
  let spawnVector = false;
  let seg: Word[] = [];
  let cur: Word | null = null;
  let redirPending = false;

  const ensure = (): Word => {
    if (!cur) {
      cur = newWord();
      if (redirPending) {
        cur.redir = true;
        redirPending = false;
      }
    }
    return cur;
  };
  const endWord = () => {
    if (cur) {
      seg.push(cur);
      cur = null;
    }
  };
  const endSeg = () => {
    endWord();
    if (seg.length) segments.push(seg);
    seg = [];
  };

  let i = 0;
  while (i < s.length) {
    const c = s[i]!;
    if (c === "'") {
      const e = s.indexOf("'", i + 1);
      ensure().text += e === -1 ? s.slice(i + 1) : s.slice(i + 1, e);
      i = e === -1 ? s.length : e + 1;
      continue;
    }
    if (c === '"') {
      i++;
      const w = ensure();
      while (i < s.length && s[i] !== '"') {
        if (s[i] === '\\' && i + 1 < s.length) {
          w.text += s[i + 1];
          i += 2;
          continue;
        }
        if (s[i] === '$' && s[i + 1] === '(') {
          const [inner, ni] = captureParens(s, i + 2);
          w.subs.push(inner);
          subs.push(inner);
          i = ni;
          continue;
        }
        if (s[i] === '`') {
          const e = s.indexOf('`', i + 1);
          const inner = e === -1 ? s.slice(i + 1) : s.slice(i + 1, e);
          w.subs.push(inner);
          subs.push(inner);
          i = e === -1 ? s.length : e + 1;
          continue;
        }
        w.text += s[i];
        i++;
      }
      i++;
      continue;
    }
    if (c === '\\' && i + 1 < s.length) {
      ensure().text += s[i + 1];
      i += 2;
      continue;
    }
    if (c === '$' && s[i + 1] === '(') {
      const w = ensure();
      if (w.text === '' && w.subs.length === 0) w.progSub = true;
      const [inner, ni] = captureParens(s, i + 2);
      w.subs.push(inner);
      subs.push(inner);
      i = ni;
      continue;
    }
    if (c === '`') {
      const w = ensure();
      if (w.text === '' && w.subs.length === 0) w.progSub = true;
      const e = s.indexOf('`', i + 1);
      const inner = e === -1 ? s.slice(i + 1) : s.slice(i + 1, e);
      w.subs.push(inner);
      subs.push(inner);
      i = e === -1 ? s.length : e + 1;
      continue;
    }
    if ((c === '<' || c === '>') && s[i + 1] === '(') {
      spawnVector = true;
      const [inner, ni] = captureParens(s, i + 2);
      subs.push(inner);
      endWord();
      i = ni;
      continue;
    }
    if (c === '<' && s[i + 1] === '<' && s[i + 2] === '<') {
      spawnVector = true;
      endWord();
      redirPending = true;
      i += 3;
      continue;
    }
    if (c === '>' || c === '<') {
      endWord();
      redirPending = true;
      i++;
      while (s[i] === '>' || s[i] === '|') i++;
      continue;
    }
    if (c === '|') {
      endSeg();
      i += s[i + 1] === '|' || s[i + 1] === '&' ? 2 : 1;
      continue;
    }
    if (c === '&') {
      endSeg();
      i += s[i + 1] === '&' ? 2 : 1;
      continue;
    }
    if (c === ';' || c === '\n' || c === '(' || c === ')' || c === '{' || c === '}') {
      endSeg();
      i++;
      continue;
    }
    if (c === ' ' || c === '\t' || c === '\r') {
      endWord();
      i++;
      continue;
    }
    ensure().text += c;
    i++;
  }
  endSeg();
  return { segments, subs, spawnVector };
}

function basename(t: string): string {
  const i = t.lastIndexOf('/');
  return i === -1 ? t : t.slice(i + 1);
}

/** The words of a simple command, as text joined by single spaces. */
function segText(words: Word[]): string {
  return words.map((w) => w.text).join(' ');
}

const SED_RUN = [
  // The e flag on an s command: s<delim>…<delim>…<delim> with an e among its flags.
  /s([^\s\w\\])(?:(?!\1).)*\1(?:(?!\1).)*\1[A-Za-z0-9]*e/,
  // The e command, after a separator or at the start of the script.
  /(?:^|[\s;{])[0-9$,]*e(?=\s|$)/,
];

/** The real program of a simple command: the first word past assignments, redirections and wrappers. */
function programWord(words: Word[]): Word | undefined {
  const live = words.filter((w) => !w.redir);
  let k = 0;
  while (k < live.length) {
    const w = live[k]!;
    // A leading NAME=value assignment (not a path, no substitution).
    if (
      w.subs.length === 0 &&
      ASSIGN.test(w.text) &&
      !w.text.slice(0, w.text.indexOf('=')).includes('/')
    ) {
      k++;
      continue;
    }
    const name = basename(w.text);
    if (WRAPPERS.has(name)) {
      k++;
      continue;
    }
    if (name === 'timeout') {
      k++;
      while (live[k] && live[k]!.text.startsWith('-')) k++;
      if (live[k] && !live[k]!.text.startsWith('-')) k++;
      continue;
    }
    if (name === 'env' && !hasSplitString(live)) {
      k++;
      while (live[k] && (live[k]!.text.startsWith('-') || ASSIGN.test(live[k]!.text))) k++;
      continue;
    }
    if (name === 'exec' && !hasExecName(live)) {
      k++;
      while (live[k] && live[k]!.text.startsWith('-')) k++;
      continue;
    }
    return w;
  }
  return undefined;
}

function hasSplitString(words: Word[]): boolean {
  return words.some((w) => /^-[A-Za-z]*S$/.test(w.text) || w.text === '--split-string');
}

function hasExecName(words: Word[]): boolean {
  return words.some((w) => /^-[A-Za-z]*a$/.test(w.text));
}

/** This simple command runs code (one of the recognised vectors). */
function segmentIsRunner(words: Word[]): boolean {
  const prog = programWord(words);
  if (!prog) return false;
  // A command substitution forms (part of) the program name, e.g. /bin/$(printf sh).
  if (prog.progSub || prog.subs.length > 0) return true;
  const name = basename(prog.text);
  if (INTERPRETERS.has(name)) return true;
  if (/^python[0-9.]*$/.test(name)) return !words.some((w) => w.text === '-m');
  if (name === 'eval' || name === 'source' || name === '.') return true;
  if (name === 'xargs') return true;
  const text = segText(words);
  if (name === 'find' && /\s-(exec|execdir|ok|okdir)\b/.test(text)) return true;
  if (name === 'tar' && /--to-command/.test(text)) return true;
  if (
    (name === 'awk' || name === 'gawk' || name === 'mawk' || name === 'nawk') &&
    /system\s*\(|\s-f\b/.test(text)
  )
    return true;
  if (name === 'sed' && SED_RUN.some((re) => re.test(text.slice(text.indexOf(' ') + 1))))
    return true;
  if (name === 'git' && /alias\.[^\s=]*\s*=\s*!/.test(text)) return true;
  if (name === 'env' && hasSplitString(words)) return true;
  if (name === 'exec' && hasExecName(words)) return true;
  return false;
}

/** The code eval/xargs run as their own command, to scan for a downloader. */
function codeArgs(words: Word[]): string | undefined {
  const prog = programWord(words);
  if (!prog) return undefined;
  const name = basename(prog.text);
  if (name === 'eval' || name === 'xargs') {
    const at = words.indexOf(prog);
    return words
      .slice(at + 1)
      .map((w) => w.text)
      .join(' ');
  }
  return undefined;
}

interface Verdict {
  download: boolean;
  runner: boolean;
}

function analyze(text: string, depth: number): Verdict {
  if (depth > MAX_DEPTH) return { download: false, runner: false };
  const { segments, subs, spawnVector } = tokenize(text);
  let download = false;
  let runner = spawnVector;
  for (const words of segments) {
    const prog = programWord(words);
    if (prog && DOWNLOADERS.has(basename(prog.text))) download = true;
    if (segmentIsRunner(words)) runner = true;
    const code = codeArgs(words);
    if (code) {
      const r = analyze(code, depth + 1);
      download ||= r.download;
      runner ||= r.runner;
    }
  }
  for (const sub of subs) {
    const r = analyze(sub, depth + 1);
    download ||= r.download;
    runner ||= r.runner;
  }
  return { download, runner };
}

function clip(s: string): string {
  return s.length > MAX_SUBJECT_LENGTH ? s.slice(0, MAX_SUBJECT_LENGTH) : s;
}

/** The text downloads something and has a way to run code. */
export function downloadsAndRuns(text: string): boolean {
  const { download, runner } = analyze(clip(text), 0);
  return download && runner;
}

/** Single-quoted text in which each ' is written '\'', captured as `cmd`. */
const QUOTED = "(?<cmd>(?:[^']|'\\\\'')*)";
/** Each harness wrapper as [regex, index of its home-directory group or -1]. */
const HARNESS = harnessWrappers(QUOTED).map((src) => ({
  re: new RegExp(src),
  // The snapshot wrapper pins the snapshot to the shell's user via this group.
  hasHome: src.includes('?<home>'),
}));

/**
 * The command an exact Claude Code wrapper runs, else the text unchanged. The
 * snapshot form is only unwrapped when its home directory is the shell's own
 * user; a foreign snapshot is left wrapped so its eval still counts.
 */
export function unwrapHarness(text: string, user?: string): string {
  for (const { re, hasHome } of HARNESS) {
    const m = re.exec(text);
    if (!m) continue;
    if (hasHome) {
      const home = m.groups?.home;
      if (home === undefined || home !== user || home === 'Shared') return text;
    }
    return m.groups!.cmd!.replace(/'\\''/g, "'");
  }
  return text;
}

/**
 * A shell's arguments after its own name, without bare flags like `-c` or
 * `-lc`, each unwrapped from Claude Code's harness when it matches exactly.
 */
export function shellScript(
  args: readonly string[] | undefined,
  user?: string,
): string | undefined {
  if (!args || args.length < 2) return undefined;
  return args
    .slice(1)
    .filter((a) => !/^-[A-Za-z]+$/.test(a))
    .map((a) => unwrapHarness(a, user))
    .join(' ');
}

/** A shell started with these arguments downloads something and can run code. */
export function shellDownloadsAndRuns(args: readonly string[] | undefined, user?: string): boolean {
  const script = shellScript(args, user);
  return script !== undefined && downloadsAndRuns(script);
}
