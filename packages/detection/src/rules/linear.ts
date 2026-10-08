import { setFlagsFromString } from 'node:v8';

/**
 * V8's linear-time regex engine (the `l` flag). Patterns that are not Vigil's
 * own run on it: matching takes time in proportion to pattern × subject
 * length, whatever the pattern, so no regex or glob a user or an AI writes can
 * stall the checks. It understands less than the usual engine: no lookahead,
 * no backreference, no repeat count above 16, and no `i` flag. foldCase
 * spells case-insensitivity out in the pattern instead, and splitRepeats
 * writes a count above 16 as several in a row.
 */

// Held in a variable: as a literal, linters reject `l` as an unknown flag.
const LINEAR = 'l';

let available: boolean | undefined;
/** For tests: pretend the runtime has, or lacks, the engine. */
let simulated: boolean | undefined;

function compiles(source: string, flags: string): boolean {
  try {
    new RegExp(source, flags);
    return true;
  } catch {
    return false;
  }
}

/** The `l` flag is taken, and a regex built with it matches. */
function works(): boolean {
  try {
    const re = new RegExp('^a+b$', LINEAR);
    return re.flags.includes(LINEAR) && re.test('aab') && !re.test('aa');
  } catch {
    return false;
  }
}

/**
 * Whether this runtime has the linear-time engine. It needs V8's
 * --enable-experimental-regexp-engine, which is turned on here the first time,
 * so Electron's main process, the helper's node and the tests need no command-line
 * flag. V8 reads it each time a regex is built, so setting it late works.
 *
 * Without it nothing falls back to the backtracking engine: a regex Vigil
 * does not ship is refused with the reason (linearProblem), except in a saved
 * rule that ran before (legacy.ts), and the app shows it in sensor health.
 */
export function linearEngine(): boolean {
  if (simulated !== undefined) return simulated;
  if (available !== undefined) return available;
  available = works();
  if (!available) {
    try {
      setFlagsFromString('--enable-experimental-regexp-engine');
    } catch {
      // Not a V8 that takes flags at run time: available stays false.
    }
    available = works();
  }
  return available;
}

/** For tests: act as if the runtime lacks (false) or has (true) the engine; undefined to stop. */
export function simulateLinearEngine(on: boolean | undefined): void {
  simulated = on;
}

/** Why a regex can't be used when this runtime has no linear-time engine. */
export const NO_LINEAR_ENGINE =
  "this copy of Vigil can't run the linear-time matcher, so only regexes Vigil ships, and those in rules saved before, can be used";

/** How the `i` flag compares characters without the `u` flag (ECMA-262 Canonicalize). */
function canonicalize(code: number): number {
  const u = String.fromCharCode(code).toUpperCase();
  if (u.length !== 1) return code;
  const up = u.charCodeAt(0);
  return code >= 128 && up < 128 ? code : up;
}

let canon: Uint16Array | undefined;

/** The code unit `i` compares `code` as (without `u`), from a table built on first use. */
export function caseFold(code: number): number {
  if (!canon) {
    canon = new Uint16Array(0x10000);
    for (let c = 0; c <= 0xffff; c++) canon[c] = canonicalize(c);
  }
  return canon[code]!;
}

/** Each code unit that `i` treats as equal to others, with all of them (itself included). */
let caseGroups: Map<number, number[]> | undefined;
/** The keys of caseGroups, in order. */
let caseCodes: number[] = [];

/** Built on first use: one pass over the 65,536 code units, a few milliseconds. */
function groups(): Map<number, number[]> {
  if (caseGroups) return caseGroups;
  const byCanon = new Map<number, number[]>();
  for (let c = 0; c <= 0xffff; c++) {
    const k = canonicalize(c);
    const g = byCanon.get(k);
    if (g) g.push(c);
    else byCanon.set(k, [c]);
  }
  caseGroups = new Map();
  for (const g of byCanon.values()) if (g.length > 1) for (const c of g) caseGroups.set(c, g);
  caseCodes = [...caseGroups.keys()].sort((a, b) => a - b);
  return caseGroups;
}

const groupOf = (code: number | undefined): number[] =>
  code === undefined ? [] : (groups().get(code) ?? []);

const hex = (code: number) => `\\u${code.toString(16).padStart(4, '0')}`;

/** One character, or a class of it and every character `i` treats as the same. */
function foldAtom(code: number, raw: string): string {
  const g = groupOf(code);
  return g.length ? `[${g.map(hex).join('')}]` : raw;
}

interface Escape {
  end: number;
  raw: string;
  /** The one character the escape stands for, when it stands for one. */
  code?: number;
}

/** Control escapes with one character each: \t \n \v \f \r. */
const CONTROL: Readonly<Record<string, number>> = { t: 9, n: 10, v: 11, f: 12, r: 13 };

/**
 * The escape at `i` (a backslash), read as without the `u` flag (ECMA-262
 * Annex B). Every escape that stands for one character gets its code, so a
 * class range between them (`[\0-\x7f]`, `[\t-\r]`) is folded as a range.
 * Without `u`, `\u{41}` is a plain `u` followed by a repeat count, and an
 * escape that is not a known one stands for its letter.
 */
function readEscape(p: string, i: number, inClass: boolean): Escape {
  const next = p[i + 1];
  if (next === undefined) return { end: i + 1, raw: '\\' };
  const at = (end: number, code?: number): Escape =>
    code === undefined ? { end, raw: p.slice(i, end) } : { end, raw: p.slice(i, end), code };
  if (next === 'x' && /^[0-9a-fA-F]{2}$/.test(p.slice(i + 2, i + 4)))
    return at(i + 4, parseInt(p.slice(i + 2, i + 4), 16));
  if (next === 'u' && /^[0-9a-fA-F]{4}$/.test(p.slice(i + 2, i + 6)))
    return at(i + 6, parseInt(p.slice(i + 2, i + 6), 16));
  const control = CONTROL[next];
  if (control !== undefined) return at(i + 2, control);
  if (next === 'c') {
    // \cJ, and in a class also \c0 and \c_: the code modulo 32. Otherwise
    // the backslash is itself, and the `c` is read next.
    const x = p[i + 2] ?? '';
    if (/^[A-Za-z]$/.test(x) || (inClass && /^[0-9_]$/.test(x)))
      return at(i + 3, x.charCodeAt(0) % 32);
    return { end: i + 1, raw: '\\', code: 92 };
  }
  // \0 (NUL) and legacy octal: \0 to \377 anywhere it starts with 0, and
  // \1 to \7 too in a class (outside one, those are backreferences).
  if (next === '0' || (inClass && /[1-7]/.test(next))) {
    let end = i + 2;
    const most = next <= '3' ? 3 : 2;
    while (end - i - 1 < most && /[0-7]/.test(p[end] ?? '')) end++;
    return at(end, parseInt(p.slice(i + 1, end), 8));
  }
  if (inClass && next === 'b') return at(i + 2, 8);
  // In a class \8, \9 and \B stand for themselves.
  if (inClass && /[89B]/.test(next)) return at(i + 2, next.charCodeAt(0));
  // Classes (\w, \d, \s, and their opposites) already hold every case;
  // assertions (\b \B) and backreferences (\1 to \9) have none.
  if (/[bBdDsSwW1-9]/.test(next)) return at(i + 2);
  // Anything else stands for itself: \., \/, and without `u`, \p and \k too.
  return at(i + 2, next.charCodeAt(0));
}

/** The class at `i` (a `[`), with every character `i` treats as equal added. */
function foldClass(p: string, i: number): { end: number; text: string } {
  let j = i + 1;
  const negated = p[j] === '^';
  if (negated) j++;
  let body = '';
  const extra = new Set<number>();
  const atom = (): Escape | undefined => {
    if (j >= p.length || p[j] === ']') return undefined;
    if (p[j] === '\\') {
      const e = readEscape(p, j, true);
      j = e.end;
      return e;
    }
    const code = p.charCodeAt(j);
    j++;
    return { end: j, raw: p[j - 1]!, code };
  };
  // A lone `-` is written escaped, so the characters added can go anywhere.
  const text = (e: Escape) => (e.raw === '-' ? '\\-' : e.raw);
  for (let a = atom(); a; a = atom()) {
    if (p[j] === '-' && p[j + 1] !== undefined && p[j + 1] !== ']') {
      j++;
      const b = atom()!;
      if (a.code !== undefined && b.code !== undefined) {
        body += `${text(a)}-${text(b)}`;
        groups();
        for (const c of caseCodes) {
          if (c < a.code) continue;
          if (c > b.code) break;
          for (const v of groupOf(c)) extra.add(v);
        }
        continue;
      }
      // Next to a class escape (\d-x) the `-` is a plain dash.
      body += `${text(a)}\\-${text(b)}`;
      for (const v of [...groupOf(a.code), ...groupOf(b.code)]) extra.add(v);
      continue;
    }
    body += text(a);
    for (const v of groupOf(a.code)) extra.add(v);
  }
  // An unclosed class is left for the RegExp constructor to report.
  const end = p[j] === ']' ? j + 1 : j;
  const added = [...extra].map(hex).join('');
  return { end, text: `[${negated ? '^' : ''}${added}${body}${p[j] === ']' ? ']' : ''}` };
}

/**
 * `pattern` rewritten to match, without the `i` flag, exactly what it matches
 * with it (and without `u`): each letter becomes a class of its cases, and
 * each class gains the other cases of what it holds. The linear-time engine
 * has no `i` flag.
 */
export function foldCase(pattern: string): string {
  let out = '';
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    if (c === '\\') {
      const e = readEscape(pattern, i, false);
      out += e.code === undefined ? e.raw : foldAtom(e.code, e.raw);
      i = e.end - 1;
    } else if (c === '[') {
      const cls = foldClass(pattern, i);
      out += cls.text;
      i = cls.end - 1;
    } else if (c === '(' && pattern[i + 1] === '?') {
      // A group's prefix, (?: (?= (?<! (?<name>, is copied: a group name is not text to match.
      let j = i + 2;
      while (j < pattern.length && !':=!>'.includes(pattern[j]!)) j++;
      out += pattern.slice(i, j + 1);
      i = j;
    } else if (c === '{') {
      const q = /^\{\d+(,\d*)?\}/.exec(pattern.slice(i));
      out += q ? q[0] : c;
      if (q) i += q[0].length - 1;
    } else {
      out += foldAtom(c.charCodeAt(0), c);
    }
  }
  return out;
}

/** Most times one quantifier may repeat in a rule's pattern: {64} fits a SHA-256 in hex. */
export const MAX_LINEAR_REPEAT = 64;
/** Most the linear-time engine repeats an atom in one quantifier, nested ones multiplied (V8's kMaxReplication). */
const ENGINE_REPEAT = 16;

/** Where the class at `i` (a `[`) ends, just past its `]`. */
function classEnd(p: string, i: number): number {
  let j = i + 1;
  if (p[j] === '^') j++;
  while (j < p.length && p[j] !== ']') j += p[j] === '\\' ? 2 : 1;
  return j + 1;
}

/** Where the group at `i` (a `(`) ends, just past its `)`. */
function groupEnd(p: string, i: number): number {
  let depth = 0;
  for (let j = i; j < p.length; j++) {
    const c = p[j];
    if (c === '\\') j++;
    else if (c === '[') j = classEnd(p, j) - 1;
    else if (c === '(') depth++;
    else if (c === ')' && --depth === 0) return j + 1;
  }
  return p.length;
}

/** `p` with every capturing group made non-capturing, so a copy of it declares no group twice. */
function uncapture(p: string): string {
  let out = '';
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    if (c === '\\') {
      out += p.slice(i, i + 2);
      i++;
    } else if (c === '[') {
      const end = classEnd(p, i);
      out += p.slice(i, end);
      i = end - 1;
    } else if (c === '(' && p[i + 1] !== '?') {
      out += '(?:';
    } else if (c === '(' && p[i + 2] === '<' && p[i + 3] !== '=' && p[i + 3] !== '!') {
      // (?<name>
      out += '(?:';
      i = p.indexOf('>', i);
    } else {
      out += c;
    }
  }
  return out;
}

/** `atom{n,m}` (m Infinity for {n,}) as quantifiers of at most ENGINE_REPEAT in a row. */
function repeatInChunks(atom: string, n: number, m: number, lazy: string): string {
  const one = uncapture(atom);
  let out = '';
  for (let left = n; left > 0; left -= ENGINE_REPEAT)
    out += `${one}{${Math.min(left, ENGINE_REPEAT)}}`;
  if (m === Infinity) return `${out}${one}*${lazy}`;
  for (let left = m - n; left > 0; left -= ENGINE_REPEAT)
    out += `${one}{0,${Math.min(left, ENGINE_REPEAT)}}${lazy}`;
  return out;
}

/**
 * `p` with each repeat count above 16 written as several counts of at most
 * 16 in a row: `x{40}` is `x{16}x{16}x{8}` and `x{20,}` is `x{16}x{4}x*`.
 * Rules only ask whether a pattern matches, so the copies need no capture
 * groups. Each count may be at most MAX_LINEAR_REPEAT; a larger one gives
 * `{ problem }`. The engine still refuses a count inside a repeated group
 * when the two multiply past 16.
 */
export function splitRepeats(p: string): { source: string } | { problem: string } {
  let out = '';
  // The atom just written, as it is in `out`, for a quantifier after it.
  let atom: string | undefined;
  for (let i = 0; i < p.length; i++) {
    const c = p[i]!;
    let next: string | undefined;
    if (c === '\\') {
      const e = readEscape(p, i, false);
      next = e.raw;
      i = e.end - 1;
    } else if (c === '[') {
      const end = classEnd(p, i);
      next = p.slice(i, end);
      i = end - 1;
    } else if (c === '(') {
      const end = groupEnd(p, i);
      let open = i + 1;
      if (p[open] === '?') {
        open++;
        while (open < end && !':=!>'.includes(p[open]!)) open++;
        open++;
      }
      const inner = splitRepeats(p.slice(open, end - 1));
      if ('problem' in inner) return inner;
      next = `${p.slice(i, open)}${inner.source})`;
      i = end - 1;
    } else if (c === '{') {
      const q = /^\{(\d+)(,(\d*))?\}(\??)/.exec(p.slice(i));
      if (q && atom !== undefined) {
        const n = Number(q[1]);
        const m = q[2] === undefined ? n : q[3] === '' ? Infinity : Number(q[3]);
        if (n > MAX_LINEAR_REPEAT || (m !== Infinity && m > MAX_LINEAR_REPEAT))
          return {
            problem: `it counts repeats only up to ${MAX_LINEAR_REPEAT}, so use * or + for {n,m} above that`,
          };
        if (n > ENGINE_REPEAT || (m !== Infinity && m > ENGINE_REPEAT)) {
          out = out.slice(0, out.length - atom.length) + repeatInChunks(atom, n, m, q[4]!);
        } else {
          out += q[0];
        }
        atom = undefined;
        i += q[0].length - 1;
        continue;
      }
      next = c;
    } else if ('*+?|^$'.includes(c)) {
      out += c;
      atom = undefined;
      continue;
    } else {
      next = c;
    }
    out += next;
    atom = next;
  }
  return { source: out };
}

/** The pattern as it runs on the linear-time engine, or why it can't. */
function linearSource(
  pattern: string,
  ignoreCase: boolean,
): { source: string } | { problem: string } {
  const split = splitRepeats(ignoreCase ? foldCase(pattern) : pattern);
  if ('problem' in split || compiles(split.source, LINEAR)) return split;
  const problem = /\(\?[=!]/.test(pattern)
    ? 'it has no lookahead, (?= or (?!'
    : /\{\d+(,\d*)?\}/.test(pattern)
      ? `it repeats at most ${ENGINE_REPEAT} times inside a repeated group, counts multiplied`
      : 'it supports no backreferences, lookaheads or large repeat counts';
  return { problem };
}

/**
 * Why `pattern` can't run on the linear-time engine, or undefined when it can.
 * Assumes regexProblem already passed it, so it is a valid regex.
 */
export function linearProblem(pattern: string, ignoreCase = false): string | undefined {
  if (!linearEngine()) return `regex can't be used: ${NO_LINEAR_ENGINE}`;
  const src = linearSource(pattern, ignoreCase);
  if (!('problem' in src)) return undefined;
  return `regex can't use the linear-time matcher that rules Vigil did not ship need: ${src.problem}`;
}

/**
 * A regex on the linear-time engine. Throws when linearProblem would refuse
 * the pattern, including when this runtime has no such engine: it never
 * falls back to the backtracking one.
 */
export function linearRegExp(pattern: string, ignoreCase: boolean): RegExp {
  if (!linearEngine()) throw new Error(`regex can't be used: ${NO_LINEAR_ENGINE}`);
  const src = linearSource(pattern, ignoreCase);
  if ('problem' in src)
    throw new Error(
      `regex can't use the linear-time matcher that rules Vigil did not ship need: ${src.problem}`,
    );
  return new RegExp(src.source, LINEAR);
}
