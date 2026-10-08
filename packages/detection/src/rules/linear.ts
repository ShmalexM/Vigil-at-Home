import { setFlagsFromString } from 'node:v8';

/**
 * V8's linear-time regex engine (the `l` flag). Patterns that are not Vigil's
 * own run on it: matching takes time in proportion to pattern × subject
 * length, whatever the pattern, so no regex or glob a user or an AI writes can
 * stall the checks. It understands less than the usual engine: no lookahead,
 * no backreference, no repeat count above 16, and no `i` flag, so foldCase
 * spells case-insensitivity out in the pattern instead.
 */

// Held in a variable: as a literal, linters reject `l` as an unknown flag.
const LINEAR = 'l';

let available: boolean | undefined;

function compiles(source: string, flags: string): boolean {
  try {
    new RegExp(source, flags);
    return true;
  } catch {
    return false;
  }
}

/**
 * Whether this runtime has the linear-time engine. It needs V8's
 * --enable-experimental-regexp-engine, which is turned on here the first time,
 * so Electron's main process, the helper's node and the tests need no command-line
 * flag. V8 reads it each time a regex is built, so setting it late works.
 */
export function linearEngine(): boolean {
  if (available !== undefined) return available;
  available = compiles('', LINEAR);
  if (!available) {
    try {
      setFlagsFromString('--enable-experimental-regexp-engine');
    } catch {
      // Not a V8 that takes flags at run time: available stays false.
    }
    available = compiles('', LINEAR);
  }
  return available;
}

/** How the `i` flag compares characters without the `u` flag (ECMA-262 Canonicalize). */
function canonicalize(code: number): number {
  const u = String.fromCharCode(code).toUpperCase();
  if (u.length !== 1) return code;
  const up = u.charCodeAt(0);
  return code >= 128 && up < 128 ? code : up;
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

/**
 * Why `pattern` can't run on the linear-time engine, or undefined when it can.
 * Assumes regexProblem already passed it, so it is a valid regex.
 */
export function linearProblem(pattern: string, ignoreCase = false): string | undefined {
  if (!linearEngine()) return undefined;
  if (compiles(ignoreCase ? foldCase(pattern) : pattern, LINEAR)) return undefined;
  const why = /\(\?[=!]/.test(pattern)
    ? 'it has no lookahead, (?= or (?!'
    : /\{\d+(,\d*)?\}/.test(pattern)
      ? 'it counts repeats only up to 16, so use * or + for {n,m} above that'
      : 'it supports no backreferences, lookaheads or large repeat counts';
  return `regex can't use the linear-time matcher that rules Vigil did not ship need: ${why}`;
}

/**
 * A regex on the linear-time engine, or on the usual one when this runtime
 * has none. Throws when linearProblem would refuse the pattern.
 */
export function linearRegExp(pattern: string, ignoreCase: boolean): RegExp {
  if (!linearEngine()) return new RegExp(pattern, ignoreCase ? 'i' : '');
  const problem = linearProblem(pattern, ignoreCase);
  if (problem) throw new Error(problem);
  return new RegExp(ignoreCase ? foldCase(pattern) : pattern, LINEAR);
}
