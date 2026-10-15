import { BlockList, isIP } from 'node:net';
import type { Condition, DetectionEvent, FieldTest } from '../types.js';
import { compileField, keyOf, type FieldGetter, type FieldValue } from './fields.js';
import { caseFold, linearRegExp } from './linear.js';
import { isLegacyPattern, type LegacyUse } from './legacy.js';
import { isTrustedPattern } from './trusted.js';

/** Longest string a regex or glob is ever run against. Bounds evaluation time. */
export const MAX_SUBJECT_LENGTH = 4096;
export const MAX_REGEX_LENGTH = 256;

/** Read-only view of the state rules can consult while evaluating. */
export interface EvalState {
  /** Has this key been seen before for this baseline scope? */
  baselineHas(scope: string, key: string): boolean;
  /** Is the value on the named list? */
  listHas(list: string, value: string): boolean;
}

export type Predicate = (e: DetectionEvent, s: EvalState) => boolean;

export interface FirstSeenSpec {
  scope: string;
  getters: FieldGetter[];
}

export interface CompiledCondition {
  test: Predicate;
  /** Baseline keys this condition reads, so the engine can learn them after evaluation. */
  firstSeen: FirstSeenSpec[];
  /** Has a regex or glob Vigil does not ship (see isTrustedPattern), so the engine times it. */
  untrusted: boolean;
  /** Regex tests of a saved rule that run on the backtracking engine (legacy.ts). */
  legacy: LegacyUse[];
}

/** The rule a condition is in, which decides how its regexes and globs run. */
export interface PatternContext {
  ruleId?: string | undefined;
  origin?: string | undefined;
  /**
   * A rule saved before this release, being loaded (admitSavedRules): a regex
   * the linear-time engine can't run keeps the backtracking engine, as it ran
   * before, instead of failing.
   */
  adoptLegacy?: boolean;
}

interface PatternHooks {
  /** The value is not one Vigil ships. */
  untrusted(): void;
  /** The regex runs on the backtracking engine as a saved rule's (legacy.ts). */
  legacy(use: LegacyUse): void;
}

/**
 * Most unbounded quantifiers (`*`, `+`, `{n,}`) on near-anything atoms (`.`,
 * `[^...]`, or a group holding one) one regex may have. Each can take any
 * share of the subject, so a few in a row backtrack polynomially. Counted per
 * lookaround, since a lookaround is matched on its own.
 */
export const MAX_BROAD_QUANTIFIERS = 3;

interface RegexGroup {
  /** A lookaround: it matches once and never backtracks into what follows. */
  look: boolean;
  /** Has `|` itself or in a group inside it. */
  alt: boolean;
  /** Has a `*`, `+` or `{...}` quantifier inside it, at any depth. */
  quant: boolean;
  /** Has a near-anything atom inside it. */
  broad: boolean;
  /** Broad quantifiers so far in this group's lookaround (or the whole pattern). */
  scope: { broad: number };
}

/** The structural part of regexProblem: walks the pattern once, tracking groups. */
function regexShapeProblem(pattern: string): string | undefined {
  const group = (look: boolean, scope = { broad: 0 }): RegexGroup => ({
    look,
    alt: false,
    quant: false,
    broad: false,
    scope,
  });
  const stack: RegexGroup[] = [group(false)];
  // The atom just read, for the quantifier that may follow it.
  let atom: { group?: RegexGroup; broad: boolean } | undefined;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i]!;
    const top = stack[stack.length - 1]!;
    if (c === '\\') {
      atom = { broad: false };
      i++;
    } else if (c === '[') {
      let j = i + 1;
      const negated = pattern[j] === '^';
      if (negated) j++;
      let negatedShorthand = false; // [\s\S], [\w\W]
      for (; j < pattern.length && pattern[j] !== ']'; j++) {
        if (pattern[j] !== '\\') continue;
        j++;
        if (/[SWD]/.test(pattern[j] ?? '')) negatedShorthand = true;
      }
      atom = { broad: negated || negatedShorthand };
      top.broad ||= atom.broad;
      i = j;
    } else if (c === '(') {
      const look = /^\(\?<?[=!]/.test(pattern.slice(i, i + 4));
      stack.push(look ? group(true) : group(false, top.scope));
      // Skip the group's prefix ((?:, (?=, (?<!, (?<name>) so its `?` is not read as a quantifier.
      if (pattern[i + 1] === '?') {
        let j = i + 2;
        while (j < pattern.length && !':=!>'.includes(pattern[j]!)) j++;
        i = j;
      }
      atom = undefined;
    } else if (c === ')') {
      // An unbalanced `)` is left for the RegExp constructor to report.
      const g = stack.length > 1 ? stack.pop()! : top;
      const parent = stack[stack.length - 1]!;
      if (!g.look) {
        parent.alt ||= g.alt;
        parent.quant ||= g.quant;
        parent.broad ||= g.broad;
      }
      atom = { group: g, broad: !g.look && g.broad };
    } else if (c === '|') {
      top.alt = true;
      atom = undefined;
    } else {
      const q = /^(?:[*+?]|\{(\d+)(,(\d*))?\})/.exec(pattern.slice(i));
      if (!q) {
        atom = { broad: c === '.' };
        top.broad ||= atom.broad;
        continue;
      }
      i += q[0].length - 1;
      if (pattern[i + 1] === '?') i++; // lazy
      const unbounded = c === '*' || c === '+' || q[3] === '';
      // `?`, `{0,1}` and `{n}` do not repeat a choice; `{n,m}` does.
      const repeats = unbounded || (q[3] !== undefined && Number(q[3]) > 1);
      if (atom?.group && repeats) {
        // A group containing a quantifier, itself repeated: (a+)+, ((.*))*, (a|b+){2,}.
        // An optional group like (sudo\s+)? is fine.
        if (atom.group.quant) return 'regex has a nested quantifier';
        // Repeated alternatives that can match the same text: (a|a)*, (?:x|xy)+.
        if (atom.group.alt) return 'regex repeats a group that has alternatives';
      }
      if (unbounded && atom?.broad && ++top.scope.broad > MAX_BROAD_QUANTIFIERS)
        return `regex has more than ${MAX_BROAD_QUANTIFIERS} open-ended wildcards like .* or [^x]+`;
      if (c !== '?') top.quant = true;
      atom = undefined;
    }
  }
  return undefined;
}

/**
 * Rejects patterns that can backtrack catastrophically. This is a conservative
 * syntactic check, not a proof; together with MAX_SUBJECT_LENGTH it keeps any
 * single regex test cheap.
 */
export function regexProblem(pattern: string): string | undefined {
  if (pattern.length > MAX_REGEX_LENGTH) return `regex longer than ${MAX_REGEX_LENGTH} characters`;
  if (/\\[1-9]|\\k</.test(pattern)) return 'regex uses a backreference';
  const shape = regexShapeProblem(pattern);
  if (shape) return shape;
  try {
    new RegExp(pattern);
  } catch (err) {
    return `regex does not compile: ${(err as Error).message}`;
  }
  return undefined;
}

function escapeRegex(s: string): string {
  return s.replace(/[.+^${}()|[\]\\]/g, '\\$&');
}

/** Most `*` or `**` one glob may have, once runs of them are merged. */
export const MAX_GLOB_WILDCARDS = 4;
/**
 * Most wildcards in one glob that can stop at many places in the path: any
 * but the last, except a `*` with a `/` before the next wildcard (it can only
 * stop at that `/`). Each one multiplies the work of a failed match by up to
 * the path's length.
 */
export const MAX_GLOB_OPEN_WILDCARDS = 1;

type GlobToken =
  | { kind: 'text'; src: string; raw: string; slash: boolean }
  | { kind: 'one' } // ?
  | { kind: 'star'; min: number } // *, plus any ? next to it
  | { kind: 'any' } // **
  | { kind: 'dirs' }; // **/

// Split a glob (after any `~/`) into tokens, merging runs of wildcards that
// would otherwise compete for the same characters: `***` is `**`, `**/**/` is
// `**/`, `**/**` is `**`, and `*?*?` is one `*` of at least two characters.
function globTokens(glob: string): GlobToken[] {
  const out: GlobToken[] = [];
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    const last = out[out.length - 1];
    if (c === '*') {
      let n = 1;
      while (glob[i + n] === '*') n++;
      i += n - 1;
      if (n === 1) {
        let min = 0;
        while (out[out.length - 1]?.kind === 'one') {
          out.pop();
          min++;
        }
        const prev = out[out.length - 1];
        if (prev?.kind === 'star') prev.min += min;
        else out.push({ kind: 'star', min });
      } else if (glob[i + 1] === '/') {
        i++;
        if (last?.kind !== 'dirs') out.push({ kind: 'dirs' });
      } else if (last?.kind === 'dirs') {
        out[out.length - 1] = { kind: 'any' };
      } else if (last?.kind !== 'any') {
        out.push({ kind: 'any' });
      }
    } else if (c === '?') {
      if (last?.kind === 'star') last.min++;
      else out.push({ kind: 'one' });
    } else if (last?.kind === 'text') {
      last.src += escapeRegex(c);
      last.raw += c;
      last.slash ||= c === '/';
    } else {
      out.push({ kind: 'text', src: escapeRegex(c), raw: c, slash: c === '/' });
    }
  }
  return out;
}

function isWildcard(t: GlobToken): boolean {
  return t.kind === 'star' || t.kind === 'any' || t.kind === 'dirs';
}

/**
 * Rejects globs that can take too long to match: too many wildcards, or
 * more than one that can stop anywhere (`**a**b**`). Paths are at most
 * MAX_SUBJECT_LENGTH long, so this keeps any single glob test cheap.
 */
export function globProblem(glob: string): string | undefined {
  const tokens = globTokens(glob.startsWith('~/') ? glob.slice(2) : glob);
  const wild = tokens.filter(isWildcard).length;
  if (wild > MAX_GLOB_WILDCARDS)
    return `glob has ${wild} wildcards (* or **), more than ${MAX_GLOB_WILDCARDS}`;
  let open = 0;
  let seen = 0;
  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i]!;
    if (!isWildcard(t) || ++seen === wild) continue;
    let slash = false;
    for (let j = i + 1; j < tokens.length && !isWildcard(tokens[j]!); j++) {
      const n = tokens[j]!;
      if (n.kind === 'text' && n.slash) slash = true;
    }
    if (t.kind !== 'star' || !slash) open++;
  }
  if (open > MAX_GLOB_OPEN_WILDCARDS)
    return `glob has ${open} wildcards that can stop anywhere in the path, more than ${MAX_GLOB_OPEN_WILDCARDS} (the last wildcard, and a * with a / after it, do not count)`;
  return undefined;
}

/**
 * Path globs. `**` crosses directories, `*` and `?` do not, and a leading `~`
 * means any user's home folder. Case-insensitive by default because APFS is.
 * Rules check globProblem first; this only builds the regex. Vigil itself
 * matches globs with globMatcher, which needs no regex; this regex is the
 * reference it is tested against (and what the bench package uses).
 */
export function globToRegExp(glob: string, ignoreCase = true): RegExp {
  let src = '';
  let rest = glob;
  if (rest.startsWith('~/')) {
    // A home folder: /Users/<name> on macOS, /home/<name> or /root on Linux.
    src += '(?:/Users/[^/]+|/home/[^/]+|/root)/';
    rest = rest.slice(2);
  }
  for (const t of globTokens(rest)) {
    if (t.kind === 'text') src += t.src;
    else if (t.kind === 'one') src += '[^/]';
    else if (t.kind === 'star') src += t.min ? `[^/]{${t.min},}` : '[^/]*';
    else if (t.kind === 'any') src += '.*';
    else src += '(?:.*/)?'; // `**/` also matches zero directories
  }
  return new RegExp(`^${src}$`, ignoreCase ? 'i' : '');
}

/** One step of a glob as globMatcher runs it. */
type GlobStep =
  | { kind: 'char'; code: number }
  | { kind: 'one' } // [^/]
  | { kind: 'star' } // [^/]*
  | { kind: 'any' } // .*
  | { kind: 'dirs' }; // (?:.*/)?

const SLASH = 47;
/** What `.` does not match without the `s` flag, so globMatcher agrees with globToRegExp. */
const isLineEnd = (c: number) => c === 10 || c === 13 || c === 0x2028 || c === 0x2029;

function globSteps(tokens: GlobToken[], fold: (c: number) => number): GlobStep[] {
  const out: GlobStep[] = [];
  for (const t of tokens) {
    if (t.kind === 'text')
      for (let i = 0; i < t.raw.length; i++)
        out.push({ kind: 'char', code: fold(t.raw.charCodeAt(i)) });
    else if (t.kind === 'star') {
      for (let i = 0; i < t.min; i++) out.push({ kind: 'one' });
      out.push({ kind: 'star' });
    } else out.push({ kind: t.kind });
  }
  return out;
}

/**
 * The steps as a test: whether a string fits them, read once from left to
 * right keeping every place in the glob it could have reached (a Thompson
 * NFA), so the time is the path's length times the glob's, whatever either
 * holds. The literal text the glob starts and ends with is checked first,
 * which settles most paths at once.
 */
function stepsTest(steps: GlobStep[], fold: (c: number) => number): (s: string) => boolean {
  const n = steps.length;
  let head = 0;
  while (head < n && steps[head]!.kind === 'char') head++;
  let tail = 0;
  while (tail < n - head && steps[n - 1 - tail]!.kind === 'char') tail++;
  const codeAt = (i: number) => (steps[i] as { code: number }).code;
  // States 0..n are "before step i" (n: matched); n+1+i is inside the `.*` of
  // a `**/` at i. A state is in a set when its mark equals that set's stamp.
  const size = 2 * n + 1;
  const mark = new Uint32Array(size);
  let stamp = 0;
  let cur = new Int32Array(size);
  let next = new Int32Array(size);
  let curLen = 0;
  let nextLen = 0;
  const add = (i: number) => {
    for (;;) {
      if (mark[i] === stamp) return;
      mark[i] = stamp;
      next[nextLen++] = i;
      const k = i < n ? steps[i]!.kind : undefined;
      // A wildcard can match nothing, so the step after it is reachable too.
      if (k === 'star' || k === 'any' || k === 'dirs') i++;
      else return;
    }
  };
  const swap = () => {
    [cur, next] = [next, cur];
    curLen = nextLen;
    nextLen = 0;
    stamp = stamp === 0xffffffff ? (mark.fill(0), 1) : stamp + 1;
  };
  return (s) => {
    if (head === n) {
      if (s.length !== n) return false;
    } else if (s.length < head + tail) return false;
    for (let i = 0; i < head; i++) if (fold(s.charCodeAt(i)) !== codeAt(i)) return false;
    for (let i = 1; i <= tail; i++)
      if (fold(s.charCodeAt(s.length - i)) !== codeAt(n - i)) return false;
    if (head === n) return true;
    stamp = stamp === 0xffffffff ? (mark.fill(0), 1) : stamp + 1;
    nextLen = 0;
    add(head);
    swap();
    for (let p = head; p < s.length && curLen; p++) {
      const c = s.charCodeAt(p);
      const f = fold(c);
      const slash = c === SLASH;
      const dot = !isLineEnd(c);
      for (let j = 0; j < curLen; j++) {
        const i = cur[j]!;
        if (i > n) {
          if (dot) add(i);
          if (slash) add(i - n);
          continue;
        }
        if (i === n) continue;
        const st = steps[i]!;
        if (st.kind === 'char') {
          if (st.code === f) add(i + 1);
        } else if (st.kind === 'one') {
          if (!slash) add(i + 1);
        } else if (st.kind === 'star') {
          if (!slash) add(i);
        } else if (st.kind === 'any') {
          if (dot) add(i);
        } else {
          if (dot) add(n + 1 + i);
          if (slash) add(i + 1);
        }
      }
      swap();
    }
    for (let j = 0; j < curLen; j++) if (cur[j] === n) return true;
    return false;
  };
}

/**
 * A glob as a test, matching exactly what globToRegExp's regex does, but
 * without a regex: its time is linear in the path whatever the glob, and it
 * needs no regex engine of any kind. Used for every glob Vigil matches,
 * shipped or not: in rules, agent identities and the safety floor's path
 * lists. Throws on a glob globProblem refuses.
 */
export function globMatcher(glob: string, ignoreCase = true): (s: string) => boolean {
  const k = `${ignoreCase ? 'i' : 's'}${glob}`;
  let m = matchers.get(k);
  if (!m) {
    m = buildGlobMatcher(glob, ignoreCase);
    // Bounded: rules are rebuilt often (replays), from much the same globs.
    if (matchers.size >= 4096) matchers.delete(matchers.keys().next().value!);
    matchers.set(k, m);
  }
  return m;
}

/** Built matchers by case setting and glob. Each resets its scratch space on every call. */
const matchers = new Map<string, (s: string) => boolean>();

function buildGlobMatcher(glob: string, ignoreCase: boolean): (s: string) => boolean {
  const problem = globProblem(glob);
  if (problem) throw new Error(problem);
  const fold = ignoreCase ? caseFold : (c: number) => c;
  const home = glob.startsWith('~/');
  const rest = home ? glob.slice(2) : glob;
  // The longest text the glob must contain, to rule most paths out at once.
  const need = longestText(globSteps(globTokens(rest), fold));
  const fits = (
    home
      ? // A home folder: /Users/<name> on macOS, /home/<name> or /root on Linux.
        ['/Users/?*/', '/home/?*/', '/root/'].map((h) => `${h}${rest}`)
      : [glob]
  ).map((g) => stepsTest(globSteps(globTokens(g), fold), fold));
  return (s) => {
    const c = clip(s);
    if (need && !folded(c, ignoreCase).includes(need)) return false;
    return fits.some((f) => f(c));
  };
}

/** The longest run of plain characters in the steps, as folded codes. */
function longestText(steps: GlobStep[]): string {
  let best = '';
  let run = '';
  for (const st of steps) {
    if (st.kind === 'char') run += String.fromCharCode(st.code);
    else run = '';
    if (run.length > best.length) best = run;
  }
  return best;
}

const NOT_ASCII = /[\u0080-\uffff]/;

/** The last string folded, so the globs tried on one path fold it once. */
let lastFolded = { s: '', ignoreCase: false, out: '' };

function folded(s: string, ignoreCase: boolean): string {
  if (!ignoreCase) return s;
  if (lastFolded.s === s && lastFolded.ignoreCase) return lastFolded.out;
  let out: string;
  // For ASCII, what `i` compares a character as is its upper case.
  if (!NOT_ASCII.test(s)) out = s.toUpperCase();
  else {
    out = '';
    for (let i = 0; i < s.length; i++) out += String.fromCharCode(caseFold(s.charCodeAt(i)));
  }
  lastFolded = { s, ignoreCase, out };
  return out;
}

function asStrings(v: FieldValue): string[] {
  if (v === undefined) return [];
  if (Array.isArray(v)) return v;
  return [String(v)];
}

/** `s`, cut to MAX_SUBJECT_LENGTH: what any regex or glob is tested against. */
export function clip(s: string): string {
  return s.length > MAX_SUBJECT_LENGTH ? s.slice(0, MAX_SUBJECT_LENGTH) : s;
}

function buildBlockList(values: string[]): BlockList {
  const bl = new BlockList();
  for (const v of values) {
    const [addr, prefixRaw] = v.split('/');
    const family = isIP(addr ?? '');
    if (!addr || family === 0) throw new Error(`not an IP or CIDR: ${v}`);
    const type = family === 4 ? 'ipv4' : 'ipv6';
    if (prefixRaw === undefined) bl.addAddress(addr, type);
    else bl.addSubnet(addr, Number(prefixRaw), type);
  }
  return bl;
}

/**
 * The test for one regex or glob value: on the usual regex engine when Vigil
 * ships that test (isTrustedPattern); otherwise a regex on the linear-time
 * engine, or globMatcher for a glob. A regex the linear-time engine can't run
 * is refused with the reason, unless the rule was saved before and had it
 * (legacy.ts). Nothing falls back to backtracking on its own.
 */
function patternTest(
  c: FieldTest & { op: 'regex' | 'glob' },
  value: string,
  ctx: PatternContext,
  hooks: PatternHooks,
): (s: string) => boolean {
  const problem = c.op === 'regex' ? regexProblem(value) : globProblem(value);
  if (problem) throw new Error(`${c.field}: ${problem}`);
  const nocase = c.op === 'regex' ? c.nocase === true : c.nocase !== false;
  const use = { ...ctx, field: c.field, op: c.op, nocase, pattern: value };
  const test = (re: RegExp) => (s: string) => re.test(clip(s));
  // Vigil's own patterns keep the usual engine (they need lookarounds);
  // any other runs in linear time, so no pattern can stall the checks.
  // Globs never use a regex (globMatcher), so only the timing differs for them.
  if (c.op === 'glob') {
    if (!isTrustedPattern(use)) hooks.untrusted();
    return globMatcher(value, nocase);
  }
  if (isTrustedPattern(use)) return test(new RegExp(value, nocase ? 'i' : ''));
  hooks.untrusted();
  try {
    return test(linearRegExp(value, nocase));
  } catch (err) {
    const legacy = { field: c.field, nocase, pattern: value };
    if (ctx.adoptLegacy || isLegacyPattern(ctx.ruleId, legacy)) {
      hooks.legacy(legacy);
      return test(new RegExp(value, nocase ? 'i' : ''));
    }
    throw new Error(`${c.field}: ${(err as Error).message}`, { cause: err });
  }
}

const NO_HOOKS: PatternHooks = { untrusted: () => undefined, legacy: () => undefined };

/** Why each regex or glob value of `c` can't be used in the rule `ctx`, for the linter. */
export function patternProblems(c: FieldTest, ctx: PatternContext): string[] {
  if (c.op !== 'regex' && c.op !== 'glob') return [];
  const values = Array.isArray(c.value) ? c.value : c.value === undefined ? [] : [c.value];
  const out: string[] = [];
  for (const v of values) {
    try {
      patternTest({ ...c, op: c.op }, String(v), ctx, NO_HOOKS);
    } catch (err) {
      out.push((err as Error).message);
    }
  }
  return out;
}

function compileMatch(c: FieldTest, ctx: PatternContext, hooks: PatternHooks): Predicate {
  const get = compileField(c.field);
  const ic = c.nocase === true;
  const norm = (s: string) => (ic ? s.toLowerCase() : s);
  const values = Array.isArray(c.value)
    ? c.value.map(String)
    : c.value === undefined
      ? []
      : [String(c.value)];
  const nvalues = values.map(norm);

  // Array-valued fields (process.args, extension.permissions) match when any element does.
  const anyString = (e: DetectionEvent, f: (s: string) => boolean) =>
    asStrings(get(e)).some((s) => f(s));

  switch (c.op) {
    case 'exists':
      return (e) => {
        const v = get(e);
        const present = v !== undefined && !(Array.isArray(v) && v.length === 0);
        return c.value === false ? !present : present;
      };
    case 'eq':
      return (e) => anyString(e, (s) => norm(s) === nvalues[0]);
    case 'neq':
      return (e) => {
        const v = get(e);
        return v !== undefined && !asStrings(v).some((s) => norm(s) === nvalues[0]);
      };
    case 'in': {
      const set = new Set(nvalues);
      return (e) => anyString(e, (s) => set.has(norm(s)));
    }
    case 'notIn': {
      const set = new Set(nvalues);
      return (e) => {
        const v = get(e);
        return v !== undefined && !asStrings(v).some((s) => set.has(norm(s)));
      };
    }
    case 'startsWith':
      return (e) => anyString(e, (s) => nvalues.some((v) => norm(s).startsWith(v)));
    case 'endsWith':
      return (e) => anyString(e, (s) => nvalues.some((v) => norm(s).endsWith(v)));
    case 'contains':
      return (e) => anyString(e, (s) => nvalues.some((v) => norm(clip(s)).includes(v)));
    case 'glob':
    case 'regex': {
      const op = c.op;
      const tests = values.map((v) => patternTest({ ...c, op }, v, ctx, hooks));
      return (e) => anyString(e, (s) => tests.some((t) => t(s)));
    }
    case 'cidr': {
      const bl = buildBlockList(values);
      return (e) =>
        anyString(e, (s) => {
          const fam = isIP(s);
          return fam !== 0 && bl.check(s, fam === 4 ? 'ipv4' : 'ipv6');
        });
    }
    case 'gt':
    case 'lt': {
      const n = Number(c.value);
      return (e) => {
        const v = get(e);
        if (typeof v !== 'number') return false;
        return c.op === 'gt' ? v > n : v < n;
      };
    }
  }
}

/**
 * @param scopePrefix baseline namespace, normally the rule's event kinds, so
 *   "first seen on a network connection" is not answered by an earlier exec.
 */
export function compileCondition(
  c: Condition,
  scopePrefix = '',
  ctx: PatternContext = {},
): CompiledCondition {
  const firstSeen: FirstSeenSpec[] = [];
  let untrusted = false;
  const legacy: LegacyUse[] = [];
  const hooks: PatternHooks = {
    untrusted: () => (untrusted = true),
    legacy: (u) => legacy.push(u),
  };

  const walk = (c: Condition): Predicate => {
    if ('all' in c) {
      const ps = c.all.map(walk);
      return (e, s) => ps.every((p) => p(e, s));
    }
    if ('any' in c) {
      const ps = c.any.map(walk);
      return (e, s) => ps.some((p) => p(e, s));
    }
    if ('not' in c) {
      const p = walk(c.not);
      return (e, s) => !p(e, s);
    }
    if ('firstSeen' in c) {
      const scope = `${scopePrefix}${c.firstSeen.key.join(',')}`;
      const getters = c.firstSeen.key.map(compileField);
      firstSeen.push({ scope, getters });
      return (e, s) => {
        const k = keyOf(getters, e);
        return k !== undefined && !s.baselineHas(scope, k);
      };
    }
    if ('inList' in c) {
      const { list } = c.inList;
      const get = compileField(c.inList.field);
      return (e, s) => asStrings(get(e)).some((v) => s.listHas(list, v));
    }
    return compileMatch(c, ctx, hooks);
  };

  const test = walk(c);
  return { test, firstSeen, untrusted, legacy };
}

/**
 * `{{field}}` placeholders. Alternatives are separated by `|` and tried in
 * order; a quoted alternative is a literal fallback:
 * `{{remoteHost|remoteAddress}}`, `{{process.parentName|'a program'}}`.
 */
export const TEMPLATE_RE = /\{\{\s*([^{}]+?)\s*\}\}/g;
const WHOLE_TEMPLATE = /^\{\{\s*([^{}]+?)\s*\}\}$/;

/** Field paths a placeholder refers to (for the linter). */
export function templateFields(placeholder: string): string[] {
  return placeholder
    .split('|')
    .map((p) => p.trim())
    .filter((p) => !/^'.*'$/.test(p));
}

function lookup(placeholder: string, e: DetectionEvent): FieldValue {
  for (const alt of placeholder.split('|').map((p) => p.trim())) {
    const lit = /^'(.*)'$/.exec(alt);
    if (lit) return lit[1];
    const v = compileField(alt)(e);
    if (v !== undefined && !(Array.isArray(v) && v.length === 0)) return v;
  }
  return undefined;
}

/**
 * Resolve a response-template value. A string that is exactly one
 * placeholder takes the field's raw value (so `{{process.pid}}` stays a
 * number); other strings are interpolated. Returns undefined when a
 * referenced field is missing, so the action is dropped rather than run
 * against the wrong target.
 */
export function resolveTemplateValue(
  v: string | number | boolean,
  e: DetectionEvent,
): string | number | boolean | undefined {
  if (typeof v !== 'string') return v;
  const whole = WHOLE_TEMPLATE.exec(v);
  if (whole) {
    const raw = lookup(whole[1]!, e);
    if (raw === undefined || Array.isArray(raw)) return undefined;
    return raw;
  }
  let missing = false;
  const out = v.replace(TEMPLATE_RE, (_, ph: string) => {
    const raw = lookup(ph, e);
    if (raw === undefined) missing = true;
    return raw === undefined ? '' : Array.isArray(raw) ? raw.join(' ') : String(raw);
  });
  return missing ? undefined : out;
}

/** Fill placeholders for display. A value that cannot be found renders as "unknown". */
export function renderTemplate(template: string, e: DetectionEvent): string {
  return template.replace(TEMPLATE_RE, (_, ph: string) => {
    const v = lookup(ph, e);
    if (v === undefined) return 'unknown';
    const s = Array.isArray(v) ? v.join(' ') : String(v);
    return s.length > 200 ? `${s.slice(0, 197)}...` : s;
  });
}
