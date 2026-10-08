import { BlockList, isIP } from 'node:net';
import type { Condition, DetectionEvent, FieldTest } from '../types.js';
import { compileField, keyOf, type FieldGetter, type FieldValue } from './fields.js';

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
  | { kind: 'text'; src: string; slash: boolean }
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
      last.slash ||= c === '/';
    } else {
      out.push({ kind: 'text', src: escapeRegex(c), slash: c === '/' });
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
 * Rules check globProblem first; this only builds the regex.
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

function asStrings(v: FieldValue): string[] {
  if (v === undefined) return [];
  if (Array.isArray(v)) return v;
  return [String(v)];
}

function clip(s: string): string {
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

function compileMatch(c: FieldTest): Predicate {
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
    case 'glob': {
      const res = values.map((g) => {
        const problem = globProblem(g);
        if (problem) throw new Error(`${c.field}: ${problem}`);
        return globToRegExp(g, c.nocase !== false);
      });
      return (e) => anyString(e, (s) => res.some((r) => r.test(clip(s))));
    }
    case 'regex': {
      const res = values.map((p) => {
        const problem = regexProblem(p);
        if (problem) throw new Error(`${c.field}: ${problem}`);
        return new RegExp(p, ic ? 'i' : '');
      });
      return (e) => anyString(e, (s) => res.some((r) => r.test(clip(s))));
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
export function compileCondition(c: Condition, scopePrefix = ''): CompiledCondition {
  const firstSeen: FirstSeenSpec[] = [];

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
    return compileMatch(c);
  };

  return { test: walk(c), firstSeen };
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
