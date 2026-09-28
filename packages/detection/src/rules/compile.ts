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
 * Rejects patterns that can backtrack catastrophically. This is a conservative
 * syntactic check, not a proof; together with MAX_SUBJECT_LENGTH it keeps any
 * single regex test cheap.
 */
export function regexProblem(pattern: string): string | undefined {
  if (pattern.length > MAX_REGEX_LENGTH) return `regex longer than ${MAX_REGEX_LENGTH} characters`;
  if (/\\[1-9]|\\k</.test(pattern)) return 'regex uses a backreference';
  // A group containing a quantifier, itself repeated without bound: (a+)+, (.*)*, (a|b+){2,}.
  // An optional group like (sudo\s+)? is fine.
  if (/\((?:[^()\\]|\\.)*[+*}](?:[^()\\]|\\.)*\)(?:[+*]|\{\d+,\d*\})/.test(pattern)) {
    return 'regex has a nested quantifier';
  }
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

/**
 * Path globs. `**` crosses directories, `*` and `?` do not, and a leading `~`
 * means any user's home folder. Case-insensitive by default because APFS is.
 */
export function globToRegExp(glob: string, ignoreCase = true): RegExp {
  let src = '';
  let rest = glob;
  if (rest.startsWith('~/')) {
    src += '/Users/[^/]+/';
    rest = rest.slice(2);
  }
  for (let i = 0; i < rest.length; i++) {
    const c = rest[i]!;
    if (c === '*') {
      if (rest[i + 1] === '*') {
        if (rest[i + 2] === '/') {
          src += '(?:.*/)?'; // `**/` also matches zero directories
          i += 2;
        } else {
          src += '.*';
          i += 1;
        }
      } else {
        src += '[^/]*';
      }
    } else if (c === '?') {
      src += '[^/]';
    } else {
      src += escapeRegex(c);
    }
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
      const res = values.map((g) => globToRegExp(g, c.nocase !== false));
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
