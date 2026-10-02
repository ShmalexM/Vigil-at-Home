import type { ActionKind } from '@vigil/core';
import { isIP } from 'node:net';
import type { Condition, DetectionRule, FieldTest } from '../types.js';
import { regexProblem, TEMPLATE_RE, templateFields } from './compile.js';
import { KNOWN_FIELDS } from './fields.js';

export interface LintResult {
  errors: string[];
  warnings: string[];
}

export interface LintOptions {
  /** Lists that exist right now. Referencing any other list is an error for AI rules. */
  knownLists?: string[];
  /** Apply the stricter checks for rules an AI proposed. */
  aiProposed?: boolean;
}

const MAX_NODES = 60;
const MAX_DEPTH = 8;
const MAX_REGEXES = 10;

/**
 * Fields precise enough to justify blocking on an AI's say-so: they name one
 * program, one signer or one destination rather than a behaviour.
 */
const ANCHOR_FIELDS = new Set([
  'process.sha256',
  'process.cdhash',
  'process.teamId',
  'process.signingId',
  'sha256',
  'remoteHost',
  'remoteAddress',
  'extensionId',
]);

/** Actions that undo containment. Only the user runs these (see core's authorizeAction). */
const RELEASE_KINDS = new Set<ActionKind>([
  'process.resume',
  'network.unblock',
  'file.restore',
  'persistence.enable',
  'santa.rule.remove',
]);

/** Response actions that end or cut something off, as opposed to pausing it. */
const HARD_ACTIONS = new Set<ActionKind>([
  'process.kill',
  'network.block',
  'file.quarantine',
  'persistence.disable',
  'santa.rule.set',
]);
const ANCHOR_OPS = new Set(['eq', 'in', 'cidr']);

function isMatch(c: Condition): c is FieldTest {
  return 'field' in c;
}

function walk(c: Condition, depth: number, visit: (c: Condition, depth: number) => void): void {
  visit(c, depth);
  if ('all' in c) c.all.forEach((x) => walk(x, depth + 1, visit));
  else if ('any' in c) c.any.forEach((x) => walk(x, depth + 1, visit));
  else if ('not' in c) walk(c.not, depth + 1, visit);
}

/** True when every way the condition can match goes through a precise anchor. */
export function isAnchored(c: Condition): boolean {
  if ('inList' in c) return true;
  if (isMatch(c)) return ANCHOR_FIELDS.has(c.field) && ANCHOR_OPS.has(c.op);
  if ('all' in c) return c.all.some(isAnchored);
  if ('any' in c) return c.any.every(isAnchored);
  return false; // not, firstSeen
}

/** True when the condition can only match with at least one specific field test. */
function hasSpecificTest(c: Condition): boolean {
  if ('inList' in c) return true;
  if (isMatch(c)) {
    if (c.op === 'exists' || c.op === 'neq' || c.op === 'notIn') return false;
    if (c.op === 'glob') {
      const vs = Array.isArray(c.value) ? c.value.map(String) : [String(c.value)];
      return vs.every((g) => g.replace(/[*?/~]/g, '').length >= 3);
    }
    if (c.op === 'regex') {
      const vs = Array.isArray(c.value) ? c.value.map(String) : [String(c.value)];
      return vs.every((r) => !/^\^?\.\*\$?$/.test(r) && r.length >= 3);
    }
    return true;
  }
  if ('all' in c) return c.all.some(hasSpecificTest);
  if ('any' in c) return c.any.every(hasSpecificTest);
  return false;
}

function checkMatch(c: FieldTest, errors: string[]): number {
  let regexes = 0;
  if (!KNOWN_FIELDS.has(c.field)) errors.push(`unknown field "${c.field}"`);
  const values = Array.isArray(c.value) ? c.value : c.value === undefined ? [] : [c.value];
  if (c.op !== 'exists' && values.length === 0) errors.push(`${c.field} ${c.op} needs a value`);
  if (c.op === 'regex') {
    for (const v of values) {
      regexes++;
      const p = regexProblem(String(v));
      if (p) errors.push(`${c.field}: ${p}`);
    }
  }
  if (c.op === 'glob') {
    for (const v of values) if (String(v).length > 512) errors.push(`${c.field}: glob too long`);
  }
  if (c.op === 'cidr') {
    for (const v of values) {
      const [addr, prefix] = String(v).split('/');
      const fam = isIP(addr ?? '');
      const max = fam === 4 ? 32 : 128;
      if (fam === 0 || (prefix !== undefined && !(Number(prefix) >= 0 && Number(prefix) <= max))) {
        errors.push(`${c.field}: "${String(v)}" is not an IP or CIDR`);
      }
    }
  }
  if ((c.op === 'gt' || c.op === 'lt') && typeof c.value !== 'number')
    errors.push(`${c.field} ${c.op} needs a number`);
  return regexes;
}

function lintCondition(
  c: Condition,
  errors: string[],
  lists: Set<string> | undefined,
  warnings: string[],
) {
  let nodes = 0;
  let regexes = 0;
  walk(c, 1, (n, depth) => {
    nodes++;
    if (depth > MAX_DEPTH) errors.push(`condition nested deeper than ${MAX_DEPTH}`);
    if (isMatch(n)) regexes += checkMatch(n, errors);
    if ('firstSeen' in n)
      for (const k of n.firstSeen.key)
        if (!KNOWN_FIELDS.has(k)) errors.push(`unknown field "${k}"`);
    if ('inList' in n) {
      if (!KNOWN_FIELDS.has(n.inList.field)) errors.push(`unknown field "${n.inList.field}"`);
      if (lists && !lists.has(n.inList.list))
        warnings.push(`list "${n.inList.list}" does not exist yet`);
    }
  });
  if (nodes > MAX_NODES) errors.push(`condition has ${nodes} parts, more than ${MAX_NODES}`);
  if (regexes > MAX_REGEXES)
    errors.push(`condition has ${regexes} regexes, more than ${MAX_REGEXES}`);
}

export function lintRule(rule: DetectionRule, opts: LintOptions = {}): LintResult {
  const errors: string[] = [];
  const warnings: string[] = [];
  const lists = opts.knownLists ? new Set(opts.knownLists) : undefined;

  lintCondition(rule.condition, errors, lists, warnings);
  for (const x of rule.exclusions) {
    lintCondition(x, errors, lists, warnings);
    if (!hasSpecificTest(x))
      errors.push('an exclusion must name something specific, or it would hide everything');
  }
  for (const st of rule.sequence?.steps ?? []) {
    lintCondition(st.condition, errors, lists, warnings);
    if (!hasSpecificTest(st.condition))
      errors.push('each step of a sequence must test something specific');
  }
  const extraFields = [
    ...(rule.sequence?.key ?? []),
    ...(rule.threshold?.groupBy ?? []),
    ...(rule.dedupe?.key ?? []),
    ...(rule.santa ? [rule.santa.from] : []),
  ];
  for (const f of extraFields) {
    if (!KNOWN_FIELDS.has(f)) errors.push(`unknown field "${f}"`);
  }
  const templates = [
    ...rule.reasons,
    ...rule.response.flatMap((t) => Object.values(t).filter((v) => typeof v === 'string')),
  ];
  for (const r of templates) {
    for (const m of r.matchAll(TEMPLATE_RE)) {
      for (const f of templateFields(m[1]!)) {
        if (!KNOWN_FIELDS.has(f)) errors.push(`"${r}" uses unknown field "${f}"`);
      }
    }
  }
  for (const t of rule.response) {
    if (RELEASE_KINDS.has(t.kind) || (t.kind === 'santa.rule.set' && t.policy === 'allow')) {
      errors.push(`${t.kind} releases or allows something; rules may only contain`);
    }
  }
  if (rule.mode === 'block' && rule.response.length === 0) {
    warnings.push('the rule is in block mode but has no response, so it only alerts');
  }

  if (opts.aiProposed) {
    if (!rule.id.startsWith('ai-'))
      errors.push('rules proposed by the AI must have ids starting with "ai-"');
    if (lists) {
      for (const w of warnings.filter((w) => w.startsWith('list '))) errors.push(w);
    }
    if (!hasSpecificTest(rule.condition)) {
      errors.push(
        'the condition must test something specific, not only whether a field exists or is first seen',
      );
    }
    const kinds = rule.response.map((t) => t.kind);
    const anchored = isAnchored(rule.condition);
    if (kinds.some((k) => HARD_ACTIONS.has(k)) && !anchored) {
      errors.push(
        'an AI-proposed rule can only kill, block, quarantine or disable when it names a specific hash, signer, host, address or extension (or uses a list); behaviour alone can ask to suspend or just alert',
      );
    }
    if (
      kinds.includes('process.suspend') &&
      !anchored &&
      rule.severity !== 'high' &&
      rule.severity !== 'critical'
    ) {
      errors.push('an AI-proposed behaviour rule can only suspend at high or critical severity');
    }
  }
  return { errors: [...new Set(errors)], warnings: [...new Set(warnings)] };
}
