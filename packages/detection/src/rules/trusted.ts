import { builtinRulesFor } from '../packs/agent-preflight.js';
import { DetectionRule, type Condition } from '../types.js';

/**
 * Regexes in the rule templates the app ships (apps/desktop
 * agent-templates.ts), which need lookarounds, with the field each one tests.
 * A template makes a rule of your own, so these are trusted by field and text
 * in any rule. Templates with a value typed in (a domain) are not listed: they
 * run on the linear-time engine like any rule you write.
 */
export const TEMPLATE_PATTERNS: readonly { field: string; regex: string }[] = [
  {
    // Ask before force-push.
    field: 'command',
    regex: String.raw`\bgit(?=\s)(?:(?!\s+(?!\s)(?<!\s-[Cc]\s+)(?!-[Cc]\s|--?[a-z][\w-]*(?:=\S*)?\s|push\b))[^|;&\n])*?\s+(?<!\s-[Cc]\s+)push\b[^|;&\n]*?(?:\s-[a-zA-Z]*f|\s--force|\s\+\S)`,
  },
];

/** The template regexes alone. */
export const TEMPLATE_REGEXES: readonly string[] = TEMPLATE_PATTERNS.map((t) => t.regex);

/** One regex or glob test, where it is: what decides whether it is trusted. */
export interface PatternUse {
  /** The rule it is in; undefined outside a rule. */
  ruleId?: string | undefined;
  /** That rule's origin. */
  origin?: string | undefined;
  field: string;
  op: 'regex' | 'glob';
  /** Whether it ignores case, as compiled: nocase for a regex, unless nocase is false for a glob. */
  nocase: boolean;
  pattern: string;
}

const key = (u: Omit<PatternUse, 'origin'>) =>
  JSON.stringify([u.ruleId ?? '', u.field, u.op, u.nocase, u.pattern]);

let shipped: Set<string> | undefined;

function collect(ruleId: string, c: Condition, into: Set<string>): void {
  if ('all' in c) for (const x of c.all) collect(ruleId, x, into);
  else if ('any' in c) for (const x of c.any) collect(ruleId, x, into);
  else if ('not' in c) collect(ruleId, c.not, into);
  else if ('op' in c && (c.op === 'regex' || c.op === 'glob')) {
    const values = Array.isArray(c.value) ? c.value : c.value === undefined ? [] : [c.value];
    const nocase = c.op === 'regex' ? c.nocase === true : c.nocase !== false;
    for (const v of values)
      into.add(key({ ruleId, field: c.field, op: c.op, nocase, pattern: String(v) }));
  }
}

/**
 * Whether Vigil itself ships this regex or glob test: the same pattern, field
 * and case setting in the built-in rule of that id (for any platform), or a
 * template's regex on its field. Those were written and tested here, so they
 * keep the usual regex engine and match exactly as they always have.
 * Anything else (rules you write, AI drafts, feeds) runs on the linear-time
 * engine.
 *
 * The text alone is not enough. Several shipped regexes are polynomial, not
 * linear, on a crafted 4096-character subject (up to tens of milliseconds a
 * test), and are acceptable only where they ship: once per event, on the
 * field they were written for, in a rule whose time is known. Copied into
 * another rule, onto a field that holds many values (process.args), or with
 * the case setting flipped, the same text could cost many times that, and it
 * would not be timed. So trust is keyed on the built-in rule's id and origin
 * and on the field, and an edit that moves a pattern elsewhere loses it.
 */
export function isTrustedPattern(use: PatternUse): boolean {
  if (!shipped) {
    const into = new Set<string>();
    for (const t of TEMPLATE_PATTERNS)
      into.add(key({ field: t.field, op: 'regex', nocase: false, pattern: t.regex }));
    for (const input of [...builtinRulesFor('darwin'), ...builtinRulesFor('linux')]) {
      const r = DetectionRule.parse(input);
      collect(r.id, r.condition, into);
      for (const x of r.exclusions) collect(r.id, x, into);
      for (const st of r.sequence?.steps ?? []) collect(r.id, st.condition, into);
    }
    shipped = into;
  }
  if (use.op === 'regex' && shipped.has(key({ ...use, ruleId: undefined }))) return true;
  return use.origin === 'builtin' && use.ruleId !== undefined && shipped.has(key(use));
}
