import { builtinRulesFor } from '../packs/agent-preflight.js';
import { DetectionRule, type Condition } from '../types.js';

/**
 * Regexes in the rule templates the app ships (apps/desktop
 * agent-templates.ts), which need lookarounds. A test there checks each
 * template's regex is listed here. Templates with a value typed in (a domain)
 * are not listed: they run on the linear-time engine like any rule you write.
 */
export const TEMPLATE_REGEXES: readonly string[] = [
  // Ask before force-push.
  String.raw`\bgit(?=\s)(?:(?!\s+(?!\s)(?<!\s-[Cc]\s+)(?!-[Cc]\s|--?[a-z][\w-]*(?:=\S*)?\s|push\b))[^|;&\n])*?\s+(?<!\s-[Cc]\s+)push\b[^|;&\n]*?(?:\s-[a-zA-Z]*f|\s--force|\s\+\S)`,
];

let shipped: { regex: Set<string>; glob: Set<string> } | undefined;

function collect(c: Condition, into: { regex: Set<string>; glob: Set<string> }): void {
  if ('all' in c) for (const x of c.all) collect(x, into);
  else if ('any' in c) for (const x of c.any) collect(x, into);
  else if ('not' in c) collect(c.not, into);
  else if ('op' in c && (c.op === 'regex' || c.op === 'glob')) {
    const values = Array.isArray(c.value) ? c.value : c.value === undefined ? [] : [c.value];
    for (const v of values) into[c.op].add(String(v));
  }
}

/**
 * Whether Vigil itself ships this regex or glob, in a built-in rule for any
 * platform or in a template. Those were written and tested here, so they keep
 * the usual regex engine and match exactly as they always have. Anything else
 * (rules you write, AI drafts, feeds) runs on the linear-time engine. The
 * same text in your own rule counts as shipped: it matches the same either way.
 */
export function isShippedPattern(op: 'regex' | 'glob', pattern: string): boolean {
  if (!shipped) {
    const into = { regex: new Set<string>(TEMPLATE_REGEXES), glob: new Set<string>() };
    for (const input of [...builtinRulesFor('darwin'), ...builtinRulesFor('linux')]) {
      const r = DetectionRule.parse(input);
      collect(r.condition, into);
      for (const x of r.exclusions) collect(x, into);
      for (const st of r.sequence?.steps ?? []) collect(st.condition, into);
    }
    shipped = into;
  }
  return shipped[op].has(pattern);
}
