/**
 * Regexes in saved rules that ran before Vigil moved rule patterns to the
 * linear-time engine, and can't run there (a lookahead, a large repeat count
 * inside a repeated group), or that can't because this runtime has no such
 * engine. Turning those rules off on upgrade would drop protection the user
 * set up, so each keeps running exactly as before, on the backtracking
 * engine, still within regexProblem's limits. Such a rule is "legacy": it
 * can't be time-limited, the watchdog still times it, and Rules says so.
 *
 * Only the rule that had the pattern keeps it, and only that text. A new
 * rule, an AI draft, an import, or an edit that writes a new pattern is
 * refused with the reason instead. Keys are added once, from the rules the
 * app (or the helper) had saved when it started (admitSavedRules in
 * engine.ts), never from a rule being added.
 */
const adopted = new Map<string, Set<string>>();

const key = (pattern: string) => pattern;

/** Whether this saved rule's regex may run on the backtracking engine. */
export function isLegacyPattern(ruleId: string | undefined, pattern: string): boolean {
  return ruleId !== undefined && adopted.get(ruleId)?.has(key(pattern)) === true;
}

/** Let these regexes of a saved rule keep the backtracking engine. */
export function adoptLegacyPatterns(ruleId: string, patterns: Iterable<string>): void {
  let set = adopted.get(ruleId);
  for (const p of patterns) {
    if (!set) adopted.set(ruleId, (set = new Set()));
    set.add(key(p));
  }
}

/** The regexes a saved rule keeps on the backtracking engine. */
export function legacyPatternsOf(ruleId: string): string[] {
  return [...(adopted.get(ruleId) ?? [])];
}

/** For tests: forget every adopted pattern. */
export function forgetLegacyPatterns(): void {
  adopted.clear();
}
