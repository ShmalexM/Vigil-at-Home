/**
 * Regexes in saved rules that ran before Vigil moved rule patterns to the
 * linear-time engine, and can't run there (a lookahead, a large repeat count
 * inside a repeated group), or that can't because this runtime has no such
 * engine. Turning those rules off on upgrade would drop protection the user
 * set up, so each keeps running exactly as before, on the backtracking
 * engine, still within regexProblem's limits. Such a rule is "legacy": it
 * can't be time-limited, the watchdog still times it, and Rules says so.
 *
 * A permission is bound to one test: the rule's id, the field, the case
 * setting and the regex text, all four. A new rule, an AI draft, an import,
 * or an edit that changes any of them is refused with the reason instead.
 * Permissions are added only from the rules saved when the app (or the
 * helper) started (admitSavedRules in engine.ts), never from a rule being
 * added, and are revoked when that rule is removed or stops using the test
 * (retainLegacyUses), so removing a rule and adding it again does not bring
 * its permission back.
 */

/** One regex test a saved rule runs on the backtracking engine. */
export interface LegacyUse {
  field: string;
  nocase: boolean;
  pattern: string;
}

const adopted = new Map<string, Set<string>>();

export const legacyKey = (u: LegacyUse): string => JSON.stringify([u.field, u.nocase, u.pattern]);

/** Whether this saved rule's regex test may run on the backtracking engine. */
export function isLegacyPattern(ruleId: string | undefined, use: LegacyUse): boolean {
  return ruleId !== undefined && adopted.get(ruleId)?.has(legacyKey(use)) === true;
}

/** Let these regex tests of a saved rule keep the backtracking engine. */
export function adoptLegacyUses(ruleId: string, uses: Iterable<LegacyUse>): void {
  let set = adopted.get(ruleId);
  for (const u of uses) {
    if (!set) adopted.set(ruleId, (set = new Set()));
    set.add(legacyKey(u));
  }
}

/**
 * Keep only the permissions of `ruleId` that it still uses (its compiled
 * `legacy`), revoking the rest; with none, the rule loses them all. Called
 * whenever the rule that holds them changes or is removed.
 */
export function retainLegacyUses(ruleId: string, uses: Iterable<LegacyUse>): void {
  const had = adopted.get(ruleId);
  if (!had) return;
  const keep = new Set([...uses].map(legacyKey).filter((k) => had.has(k)));
  if (keep.size) adopted.set(ruleId, keep);
  else adopted.delete(ruleId);
}

/** Rule ids that hold a permission. */
export function legacyRuleIds(): string[] {
  return [...adopted.keys()];
}

/** For tests: forget every permission. */
export function forgetLegacyPatterns(): void {
  adopted.clear();
}
