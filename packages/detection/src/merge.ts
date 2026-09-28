import type { DetectionRule, DetectionRuleInput } from './types.js';

/**
 * Combine the built-in pack with saved rules (user-approved AI rules, tuned
 * versions of built-ins, and the user's own edits). A user's edit of a
 * built-in always wins; the rule editor offers the newer built-in when a pack
 * update ships one. Any other saved rule replaces a built-in only when its
 * version is at least as new, so a pack update wins over an old AI tuning.
 */
export function mergeRules(
  builtin: DetectionRuleInput[],
  saved: DetectionRule[],
): Array<DetectionRuleInput | DetectionRule> {
  const byId = new Map<string, DetectionRuleInput | DetectionRule>(builtin.map((r) => [r.id, r]));
  for (const s of saved) {
    const b = byId.get(s.id);
    if (!b || s.editedFrom !== undefined || s.version >= b.version) byId.set(s.id, s);
  }
  return [...byId.values()];
}
