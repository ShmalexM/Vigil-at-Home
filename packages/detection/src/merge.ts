import type { DetectionRule, DetectionRuleInput } from './types.js';

/**
 * Combine the built-in pack with saved rules (user-approved AI rules and
 * tuned versions of built-ins). A saved rule replaces a built-in with the same
 * id only when its version is at least as new, so a pack update that ships a
 * newer built-in wins over an old tuning.
 */
export function mergeRules(
  builtin: DetectionRuleInput[],
  saved: DetectionRule[],
): Array<DetectionRuleInput | DetectionRule> {
  const byId = new Map<string, DetectionRuleInput | DetectionRule>(builtin.map((r) => [r.id, r]));
  for (const s of saved) {
    const b = byId.get(s.id);
    if (!b || s.version >= b.version) byId.set(s.id, s);
  }
  return [...byId.values()];
}
