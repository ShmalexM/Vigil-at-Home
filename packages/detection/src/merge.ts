import type { Rule, RuleInput } from "./rules/schema.js";

/**
 * Combine the built-in pack with saved rules (user-approved AI rules and
 * tuned versions of built-ins). A saved rule replaces a built-in with the same
 * id only when its version is at least as new, so a pack update that ships a
 * newer built-in wins over an old tuning.
 */
export function mergeRules(builtin: RuleInput[], saved: Rule[]): Array<RuleInput | Rule> {
  const byId = new Map<string, RuleInput | Rule>(builtin.map((r) => [r.id, r]));
  for (const s of saved) {
    const b = byId.get(s.id);
    if (!b || (s.version ?? 1) >= (b.version ?? 1)) byId.set(s.id, s);
  }
  return [...byId.values()];
}
