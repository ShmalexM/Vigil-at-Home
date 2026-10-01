// The pack's permission gate: whether a dog's tool call or a Lead dog's
// change to the pack goes ahead, waits for the user, or is refused. Plain
// rules, in this order (docs/pack.md has the flow):
//
//   1. The user switched the tool off: refused.
//   2. Vigil's rules say stop: refused. Rules say ask: the user is asked.
//      This holds in every mode, Full access included.
//   3. The user's own choice for the tool: always ask, or always allow.
//   4. Tools that only read (Vigil's own, and connector tools their server
//      marks read-only) go ahead.
//   5. Otherwise the mode decides: Ask for approval asks; Full access goes
//      ahead; Let AI decide asks the user's AI, and anything it doesn't rate
//      low risk (or can't rate) is asked.
//
// Whatever the gate says, no dog can block or allow anything on the Mac,
// release a block, or approve or edit a rule: no tool that does exists.

import type {
  LeadActionKind,
  PermissionMode,
  ToolApproval,
  ToolChoice,
} from '../../shared/pack.js';

export type GateDecision =
  | { kind: 'run' }
  | { kind: 'ask'; why: ToolApproval['why']; reason?: string }
  | { kind: 'deny'; reason: string }
  | { kind: 'judge' };

export interface GateInput {
  mode: PermissionMode;
  choice: ToolChoice;
  readOnly: boolean;
  /** What Vigil's rules answered; none for Vigil's own tools. */
  rules: { decision: 'deny' | 'ask' | 'none'; reason?: string };
}

export function gateTool(i: GateInput): GateDecision {
  if (i.choice === 'off') return { kind: 'deny', reason: 'You switched this tool off.' };
  if (i.rules.decision === 'deny')
    return { kind: 'deny', reason: i.rules.reason ?? 'A Vigil rule stops this call.' };
  if (i.rules.decision === 'ask')
    return { kind: 'ask', why: 'rule', ...(i.rules.reason ? { reason: i.rules.reason } : {}) };
  if (i.choice === 'ask') return { kind: 'ask', why: 'always-ask' };
  if (i.choice === 'allow') return { kind: 'run' };
  if (i.readOnly) return { kind: 'run' };
  if (i.mode === 'full') return { kind: 'run' };
  if (i.mode === 'auto') return { kind: 'judge' };
  return { kind: 'ask', why: 'mode' };
}

/** After the AI judged a call in Let AI decide: only low risk goes ahead. */
export function afterJudge(
  judged: { risk: 'low' | 'medium' | 'high'; reason: string } | undefined,
): GateDecision {
  if (!judged) return { kind: 'ask', why: 'no-judge' };
  if (judged.risk === 'low') return { kind: 'run' };
  return { kind: 'ask', why: 'judged-risky', reason: judged.reason };
}

/**
 * A change the Lead dog wants to make to the pack. Ask for approval: every
 * change waits. Full access: all go ahead. Let AI decide: adding, changing
 * or running a dog goes ahead when every tool it would get only reads;
 * anything that hands a dog a tool that can change things, and retiring a
 * dog, waits.
 */
export function gateAction(
  mode: PermissionMode,
  kind: LeadActionKind,
  grantsWriteTool: boolean,
): 'apply' | 'ask' {
  if (mode === 'full') return 'apply';
  if (mode === 'ask') return 'ask';
  if (kind === 'retire' || grantsWriteTool) return 'ask';
  return 'apply';
}
