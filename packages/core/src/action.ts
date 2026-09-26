import { z } from 'zod';
import { Id, Timestamp } from './common.js';

/**
 * Response actions. Each maps to one fixed command of the privileged helper
 * (or to a Santa rule change). Containment actions stop something; release
 * actions undo containment. The split drives who may request what: see
 * {@link authorizeAction}.
 */
export const ProcessSuspend = z.object({
  kind: z.literal('process.suspend'),
  pid: z.number().int().positive(),
  startTime: Timestamp.optional(),
});
export const ProcessResume = z.object({
  kind: z.literal('process.resume'),
  pid: z.number().int().positive(),
  startTime: Timestamp.optional(),
});
export const ProcessKill = z.object({
  kind: z.literal('process.kill'),
  pid: z.number().int().positive(),
  startTime: Timestamp.optional(),
});
export const NetworkBlock = z.object({
  kind: z.literal('network.block'),
  /** IPv4/IPv6 address or CIDR. */
  address: z.string(),
  port: z.number().int().optional(),
});
export const NetworkUnblock = z.object({
  kind: z.literal('network.unblock'),
  address: z.string(),
  port: z.number().int().optional(),
});
export const FileQuarantine = z.object({
  kind: z.literal('file.quarantine'),
  path: z.string(),
});
export const FileRestore = z.object({
  kind: z.literal('file.restore'),
  /** Returned by the quarantine result. */
  quarantineId: Id,
});

export const SantaRuleType = z.enum(['binary', 'certificate', 'signingid', 'teamid', 'cdhash']);
export type SantaRuleType = z.infer<typeof SantaRuleType>;

export const SantaRuleSet = z.object({
  kind: z.literal('santa.rule.set'),
  ruleType: SantaRuleType,
  identifier: z.string(),
  policy: z.enum(['block', 'silent_block', 'allow']),
  /** Shown in Santa's own block dialog. */
  message: z.string().optional(),
});
export const SantaRuleRemove = z.object({
  kind: z.literal('santa.rule.remove'),
  ruleType: SantaRuleType,
  identifier: z.string(),
});
export const PersistenceDisable = z.object({
  kind: z.literal('persistence.disable'),
  /** Path of the launchd plist or login item. */
  path: z.string(),
});
export const PersistenceEnable = z.object({
  kind: z.literal('persistence.enable'),
  path: z.string(),
});

export const Action = z.discriminatedUnion('kind', [
  ProcessSuspend,
  ProcessResume,
  ProcessKill,
  NetworkBlock,
  NetworkUnblock,
  FileQuarantine,
  FileRestore,
  SantaRuleSet,
  SantaRuleRemove,
  PersistenceDisable,
  PersistenceEnable,
]);
export type Action = z.infer<typeof Action>;
export type ActionKind = Action['kind'];
export const ActionKind = z.enum(
  Action.options.map((o) => o.shape.kind.value) as [ActionKind, ...ActionKind[]],
);

/** Who is asking for an action. */
export const Actor = z.enum([
  'user', // a click in the app
  'rule', // the deterministic engine, from a rule in block mode
  'ai', // an AI assistant; may only propose, never execute
]);
export type Actor = z.infer<typeof Actor>;

/**
 * True when the action lifts containment or trusts something. Removing a Santa
 * rule counts as release because the only rules Vigil creates on its own are blocks.
 */
export function isRelease(action: Action): boolean {
  switch (action.kind) {
    case 'process.resume':
    case 'network.unblock':
    case 'file.restore':
    case 'persistence.enable':
    case 'santa.rule.remove':
      return true;
    case 'santa.rule.set':
      return action.policy === 'allow';
    default:
      return false;
  }
}

export type Authorization = { ok: true } | { ok: false; reason: string };

/**
 * The one policy every executor checks before acting.
 * - The user may do anything.
 * - Rules may contain, never release.
 * - The AI executes nothing; see {@link canPropose}.
 */
export function authorizeAction(actor: Actor, action: Action): Authorization {
  if (actor === 'user') return { ok: true };
  if (actor === 'ai') return { ok: false, reason: 'AI can only propose actions' };
  if (isRelease(action)) return { ok: false, reason: 'Only the user can release or allow' };
  return { ok: true };
}

/** The AI may argue for containment, never for releasing or allowing. */
export function canPropose(actor: Actor, action: Action): Authorization {
  if (isRelease(action) && actor !== 'user') {
    return { ok: false, reason: 'Only the user can release or allow' };
  }
  return { ok: true };
}

/** The action that reverses `action`, when one exists. Needs the result for quarantines. */
export function undoOf(action: Action, result?: ActionResult): Action | undefined {
  switch (action.kind) {
    case 'process.suspend':
      return { kind: 'process.resume', pid: action.pid, ...opt('startTime', action.startTime) };
    case 'network.block':
      return { kind: 'network.unblock', address: action.address, ...opt('port', action.port) };
    case 'file.quarantine':
      return result?.quarantineId
        ? { kind: 'file.restore', quarantineId: result.quarantineId }
        : undefined;
    case 'santa.rule.set':
      return {
        kind: 'santa.rule.remove',
        ruleType: action.ruleType,
        identifier: action.identifier,
      };
    case 'persistence.disable':
      return { kind: 'persistence.enable', path: action.path };
    default:
      return undefined;
  }
}

function opt<K extends string, V>(key: K, value: V | undefined): { [P in K]?: V } {
  return (value === undefined ? {} : { [key]: value }) as { [P in K]?: V };
}

export const ActionStatus = z.enum(['pending', 'done', 'failed', 'denied', 'undone']);
export type ActionStatus = z.infer<typeof ActionStatus>;

/** A requested action and what happened to it. One row in the action log. */
export const ActionRecord = z.object({
  id: Id,
  action: Action,
  actor: Actor,
  /** The alert this action responds to, if any. */
  alertId: Id.optional(),
  /** Rule that triggered it when actor is `rule`. */
  ruleId: z.string().optional(),
  reason: z.string(),
  requestedAt: Timestamp,
  status: ActionStatus,
  result: z
    .object({
      at: Timestamp,
      error: z.string().optional(),
      quarantineId: Id.optional(),
    })
    .optional(),
  /** Set when this record undoes an earlier one. */
  undoes: Id.optional(),
});
export type ActionRecord = z.infer<typeof ActionRecord>;
export type ActionResult = NonNullable<ActionRecord['result']>;

/** An action the AI (or a rule in alert mode) suggests, waiting on the user. */
export const ActionProposal = z.object({
  id: Id,
  action: Action,
  proposedBy: Actor,
  alertId: Id.optional(),
  rationale: z.string(),
  createdAt: Timestamp,
  status: z.enum(['pending', 'approved', 'rejected', 'expired']),
  decidedAt: Timestamp.optional(),
  /** The ActionRecord created when the user approved it. */
  actionId: Id.optional(),
});
export type ActionProposal = z.infer<typeof ActionProposal>;
