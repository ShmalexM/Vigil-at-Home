import { z } from 'zod';
import { Id, Severity, Timestamp } from './common.js';

/** The AI's read on an alert. Advisory only: it never changes containment. */
export const AiAssessment = z.object({
  provider: z.string(),
  model: z.string().optional(),
  at: Timestamp,
  verdict: z.enum(['likely_malicious', 'suspicious', 'likely_benign', 'unsure']),
  /** 0 to 1, as stated by the model. Shown, never acted on. */
  confidence: z.number().min(0).max(1).optional(),
  summary: z.string(),
  details: z.string().optional(),
  /** ActionProposal ids the AI made for this alert. */
  proposalIds: z.array(Id).default([]),
});
export type AiAssessment = z.infer<typeof AiAssessment>;

/** The user's call on an alert. Feeds rule stats and Vigil's memory of past decisions. */
export const UserDecision = z.object({
  at: Timestamp,
  verdict: z.enum(['malicious', 'benign', 'expected']),
  /** Allow this again without asking (creates an allow entry scoped by `scope`). */
  remember: z.boolean().default(false),
  scope: z.enum(['this_event', 'this_binary', 'this_signer', 'this_rule']).optional(),
  note: z.string().optional(),
});
export type UserDecision = z.infer<typeof UserDecision>;

/**
 * How loudly to tell the user.
 * - popup: always-on-top panel right away (blocks and high-fidelity alerts).
 * - badge: the menu-bar "Needs you" count only.
 * - silent: logged for the timeline.
 */
export const NotifyLevel = z.enum(['popup', 'badge', 'silent']);
export type NotifyLevel = z.infer<typeof NotifyLevel>;

export const Alert = z.object({
  id: Id,
  createdAt: Timestamp,
  updatedAt: Timestamp,
  ruleId: z.string(),
  ruleVersion: z.number().int(),
  title: z.string(),
  summary: z.string(),
  severity: Severity,
  fidelity: z.enum(['high', 'medium', 'low']),
  notify: NotifyLevel,
  status: z.enum(['open', 'resolved']),
  /** `active` while any containment action from this alert is in force. */
  containment: z.enum(['none', 'active', 'released']),
  eventIds: z.array(Id).min(1),
  actionIds: z.array(Id).default([]),
  /** Primary subject, for grouping and the popup header. */
  subject: z
    .object({
      kind: z.enum(['process', 'file', 'network', 'persistence']),
      label: z.string(),
      path: z.string().optional(),
    })
    .optional(),
  ai: AiAssessment.optional(),
  decision: UserDecision.optional(),
  /**
   * Set on alerts that may fold in identical repeats (see the app's
   * AlertService): `key` is the evidence that must match exactly, `count`
   * how many detections this row stands for, and `lastAt` the latest one.
   * Every repeat's events stay in `eventIds`.
   */
  repeats: z
    .object({
      key: z.string(),
      count: z.number().int().positive(),
      lastAt: Timestamp,
    })
    .optional(),
  /**
   * Alerts that share `key` (one rule, one agent run or one program) form a
   * pile: the app shows them as one row with one decision, and only the first
   * of a burst interrupts. Each alert in a pile is still its own record.
   * `who` names the agent or program, `what` the file or address this one is about.
   */
  pile: z
    .object({
      key: z.string(),
      who: z.string(),
      what: z.string().optional(),
    })
    .optional(),
});
export type Alert = z.infer<typeof Alert>;
