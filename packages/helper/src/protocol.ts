// The helper's entire command surface: the response actions defined in
// @vigil/core, four read-only queries, and the list of rules Santa should
// enforce before launch (santa.preexec.set). Nothing else can be asked of the
// root process: no shell, no programs to run, no generic "execute".
//
// Containment actions (suspend, kill, block, quarantine, disable, Santa block
// rules) run straight away. Release actions (core's isRelease: resume,
// unblock, restore, enable, Santa allow or rule removal) also need the
// user's macOS admin password, because malware running as the user could
// otherwise drive the app and release its own block.

import { z } from 'zod';
import {
  Action as CoreAction,
  FileQuarantine,
  FileRestore,
  NetworkBlock,
  NetworkUnblock,
  PersistenceDisable,
  PersistenceEnable,
  ProcessKill,
  ProcessResume,
  ProcessSuspend,
  SantaRuleRemove,
  SantaRuleSet,
  isRelease,
} from '@vigil/core';
import { DetectionRule } from '@vigil/detection';

export const HelperAction = z.discriminatedUnion('kind', [
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
export type HelperAction = z.infer<typeof HelperAction>;

export const HelperQuery = z.discriminatedUnion('kind', [
  z.strictObject({ kind: z.literal('helper.status') }),
  z.strictObject({
    kind: z.literal('helper.journal'),
    limit: z.number().int().min(1).max(1000).optional(),
  }),
  z.strictObject({ kind: z.literal('santa.profile') }),
  z.strictObject({ kind: z.literal('events.subscribe'), since: z.string().max(200).optional() }),
]);
export type HelperQuery = z.infer<typeof HelperQuery>;

/**
 * The rules Vigil is enforcing in block mode, for Santa to enforce before
 * launch where it can. The helper builds the Santa rules itself (preexec.ts)
 * and only ever targets Apple's own programs, so this can add blocks but
 * never allow anything. Sending fewer rules only moves those blocks back to
 * Vigil's own engine, which still kills the program after it starts, so it
 * needs no admin password.
 */
export const SantaPreexecSet = z.strictObject({
  kind: z.literal('santa.preexec.set'),
  rules: z.array(DetectionRule).max(64),
});
export type SantaPreexecSet = z.infer<typeof SantaPreexecSet>;

export type HelperCommand = HelperAction | HelperQuery | SantaPreexecSet;

export interface HelperRequest {
  id: string;
  command: HelperCommand;
  /** Nonce from a previous needs-approval reply, after the user approved it. */
  approval?: string;
}

export type ErrorCode = 'invalid' | 'refused' | 'failed' | 'not_found';

export type HelperResponse =
  | { id: string; ok: true; result: unknown }
  | { id: string; ok: false; error: string; code: ErrorCode }
  | { id: string; ok: false; needsApproval: true; nonce: string; prompt: string };

export function isAction(cmd: HelperCommand): cmd is HelperAction {
  return ![
    'helper.status',
    'helper.journal',
    'santa.profile',
    'events.subscribe',
    'santa.preexec.set',
  ].includes(cmd.kind);
}

/** Commands that loosen protection and so need the user's admin password. */
export function needsApproval(cmd: HelperCommand): boolean {
  if (!isAction(cmd)) return false;
  return isRelease(CoreAction.parse(cmd));
}

const RequestEnvelope = z.strictObject({
  id: z.string().min(1).max(100),
  command: z.record(z.string(), z.unknown()),
  approval: z
    .string()
    .regex(/^[a-f0-9]{32}$/)
    .optional(),
});

/** Parse and strictly validate one request line. Unknown kinds and unknown fields are rejected. */
export function parseRequest(line: string): HelperRequest | { error: string; id?: string } {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return { error: 'invalid JSON' };
  }
  const id =
    raw && typeof raw === 'object' && typeof (raw as { id?: unknown }).id === 'string'
      ? (raw as { id: string }).id.slice(0, 100)
      : undefined;
  const env = RequestEnvelope.safeParse(raw);
  if (!env.success) return withId(id, `bad request: ${env.error.issues[0]?.message ?? 'invalid'}`);
  const kind = env.data.command.kind;
  const isQuery =
    typeof kind === 'string' &&
    ['helper.status', 'helper.journal', 'santa.profile', 'events.subscribe'].includes(kind);
  const parsed = isQuery
    ? HelperQuery.safeParse(env.data.command)
    : kind === 'santa.preexec.set'
      ? SantaPreexecSet.safeParse(env.data.command)
      : HelperAction.safeParse(env.data.command);
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    return withId(
      id,
      `bad command: ${issue ? `${issue.path.join('.') || 'kind'} ${issue.message}` : 'invalid'}`,
    );
  }
  // Core schemas drop unknown fields silently; the helper refuses them so a
  // typo never turns into a different action than the caller meant.
  const known = new Set(Object.keys(parsed.data));
  const extra = Object.keys(env.data.command).find((k) => !known.has(k));
  if (extra) return withId(id, `unknown field ${extra}`);
  const req: HelperRequest = { id: env.data.id, command: parsed.data };
  if (env.data.approval) req.approval = env.data.approval;
  return req;
}

function withId(id: string | undefined, error: string): { error: string; id?: string } {
  return id === undefined ? { error } : { error, id };
}
