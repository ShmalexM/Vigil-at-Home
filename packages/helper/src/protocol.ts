// The helper's entire command surface: the response actions defined in
// @vigil/core, four read-only queries, and the blocking rules the helper runs
// itself and hands to Santa (detection.sync, detection.list.set). Nothing else can be asked of the
// root process: no shell, no programs to run, no generic "execute".
//
// Containment actions (suspend, kill, block, quarantine, disable, Santa block
// rules) run straight away. Release actions (core's isRelease: resume,
// unblock, restore, enable, Santa allow or rule removal) also need the
// user's macOS admin password, because malware running as the user could
// otherwise drive the app and release its own block. So does a detection.sync
// that weakens the helper's own rules (FastPath.loosening).

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

const Id = z.string().min(1).max(200);
const ListName = z.string().regex(/^[a-z0-9_]{1,64}$/);
const Digest = z.string().regex(/^[a-f0-9]{64}$/);

export const RuleExceptionSchema = z.strictObject({
  id: Id,
  ruleId: Id,
  match: z.record(z.string().max(100), z.string().max(1024)),
  createdAt: z.number(),
  note: z.string().max(1000).optional(),
});

/**
 * The rules Vigil enforces in block mode that the helper can run itself
 * (fastpath.ts), with the user's exceptions and Vigil's own paths. The helper
 * runs them on every sensor event, so a block happens even while the app is
 * closed, and hands Santa the ones it can stop before launch (preexec.ts).
 * `lists` names each indicator list the rules use with a digest of its
 * contents; the helper answers with the lists it needs sent.
 *
 * The app runs every rule too, but only while it is open. A sync that drops
 * or changes a rule, adds an exception or adds a self path therefore needs
 * the admin password, like a release; one that only adds rules does not.
 * Lists may change freely: an entry a list drops keeps blocking for a week.
 */
export const DetectionSync = z.strictObject({
  kind: z.literal('detection.sync'),
  rules: z.array(DetectionRule).max(64),
  exceptions: z.array(RuleExceptionSchema).max(2000),
  selfPaths: z.array(z.string().min(1).max(1024)).max(8),
  lists: z.record(ListName, Digest),
});
export type DetectionSync = z.infer<typeof DetectionSync>;

/** Sent in parts because feeds run to thousands of entries. */
export const LIST_PART_MAX = 1000;
export const DetectionListSet = z.strictObject({
  kind: z.literal('detection.list.set'),
  list: ListName,
  digest: Digest,
  part: z.number().int().min(0).max(199),
  parts: z.number().int().min(1).max(200),
  entries: z.array(z.string().max(255)).max(LIST_PART_MAX),
});
export type DetectionListSet = z.infer<typeof DetectionListSet>;

export type HelperCommand = HelperAction | HelperQuery | DetectionSync | DetectionListSet;

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
    'detection.sync',
    'detection.list.set',
  ].includes(cmd.kind);
}

/**
 * Actions that loosen protection and so need the user's admin password.
 * detection.sync depends on the rules in force, so the executor checks it.
 */
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
    : kind === 'detection.sync'
      ? DetectionSync.safeParse(env.data.command)
      : kind === 'detection.list.set'
        ? DetectionListSet.safeParse(env.data.command)
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
