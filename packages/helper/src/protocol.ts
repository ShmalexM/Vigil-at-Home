// The helper's entire command surface: the response actions defined in
// @vigil/core, four read-only queries, the blocking rules the helper runs
// itself and hands to Santa (detection.sync, detection.list.set), and what
// counts as Vigil's own (self.grant). Nothing else can be asked of the root
// process: no shell, no programs to run, no generic "execute".
//
// Containment actions (suspend, kill, block, quarantine, disable, Santa block
// rules) run straight away. Release actions (core's isRelease: resume,
// unblock, restore, enable, Santa allow or rule removal) also need the
// user's macOS admin password, because malware running as the user could
// otherwise drive the app and release its own block. So does a detection.sync
// that weakens the helper's own rules, and a self.grant that names anything
// new as Vigil's own (FastPath.loosening, FastPath.selfLoosening).

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
import { SELF_HASH_MAX_FILES } from '@vigil/core/self';
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

/** A Linux AppImage by its path and device:inode. */
export const SelfImageSchema = z.strictObject({
  path: z.string().min(1).max(1024),
  id: z.string().regex(/^\d{1,20}:\d{1,20}$/),
});

const SelfPaths = z.array(z.string().min(1).max(1024)).max(8);
const SelfImages = z.array(SelfImageSchema).max(4);
const SelfHashes = z.array(Digest).max(SELF_HASH_MAX_FILES);

/**
 * What the helper never pauses, kills or blocks because it is Vigil's own.
 * Vigil's programs are named three ways: `selfPaths` (install folders and
 * files), `selfImages` (a Linux AppImage by device and inode, so a rename
 * while it runs still matches) and `selfHashes` (the sha256 of the programs
 * inside that image, which no block rule may name). Only Linux AppImages send
 * the last two.
 *
 * Being Vigil exempts a program from every block, so naming anything new
 * needs the admin password. The one exemption: until the helper has taken
 * any self grant, it may name the installer's own root-owned folder.
 *
 * Sent on its own, apart from the rules, so a password dialog for it never
 * holds up the rules or the user's decisions. Replaces the whole set:
 * dropping something asks nothing.
 */
export const SelfGrant = z.strictObject({
  kind: z.literal('self.grant'),
  selfPaths: SelfPaths,
  selfImages: SelfImages.optional(),
  selfHashes: SelfHashes.optional(),
});
export type SelfGrant = z.infer<typeof SelfGrant>;

/**
 * The rules Vigil enforces in block mode that the helper can run itself
 * (fastpath.ts), with the user's exceptions. The helper runs them on every
 * sensor event, so a block happens even while the app is closed, and hands
 * Santa the ones it can stop before launch (preexec.ts). `lists` names each
 * indicator list the rules use with a digest of its contents; the helper
 * answers with the lists it needs sent.
 *
 * The app runs every rule too, but only while it is open. A sync that drops
 * or changes a rule or adds an exception therefore needs the admin password,
 * like a release; one that only adds rules does not. Lists may change
 * freely: an entry a list drops keeps blocking for a week.
 *
 * The self fields are how apps before self.grant named Vigil's own: a sync
 * that carries them replaces the self set too, and needs the password for
 * anything new there, exactly as before. Without them the self set stays
 * as it is.
 */
export const DetectionSync = z.strictObject({
  kind: z.literal('detection.sync'),
  rules: z.array(DetectionRule).max(64),
  exceptions: z.array(RuleExceptionSchema).max(2000),
  selfPaths: SelfPaths.optional(),
  selfImages: SelfImages.optional(),
  selfHashes: SelfHashes.optional(),
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

export type HelperCommand =
  HelperAction | HelperQuery | DetectionSync | DetectionListSet | SelfGrant;

export interface HelperRequest {
  id: string;
  command: HelperCommand;
  /** Nonce from a previous needs-approval reply, after the user approved it. */
  approval?: string;
}

/**
 * `installer-owned`: a refusal to move an item root owns in a folder others
 * can write to, like an app a package installed in /Applications
 * (commands/transfer.ts). The app words it for the user.
 * `owner-cannot-write`: a restore refused because the item's owner can't
 * write where it goes back, or it has more than one owner; restores run as
 * the item's owner (commands/quarantine.ts).
 * `startup-folder-linked`: a startup item whose folder is a link to
 * somewhere else, which Vigil does not follow (commands/persistence.ts).
 * `not-your-item`: a startup item in another user's folder, or not the
 * asking user's own (commands/persistence.ts).
 */
export type ErrorCode =
  | 'invalid'
  | 'refused'
  | 'failed'
  | 'not_found'
  | 'installer-owned'
  | 'owner-cannot-write'
  | 'startup-folder-linked'
  | 'not-your-item';

/** The codes the app words itself, in one calm line, rather than showing the message. */
export const APP_WORDED_CODES = [
  'installer-owned',
  'owner-cannot-write',
  'startup-folder-linked',
  'not-your-item',
] as const;
export type AppWordedCode = (typeof APP_WORDED_CODES)[number];

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
    'self.grant',
  ].includes(cmd.kind);
}

/**
 * Actions that loosen protection and so need the user's admin password.
 * detection.sync and self.grant depend on the policy in force, so the
 * executor checks them.
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
        : kind === 'self.grant'
          ? SelfGrant.safeParse(env.data.command)
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
