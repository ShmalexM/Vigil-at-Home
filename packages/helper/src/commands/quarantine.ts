// Moves files and apps into a root-only quarantine folder, and back.
//
// A quarantined item is copied into Quarantine/<action id>/ and then removed
// from where it was, and its permissions there are set to 000 so nothing
// but root can read or run it. The original mode and owner are kept for
// restore. Restore never overwrites something that has since appeared at
// the original path.
//
// What may be moved is decided twice: by name (vetPath, the quick first
// pass), then by identity (protectedSet.ts), which catches other spellings
// of a protected path and hard links to protected files.
//
// Root never acts through a path a user can change: each side of a move
// runs as the user who controls it (transfer.ts), and root writes only in
// its own quarantine folder. Something swapped in after the checks is
// copied as that user could copy it, never changed in place: a protected
// file the user can only read is left as it was.

import { chmodSync, lstatSync, mkdirSync, readdirSync, realpathSync, rmSync } from 'node:fs';
import type { BigIntStats } from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';
import { protectionFor } from '../config.js';
import type { Platform } from '../platform.js';
import type { System } from '../system.js';
import { ActionError } from './errors.js';
import {
  checkFolders,
  checkIdentity,
  checkSelf,
  protectedIds,
  protectedPaths,
  type ProtectedIds,
} from './protectedSet.js';
import { actorFor, groupOf, self, transfer, type Actor } from './transfer.js';

export interface QuarantineRecord {
  originalPath: string;
  storedPath: string;
  mode: number;
  uid: number;
  gid: number;
  isDirectory: boolean;
  /** Owner and mode of the folder it came from, for making it again on restore. Absent in older records. */
  parent?: { uid: number; gid: number; mode: number };
}

export interface QuarantineOptions {
  quarantineDir: string;
  /**
   * The helper's state folder (config supportDir). Like the platform's
   * default one (Protection stateDir), nothing in it or above it is ever
   * moved, deleted or restored into.
   */
  stateDir?: string;
  protectedPrefixes?: string[];
  protectedExact?: Set<string>;
  /** Picks the protected lists when they aren't given. macOS when absent. */
  platform?: Platform;
  /** Vigil's own files on this machine (runtime, socket, data), protected like the built-in lists. */
  selfPaths?: string[];
  /**
   * A tripwire over the files the helper keeps (pinStore.ts): whether they
   * are all still where and what the helper left them. Checked before and
   * after every move; a change refuses the command and is logged. It never
   * moves anything itself.
   */
  guard?: () => Promise<boolean>;
  log?: (msg: string) => void;
  /** Who acts on a path; tests swap it. */
  actorFor?: (sys: System, path: string) => Promise<Actor>;
}

/** macOS disks ignore case by default, so paths there are compared without it. */
const caseless = (opts: QuarantineOptions) => opts.platform !== 'linux';

function realpathOrUndefined(path: string): string | undefined {
  try {
    return realpathSync(path);
  } catch {
    return undefined; // Not created yet: nothing can be inside it.
  }
}

/** `path` without trailing slashes (a loop, so a long run of them stays cheap). */
function trimSlashes(path: string): string {
  let end = path.length;
  while (end > 1 && path[end - 1] === '/') end--;
  return path.slice(0, end);
}

/**
 * The folders the helper keeps for itself: the quarantine folder and its
 * whole state folder (the one configured and the platform's default), each
 * as given and at its real location, so a path that reaches one through a
 * symlink (like /var -> /private/var on macOS) is caught too.
 */
function helperRoots(opts: QuarantineOptions): string[] {
  const roots = new Set<string>();
  for (const dir of [opts.quarantineDir, opts.stateDir, protectionFor(opts.platform).stateDir]) {
    if (!dir) continue;
    const trimmed = trimSlashes(dir);
    for (const r of [trimmed, realpathOrUndefined(trimmed)])
      if (r) roots.add(caseless(opts) ? r.toLowerCase() : r);
  }
  return [...roots];
}

/**
 * Whether `path` is one of the helper's own folders (helperRoots), is
 * inside one, or holds one. Every file command refuses such a path, so no
 * client can move, delete or restore over anything the helper keeps there,
 * the app pin included.
 */
export function touchesHelperState(path: string, opts: QuarantineOptions): boolean {
  const p = caseless(opts) ? path.toLowerCase() : path;
  return helperRoots(opts).some((q) => p === q || p.startsWith(q + '/') || q.startsWith(p + '/'));
}

/** Reject relative, unnormalized or protected paths, and user home folders themselves. */
export function vetPath(path: string, opts: QuarantineOptions): string {
  if (!isAbsolute(path) || normalize(path) !== path || path.endsWith('/') || path.includes('\0')) {
    throw new ActionError('invalid', `${path} must be an absolute, normalized path`);
  }
  const protection = protectionFor(opts.platform);
  const exact = opts.protectedExact ?? protection.exact;
  const prefixes = [
    ...(opts.protectedPrefixes ?? protection.prefixes),
    ...protection.processPrefixes,
    ...protection.services,
    ...(opts.selfPaths ?? []),
  ];
  // macOS disks ignore case by default, so /library/... is /Library/... there.
  // Other spellings the disk treats as equal are caught by identity later.
  const key = (s: string) => (caseless(opts) ? s.toLowerCase() : s);
  const p = key(path);
  if (
    [...exact].some((e) => key(e) === p) ||
    prefixes.some((raw) => {
      const pre = key(raw);
      // The protected path, anything inside it, or a folder that holds it.
      return (
        p === pre.replace(/\/$/, '') ||
        p.startsWith(pre.endsWith('/') ? pre : pre + '/') ||
        pre.startsWith(p + '/')
      );
    }) ||
    touchesHelperState(path, opts) ||
    protection.homes.some((re) => re.test(path))
  ) {
    throw new ActionError('refused', `${path} is protected`);
  }
  return path;
}

/** Everything protected from file moves, by identity. */
export function protectedFor(opts: QuarantineOptions): ProtectedIds {
  return protectedIds(protectedPaths(opts));
}

/** The path with symlinks in its parent folders resolved, or the path itself when they don't exist. */
export function realParentPath(path: string): string {
  try {
    return join(realpathSync.native(dirname(path)), basename(path));
  } catch {
    return path;
  }
}

function lstatOrNull(path: string): BigIntStats | null {
  try {
    return lstatSync(path, { bigint: true });
  } catch {
    return null;
  }
}

/**
 * Resolve symlinks in the parent folders and vet the real location by name,
 * then by identity: the target itself (a link is judged as the link, never
 * what it points to) and every folder above it.
 */
export function resolveTarget(
  path: string,
  opts: QuarantineOptions,
  ids: ProtectedIds = protectedFor(opts),
): string {
  vetPath(path, opts);
  let parent: string;
  try {
    // The kernel's own spelling of the folders (on macOS, as named on disk).
    parent = realpathSync.native(dirname(path));
  } catch {
    throw new ActionError('not_found', `${path} does not exist`);
  }
  const real = vetPath(join(parent, basename(path)), opts);
  checkIdentity(real, lstatOrNull(real), ids);
  return real;
}

/** What may be quarantined: a file with no other names, a folder or a link, none of them protected. */
function vetItem(path: string, st: BigIntStats, ids: ProtectedIds): void {
  if (!st.isFile() && !st.isDirectory() && !st.isSymbolicLink()) {
    throw new ActionError('refused', `${path} is not a file, folder or link`);
  }
  if (st.isFile() && st.nlink > 1n) {
    throw new ActionError(
      'refused',
      `${path} has other hard links; quarantine would leave those names in place`,
    );
  }
  checkSelf(path, st, ids);
}

/** The tripwire (QuarantineOptions guard): refuse, and log, when a file the helper keeps changed. */
async function checkGuard(opts: QuarantineOptions, when: string, after: string): Promise<void> {
  if (!opts.guard || (await opts.guard())) return;
  const msg = `a file Vigil's helper keeps changed ${when}; ${after}`;
  opts.log?.(msg);
  throw new ActionError(when === 'before the move' ? 'refused' : 'failed', msg);
}

export async function quarantine(
  sys: System,
  requestedPath: string,
  actionId: string,
  opts: QuarantineOptions,
): Promise<QuarantineRecord> {
  const ids = protectedFor(opts);
  const path = resolveTarget(requestedPath, opts, ids);
  // lstat: a symlink is quarantined as the link itself, never its target.
  const st = lstatOrNull(path);
  if (!st) throw new ActionError('not_found', `${path} does not exist`);
  vetItem(path, st, ids);
  const folder = lstatSync(dirname(path));
  const actor = await (opts.actorFor ?? actorFor)(sys, path);
  await checkGuard(opts, 'before the move', 'nothing was moved');
  mkdirSync(opts.quarantineDir, { recursive: true, mode: 0o700 });
  chmodSync(opts.quarantineDir, 0o700);
  const slot = join(opts.quarantineDir, actionId);
  mkdirSync(slot, { mode: 0o700 });
  const storedPath = join(slot, basename(path));
  try {
    await transfer(
      { path, actor },
      { path: storedPath, actor: self() },
      { owners: true, removeSource: true },
    );
  } catch (err) {
    // A complete copy whose original could not be (fully) removed is kept.
    if ((err as { copied?: boolean }).copied)
      throw new ActionError('failed', `${(err as Error).message}; the copy is at ${storedPath}`);
    // Otherwise whatever was copied is the helper's own; the original was not removed.
    rmSync(slot, { recursive: true, force: true });
    throw err;
  }
  await checkGuard(opts, 'during the move', `the item is in quarantine at ${storedPath}`);
  const stored = lstatSync(storedPath);
  if (!stored.isSymbolicLink()) chmodSync(storedPath, 0o000);
  return {
    originalPath: path,
    storedPath,
    mode: stored.mode & 0o7777,
    uid: Number(st.uid),
    gid: Number(st.gid),
    isDirectory: stored.isDirectory(),
    parent: { uid: folder.uid, gid: folder.gid, mode: folder.mode & 0o7777 },
  };
}

/** Every owner but root of the stored item and what is in it, from the helper's own store. */
function storedOwners(path: string): Set<number> {
  const owners = new Set<number>();
  const stack = [path];
  while (stack.length) {
    const p = stack.pop()!;
    const st = lstatSync(p);
    if (st.uid !== 0) owners.add(st.uid);
    if (st.isDirectory()) for (const n of readdirSync(p)) stack.push(join(p, n));
  }
  return owners;
}

/**
 * Who puts a quarantined item back.
 *
 *   root        when the destination is root's alone (actorFor): no one
 *               else can change it, and root gives every entry its owner.
 *   its owner   otherwise, for anything of a user's, so root never fills a
 *               folder someone else can change (records from before, too).
 *               Something of more than one user's can't go back that way.
 */
async function restoreActor(
  sys: System,
  rec: QuarantineRecord,
  opts: QuarantineOptions,
): Promise<Actor> {
  let dest: Actor | undefined;
  let refusal: unknown;
  try {
    dest = await (opts.actorFor ?? actorFor)(sys, rec.originalPath);
  } catch (err) {
    refusal = err;
  }
  if (dest?.uid === 0) return dest;
  const owners = storedOwners(rec.storedPath);
  if (owners.size > 1)
    throw new ActionError(
      'owner-cannot-write',
      `${rec.originalPath} belongs to more than one user; Vigil can't put it back as one of them`,
    );
  const owner = [...owners][0];
  if (owner !== undefined) return { uid: owner, gid: await groupOf(sys, owner) };
  if (dest) return dest;
  throw refusal;
}

export async function restore(
  sys: System,
  rec: QuarantineRecord,
  opts: QuarantineOptions,
): Promise<void> {
  const slot = dirname(rec.storedPath);
  if (dirname(slot) !== trimSlashes(opts.quarantineDir))
    throw new ActionError('refused', 'the quarantined copy is not in the quarantine folder');
  let exists = true;
  try {
    lstatSync(rec.originalPath);
  } catch {
    exists = false;
  }
  if (exists) {
    throw new ActionError(
      'refused',
      `something new is already at ${rec.originalPath}; not overwriting it`,
    );
  }
  let stored;
  try {
    stored = lstatSync(rec.storedPath);
  } catch {
    throw new ActionError('not_found', 'the quarantined copy is gone');
  }
  vetPath(rec.originalPath, opts);
  vetPath(realParentPath(rec.originalPath), opts);
  // By identity too: no folder it goes back into is one of the protected ones.
  checkFolders(dirname(rec.originalPath), protectedFor(opts));
  const isLink = stored.isSymbolicLink();
  // The store is root's own: readable again only for the copy back, and
  // for listing who owns what is in it.
  if (!isLink) chmodSync(rec.storedPath, rec.mode);
  let actor: Actor | undefined;
  let moving = false;
  try {
    actor = await restoreActor(sys, rec, opts);
    await checkGuard(opts, 'before the move', 'nothing was moved');
    moving = true;
    await transfer(
      { path: rec.storedPath, actor: self(), ownTree: true },
      { path: rec.originalPath, actor },
      {
        parents: true,
        ...(rec.parent ? { parentMode: rec.parent.mode } : {}),
        ...(isLink ? {} : { topMode: rec.mode }),
        owners: actor.uid === 0,
      },
    );
  } catch (err) {
    if (!isLink) chmodSync(rec.storedPath, 0o000);
    if (moving && actor!.uid !== 0 && /EACCES|EPERM/.test((err as Error).message))
      throw new ActionError(
        'owner-cannot-write',
        `${rec.originalPath} can't be put back: its owner can't write to that folder`,
      );
    throw err;
  }
  rmSync(slot, { recursive: true, force: true });
  await checkGuard(opts, 'during the move', `${rec.originalPath} was restored`);
}
