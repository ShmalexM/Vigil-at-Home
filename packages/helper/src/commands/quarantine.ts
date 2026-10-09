// Moves files and apps into a root-only quarantine folder, and back.
//
// A quarantined item is copied into Quarantine/<action id>/ and then removed
// from where it was, and its permissions there are set to 000 so nothing
// but root can read or run it. The original mode and owner are kept for
// restore. Restore never overwrites something that has since appeared at
// the original path.
//
// Root never acts through a path a user can change: each side of a move
// runs as the user who controls it (transfer.ts), and root writes only in
// its own quarantine folder.

import { chmodSync, lstatSync, mkdirSync, readdirSync, realpathSync, rmSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';
import { protectionFor } from '../config.js';
import type { Platform } from '../platform.js';
import type { System } from '../system.js';
import { ActionError } from './errors.js';
import { actorFor, groupOf, self, transfer, type Actor } from './transfer.js';

export interface QuarantineRecord {
  originalPath: string;
  storedPath: string;
  mode: number;
  uid: number;
  gid: number;
  isDirectory: boolean;
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
    const trimmed = dir.replace(/\/+$/, '');
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
  const prefixes = opts.protectedPrefixes ?? protection.prefixes;
  const key = (s: string) => (caseless(opts) ? s.toLowerCase() : s);
  const p = key(path);
  if (
    [...exact].some((e) => key(e) === p) ||
    prefixes.some((raw) => {
      const pre = key(raw);
      return p === pre.replace(/\/$/, '') || p.startsWith(pre.endsWith('/') ? pre : pre + '/');
    }) ||
    touchesHelperState(path, opts) ||
    protection.homes.some((re) => re.test(path))
  ) {
    throw new ActionError('refused', `${path} is protected`);
  }
  return path;
}

/** The path with symlinks in its parent folders resolved, or the path itself when they don't exist. */
export function realParentPath(path: string): string {
  try {
    return join(realpathSync(dirname(path)), basename(path));
  } catch {
    return path;
  }
}

/**
 * Resolve symlinks in the parent folders and vet the real location too, so a
 * symlinked folder cannot redirect the move into a protected place.
 */
export function resolveTarget(path: string, opts: QuarantineOptions): string {
  vetPath(path, opts);
  let parent: string;
  try {
    parent = realpathSync(dirname(path));
  } catch {
    throw new ActionError('not_found', `${path} does not exist`);
  }
  return vetPath(join(parent, basename(path)), opts);
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
  const path = resolveTarget(requestedPath, opts);
  let st;
  try {
    // lstat: a symlink is quarantined as the link itself, never its target.
    st = lstatSync(path);
  } catch {
    throw new ActionError('not_found', `${path} does not exist`);
  }
  if (!st.isFile() && !st.isDirectory() && !st.isSymbolicLink())
    throw new ActionError('refused', `${path} is not a file, folder or link`);
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
    // Whatever was copied is the helper's own; the original was not removed.
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
    uid: st.uid,
    gid: st.gid,
    isDirectory: stored.isDirectory(),
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

export async function restore(
  sys: System,
  rec: QuarantineRecord,
  opts: QuarantineOptions,
): Promise<void> {
  const slot = dirname(rec.storedPath);
  if (dirname(slot) !== opts.quarantineDir.replace(/\/+$/, ''))
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
  // Anything of a user's goes back as that user, so root never fills a
  // folder someone else owns (this covers records from before, too).
  const owners = storedOwners(rec.storedPath);
  if (owners.size > 1)
    throw new ActionError(
      'owner-cannot-write',
      `${rec.originalPath} belongs to more than one user; Vigil can't put it back as one of them`,
    );
  const owner = [...owners][0];
  const actor =
    owner !== undefined
      ? { uid: owner, gid: await groupOf(sys, owner) }
      : await (opts.actorFor ?? actorFor)(sys, rec.originalPath);
  await checkGuard(opts, 'before the move', 'nothing was moved');
  const isLink = stored.isSymbolicLink();
  // The store is root's own: readable again only for the copy back.
  if (!isLink) chmodSync(rec.storedPath, rec.mode);
  try {
    await transfer(
      { path: rec.storedPath, actor: self(), ownTree: true },
      { path: rec.originalPath, actor },
      {
        parents: true,
        ...(isLink ? {} : { topMode: rec.mode }),
        owners: actor.uid === 0,
      },
    );
  } catch (err) {
    if (!isLink) chmodSync(rec.storedPath, 0o000);
    if (actor.uid !== 0 && /EACCES|EPERM/.test((err as Error).message))
      throw new ActionError(
        'owner-cannot-write',
        `${rec.originalPath} can't be put back: its owner can't write to that folder`,
      );
    throw err;
  }
  rmSync(slot, { recursive: true, force: true });
  await checkGuard(opts, 'during the move', `${rec.originalPath} was restored`);
}
