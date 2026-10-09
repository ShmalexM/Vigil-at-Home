// Moves files and apps into a root-only quarantine folder, and back.
//
// A quarantined item is renamed (not copied) into Quarantine/<action id>/,
// and its permissions are set to 000 so nothing but root can read or run it.
// The original mode and owner are kept for restore. Restore never overwrites
// something that has since appeared at the original path.

import {
  chmodSync,
  chownSync,
  cpSync,
  rmSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  renameSync,
  readdirSync,
  rmdirSync,
  existsSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';
import { protectionFor } from '../config.js';
import type { Platform } from '../platform.js';
import { ActionError } from './errors.js';

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
   * Files the helper keeps (the app pin and its key, pinStore.ts), by path
   * and device and inode. A move that ends up taking or replacing one of
   * them, by whatever path it got there, is undone and refused.
   */
  guarded?: () => readonly GuardedFile[];
}

/** A file the helper keeps, by path and the device and inode it should have there. */
export interface GuardedFile {
  path: string;
  id: string;
}

/** A move took or replaced a file the helper keeps; it was undone. */
export class GuardTripped extends ActionError {
  constructor(path: string) {
    super('refused', `moving ${path} would have moved a file Vigil's helper keeps; undone`);
  }
}

function lstatIdOf(path: string): string | undefined {
  try {
    const st = lstatSync(path, { bigint: true });
    return `${st.dev}:${st.ino}`;
  } catch {
    return undefined;
  }
}

/**
 * Checked synchronously right after a move to `arrived`: whether what
 * arrived is one of the guarded files (a hard link to it, say), or whether
 * any guarded file is no longer at its path with its device and inode (the
 * move took a folder holding it, or replaced it).
 */
export function tookGuarded(arrived: string, guards: readonly GuardedFile[] | undefined): boolean {
  if (!guards?.length) return false;
  const moved = lstatIdOf(arrived);
  if (moved !== undefined && guards.some((g) => g.id === moved)) return true;
  return guards.some((g) => lstatIdOf(g.path) !== g.id);
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

export function quarantine(
  requestedPath: string,
  actionId: string,
  opts: QuarantineOptions,
): QuarantineRecord {
  const path = resolveTarget(requestedPath, opts);
  let st;
  try {
    // lstat: a symlink is quarantined as the link itself, never its target.
    st = lstatSync(path);
  } catch {
    throw new ActionError('not_found', `${path} does not exist`);
  }
  mkdirSync(opts.quarantineDir, { recursive: true, mode: 0o700 });
  chmodSync(opts.quarantineDir, 0o700);
  const slot = join(opts.quarantineDir, actionId);
  mkdirSync(slot, { mode: 0o700 });
  const storedPath = join(slot, basename(path));
  const guards = opts.guarded?.();
  try {
    // Linux homes are often their own partition, so a move there may have to copy.
    if (opts.platform === 'linux') moveAcrossDisks(path, storedPath, guards);
    else renameSync(path, storedPath);
  } catch (err) {
    rmSync(slot, { recursive: true, force: true });
    if (err instanceof GuardTripped) throw err;
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EXDEV') {
      throw new ActionError(
        'failed',
        `${path} is on another disk; quarantine only works on the startup disk for now`,
      );
    }
    throw new ActionError('failed', `could not move ${path}: ${(err as Error).message}`);
  }
  // Whatever path got the move there, it must not have taken a file the helper keeps.
  if (tookGuarded(storedPath, guards)) {
    undoMove(storedPath, path, opts);
    rmSync(slot, { recursive: true, force: true });
    throw new GuardTripped(path);
  }
  if (!st.isSymbolicLink()) chmodSync(storedPath, 0o000);
  return {
    originalPath: path,
    storedPath,
    mode: st.mode & 0o7777,
    uid: st.uid,
    gid: st.gid,
    isDirectory: st.isDirectory(),
  };
}

/**
 * rename, or when source and destination are on different filesystems, copy
 * (links stay links, times are kept) and then delete the source. The copy
 * is complete before anything is deleted, so a failure leaves the original.
 */
export function moveAcrossDisks(from: string, to: string, guards?: readonly GuardedFile[]): void {
  try {
    renameSync(from, to);
    return;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EXDEV') throw err;
  }
  try {
    cpSync(from, to, {
      recursive: true,
      verbatimSymlinks: true,
      preserveTimestamps: true,
      errorOnExist: true,
      force: false,
    });
  } catch (err) {
    rmSync(to, { recursive: true, force: true });
    throw err;
  }
  // The source is about to be deleted: never with a file the helper keeps in it.
  if (guards?.length && holdsGuarded(from, guards)) {
    rmSync(to, { recursive: true, force: true });
    throw new GuardTripped(from);
  }
  rmSync(from, { recursive: true, force: true });
}

/** Whether `path`, or anything under it (not following links), is one of the guarded files. */
function holdsGuarded(path: string, guards: readonly GuardedFile[]): boolean {
  const ids = new Set(guards.map((g) => g.id));
  const stack = [path];
  let seen = 0;
  while (stack.length) {
    const p = stack.pop()!;
    // Too big to check: treat as holding one, and leave the source alone.
    if (++seen > 200_000) return true;
    let st;
    try {
      st = lstatSync(p, { bigint: true });
    } catch {
      continue;
    }
    if (ids.has(`${st.dev}:${st.ino}`)) return true;
    if (st.isDirectory()) {
      try {
        for (const name of readdirSync(p)) stack.push(join(p, name));
      } catch {
        return true;
      }
    }
  }
  return false;
}

/** Put a move back after a guard tripped; a failure leaves it where it is, reported by the caller. */
function undoMove(from: string, to: string, opts: QuarantineOptions): void {
  try {
    if (opts.platform === 'linux') moveAcrossDisks(from, to);
    else renameSync(from, to);
  } catch {
    // Left in the quarantine slot; the refusal says what happened.
  }
}

export function restore(rec: QuarantineRecord, guards?: readonly GuardedFile[]): void {
  if (existsSync(rec.originalPath)) {
    throw new ActionError(
      'refused',
      `something new is already at ${rec.originalPath}; not overwriting it`,
    );
  }
  if (!existsSync(rec.storedPath))
    throw new ActionError('not_found', 'the quarantined copy is gone');
  mkdirSync(dirname(rec.originalPath), { recursive: true });
  const isLink = lstatSync(rec.storedPath).isSymbolicLink();
  if (!isLink) chmodSync(rec.storedPath, rec.mode);
  // Only Linux quarantines ever cross disks; on macOS this is a plain rename.
  moveAcrossDisks(rec.storedPath, rec.originalPath, guards);
  // A restore that landed on, or replaced, a file the helper keeps goes back.
  if (tookGuarded(rec.originalPath, guards)) {
    try {
      moveAcrossDisks(rec.originalPath, rec.storedPath);
    } catch {
      // Left where it landed; the refusal says what happened.
    }
    throw new GuardTripped(rec.originalPath);
  }
  try {
    if (!isLink) chownSync(rec.originalPath, rec.uid, rec.gid);
  } catch {
    // Only root can chown; in tests the owner is already right.
  }
  try {
    rmdirSync(dirname(rec.storedPath));
  } catch {
    // Leave a non-empty slot alone.
  }
}
