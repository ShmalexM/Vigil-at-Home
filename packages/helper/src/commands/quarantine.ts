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
  protectedPrefixes?: string[];
  protectedExact?: Set<string>;
  /** Picks the protected lists when they aren't given. macOS when absent. */
  platform?: Platform;
}

/** Reject relative, unnormalized or protected paths, and user home folders themselves. */
export function vetPath(path: string, opts: QuarantineOptions): string {
  if (!isAbsolute(path) || normalize(path) !== path || path.endsWith('/') || path.includes('\0')) {
    throw new ActionError('invalid', `${path} must be an absolute, normalized path`);
  }
  const protection = protectionFor(opts.platform);
  const exact = opts.protectedExact ?? protection.exact;
  const prefixes = opts.protectedPrefixes ?? protection.prefixes;
  // macOS disks ignore case by default, so /library/... is /Library/... there.
  const fold = (s: string) => (opts.platform === 'linux' ? s : s.toLowerCase());
  const key = fold(path);
  const quarantineRoot = opts.quarantineDir.replace(/\/$/, '');
  // Compare against the quarantine folder's real location too, so a path that
  // reaches it through a symlink (like /var -> /private/var on macOS) is caught.
  const quarantineRoots = [quarantineRoot];
  try {
    quarantineRoots.push(realpathSync(quarantineRoot));
  } catch {
    // Not created yet: nothing can be inside it.
  }
  if (
    [...exact].some((e) => fold(e) === key) ||
    prefixes.some((raw) => {
      const p = fold(raw);
      return key === p.replace(/\/$/, '') || key.startsWith(p.endsWith('/') ? p : p + '/');
    }) ||
    quarantineRoots.some((raw) => {
      const q = fold(raw);
      return key === q || key.startsWith(q + '/') || q.startsWith(key + '/');
    }) ||
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

function realpathOrNull(path: string): string | null {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
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
  try {
    // Linux homes are often their own partition, so a move there may have to copy.
    if (opts.platform === 'linux') moveAcrossDisks(path, storedPath);
    else renameSync(path, storedPath);
  } catch (err) {
    rmSync(slot, { recursive: true, force: true });
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EXDEV') {
      throw new ActionError(
        'failed',
        `${path} is on another disk; quarantine only works on the startup disk for now`,
      );
    }
    throw new ActionError('failed', `could not move ${path}: ${(err as Error).message}`);
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
export function moveAcrossDisks(from: string, to: string): void {
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
  rmSync(from, { recursive: true, force: true });
}

/**
 * Restore moves the file back as root, so check again that the original
 * folder is still where it was: a folder swapped for a symlink since the
 * quarantine could otherwise send the file somewhere protected.
 */
export function restore(rec: QuarantineRecord, opts: QuarantineOptions): void {
  if (existsSync(rec.originalPath)) {
    throw new ActionError(
      'refused',
      `something new is already at ${rec.originalPath}; not overwriting it`,
    );
  }
  if (!existsSync(rec.storedPath))
    throw new ActionError('not_found', 'the quarantined copy is gone');
  vetPath(rec.originalPath, opts);
  const parent = dirname(rec.originalPath);
  if (!existsSync(parent)) {
    // Recreate missing folders only below one that is still its real self.
    let base = dirname(parent);
    while (!existsSync(base)) base = dirname(base);
    if (realpathOrNull(base) !== base) {
      throw new ActionError('refused', `${parent} has moved; not restoring into it`);
    }
    try {
      mkdirSync(parent, { recursive: true });
    } catch {
      throw new ActionError('failed', `could not recreate ${parent}`);
    }
  }
  if (realpathOrNull(parent) !== parent) {
    throw new ActionError('refused', `${parent} has moved; not restoring into it`);
  }
  const isLink = lstatSync(rec.storedPath).isSymbolicLink();
  if (!isLink) chmodSync(rec.storedPath, rec.mode);
  // Only Linux quarantines ever cross disks; on macOS this is a plain rename.
  moveAcrossDisks(rec.storedPath, rec.originalPath);
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
