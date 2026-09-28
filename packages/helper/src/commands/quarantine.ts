// Moves files and apps into a root-only quarantine folder, and back.
//
// A quarantined item is renamed (not copied) into Quarantine/<action id>/,
// and its permissions are set to 000 so nothing but root can read or run it.
// The original mode and owner are kept for restore. Restore never overwrites
// something that has since appeared at the original path.

import {
  chmodSync,
  chownSync,
  lstatSync,
  mkdirSync,
  realpathSync,
  renameSync,
  rmdirSync,
  existsSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';
import { PROTECTED_EXACT, PROTECTED_PREFIXES } from '../config.js';
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
}

/** Reject relative, unnormalized or protected paths, and user home folders themselves. */
export function vetPath(path: string, opts: QuarantineOptions): string {
  if (!isAbsolute(path) || normalize(path) !== path || path.endsWith('/') || path.includes('\0')) {
    throw new ActionError('invalid', `${path} must be an absolute, normalized path`);
  }
  const exact = opts.protectedExact ?? PROTECTED_EXACT;
  const prefixes = opts.protectedPrefixes ?? PROTECTED_PREFIXES;
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
    exact.has(path) ||
    prefixes.some(
      (p) =>
        path === p.replace(/\/$/, '') ||
        path.startsWith(p.endsWith('/') ? p : p + '/') ||
        path === p,
    ) ||
    quarantineRoots.some(
      (q) => path === q || path.startsWith(q + '/') || q.startsWith(path + '/'),
    ) ||
    /^\/Users\/[^/]+$/.test(path) ||
    /^\/Users\/[^/]+\/(Library|Desktop|Documents|Downloads)$/.test(path)
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
  try {
    renameSync(path, storedPath);
  } catch (err) {
    rmdirSync(slot);
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

export function restore(rec: QuarantineRecord): void {
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
  renameSync(rec.storedPath, rec.originalPath);
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
