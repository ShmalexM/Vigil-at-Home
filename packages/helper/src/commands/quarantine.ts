// Moves files and apps into a root-only quarantine folder, and back.
//
// A quarantined item is renamed (not copied) into Quarantine/<action id>/,
// and its permissions are set to 000 so nothing but root can read or run it.
// The original mode and owner are kept for restore. Restore never overwrites
// something that has since appeared at the original path.
//
// What may be moved is decided twice: by name (vetPath, the quick first
// pass), then by identity (protectedSet.ts), which catches other spellings
// of a protected path and hard links to protected files. The moves
// themselves never follow a link swapped in after the checks: the item is
// held open while it is checked, its mode is set through that handle, and
// the folder on the far side is pinned and checked through the pin
// (safeFs.ts), so a folder swapped for a link is noticed, not followed.

import {
  chmodSync,
  closeSync,
  cpSync,
  fchmodSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, join, normalize } from 'node:path';
import { protectionFor } from '../config.js';
import type { Platform } from '../platform.js';
import { ActionError } from './errors.js';
import {
  checkChain,
  checkFolders,
  checkIdentity,
  checkSelf,
  protectedIds,
  protectedPaths,
  sameId,
  type ProtectedIds,
} from './protectedSet.js';
import {
  euid,
  fchownIfRoot,
  fdPath,
  fstatBig,
  lexists,
  lstatOrNull,
  O_CHECK,
  O_FOLDER,
  pinFolder,
  withFolderFd,
  type Pinning,
} from './safeFs.js';
import type { BigIntStats } from 'node:fs';

export interface QuarantineRecord {
  originalPath: string;
  storedPath: string;
  mode: number;
  uid: number;
  gid: number;
  isDirectory: boolean;
  /** Owner and mode of the folder it came from, for recreating it on restore. Absent in older records. */
  parent?: { uid: number; gid: number; mode: number };
}

export interface QuarantineOptions {
  quarantineDir: string;
  protectedPrefixes?: string[];
  protectedExact?: Set<string>;
  /** Picks the protected lists when they aren't given. macOS when absent. */
  platform?: Platform;
  /** Vigil's own files on this machine (runtime, socket, data), protected like the built-in lists. */
  selfPaths?: string[];
  /** How folders are held during a move (see safeFs.ts). Picked from the OS when absent. */
  pinning?: Pinning;
  /** Test hook, called after the checks and right before each move. */
  beforeMove?: (step: 'quarantine' | 'mkdir' | 'restore') => void;
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
      // The protected path, anything inside it, or a folder that holds it.
      return (
        key === p.replace(/\/$/, '') ||
        key.startsWith(p.endsWith('/') ? p : p + '/') ||
        p.startsWith(key + '/')
      );
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

function realpathOrNull(path: string): string | null {
  try {
    return realpathSync.native(path);
  } catch {
    return null;
  }
}

function changed(path: string): ActionError {
  return new ActionError(
    'refused',
    `${path} changed while it was being checked; nothing was moved`,
  );
}

function hasMoved(dir: string): ActionError {
  return new ActionError('refused', `${dir} has moved; nothing was moved`);
}

/** What may be quarantined: a file with no other names, a folder or a link, none of them protected. */
function vetItem(path: string, st: BigIntStats, ids: ProtectedIds): void {
  if (!st.isFile() && !st.isDirectory() && !st.isSymbolicLink()) {
    throw new ActionError('refused', `${path} is not a file, folder or link`);
  }
  if (st.isFile() && st.nlink > 1n) {
    throw new ActionError(
      'refused',
      `${path} has other hard links; quarantining it would lock those too`,
    );
  }
  checkSelf(path, st, ids);
}

/**
 * Open the item without following a link and check the handle is the item
 * that was checked. Links are moved as themselves and need no handle.
 */
function holdItem(
  path: string,
  st: BigIntStats,
  shown: string,
  ids: ProtectedIds,
): number | undefined {
  if (st.isSymbolicLink()) return undefined;
  let fd: number;
  try {
    fd = openSync(path, O_CHECK);
  } catch {
    throw changed(shown);
  }
  try {
    const now = fstatBig(fd);
    if (!sameId(now, st) || now.isDirectory() !== st.isDirectory()) throw changed(shown);
    vetItem(shown, now, ids);
    return fd;
  } catch (err) {
    closeSync(fd);
    throw err;
  }
}

function moveError(path: string, err: unknown): ActionError {
  if (err instanceof ActionError) return err;
  if ((err as NodeJS.ErrnoException).code === 'EXDEV') {
    return new ActionError(
      'failed',
      `${path} is on another disk; quarantine only works on the startup disk for now`,
    );
  }
  return new ActionError('failed', `could not move ${path}: ${(err as Error).message}`);
}

/** After a move, the thing that arrived must be the one that was checked; otherwise undo it. */
function confirmMoved(at: string, st: BigIntStats, shown: string, putBack: () => void): void {
  const now = lstatOrNull(at);
  if (now && sameId(now, st)) return;
  if (now) {
    try {
      putBack();
    } catch {
      // Left where it is; the error says nothing was quarantined.
    }
  }
  throw new ActionError(
    'refused',
    `${shown} changed while it was being moved; nothing was quarantined`,
  );
}

/**
 * Open an item in a folder only this process can reach (the store or a
 * handoff folder) to change its mode. Root can open a mode-000 item; without
 * root (tests) it can't, and the path is used instead, which is safe there
 * because nobody else can change those folders.
 */
function withItem(path: string, fn: (fd: number | null) => void): void {
  let fd: number;
  try {
    fd = openSync(path, O_CHECK);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'EACCES' && euid() !== 0) return fn(null);
    throw err;
  }
  try {
    fn(fd);
  } finally {
    closeSync(fd);
  }
}

/** Set the stored item's mode to 000 through a handle, never by a path a link could redirect. */
function lockStored(fd: number | undefined, storedPath: string): void {
  const st = lstatOrNull(storedPath);
  if (!st || st.isSymbolicLink()) return;
  if (fd !== undefined) {
    fchmodSync(fd, 0o000);
    return;
  }
  withItem(storedPath, (h) => (h === null ? chmodSync(storedPath, 0) : fchmodSync(h, 0)));
}

export function quarantine(
  requestedPath: string,
  actionId: string,
  opts: QuarantineOptions,
): QuarantineRecord {
  const ids = protectedFor(opts);
  const path = resolveTarget(requestedPath, opts, ids);
  const before = lstatOrNull(path);
  if (!before) throw new ActionError('not_found', `${path} does not exist`);
  vetItem(path, before, ids);
  mkdirSync(opts.quarantineDir, { recursive: true, mode: 0o700 });
  chmodSync(opts.quarantineDir, 0o700);
  const slot = join(opts.quarantineDir, actionId);
  mkdirSync(slot, { mode: 0o700 });
  const storedPath = join(slot, basename(path));
  let moved: { st: BigIntStats; parent: BigIntStats };
  try {
    moved = moveIn(path, storedPath, ids, opts);
  } catch (err) {
    if (!lexists(storedPath)) rmSync(slot, { recursive: true, force: true });
    throw err;
  }
  const { st, parent } = moved;
  return {
    originalPath: path,
    storedPath,
    mode: Number(st.mode & 0o7777n),
    uid: Number(st.uid),
    gid: Number(st.gid),
    isDirectory: st.isDirectory(),
    parent: {
      uid: Number(parent.uid),
      gid: Number(parent.gid),
      mode: Number(parent.mode & 0o7777n),
    },
  };
}

/**
 * Pin the item's folder, check it and the item through the pin, hold the
 * item open, move it into the store and lock it through the handle.
 */
function moveIn(
  path: string,
  storedPath: string,
  ids: ProtectedIds,
  opts: QuarantineOptions,
): { st: BigIntStats; parent: BigIntStats } {
  const name = basename(path);
  const pin = pinFolder(dirname(path), opts.pinning);
  try {
    const chain = pin.chain();
    checkChain(chain, path, ids);
    const src = pin.at(name);
    const st = lstatOrNull(src);
    if (!st) throw new ActionError('not_found', `${path} does not exist`);
    vetItem(path, st, ids);
    const fd = holdItem(src, st, path, ids);
    try {
      opts.beforeMove?.('quarantine');
      if (pin.where() !== dirname(path)) throw hasMoved(dirname(path));
      let copied = false;
      try {
        renameSync(src, storedPath);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EXDEV' || pin.fd === undefined) {
          throw moveError(path, err);
        }
        copyOut(pin.fd, name, storedPath, st, path);
        copied = true;
      }
      if (!copied) {
        confirmMoved(storedPath, st, path, () => {
          if (!lexists(src)) renameSync(storedPath, src);
        });
      }
      lockStored(copied ? undefined : fd, storedPath);
    } finally {
      if (fd !== undefined) closeSync(fd);
    }
    return { st, parent: chain[0]! };
  } finally {
    pin.release();
  }
}

/**
 * Linux homes are often their own partition. The item first moves into a
 * fresh root-only folder beside it, so what is copied and then deleted is
 * exactly what was checked.
 */
function copyOut(
  pfd: number,
  name: string,
  storedPath: string,
  st: BigIntStats,
  shown: string,
): void {
  const hold = mkdtempSync(fdPath(pfd, '.vigil-quarantine-'));
  const holdName = basename(hold);
  const hfd = openSync(hold, O_FOLDER);
  try {
    if (fstatBig(hfd).uid !== BigInt(euid())) throw changed(shown);
    const src = fdPath(pfd, name);
    const held = fdPath(hfd, name);
    renameSync(src, held);
    confirmMoved(held, st, shown, () => {
      if (!lexists(src)) renameSync(held, src);
    });
    try {
      moveAcrossDisks(held, storedPath);
    } catch (err) {
      if (lexists(held) && !lexists(src)) renameSync(held, src);
      throw moveError(shown, err);
    }
  } finally {
    closeSync(hfd);
    try {
      rmdirSync(fdPath(pfd, holdName));
    } catch {
      // Not empty, or already gone.
    }
  }
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

interface FolderOwner {
  uid: number;
  gid: number;
  /** Mode of the folder the item was in; folders above it get 0755. */
  mode: number;
}

/** Who owns folders recreated on restore: as recorded, else the existing folder's owner or the item's. */
function newFolderOwner(rec: QuarantineRecord, base: BigIntStats): FolderOwner {
  if (rec.parent) return { ...rec.parent, mode: rec.parent.mode & 0o7777 };
  if (base.uid !== 0n) return { uid: Number(base.uid), gid: Number(base.gid), mode: 0o755 };
  return { uid: rec.uid, gid: rec.gid, mode: 0o755 };
}

/** Give an item its old mode and owner, through a handle, where only this process can reach it. */
function settle(path: string, rec: QuarantineRecord): void {
  const st = lstatOrNull(path);
  if (!st || st.isSymbolicLink()) return;
  withItem(path, (fd) => {
    if (fd === null) return chmodSync(path, rec.mode);
    fchmodSync(fd, rec.mode);
    fchownIfRoot(fd, rec.uid, rec.gid);
  });
}

/**
 * Restore moves the file back as root, so the folder it goes into must be
 * the folder it came from at the moment of the move, not just at the check.
 * The folder (or the nearest one that still exists) is pinned, missing
 * folders are made inside the pin one by one, and the item is renamed into
 * the pinned folder by name. A folder swapped for a link since is noticed
 * when the pin is checked, and the item stays in the store.
 */
export function restore(rec: QuarantineRecord, opts: QuarantineOptions): void {
  if (lexists(rec.originalPath)) {
    throw new ActionError(
      'refused',
      `something new is already at ${rec.originalPath}; not overwriting it`,
    );
  }
  if (!lexists(rec.storedPath)) throw new ActionError('not_found', 'the quarantined copy is gone');
  vetPath(rec.originalPath, opts);
  const ids = protectedFor(opts);
  const parent = dirname(rec.originalPath);
  const name = basename(rec.originalPath);
  const missing: string[] = [];
  let base = parent;
  while (!lexists(base)) {
    missing.unshift(basename(base));
    base = dirname(base);
  }
  // Recreate missing folders only below one that is still its real self.
  if (realpathOrNull(base) !== base) {
    throw new ActionError('refused', `${parent} has moved; not restoring into it`);
  }
  checkFolders(base, ids);
  const owner = newFolderOwner(rec, lstatOrNull(base)!);

  const pin = pinFolder(base, opts.pinning);
  try {
    checkChain(pin.chain(), parent, ids);
    for (const [i, part] of missing.entries()) {
      opts.beforeMove?.('mkdir');
      try {
        mkdirSync(pin.at(part), { mode: 0o700 });
      } catch {
        throw new ActionError('failed', `could not recreate ${parent}`);
      }
      pin.enter(part);
      withFolderFd(pin, (fd) => {
        if (fstatBig(fd).uid !== BigInt(euid())) throw changed(parent);
        fchownIfRoot(fd, owner.uid, owner.gid);
        fchmodSync(fd, i === missing.length - 1 ? owner.mode : 0o755);
      });
    }
    if (pin.where() !== parent)
      throw new ActionError('refused', `${parent} has moved; not restoring into it`);
    checkChain(pin.chain(), parent, ids);

    // Give the item its mode and owner back while it is still in the store,
    // where nobody else can reach it, then rename it in by name.
    settle(rec.storedPath, rec);
    try {
      opts.beforeMove?.('restore');
      if (pin.where() !== parent) {
        throw new ActionError('refused', `${parent} has moved; not restoring into it`);
      }
      if (lexists(pin.at(name))) {
        throw new ActionError(
          'refused',
          `something new is already at ${rec.originalPath}; not overwriting it`,
        );
      }
      try {
        renameSync(rec.storedPath, pin.at(name));
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EXDEV' || pin.fd === undefined) {
          throw new ActionError(
            'failed',
            `could not move ${rec.originalPath} back: ${(err as Error).message}`,
          );
        }
        copyIn(pin.fd, name, rec);
      }
    } catch (err) {
      lockStored(undefined, rec.storedPath);
      throw err;
    }
  } finally {
    pin.release();
  }
  try {
    rmdirSync(dirname(rec.storedPath));
  } catch {
    // Leave a non-empty slot alone.
  }
}

/**
 * Linux, store and destination on different disks: copy into a fresh
 * root-only folder inside the pinned destination, then rename from there.
 */
function copyIn(pfd: number, name: string, rec: QuarantineRecord): void {
  const hand = mkdtempSync(fdPath(pfd, '.vigil-restore-'));
  const handName = basename(hand);
  const hfd = openSync(hand, O_FOLDER);
  const held = fdPath(hfd, name);
  try {
    if (fstatBig(hfd).uid !== BigInt(euid())) throw changed(rec.originalPath);
    try {
      moveAcrossDisks(rec.storedPath, held);
    } catch (err) {
      throw new ActionError(
        'failed',
        `could not move ${rec.originalPath} back: ${(err as Error).message}`,
      );
    }
    settle(held, rec);
    renameSync(held, fdPath(pfd, name));
  } catch (err) {
    if (lexists(held)) {
      try {
        moveAcrossDisks(held, rec.storedPath);
      } catch {
        // Stays in the root-only handoff folder.
      }
    }
    throw err;
  } finally {
    closeSync(hfd);
    try {
      rmdirSync(fdPath(pfd, handName));
    } catch {
      // Not empty: it holds the item, in a folder only root can open.
    }
  }
}
