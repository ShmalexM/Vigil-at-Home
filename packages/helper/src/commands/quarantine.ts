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
//
// Every move is either one that cannot land on something else (a file is
// linked into place, which fails if the name is taken, then unlinked), or is
// checked afterwards and undone when what arrived is not what was checked.
// When an undo itself fails, the error says where the item is now
// (StrandedError), so the executor can record it and the user can get it
// back.

import {
  chmodSync,
  closeSync,
  cpSync,
  fchmodSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readlinkSync,
  realpathSync,
  renameSync,
  rmdirSync,
  rmSync,
  symlinkSync,
  unlinkSync,
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
  idKey,
  sameId,
  type ProtectedIds,
} from './protectedSet.js';
import {
  euid,
  fchownIfRoot,
  fdPath,
  fstatBig,
  lchownIfRoot,
  lexists,
  lstatOrNull,
  O_CHECK,
  O_FOLDER,
  pinFolder,
  withFolderFd,
  type Pin,
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
  /** Test hook, called after the checks and right before each move or folder creation. */
  beforeMove?: (step: 'quarantine' | 'mkdir' | 'restore') => void;
  /** Test hook, called right after a move, before it is checked. */
  afterMove?: (step: 'quarantine' | 'restore') => void;
  /** Test hook, called between making a missing folder and opening it. */
  afterMkdir?: (name: string) => void;
}

/**
 * A move went wrong and could not be undone. `recovery` says where the item
 * is now and where it came from; `inStore` is true when it is in a folder
 * only root can reach, from which a normal restore can put it back.
 */
export class StrandedError extends ActionError {
  constructor(
    message: string,
    readonly recovery: QuarantineRecord,
    readonly inStore: boolean,
  ) {
    super('failed', message);
  }
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

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function eexist(err: unknown): boolean {
  return (err as NodeJS.ErrnoException).code === 'EEXIST';
}

/**
 * Move `from` to `to` without ever replacing something already at `to`.
 * A file is hard-linked to the new name, which fails if the name is taken,
 * then its old name removed. A link is made again at the new name the same
 * way. A folder is renamed, which can at worst replace an empty folder; the
 * caller checks what arrived. `from` is always somewhere only this process
 * can change (the store, a handoff folder, or a pinned item it just moved).
 * Returns what is at `to` afterwards.
 */
export function moveNoReplace(from: string, to: string, st: BigIntStats): BigIntStats {
  if (st.isFile() || st.isSymbolicLink()) {
    if (st.isFile()) linkSync(from, to);
    else symlinkSync(readlinkSync(from), to);
    try {
      const now = lstatOrNull(to);
      if (!now || (st.isFile() && !sameId(now, st))) {
        throw new ActionError('refused', 'the item changed while it was being moved');
      }
      if (st.isSymbolicLink()) lchownIfRoot(to, Number(st.uid), Number(st.gid));
      unlinkSync(from);
      return now;
    } catch (err) {
      removeQuietly(to);
      throw err;
    }
  }
  if (lexists(to)) {
    const err = new Error(`${to} already exists`) as NodeJS.ErrnoException;
    err.code = 'EEXIST';
    throw err;
  }
  renameSync(from, to);
  const now = lstatOrNull(to);
  if (!now) throw new ActionError('failed', 'the folder vanished as it was moved');
  return now;
}

function removeQuietly(path: string): void {
  try {
    unlinkSync(path);
  } catch {
    // Already gone.
  }
}

/** The record for an item at `storedPath`, as it is now. */
function recordFor(
  originalPath: string,
  storedPath: string,
  st: BigIntStats,
  parent: BigIntStats | undefined,
): QuarantineRecord {
  const rec: QuarantineRecord = {
    originalPath,
    storedPath,
    mode: Number(st.mode & 0o7777n),
    uid: Number(st.uid),
    gid: Number(st.gid),
    isDirectory: st.isDirectory(),
  };
  if (parent) {
    rec.parent = {
      uid: Number(parent.uid),
      gid: Number(parent.gid),
      mode: Number(parent.mode & 0o7777n),
    };
  }
  return rec;
}

/**
 * A move into quarantine failed a check after the item had moved: put back
 * whatever arrived, without replacing anything that has since appeared at
 * the original name. When that fails, say exactly where the item is.
 */
function undoMoveIn(
  err: unknown,
  at: string,
  back: string,
  where: { originalPath: string; storedPath: string; inStore: boolean; parent?: BigIntStats },
): never {
  const now = lstatOrNull(at);
  if (!now) throw err;
  try {
    moveNoReplace(at, back, now);
  } catch (undoErr) {
    const why = eexist(undoErr) ? 'something new is at its old place' : errorText(undoErr);
    throw new StrandedError(
      `${errorText(err)}; it could not be put back (${why}) and is now at ${where.storedPath}`,
      recordFor(where.originalPath, where.storedPath, now, where.parent),
      where.inStore,
    );
  }
  throw err;
}

/**
 * The checks after a move into quarantine: what arrived is the item that
 * was checked, and nobody gave it another name meanwhile (a hard link
 * added after the first check would be locked too).
 */
function checkArrived(at: string, st: BigIntStats, fd: number | undefined, shown: string): void {
  const now = lstatOrNull(at);
  if (!now || !sameId(now, st)) {
    throw new ActionError(
      'refused',
      `${shown} changed while it was being moved; nothing was quarantined`,
    );
  }
  const links =
    fd !== undefined && st.isFile() ? fstatBig(fd).nlink : now.isFile() ? now.nlink : 1n;
  if (links > 1n) {
    throw new ActionError(
      'refused',
      `${shown} was given another hard link while it was being moved; nothing was quarantined`,
    );
  }
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
  return recordFor(path, storedPath, moved.st, moved.parent);
}

/**
 * Pin the item's folder, check it and the item through the pin, hold the
 * item open, move it into the store, check what arrived and lock it through
 * the handle. Anything wrong after the move puts the item back.
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
      try {
        renameSync(src, storedPath);
      } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== 'EXDEV' || pin.fd === undefined) {
          throw moveError(path, err);
        }
        copyOut(pin.fd, name, storedPath, (at) => checkArrived(at, st, fd, path), {
          originalPath: path,
          parent: chain[0]!,
        });
        try {
          lockStored(undefined, storedPath);
        } catch (lockErr) {
          const now = lstatOrNull(storedPath)!;
          throw new StrandedError(
            `${path} was moved into quarantine but could not be locked: ${errorText(lockErr)}`,
            recordFor(path, storedPath, now, chain[0]!),
            true,
          );
        }
        return { st, parent: chain[0]! };
      }
      try {
        opts.afterMove?.('quarantine');
        checkArrived(storedPath, st, fd, path);
        lockStored(fd, storedPath);
      } catch (err) {
        undoMoveIn(err, storedPath, src, {
          originalPath: path,
          storedPath,
          inStore: true,
          parent: chain[0]!,
        });
      }
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
  check: (at: string) => void,
  item: { originalPath: string; parent: BigIntStats },
): void {
  const hold = mkdtempSync(fdPath(pfd, '.vigil-quarantine-'));
  const holdName = basename(hold);
  const hfd = openSync(hold, O_FOLDER);
  // Where the held item is, for the error if it cannot be put back.
  const heldShown = join(dirname(item.originalPath), holdName, name);
  try {
    if (fstatBig(hfd).uid !== BigInt(euid())) throw changed(item.originalPath);
    const src = fdPath(pfd, name);
    const held = fdPath(hfd, name);
    renameSync(src, held);
    const where = { ...item, storedPath: heldShown, inStore: false };
    try {
      check(held);
    } catch (err) {
      undoMoveIn(err, held, src, where);
    }
    try {
      moveAcrossDisks(held, storedPath);
    } catch (err) {
      undoMoveIn(moveError(item.originalPath, err), held, src, where);
    }
  } finally {
    closeSync(hfd);
    try {
      rmdirSync(fdPath(pfd, holdName));
    } catch {
      // Not empty (it holds an item that could not be put back), or already gone.
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
 * Make one missing folder inside the pin and enter it. Its owner and mode are
 * changed only when it is provably the folder just made: opened without
 * following a link, never seen before, owned by this process with no more
 * than the mode it was made with, and the very folder the pin then enters.
 * Otherwise the restore stops, and a folder that is ours is left root-owned
 * with mode 0755.
 */
function makeFolder(
  pin: Pin,
  part: string,
  mode: number,
  owner: FolderOwner,
  seen: Set<string>,
  shown: string,
  opts: QuarantineOptions,
): void {
  try {
    mkdirSync(pin.at(part), { mode: 0o700 });
  } catch {
    throw new ActionError('failed', `could not recreate ${shown}`);
  }
  opts.afterMkdir?.(part);
  let fd: number;
  try {
    fd = openSync(pin.at(part), O_FOLDER);
  } catch {
    throw changed(shown);
  }
  try {
    const made = fstatBig(fd);
    const ours =
      made.isDirectory() &&
      !seen.has(idKey(made)) &&
      made.uid === BigInt(euid()) &&
      (made.mode & 0o7077n) === 0n;
    let entered = false;
    if (ours) {
      seen.add(idKey(made));
      pin.enter(part);
      entered = withFolderFd(pin, (pfd) => sameId(fstatBig(pfd), made));
    }
    if (!ours || !entered) {
      if (ours) fchmodSync(fd, 0o755);
      throw changed(shown);
    }
    fchownIfRoot(fd, owner.uid, owner.gid);
    fchmodSync(fd, mode);
  } finally {
    closeSync(fd);
  }
}

/**
 * Restore moves the file back as root, so the folder it goes into must be
 * the folder it came from at the moment of the move, not just at the check.
 * The folder (or the nearest one that still exists) is pinned, missing
 * folders are made inside the pin one by one, and the item is moved into
 * the pinned folder by name, never over something already there. Then the
 * folder's place and what arrived are checked again; when either is wrong
 * the item goes back into the store.
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
  const notThere = () => new ActionError('refused', `${parent} has moved; not restoring into it`);

  const pin = pinFolder(base, opts.pinning);
  try {
    try {
      const chain = pin.chain();
      checkChain(chain, parent, ids);
      const seen = new Set(chain.map(idKey));
      for (const [i, part] of missing.entries()) {
        opts.beforeMove?.('mkdir');
        const mode = i === missing.length - 1 ? owner.mode : 0o755;
        makeFolder(pin, part, mode, owner, seen, parent, opts);
      }
    } catch (err) {
      lockStored(undefined, rec.storedPath);
      throw err;
    }
    const placed = moveOut(pin, name, rec, opts, ids, notThere);
    const there = (): boolean => {
      if (pin.where() !== parent) return false;
      try {
        checkChain(pin.chain(), parent, ids);
      } catch {
        return false;
      }
      const now = lstatOrNull(pin.at(name));
      return now !== null && sameId(now, placed);
    };
    opts.afterMove?.('restore');
    if (!there()) takeBack(pin, name, placed, rec, parent);
  } finally {
    pin.release();
  }
  try {
    rmdirSync(dirname(rec.storedPath));
  } catch {
    // Leave a non-empty slot alone.
  }
}

/** Move the stored item into the pinned folder by name. Returns what arrived. */
function moveOut(
  pin: Pin,
  name: string,
  rec: QuarantineRecord,
  opts: QuarantineOptions,
  ids: ProtectedIds,
  notThere: () => ActionError,
): BigIntStats {
  const parent = dirname(rec.originalPath);
  try {
    if (pin.where() !== parent) throw notThere();
    checkChain(pin.chain(), parent, ids);
    // Give the item its mode and owner back while it is still in the store,
    // where nobody else can reach it, then move it in by name.
    settle(rec.storedPath, rec);
    opts.beforeMove?.('restore');
    if (pin.where() !== parent) throw notThere();
    const stored = lstatOrNull(rec.storedPath);
    if (!stored) throw new ActionError('not_found', 'the quarantined copy is gone');
    try {
      return moveNoReplace(rec.storedPath, pin.at(name), stored);
    } catch (err) {
      if (eexist(err)) {
        throw new ActionError(
          'refused',
          `something new is already at ${rec.originalPath}; not overwriting it`,
        );
      }
      if ((err as NodeJS.ErrnoException).code !== 'EXDEV' || pin.fd === undefined) {
        throw new ActionError(
          'failed',
          `could not move ${rec.originalPath} back: ${errorText(err)}`,
        );
      }
      return copyIn(pin.fd, name, rec);
    }
  } catch (err) {
    lockStored(undefined, rec.storedPath);
    throw err;
  }
}

/**
 * The folder moved, or something else is at the name, just after the item
 * arrived: take the item back into the store through the pin and lock it.
 * When it cannot be taken back, say where it is.
 */
function takeBack(
  pin: Pin,
  name: string,
  placed: BigIntStats,
  rec: QuarantineRecord,
  parent: string,
): never {
  const at = pin.at(name);
  const now = lstatOrNull(at);
  const where = join(pin.where() ?? parent, name);
  const problem = `${parent} changed while ${rec.originalPath} was being restored`;
  if (!now || !sameId(now, placed)) {
    throw new StrandedError(
      `${problem}, and the restored item was moved away from ${where}`,
      { ...rec, storedPath: where },
      false,
    );
  }
  try {
    moveNoReplace(at, rec.storedPath, now);
    lockStored(undefined, rec.storedPath);
  } catch (err) {
    throw new StrandedError(
      `${problem}; it could not be taken back into quarantine (${errorText(err)}) and is at ${where}`,
      { ...rec, storedPath: where },
      false,
    );
  }
  throw new ActionError('refused', `${problem}; it is back in quarantine`);
}

/**
 * Linux, store and destination on different disks: copy into a fresh
 * root-only folder inside the pinned destination, then move it in by name,
 * never over something already there. Returns what arrived.
 */
function copyIn(pfd: number, name: string, rec: QuarantineRecord): BigIntStats {
  const hand = mkdtempSync(fdPath(pfd, '.vigil-restore-'));
  const handName = basename(hand);
  const hfd = openSync(hand, O_FOLDER);
  const held = fdPath(hfd, name);
  try {
    if (fstatBig(hfd).uid !== BigInt(euid())) throw changed(rec.originalPath);
    try {
      moveAcrossDisks(rec.storedPath, held);
    } catch (err) {
      throw new ActionError('failed', `could not move ${rec.originalPath} back: ${errorText(err)}`);
    }
    settle(held, rec);
    const st = lstatOrNull(held);
    if (!st) throw changed(rec.originalPath);
    try {
      return moveNoReplace(held, fdPath(pfd, name), st);
    } catch (err) {
      if (eexist(err)) {
        throw new ActionError(
          'refused',
          `something new is already at ${rec.originalPath}; not overwriting it`,
        );
      }
      throw err;
    }
  } catch (err) {
    if (lexists(held)) {
      try {
        moveAcrossDisks(held, rec.storedPath);
      } catch (backErr) {
        throw new StrandedError(
          `${errorText(err)}; it could not be put back into quarantine (${errorText(backErr)}) and is at ${join(dirname(rec.originalPath), handName, name)}`,
          { ...rec, storedPath: join(dirname(rec.originalPath), handName, name) },
          false,
        );
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
