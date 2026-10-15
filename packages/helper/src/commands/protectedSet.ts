// Decides whether a path is one the helper must never move, by what it is on
// disk rather than how it is spelled. macOS disks fold names (case, Unicode
// forms and lookalikes) differently from JavaScript, so two spellings can name
// the same file. Every protected path that exists is stat'ed and its
// (device, inode) pair collected; a target is then refused when it, or any
// folder above it, is one of them.

import {
  lstatSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
  type BigIntStats,
} from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { protectionFor } from '../config.js';
import type { Platform } from '../platform.js';
import { ActionError } from './errors.js';

export interface ProtectionInput {
  quarantineDir?: string;
  protectedPrefixes?: string[];
  protectedExact?: Set<string>;
  platform?: Platform;
  /** Vigil's own files on this machine (its runtime, socket, data), protected like the built-in lists. */
  selfPaths?: string[];
  /** The helper's state folder as configured (QuarantineOptions stateDir). */
  stateDir?: string;
  /** Vigil's own files known only by identity (`<device>:<inode>`), like an approved AppImage. */
  selfIds?: readonly string[];
}

export interface ProtectedPaths {
  /** Protected along with everything inside them. */
  inside: string[];
  /** Never moved as a whole, though what is inside may be (system and home folders). */
  whole: string[];
}

export interface ProtectedIds {
  /** (dev, ino) of protected things; refused along with everything inside them. */
  inside: Map<string, string>;
  /** (dev, ino) of folders refused as a whole: system and home folders, and every folder holding a protected path. */
  whole: Map<string, string>;
}

type Ids = Pick<BigIntStats, 'dev' | 'ino'>;

export const idKey = (s: Ids): string => `${s.dev}:${s.ino}`;
export const sameId = (a: Ids, b: Ids): boolean => a.dev === b.dev && a.ino === b.ino;

function lstatOrNull(path: string): BigIntStats | null {
  try {
    return lstatSync(path, { bigint: true });
  } catch {
    return null;
  }
}

function statOrNull(path: string): BigIntStats | null {
  try {
    return statSync(path, { bigint: true });
  } catch {
    return null;
  }
}

function readdirOrEmpty(dir: string): string[] {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

/** A path without trailing slashes (`/` stays `/`). A loop, not a regex, so it stays linear. */
function strip(p: string): string {
  let end = p.length;
  while (end > 1 && p[end - 1] === '/') end--;
  return p.slice(0, end);
}

/**
 * Vigil's and the sensors' launch items or units as they are actually named
 * on disk, including aliases (links to a protected unit).
 */
function serviceItems(platform: Platform | undefined): string[] {
  const protection = protectionFor(platform);
  const found: string[] = [];
  for (const dir of protection.serviceItemDirs) {
    for (const name of readdirOrEmpty(dir)) {
      const path = join(dir, name);
      if (protection.isServiceItem(name)) {
        found.push(path);
        continue;
      }
      try {
        if (protection.isServiceItem(basename(readlinkSync(path)))) found.push(path);
      } catch {
        // Not a link.
      }
    }
  }
  return found;
}

/** Each user's home folder and its main subfolders, as named on disk. */
function homeFolders(platform: Platform | undefined): string[] {
  const protection = protectionFor(platform);
  return readdirOrEmpty(protection.homeRoot).flatMap((user) => {
    const home = join(protection.homeRoot, user);
    return [home, ...protection.homeSubfolders.map((s) => join(home, s))];
  });
}

/** The protected paths for file moves: system folders, Vigil, its sensors and the quarantine itself. */
export function protectedPaths(opts: ProtectionInput): ProtectedPaths {
  const protection = protectionFor(opts.platform);
  const inside = [
    ...(opts.protectedPrefixes ?? protection.prefixes),
    ...protection.processPrefixes,
    ...protection.services,
    ...serviceItems(opts.platform),
    ...(opts.selfPaths ?? []),
    ...(opts.quarantineDir ? [opts.quarantineDir] : []),
    // The helper's whole state folder, as configured and where it is by default.
    ...(opts.stateDir ? [opts.stateDir] : []),
    protection.stateDir,
  ];
  const whole = [...(opts.protectedExact ?? protection.exact), ...homeFolders(opts.platform)];
  return { inside: inside.map(strip), whole: whole.map(strip) };
}

/** Only Vigil's and the sensors' own files: what a startup item must not run. */
export function servicePaths(opts: ProtectionInput): ProtectedPaths {
  const protection = protectionFor(opts.platform);
  return {
    inside: [...protection.services, ...(opts.selfPaths ?? [])].map(strip),
    whole: [],
  };
}

function addAncestors(path: string, into: Map<string, string>, owner: string): void {
  for (let a = dirname(path); ; a = dirname(a)) {
    const st = lstatOrNull(a);
    if (st) into.set(idKey(st), owner);
    const real = st?.isSymbolicLink() ? statOrNull(a) : null;
    if (real) into.set(idKey(real), owner);
    if (a === '/' || a === '.') break;
  }
}

/** Stat every protected path that exists, and the folders that hold them. */
export function protectedIds(paths: ProtectedPaths): ProtectedIds {
  const inside = new Map<string, string>();
  const whole = new Map<string, string>();
  for (const p of paths.inside) {
    if (!isAbsolute(p)) continue;
    const st = lstatOrNull(p);
    if (!st) continue;
    inside.set(idKey(st), p);
    const target = st.isSymbolicLink() ? statOrNull(p) : null;
    if (target) inside.set(idKey(target), p);
    addAncestors(p, whole, p);
    let real: string | null = null;
    try {
      real = realpathSync(p);
    } catch {
      // A dangling link: the link itself is protected above.
    }
    if (real && real !== p) {
      const rs = lstatOrNull(real);
      if (rs) inside.set(idKey(rs), p);
      addAncestors(real, whole, p);
    }
  }
  for (const p of paths.whole) {
    const st = lstatOrNull(p);
    if (st) whole.set(idKey(st), p);
    const target = st?.isSymbolicLink() ? statOrNull(p) : null;
    if (target) whole.set(idKey(target), p);
  }
  // A protected thing is never movable as a whole either.
  return { inside, whole };
}

function refuse(path: string, what: string | undefined): never {
  throw new ActionError(
    'refused',
    what && what !== path ? `${path} is protected (it is ${what})` : `${path} is protected`,
  );
}

/**
 * Refuse when `folder` or any folder above it is protected. The folders are
 * stat'ed one by one, so a folder reached by another spelling is still caught.
 */
export function checkFolders(folder: string, ids: ProtectedIds): void {
  for (let a = folder; ; a = dirname(a)) {
    const st = statOrNull(a);
    if (st && ids.inside.has(idKey(st))) refuse(folder, ids.inside.get(idKey(st)));
    if (a === '/' || a === '.') break;
  }
}

/** Refuse when a pinned folder or any folder above it, as the kernel found them, is protected. */
export function checkChain(chain: Ids[], path: string, ids: ProtectedIds): void {
  for (const st of chain) {
    if (ids.inside.has(idKey(st))) refuse(path, ids.inside.get(idKey(st)));
  }
}

/** Refuse an item that is itself protected, or holds something protected. */
export function checkSelf(path: string, st: Ids, ids: ProtectedIds): void {
  const k = idKey(st);
  if (ids.inside.has(k)) refuse(path, ids.inside.get(k));
  if (ids.whole.has(k)) refuse(path, ids.whole.get(k));
}

/** Refuse a target whose own identity is protected, or that sits inside something protected. */
export function checkIdentity(path: string, st: Ids | null, ids: ProtectedIds): void {
  if (st) checkSelf(path, st, ids);
  checkFolders(dirname(path), ids);
}

/** Programs a startup item might name without a folder, leaving launchd or systemd to find them. */
const PROTECTED_PROGRAM_NAMES = ['osqueryd', 'vigil-helper', 'santad', 'fapolicyd'];

/**
 * Whether a program a startup item runs is Vigil or one of its sensors: by
 * name, then by the identity of the file it resolves to and its folders.
 */
export function runsProtectedProgram(program: string, opts: ProtectionInput): boolean {
  const fold = (s: string) => (opts.platform === 'linux' ? s : s.toLowerCase());
  if (!isAbsolute(program)) return PROTECTED_PROGRAM_NAMES.includes(fold(basename(program)));
  const paths = servicePaths(opts);
  const named = (p: string) =>
    paths.inside.some((q) => fold(p) === fold(q) || fold(p).startsWith(fold(q) + '/'));
  if (named(program)) return true;
  let real: string;
  try {
    real = realpathSync(program);
  } catch {
    return false;
  }
  if (named(real)) return true;
  const ids = protectedIds(paths);
  const st = lstatOrNull(real);
  if (st && (ids.inside.has(idKey(st)) || opts.selfIds?.includes(idKey(st)))) return true;
  for (let a = dirname(real); ; a = dirname(a)) {
    const s = statOrNull(a);
    if (s && ids.inside.has(idKey(s))) return true;
    if (a === '/') return false;
  }
}
