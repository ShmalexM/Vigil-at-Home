// Decides whether a path is one the helper must never move, by what it is on
// disk rather than how it is spelled. macOS disks fold names (case, Unicode
// forms and lookalikes) differently from JavaScript, so two spellings can name
// the same file. Every protected path that exists is stat'ed and its
// (device, inode) pair collected; a target is then refused when it, or any
// folder above it, is one of them.
//
// Vigil's and the sensors' folders may hold links to files kept elsewhere
// (a vendor's bin folder linked in, say). Those links are followed, a few
// levels deep, and what they point at is protected as well.

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
}

export interface ProtectedPaths {
  /** Protected along with everything inside them. */
  inside: string[];
  /** Never moved as a whole, though what is inside may be (system and home folders). */
  whole: string[];
  /** Folders among `inside` whose links are followed, so what they point at is protected too. */
  linked?: string[];
}

export interface ProtectedIds {
  /** (dev, ino) of protected things; refused along with everything inside them. */
  inside: Map<string, string>;
  /** (dev, ino) of folders refused as a whole: system and home folders, and every folder holding a protected path. */
  whole: Map<string, string>;
  /** Where the links inside protected folders point, protected along with them. */
  linkTargets: string[];
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
  ];
  const whole = [...(opts.protectedExact ?? protection.exact), ...homeFolders(opts.platform)];
  return {
    inside: inside.map(strip),
    whole: whole.map(strip),
    linked: ownFolders(opts).map(strip),
  };
}

/** Vigil's and the sensors' own files and folders. */
function ownFolders(opts: ProtectionInput): string[] {
  return [...protectionFor(opts.platform).services, ...(opts.selfPaths ?? [])];
}

/** Only Vigil's and the sensors' own files: what a startup item must not run. */
export function servicePaths(opts: ProtectionInput): ProtectedPaths {
  const own = ownFolders(opts).map(strip);
  return { inside: own, whole: [], linked: own };
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

/** How far links inside a protected folder are looked for. */
export const LINK_WALK = { depth: 4, entries: 2000 };

/**
 * Where the links inside `dir` point, looking at most LINK_WALK.depth folders
 * down and at LINK_WALK.entries entries. Links are not followed during the
 * walk itself, so the walk stays inside `dir`.
 */
export function linkTargetsIn(dir: string): string[] {
  const top = lstatOrNull(dir);
  if (!top?.isDirectory()) return [];
  const out: string[] = [];
  let seen = 0;
  let level = [dir];
  for (let depth = 0; depth <= LINK_WALK.depth && level.length; depth++) {
    const next: string[] = [];
    for (const folder of level) {
      for (const name of readdirOrEmpty(folder)) {
        if (++seen > LINK_WALK.entries) return out;
        const path = join(folder, name);
        const st = lstatOrNull(path);
        if (st?.isDirectory()) next.push(path);
        else if (st?.isSymbolicLink()) {
          try {
            out.push(realpathSync(path));
          } catch {
            // Dangling: the link itself is inside the protected folder.
          }
        }
      }
    }
    level = next;
  }
  return out;
}

/** Stat every protected path that exists, and the folders that hold them. */
export function protectedIds(paths: ProtectedPaths): ProtectedIds {
  const inside = new Map<string, string>();
  const whole = new Map<string, string>();
  const linkTargets: string[] = [];
  const wholeSet = new Set(paths.whole);
  for (const dir of paths.linked ?? []) {
    let real: string;
    try {
      real = realpathSync(dir);
    } catch {
      continue;
    }
    for (const target of linkTargetsIn(real)) {
      if (target === real || target.startsWith(real + '/')) continue;
      // A link to / or to a system or home folder never makes that whole
      // folder protected; it stays unmovable as a whole, as it already is.
      if (target === '/' || wholeSet.has(target)) {
        const st = lstatOrNull(target);
        if (st) whole.set(idKey(st), dir);
        continue;
      }
      linkTargets.push(target);
    }
  }
  for (const p of [...paths.inside, ...linkTargets]) {
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
  return { inside, whole, linkTargets };
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
export function runsProtectedProgram(
  program: string,
  opts: ProtectionInput,
  ids: ProtectedIds = protectedIds(servicePaths(opts)),
): boolean {
  const fold = (s: string) => (opts.platform === 'linux' ? s : s.toLowerCase());
  if (!isAbsolute(program)) return PROTECTED_PROGRAM_NAMES.includes(fold(basename(program)));
  const paths = servicePaths(opts);
  const roots = [...paths.inside, ...ids.linkTargets];
  const named = (p: string) =>
    roots.some((q) => fold(p) === fold(q) || fold(p).startsWith(fold(q) + '/'));
  if (named(program)) return true;
  let real: string;
  try {
    real = realpathSync(program);
  } catch {
    return false;
  }
  if (named(real)) return true;
  const st = lstatOrNull(real);
  if (st && ids.inside.has(idKey(st))) return true;
  for (let a = dirname(real); ; a = dirname(a)) {
    const s = statOrNull(a);
    if (s && ids.inside.has(idKey(s))) return true;
    if (a === '/') return false;
  }
}

const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash']);
const WRAPPERS = new Set(['env', 'exec', 'nice', 'nohup']);

/**
 * Split a command line into words the way a shell roughly would: spaces
 * separate words, quotes group them, and ; & | ( ) end a command.
 */
export function splitCommand(cmd: string): string[] {
  const out: string[] = [];
  let word = '';
  let has = false;
  let quote: string | null = null;
  const end = () => {
    if (has) out.push(word);
    word = '';
    has = false;
  };
  for (let i = 0; i < cmd.length; i++) {
    const c = cmd[i]!;
    if (quote) {
      if (c === quote) quote = null;
      else if (c === '\\' && quote === '"' && i + 1 < cmd.length) word += cmd[++i];
      else word += c;
    } else if (c === "'" || c === '"') {
      quote = c;
      has = true;
    } else if (c === '\\' && i + 1 < cmd.length) {
      word += cmd[++i];
      has = true;
    } else if (/\s/.test(c) || ';&|()'.includes(c)) {
      end();
    } else {
      word += c;
      has = true;
    }
  }
  end();
  return out;
}

/**
 * The programs an argument list may start: the program itself and, one
 * level down, the words of a shell's -c string or what a wrapper such as
 * env or nohup runs next.
 */
export function launchedPrograms(argv: string[]): string[] {
  const [program, ...rest] = argv;
  if (!program) return [];
  const out = [program];
  const name = basename(program);
  if (SHELLS.has(name)) {
    const flag = rest.findIndex((a) => /^-[A-Za-z]*c[A-Za-z]*$/.test(a));
    const script = flag >= 0 ? rest[flag + 1] : undefined;
    if (script !== undefined) out.push(...splitCommand(script));
  } else if (WRAPPERS.has(name)) {
    let i = 0;
    while (
      i < rest.length &&
      (rest[i]!.startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(rest[i]!))
    ) {
      // Options that take a value as the next word.
      if (/^-(n|u|S|C|-adjustment|-unset|-chdir|-split-string)$/.test(rest[i]!)) i++;
      i++;
    }
    if (rest[i] !== undefined) out.push(rest[i]!);
  }
  return out;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/**
 * Whether a command line names Vigil or a sensor anywhere: one of their
 * paths, or a protected program name as a whole word.
 */
export function mentionsProtected(line: string, opts: ProtectionInput): boolean {
  const flags = opts.platform === 'linux' ? '' : 'i';
  const roots = servicePaths(opts).inside.filter(isAbsolute);
  for (const root of roots) {
    if (new RegExp(`${escapeRe(root)}(?=$|[/\\s'";&|)])`, flags).test(line)) return true;
  }
  return PROTECTED_PROGRAM_NAMES.some((n) =>
    new RegExp(`(?<![\\w.-])${escapeRe(n)}(?![\\w.-])`, flags).test(line),
  );
}

/** The program or word that makes an argument list start Vigil or a sensor, if any. */
export function commandRunsProtected(argv: string[], opts: ProtectionInput): string | undefined {
  const ids = protectedIds(servicePaths(opts));
  for (const word of launchedPrograms(argv)) {
    if (runsProtectedProgram(word, opts, ids)) return word;
  }
  const line = argv.join(' ');
  return mentionsProtected(line, opts) ? line : undefined;
}
