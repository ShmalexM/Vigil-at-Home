// Moving items between a user's folders and the helper's own, without root
// ever touching a path a user can change.
//
// Each side of a move is done by fsChild.ts in its own process, as the
// user who controls that side (actorFor): the side being read packs the
// item into an archive, the side being written places it, and the
// original is removed only once the copy is complete. Root acts directly
// only inside folders that are root's alone, such as the quarantine store.
// A path that turns out to point somewhere else is then followed with the
// user's rights, never root's. There is no rename and no copy-then-delete
// fallback across disks: the archive is the same either way.

import { spawn, type ChildProcess } from 'node:child_process';
import { lstatSync, realpathSync, type Stats } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { System } from '../system.js';
import { ActionError } from './errors.js';
import type { FsRequest } from './fsChild.js';

/** Who a side of a move runs as. */
export interface Actor {
  uid: number;
  gid: number;
}

/** The helper itself (root in production). */
export const self = (): Actor => ({ uid: process.getuid?.() ?? 0, gid: process.getgid?.() ?? 0 });

/**
 * The program and arguments that run fsChild: the bundled helper with
 * `fs-child`, or, running from source (tests), fsChild.ts itself. Never
 * anything a request names.
 */
export function childCommand(): [string, string[]] {
  const here = fileURLToPath(import.meta.url);
  const script = here.endsWith('.ts') ? join(dirname(here), 'fsChild.ts') : here;
  return [process.execPath, [script, 'fs-child']];
}

/** Every folder from / down to `dir`, which must be absolute and real. */
function folders(dir: string): string[] {
  const out = ['/'];
  let p = '';
  for (const c of dir.split('/').filter(Boolean)) out.push((p += '/' + c));
  return out;
}

/** The nearest folder at or above `path` that exists, with symlinks resolved. */
function realExisting(path: string): string {
  for (let p = path; ; p = dirname(p)) {
    try {
      return realpathSync(p);
    } catch {
      if (dirname(p) === p) throw new ActionError('not_found', `${path} is not reachable`);
    }
  }
}

/**
 * Whether every folder from / to `dir` is root's alone: each a real folder
 * owned by root. `dir` itself is writable by no one else; a folder above it
 * may be only when sticky (like /tmp), where no one else can rename or
 * remove the root-owned folder below it.
 */
export function rootOnly(dir: string): boolean {
  const all = folders(dir);
  return all.every((f, i) => {
    try {
      const st = lstatSync(f);
      if (!st.isDirectory() || st.uid !== 0) return false;
      if ((st.mode & 0o022) === 0) return true;
      return i < all.length - 1 && (st.mode & 0o1000) !== 0;
    } catch {
      return false;
    }
  });
}

/**
 * The same for `dir` as written, before any link in it is followed: every
 * part that exists is root's (a link included, like /var on macOS), and
 * every folder among them is root's alone as in rootOnly. A path through a
 * user's folder or link is a user's path wherever it ends up.
 */
export function rootOnlyAsWritten(dir: string): boolean {
  const all = folders(dir);
  const existing: { st: Stats }[] = [];
  for (const f of all) {
    try {
      existing.push({ st: lstatSync(f) });
    } catch {
      break;
    }
  }
  return existing.every(({ st }, i) => {
    if (st.uid !== 0) return false;
    if (st.isSymbolicLink()) return true;
    if (!st.isDirectory()) return false;
    if ((st.mode & 0o022) === 0) return true;
    return i < existing.length - 1 && (st.mode & 0o1000) !== 0;
  });
}

async function groupOf(sys: System, uid: number): Promise<number> {
  if (uid === process.getuid?.()) return process.getgid?.() ?? 0;
  const r = await sys.run('id', ['-g', String(uid)]);
  const gid = Number(r.stdout.trim());
  if (r.code !== 0 || !/^\d+$/.test(r.stdout.trim()) || !Number.isInteger(gid))
    throw new ActionError('failed', `could not look up user ${uid}`);
  return gid;
}

/**
 * Who acts on `path` (an item, or where one will be created).
 *
 *   root      when every folder above it is root's alone (lstat on each
 *             component of the path as written and of its real parent):
 *             no one else can change them. Not for a folder of a user's in
 *             such a place.
 *   a user    otherwise: the owner of its parent folder, or, when root owns
 *             that folder but others may write to it (/Applications, /tmp),
 *             the item's own owner.
 *
 * A path that names neither (a root-owned item in a folder others can
 * write to) is refused: only root could move it, and root does not act
 * through such a path.
 */
export async function actorFor(sys: System, path: string): Promise<Actor> {
  const parent = realExisting(dirname(path));
  let item;
  try {
    item = lstatSync(path);
  } catch {
    item = undefined;
  }
  // A user's folder inside root's is still the user's to change.
  if (
    rootOnlyAsWritten(dirname(path)) &&
    rootOnly(parent) &&
    !(item?.isDirectory() && item.uid !== 0)
  )
    return { uid: 0, gid: 0 };
  let uid = lstatSync(parent).uid;
  if (uid === 0) {
    if (!item || item.uid === 0)
      throw new ActionError(
        'refused',
        `${path} belongs to root in a folder others can change; Vigil's helper does not move it`,
      );
    uid = item.uid;
  }
  return { uid, gid: await groupOf(sys, uid) };
}

interface Run {
  child: ChildProcess;
  done: Promise<{ code: number | null; message: string }>;
}

function start(req: FsRequest): Run {
  const [bin, args] = childCommand();
  const child = spawn(bin, args, { stdio: ['pipe', 'pipe', 'pipe'], env: {}, cwd: '/' });
  let err = '';
  child.stderr!.setEncoding('utf8');
  child.stderr!.on('data', (d: string) => {
    if (err.length < 64 * 1024) err += d;
  });
  // A child that dies early closes its stdin; that shows in its exit, not here.
  child.stdin!.on('error', () => undefined);
  child.stdout!.on('error', () => undefined);
  const done = new Promise<{ code: number | null; message: string }>((resolve) => {
    child.on('error', (e) => resolve({ code: null, message: e.message }));
    child.on('close', (code) => {
      const line = err
        .split('\n')
        .reverse()
        .find((l) => l.startsWith('vigil-fs: '));
      resolve({ code, message: line ? line.slice('vigil-fs: '.length) : err.trim() });
    });
  });
  child.stdin!.write(JSON.stringify(req) + '\n');
  return { child, done };
}

export interface TransferOptions {
  /** place: make missing parent folders. */
  parents?: boolean;
  /** place: the top entry's mode. */
  topMode?: number;
  /** place, as root: keep the archived owners. */
  owners?: boolean;
  /** Remove the original once the copy is complete (else the caller removes it). */
  removeSource?: boolean;
}

/**
 * Copy the item at `from.path` to `to.path` (which must not exist), each side
 * as its actor, then remove the original when asked. On failure nothing is
 * left at `to.path` that this transfer made, and the original is untouched.
 */
export async function transfer(
  from: { path: string; actor: Actor; ownTree?: boolean },
  to: { path: string; actor: Actor },
  opts: TransferOptions = {},
): Promise<void> {
  const packer = start({
    op: 'pack',
    path: from.path,
    uid: from.actor.uid,
    gid: from.actor.gid,
    ...(from.ownTree ? { ownTree: true } : {}),
  });
  const placer = start({
    op: 'place',
    path: to.path,
    ...to.actor,
    ...(opts.parents ? { parents: true } : {}),
    ...(opts.topMode !== undefined ? { topMode: opts.topMode } : {}),
    ...(opts.owners ? { owners: true } : {}),
  });
  packer.child.stdout!.pipe(placer.child.stdin!);
  const placed = await placer.done;
  if (placed.code !== 0) {
    packer.child.stdin!.end('keep\n');
    const packed = await packer.done;
    // The reader's reason comes first: a placer that saw the archive end early only echoes it.
    const why = packed.code !== 0 && packed.message ? packed.message : placed.message;
    throw new ActionError('failed', `could not move ${from.path}: ${why}`);
  }
  packer.child.stdin!.end(opts.removeSource ? 'remove\n' : 'keep\n');
  const packed = await packer.done;
  if (packed.code !== 0) {
    throw Object.assign(
      new ActionError('failed', `copied ${from.path} but could not remove it: ${packed.message}`),
      { copied: true },
    );
  }
}
