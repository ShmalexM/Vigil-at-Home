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
import { lstatSync, readdirSync, realpathSync, type Stats } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { System } from '../system.js';
import { ActionError } from './errors.js';
import type { FsRequest } from './fsChild.js';

/**
 * Bounds on the processes a move starts, so no item (or user stopping a
 * process of theirs) can hold the helper up for good.
 *
 *   deadlineMs   a move or read still running after this is stopped: the
 *                reading side is killed, the writing side gets graceMs to
 *                remove what it made, and is then killed too.
 *   maxActive    moves at once; more are refused until one ends.
 *   maxEntries   files, folders and links in one item.
 *   maxBytes     bytes of file data in one item.
 *
 * Tests lower them.
 */
export const transferLimits = {
  deadlineMs: 120_000,
  graceMs: 5_000,
  maxActive: 4,
  maxEntries: 200_000,
  maxBytes: 8 * 1024 ** 3,
  /** Tests: each child as it starts. */
  onSpawn: undefined as ((child: ChildProcess, op: FsRequest['op']) => void) | undefined,
};

let activeTransfers = 0;

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

/** ACL permissions that let a principal add, remove, rename or rewrite entries, or change who may. */
const ACL_WRITE = new Set([
  'write',
  'append',
  'add_file',
  'add_subdirectory',
  'delete_child',
  'delete',
  'writesecurity',
  'chown',
]);

/**
 * macOS: whether `ls -led` output gives anyone but root a way to change the
 * folder. Each ACL line reads "<n>: <kind>:<name> [inherited] allow|deny
 * <perm>,<perm>...". Deny entries take nothing away from this answer, and an
 * entry line in any other shape counts as letting others write.
 */
export function macAclLetsOthersWrite(lsOutput: string): boolean {
  for (const line of lsOutput.split('\n').slice(1)) {
    const m = /^\s*\d+:\s+(.+?)\s+(?:inherited\s+)?(allow|deny)\s+(\S+)\s*$/.exec(line);
    if (!m) {
      // An ACL entry that doesn't read as expected counts as letting others write.
      if (/^\s*\d+:/.test(line)) return true;
      continue;
    }
    if (m[2] !== 'allow' || m[1] === 'user:root') continue;
    if (m[3]!.split(',').some((p) => ACL_WRITE.has(p))) return true;
  }
  return false;
}

/**
 * Whether an ACL on folder `dir` lets someone other than root change it.
 *
 *   macOS   read with `ls -ledP` (fixed argv) and parsed; an ACL that can't
 *           be read counts as letting others write.
 *   Linux   POSIX ACLs need no separate read: with an ACL, the group bits of
 *           the mode are its mask, which caps every named user and group
 *           entry (and the owning group), so a mode without group or other
 *           write (checked by the caller) means no ACL entry can write.
 */
async function aclLetsOthersWrite(sys: System, dir: string): Promise<boolean> {
  if (sys.platform === 'linux') return false;
  const r = await sys.run('ls', ['-ledP', dir]);
  if (r.code !== 0) return true;
  return macAclLetsOthersWrite(r.stdout);
}

/** Root's alone, by mode: root-owned; writable by no one else, or (above the last) sticky. */
function rootOnlyMode(st: Stats, last: boolean): boolean {
  if (st.uid !== 0) return false;
  if ((st.mode & 0o022) === 0) return true;
  return !last && (st.mode & 0o1000) !== 0;
}

/**
 * Whether every folder from / to `dir` is root's alone: each a real folder
 * owned by root, with no ACL letting anyone else write to it. `dir` itself
 * is writable by no one else; a folder above it may be only when sticky
 * (like /tmp), where no one else can rename or remove the root-owned folder
 * below it.
 */
export async function rootOnly(sys: System, dir: string): Promise<boolean> {
  const all = folders(dir);
  for (const [i, f] of all.entries()) {
    let st;
    try {
      st = lstatSync(f);
    } catch {
      return false;
    }
    if (!st.isDirectory() || !rootOnlyMode(st, i === all.length - 1)) return false;
    if (await aclLetsOthersWrite(sys, f)) return false;
  }
  return true;
}

/**
 * The same for `dir` as written, before any link in it is followed: every
 * part that exists is root's (a link included, like /var on macOS), and
 * every folder among them is root's alone as in rootOnly. A path through a
 * user's folder or link is a user's path wherever it ends up.
 */
export async function rootOnlyAsWritten(sys: System, dir: string): Promise<boolean> {
  const existing: { path: string; st: Stats }[] = [];
  for (const f of folders(dir)) {
    try {
      existing.push({ path: f, st: lstatSync(f) });
    } catch {
      break;
    }
  }
  for (const [i, { path, st }] of existing.entries()) {
    if (st.uid !== 0) return false;
    if (st.isSymbolicLink()) continue;
    if (!st.isDirectory() || !rootOnlyMode(st, i === existing.length - 1)) return false;
    if (await aclLetsOthersWrite(sys, path)) return false;
  }
  return true;
}

/** At most this many folders are checked inside an item root would move; more is refused. */
const TREE_MAX = 2000;

/**
 * Whether every folder in the tree at `dir` (itself included, links not
 * followed) is root's alone as rootOnly asks of the last folder, so root
 * walking and emptying it can't be redirected.
 */
async function treeRootOnly(sys: System, dir: string): Promise<boolean> {
  const stack = [dir];
  let seen = 0;
  while (stack.length) {
    const d = stack.pop()!;
    if (++seen > TREE_MAX) return false;
    let st;
    try {
      st = lstatSync(d);
    } catch {
      return false;
    }
    if (!st.isDirectory()) continue;
    if (!rootOnlyMode(st, true) || (await aclLetsOthersWrite(sys, d))) return false;
    try {
      for (const name of readdirSync(d)) stack.push(join(d, name));
    } catch {
      return false;
    }
  }
  return true;
}

export async function groupOf(sys: System, uid: number): Promise<number> {
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
  // A user's folder inside root's is still the user's to change, and so is
  // a root folder with anything inside it others can change.
  if (
    !(item?.isDirectory() && item.uid !== 0) &&
    (await rootOnlyAsWritten(sys, dirname(path))) &&
    (await rootOnly(sys, parent)) &&
    (!item?.isDirectory() || (await treeRootOnly(sys, path)))
  )
    return { uid: 0, gid: 0 };
  let uid = lstatSync(parent).uid;
  if (uid === 0) {
    if (!item || item.uid === 0)
      throw new ActionError(
        'installer-owned',
        `${path} belongs to root in a folder others can change; Vigil's helper does not move it`,
      );
    uid = item.uid;
  }
  return { uid, gid: await groupOf(sys, uid) };
}

/** One small regular file, read by `actor` without following a link (fsChild read). */
export async function readAs(
  actor: Actor,
  path: string,
): Promise<{ uid: number; gid: number; mode: number; data: Buffer }> {
  const run = start({ op: 'read', path, uid: actor.uid, gid: actor.gid });
  const chunks: Buffer[] = [];
  run.child.stdout!.on('data', (c: Buffer) => chunks.push(c));
  run.child.stdin!.end();
  let late = false;
  const timer = setTimeout(() => {
    late = true;
    run.child.kill('SIGKILL');
  }, transferLimits.deadlineMs);
  const r = await run.done.finally(() => clearTimeout(timer));
  if (late) throw new ActionError('failed', `reading ${path} took too long and was stopped`);
  if (r.code !== 0) {
    if (/ENOENT/.test(r.message)) throw new ActionError('not_found', `${path} does not exist`);
    throw new ActionError('refused', `could not read ${path}: ${r.message}`);
  }
  const buf = Buffer.concat(chunks);
  const nl = buf.indexOf(10);
  const head = JSON.parse(buf.subarray(0, nl).toString('utf8')) as {
    uid: number;
    gid: number;
    mode: number;
    size: number;
  };
  const data = buf.subarray(nl + 1);
  if (data.length !== head.size) throw new ActionError('failed', `could not read ${path}`);
  return { uid: head.uid, gid: head.gid, mode: head.mode, data };
}

interface Run {
  child: ChildProcess;
  done: Promise<{ code: number | null; message: string }>;
}

function start(req: FsRequest): Run {
  const [bin, args] = childCommand();
  const child = spawn(bin, args, { stdio: ['pipe', 'pipe', 'pipe'], env: {}, cwd: '/' });
  transferLimits.onSpawn?.(child, req.op);
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
  if (activeTransfers >= transferLimits.maxActive)
    throw new ActionError('refused', 'Vigil is already moving other items; try again in a moment');
  activeTransfers++;
  try {
    await transferOnce(from, to, opts);
  } finally {
    activeTransfers--;
  }
}

async function transferOnce(
  from: { path: string; actor: Actor; ownTree?: boolean },
  to: { path: string; actor: Actor },
  opts: TransferOptions,
): Promise<void> {
  const caps = { maxEntries: transferLimits.maxEntries, maxBytes: transferLimits.maxBytes };
  const packer = start({
    op: 'pack',
    path: from.path,
    uid: from.actor.uid,
    gid: from.actor.gid,
    ...caps,
    ...(from.ownTree ? { ownTree: true } : {}),
  });
  const placer = start({
    op: 'place',
    path: to.path,
    ...to.actor,
    ...caps,
    ...(opts.parents ? { parents: true } : {}),
    ...(opts.topMode !== undefined ? { topMode: opts.topMode } : {}),
    ...(opts.owners ? { owners: true } : {}),
  });
  // Past the deadline the reader is killed; the writer, its input gone,
  // removes what it made, and is killed too if it hasn't ended by then.
  let late = false;
  let grace: NodeJS.Timeout | undefined;
  const timer = setTimeout(() => {
    late = true;
    packer.child.kill('SIGKILL');
    grace = setTimeout(() => placer.child.kill('SIGKILL'), transferLimits.graceMs);
  }, transferLimits.deadlineMs);
  const tooLong = () =>
    new ActionError('failed', `moving ${from.path} took too long and was stopped`);
  try {
    packer.child.stdout!.pipe(placer.child.stdin!);
    const placed = await placer.done;
    if (placed.code !== 0) {
      packer.child.stdin!.end('keep\n');
      const packed = await packer.done;
      if (late) throw tooLong();
      // The reader's reason comes first: a placer that saw the archive end early only echoes it.
      const why = packed.code !== 0 && packed.message ? packed.message : placed.message;
      throw new ActionError('failed', `could not move ${from.path}: ${why}`);
    }
    packer.child.stdin!.end(opts.removeSource ? 'remove\n' : 'keep\n');
    const packed = await packer.done;
    if (packed.code !== 0) {
      const why = late ? 'it took too long and was stopped' : packed.message;
      throw Object.assign(
        new ActionError('failed', `copied ${from.path} but could not remove it: ${why}`),
        { copied: true },
      );
    }
  } finally {
    clearTimeout(timer);
    clearTimeout(grace);
  }
}
