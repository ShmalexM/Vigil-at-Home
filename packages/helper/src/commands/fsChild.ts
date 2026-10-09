// One file operation for the helper, in its own process, as the user it names.
//
// The root helper never creates, renames, deletes or copies anything through
// a path a user can change. It starts this program instead (always the same
// program and argv, an empty environment), and sends it one request on
// stdin. Before reading anything else the program takes on the user, group
// and supplementary groups the request names, so whatever a path turns out
// to point at, it can only do what that user could do anyway. For paths
// whose every folder is root's alone, the helper names root.
//
//   pack   Write the item at `path` (a file, a symlink as itself, or a
//          folder and everything in it) to stdout as an archive, every
//          file read through one descriptor opened without following
//          links. Then wait for "remove" or "keep" on stdin: "remove"
//          deletes exactly the entries it packed, each only while it is
//          still the same device and inode.
//   place  Read an archive from stdin and create it at `path`, which must
//          not exist: files with O_EXCL|O_NOFOLLOW, folders with mkdir,
//          links with symlink, so nothing already there is ever replaced
//          or written through. Missing parent folders are made when asked.
//          If anything fails, it removes what it created, each only while
//          it is still the device and inode it created, and nothing else.
//          As root, owners are given last, deepest first, once nothing more
//          is written beneath them.
//   read   Write one small regular file's owner, mode and bytes to stdout,
//          read through one descriptor opened without following a link
//          and without blocking.
//
// Archive: frames of one JSON line, followed for a file by exactly `size`
// bytes. The last frame is {"t":"end"}. Failures exit non-zero with one
// "vigil-fs: <reason>" line on stderr.
//
// Only node: builtins are imported: tests run this file directly with node.

import {
  closeSync,
  constants,
  fchmodSync,
  fchownSync,
  fstatSync,
  futimesSync,
  lchownSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readlinkSync,
  readSync,
  rmdirSync,
  statSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeSync,
  type BigIntStats,
} from 'node:fs';
import { dirname, isAbsolute, join, normalize } from 'node:path';

export interface FsRequest {
  op: 'pack' | 'place' | 'read';
  path: string;
  /** Who to run as. */
  uid: number;
  gid: number;
  /** place: create missing parent folders. */
  parents?: boolean;
  /** place: the top entry's mode, instead of the archived one. */
  topMode?: number;
  /** place, as root: give entries their archived owner. */
  owners?: boolean;
  /** pack: the item is in the helper's own root-only folder, where no one else reaches. */
  ownTree?: boolean;
  /** pack and place: at most this many entries, and bytes of file data (never above the built-in caps). */
  maxEntries?: number;
  maxBytes?: number;
}

const MAX_ENTRIES = 200_000;
const MAX_BYTES = 8 * 1024 ** 3;

/** Counts entries and file bytes against the request's caps, refusing past either. */
class Budget {
  private entries = 0;
  private bytes = 0;
  private readonly maxEntries: number;
  private readonly maxBytes: number;
  constructor(req: FsRequest) {
    this.maxEntries = Math.min(req.maxEntries ?? MAX_ENTRIES, MAX_ENTRIES);
    this.maxBytes = Math.min(req.maxBytes ?? MAX_BYTES, MAX_BYTES);
  }
  take(bytes: number): void {
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new Refusal('the archive is not readable');
    if (++this.entries > this.maxEntries) throw new Refusal('the item has too many files');
    this.bytes += bytes;
    if (this.bytes > this.maxBytes) throw new Refusal('the item is too large');
  }
}

export type Frame =
  | { t: 'd'; rel: string; mode: number; uid: number; gid: number; mtime: string }
  | { t: 'f'; rel: string; mode: number; uid: number; gid: number; mtime: string; size: number }
  | { t: 'l'; rel: string; target: string; uid: number; gid: number }
  | { t: 'end' };

class Refusal extends Error {}

const CHUNK = 1 << 20;
const sleeper = new Int32Array(new SharedArrayBuffer(4));

/** Blocking reads and writes on the stdio pipes, which may be non-blocking. */
function readSome(fd: number, buf: Buffer, off: number, len: number): number {
  for (;;) {
    try {
      return readSync(fd, buf, off, len, null);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EAGAIN') throw err;
      Atomics.wait(sleeper, 0, 0, 2);
    }
  }
}

function writeAll(fd: number, buf: Buffer): void {
  let off = 0;
  while (off < buf.length) {
    try {
      off += writeSync(fd, buf, off, buf.length - off);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== 'EAGAIN') throw err;
      Atomics.wait(sleeper, 0, 0, 2);
    }
  }
}

/** Buffered reader over a file descriptor: lines and exact byte counts. */
export class FdReader {
  private buf = Buffer.alloc(0);
  private eof = false;
  private readonly fd: number;
  constructor(fd: number) {
    this.fd = fd;
  }

  private fill(): boolean {
    if (this.eof) return false;
    const chunk = Buffer.alloc(CHUNK);
    const n = readSome(this.fd, chunk, 0, chunk.length);
    if (n === 0) {
      this.eof = true;
      return false;
    }
    this.buf = this.buf.length
      ? Buffer.concat([this.buf, chunk.subarray(0, n)])
      : chunk.subarray(0, n);
    return true;
  }

  /** The next line without its newline, or undefined at end of input. */
  line(max = 1 << 20): string | undefined {
    for (;;) {
      const nl = this.buf.indexOf(10);
      if (nl >= 0) {
        const s = this.buf.subarray(0, nl).toString('utf8');
        this.buf = this.buf.subarray(nl + 1);
        return s;
      }
      if (this.buf.length > max) throw new Refusal('a line in the archive is too long');
      if (!this.fill()) return undefined;
    }
  }

  /** Up to `max` bytes, at least one unless input ended. */
  some(max: number): Buffer {
    if (!this.buf.length) this.fill();
    const n = Math.min(max, this.buf.length);
    const out = this.buf.subarray(0, n);
    this.buf = this.buf.subarray(n);
    return out;
  }
}

const idOf = (st: BigIntStats) => `${st.dev}:${st.ino}`;

/** Take on `uid` and `gid` (with that user's groups) for good, or refuse. */
export function becomeUser(uid: number, gid: number): void {
  const me = process.getuid?.();
  if (me === undefined) throw new Refusal('cannot change user here');
  if (me === uid) return;
  if (me !== 0) throw new Refusal(`cannot act as user ${uid}`);
  (process as unknown as { initgroups(user: number, group: number): void }).initgroups(uid, gid);
  process.setgid!(gid);
  process.setuid!(uid);
  if (
    process.getuid!() !== uid ||
    process.geteuid!() !== uid ||
    process.getgid!() !== gid ||
    process.getegid!() !== gid
  )
    throw new Refusal('could not change user');
}

function checkRel(rel: string): void {
  if (
    rel !== '' &&
    (isAbsolute(rel) ||
      rel.includes('\0') ||
      normalize(rel) !== rel ||
      rel.split('/').some((c) => c === '..' || c === '.' || c === ''))
  )
    throw new Refusal(`bad entry name in the archive: ${JSON.stringify(rel)}`);
}

const at = (top: string, rel: string) => (rel ? join(top, rel) : top);

// ---------------------------------------------------------------- pack

interface Packed {
  rel: string;
  id: string;
  dir: boolean;
}

function packFile(top: string, rel: string, st: BigIntStats, out: number): void {
  const fd = openSync(
    at(top, rel),
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK,
  );
  try {
    const f = fstatSync(fd, { bigint: true });
    if (!f.isFile() || idOf(f) !== idOf(st))
      throw new Refusal(`${at(top, rel)} changed while it was read`);
    const size = Number(f.size);
    budget.take(size);
    const frame: Frame = {
      t: 'f',
      rel,
      mode: Number(f.mode & 0o7777n),
      uid: Number(f.uid),
      gid: Number(f.gid),
      mtime: String(f.mtimeNs),
      size,
    };
    writeAll(out, Buffer.from(JSON.stringify(frame) + '\n'));
    const buf = Buffer.alloc(Math.min(CHUNK, Math.max(size, 1)));
    let pos = 0;
    while (pos < size) {
      const n = readSync(fd, buf, 0, Math.min(buf.length, size - pos), pos);
      if (n <= 0) break;
      writeAll(out, buf.subarray(0, n));
      pos += n;
    }
    const after = fstatSync(fd, { bigint: true });
    if (pos !== size || after.size !== f.size || after.mtimeNs !== f.mtimeNs)
      throw new Refusal(`${at(top, rel)} changed while it was read`);
  } finally {
    closeSync(fd);
  }
}

/** Set for a pack of the helper's own store (FsRequest ownTree). */
let ownTree = false;
/** The pack's caps (FsRequest maxEntries, maxBytes). */
let budget = new Budget({ op: 'pack', path: '', uid: 0, gid: 0 });

function packEntry(top: string, rel: string, out: number, packed: Packed[]): void {
  const path = at(top, rel);
  const st = lstatSync(path, { bigint: true });
  const owner = { uid: Number(st.uid), gid: Number(st.gid) };
  if (!st.isFile()) budget.take(0);
  if (st.isSymbolicLink()) {
    const frame: Frame = { t: 'l', rel, target: readlinkSync(path), ...owner };
    writeAll(out, Buffer.from(JSON.stringify(frame) + '\n'));
    packed.push({ rel, id: idOf(st), dir: false });
  } else if (st.isFile()) {
    packFile(top, rel, st, out);
    packed.push({ rel, id: idOf(st), dir: false });
  } else if (st.isDirectory()) {
    // Root walks only folders no one else can change.
    if (!ownTree && process.getuid?.() === 0 && (st.uid !== 0n || (st.mode & 0o022n) !== 0n))
      throw new Refusal(`${path} is a folder others can change`);
    const frame: Frame = {
      t: 'd',
      rel,
      mode: Number(st.mode & 0o7777n),
      mtime: String(st.mtimeNs),
      ...owner,
    };
    writeAll(out, Buffer.from(JSON.stringify(frame) + '\n'));
    packed.push({ rel, id: idOf(st), dir: true });
    for (const name of readdirSync(path).sort())
      packEntry(top, rel ? `${rel}/${name}` : name, out, packed);
  } else {
    throw new Refusal(`${path} is not a file, folder or link`);
  }
}

function removePacked(top: string, packed: Packed[]): void {
  // Children before the folders holding them.
  for (const p of [...packed].reverse()) {
    const path = at(top, p.rel);
    let st;
    try {
      st = lstatSync(path, { bigint: true });
    } catch {
      throw new Refusal(`${path} went away before it was removed`);
    }
    if (idOf(st) !== p.id) throw new Refusal(`${path} changed before it was removed`);
    if (p.dir) rmdirSync(path);
    else unlinkSync(path);
  }
}

export function pack(req: FsRequest, input: FdReader, out = 1): void {
  const packed: Packed[] = [];
  ownTree = req.ownTree === true;
  budget = new Budget(req);
  packEntry(req.path, '', out, packed);
  writeAll(out, Buffer.from(JSON.stringify({ t: 'end' } satisfies Frame) + '\n'));
  closeSync(out);
  const what = input.line();
  if (what === 'remove') removePacked(req.path, packed);
  else if (what !== 'keep') throw new Refusal('no instruction after packing');
}

// ---------------------------------------------------------------- place

interface Created {
  path: string;
  id: string;
  dir: boolean;
}

function parseFrame(line: string | undefined): Frame {
  if (line === undefined) throw new Refusal('the archive ended early');
  let f: unknown;
  try {
    f = JSON.parse(line);
  } catch {
    throw new Refusal('the archive is not readable');
  }
  const frame = f as Frame;
  if (!frame || typeof frame !== 'object' || !['d', 'f', 'l', 'end'].includes(frame.t))
    throw new Refusal('the archive is not readable');
  if (frame.t !== 'end') {
    if (typeof frame.rel !== 'string') throw new Refusal('the archive is not readable');
    checkRel(frame.rel);
  }
  return frame;
}

/** Remove what this run created, newest first, each only while it is still what was created. */
function undoCreated(created: Created[]): void {
  for (const c of [...created].reverse()) {
    try {
      const st = lstatSync(c.path, { bigint: true });
      if (idOf(st) !== c.id) continue;
      if (c.dir) rmdirSync(c.path);
      else unlinkSync(c.path);
    } catch {
      // Gone already, or not empty: leave it.
    }
  }
}

function makeParents(path: string, created: Created[]): void {
  const missing: string[] = [];
  for (let p = dirname(path); ; p = dirname(p)) {
    try {
      if (!statSync(p).isDirectory()) throw new Refusal(`${p} is not a folder`);
      break;
    } catch (err) {
      if (err instanceof Refusal) throw err;
      if ((err as NodeJS.ErrnoException).code !== 'ENOENT') throw err;
      missing.unshift(p);
      if (dirname(p) === p) break;
    }
  }
  for (const p of missing) {
    mkdirSync(p, 0o700);
    created.push({ path: p, id: idOf(lstatSync(p, { bigint: true })), dir: true });
    chmodPath(p, 0o755);
  }
}

const nsToDate = (ns: string) => {
  const ms = Number(BigInt(ns) / 1_000_000n);
  return new Date(ms);
};

export function place(req: FsRequest, input: FdReader): void {
  const created: Created[] = [];
  const dirs: { path: string; mode: number; mtime: string }[] = [];
  const budget = new Budget(req);
  const asRoot = process.getuid?.() === 0;
  /** Owners to give once everything is written, in the order things were made. */
  const owners: Owner[] = [];
  // Root gives the archived owner when asked. A user keeps each entry's
  // archived group when it is one of theirs; where the system says no, the
  // entry keeps the user's own group.
  const groups = asRoot ? [] : (process.getgroups?.() ?? []);
  const myGid = process.getegid?.();
  const chown = (
    path: string,
    frame: { uid: number; gid: number; t: 'd' | 'f' | 'l' },
    mode?: number,
  ) => {
    const kind = frame.t;
    if (asRoot) {
      if (req.owners) owners.push({ path, uid: frame.uid, gid: frame.gid, kind, mode });
    } else if (frame.gid !== myGid && groups.includes(frame.gid)) {
      owners.push({ path, uid: -1, gid: frame.gid, kind, mode, mayRefuse: true });
    }
  };
  try {
    if (req.parents) makeParents(req.path, created);
    const madeDirs = new Set<string>();
    let first = true;
    for (;;) {
      const frame = parseFrame(input.line());
      if (frame.t === 'end') break;
      budget.take(frame.t === 'f' ? frame.size : 0);
      if (first !== (frame.rel === '')) throw new Refusal('the archive is not readable');
      if (!first) {
        const parent = frame.rel.includes('/')
          ? frame.rel.slice(0, frame.rel.lastIndexOf('/'))
          : '';
        if (!madeDirs.has(parent)) throw new Refusal('the archive is not readable');
      }
      const top = first;
      first = false;
      const path = at(req.path, frame.rel);
      const mode =
        top && req.topMode !== undefined ? req.topMode : 'mode' in frame ? frame.mode : 0;
      if (frame.t === 'd') {
        mkdirSync(path, 0o700);
        created.push({ path, id: idOf(lstatSync(path, { bigint: true })), dir: true });
        madeDirs.add(frame.rel);
        chown(path, frame);
        dirs.push({ path, mode, mtime: frame.mtime });
      } else if (frame.t === 'l') {
        symlinkSync(frame.target, path);
        created.push({ path, id: idOf(lstatSync(path, { bigint: true })), dir: false });
        chown(path, frame);
      } else {
        const fd = openSync(
          path,
          constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
          0o600,
        );
        try {
          created.push({ path, id: idOf(fstatSync(fd, { bigint: true })), dir: false });
          let left = frame.size;
          while (left > 0) {
            const chunk = input.some(Math.min(left, CHUNK));
            if (!chunk.length) throw new Refusal('the archive ended early');
            writeAll(fd, chunk);
            left -= chunk.length;
          }
          chown(path, frame, mode);
          fchmodSync(fd, mode);
          const t = nsToDate(frame.mtime);
          futimesSync(fd, t, t);
        } finally {
          closeSync(fd);
        }
      }
    }
    if (first) throw new Refusal('the archive is empty');
    // Folders last, deepest first, so a read-only folder is filled before it is closed.
    for (const d of dirs.reverse()) {
      utimesSync(d.path, nsToDate(d.mtime), nsToDate(d.mtime));
      // chmod by path: only on a folder this run made, checked just above by its id.
      const c = created.find((x) => x.path === d.path)!;
      if (idOf(lstatSync(d.path, { bigint: true })) !== c.id)
        throw new Refusal(`${d.path} changed while it was filled`);
      chmodPath(d.path, d.mode);
    }
    // Owners last, children before the folders holding them, so nothing is
    // written beneath a folder once someone else owns it.
    for (const o of owners.reverse()) giveOwner(o, created);
  } catch (err) {
    undoCreated(created);
    throw err;
  }
}

interface Owner {
  path: string;
  /** -1 leaves the owner as it is. */
  uid: number;
  gid: number;
  kind: 'd' | 'f' | 'l';
  /** A file's mode, set again after the change of owner (which clears setuid and setgid). */
  mode?: number | undefined;
  /** A user's group change: when the system refuses it, the entry keeps the user's group. */
  mayRefuse?: boolean;
}

/** Give `o` its owner, through a descriptor (by name for a link), only while it is what this run made. */
function giveOwner(o: Owner, created: Created[]): void {
  const c = created.find((x) => x.path === o.path);
  if (!c) throw new Refusal(`${o.path} was not made here`);
  const own = (fn: () => void) => {
    try {
      fn();
    } catch (err) {
      if (!(o.mayRefuse && (err as NodeJS.ErrnoException).code === 'EPERM')) throw err;
    }
  };
  if (o.kind === 'l') {
    if (idOf(lstatSync(o.path, { bigint: true })) !== c.id)
      throw new Refusal(`${o.path} changed while it was placed`);
    own(() => lchownSync(o.path, o.uid, o.gid));
    return;
  }
  const flags =
    constants.O_RDONLY |
    constants.O_NOFOLLOW |
    constants.O_NONBLOCK |
    (o.kind === 'd' ? constants.O_DIRECTORY : 0);
  const fd = openSync(o.path, flags);
  try {
    if (idOf(fstatSync(fd, { bigint: true })) !== c.id)
      throw new Refusal(`${o.path} changed while it was placed`);
    own(() => fchownSync(fd, o.uid, o.gid));
    if (o.mode !== undefined) fchmodSync(fd, o.mode);
  } finally {
    closeSync(fd);
  }
}

// ---------------------------------------------------------------- read

const READ_MAX = 1 << 20;

/** One small regular file: a JSON line with its owner, mode and size, then its bytes. */
export function readOne(req: FsRequest, out = 1): void {
  const fd = openSync(req.path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile()) throw new Refusal(`${req.path} is not a regular file`);
    if (st.size > BigInt(READ_MAX)) throw new Refusal(`${req.path} is too large`);
    const buf = Buffer.alloc(Number(st.size));
    let got = 0;
    while (got < buf.length) {
      const n = readSync(fd, buf, got, buf.length - got, got);
      if (n <= 0) break;
      got += n;
    }
    const head = { uid: Number(st.uid), gid: Number(st.gid), mode: Number(st.mode), size: got };
    writeAll(out, Buffer.from(JSON.stringify(head) + '\n'));
    writeAll(out, buf.subarray(0, got));
  } finally {
    closeSync(fd);
  }
}

function chmodPath(path: string, mode: number): void {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY);
  try {
    fchmodSync(fd, mode);
  } finally {
    closeSync(fd);
  }
}

// ---------------------------------------------------------------- main

function parseRequest(line: string | undefined): FsRequest {
  if (line === undefined) throw new Refusal('no request');
  const r = JSON.parse(line) as FsRequest;
  if (
    (r.op !== 'pack' && r.op !== 'place' && r.op !== 'read') ||
    typeof r.path !== 'string' ||
    !isAbsolute(r.path) ||
    normalize(r.path) !== r.path ||
    r.path.includes('\0') ||
    !Number.isInteger(r.uid) ||
    !Number.isInteger(r.gid) ||
    r.uid < 0 ||
    r.gid < 0
  )
    throw new Refusal('bad request');
  return r;
}

/** The child's whole life: one request, one operation, an exit code. */
export function runFsChild(): number {
  const input = new FdReader(0);
  try {
    const req = parseRequest(input.line());
    becomeUser(req.uid, req.gid);
    process.umask(0o077);
    if (req.op === 'pack') pack(req, input);
    else if (req.op === 'read') readOne(req);
    else place(req, input);
    return 0;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    try {
      writeAll(2, Buffer.from(`vigil-fs: ${msg.replace(/\n/g, ' ')}\n`));
    } catch {
      // Nobody is listening.
    }
    return 1;
  }
}

// Run directly (tests start this file with node); the bundled helper calls runFsChild from cli.ts.
if (process.argv[2] === 'fs-child' && /fsChild\.ts$/.test(process.argv[1] ?? '')) {
  process.exitCode = runFsChild();
}
