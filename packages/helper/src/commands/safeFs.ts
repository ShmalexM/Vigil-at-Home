// File-system building blocks for moving things as root without being
// redirected. A path is looked up again on every call, so a folder renamed or
// swapped for a link between a check and a move would send root's move
// somewhere else. So a folder is pinned once, checked through the pin, and
// every later step names files relative to the pin:
//
// - On Linux the folder is opened and later steps go through
//   /proc/self/fd/<fd>/<name>, which the kernel resolves through the open
//   handle, not the path.
// - Elsewhere (macOS) the process's working folder is the pin: chdir into it,
//   check it, and use bare names. The kernel resolves those from the working
//   folder itself. Everything done under the pin is synchronous, so nothing
//   else in the helper runs while the working folder is moved, and the
//   helper names files by absolute path everywhere else.
//
// Either way, where the pinned folder is and what is above it are read back
// from the kernel (/proc or getcwd, and "..") rather than from the path that
// was asked for, so a swapped path is noticed rather than followed.

import {
  closeSync,
  constants,
  existsSync,
  fchownSync,
  fstatSync,
  lstatSync,
  openSync,
  readlinkSync,
  realpathSync,
  statSync,
  type BigIntStats,
} from 'node:fs';
import { ActionError } from './errors.js';
import { sameId } from './protectedSet.js';

/** Open for a check only: never follow a final link, never wait on a FIFO. */
export const O_CHECK = constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
/** Open a folder, refusing a final link. */
export const O_FOLDER = constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW;

export type Pinning = 'proc' | 'cwd';

/** /proc handles when the kernel offers them (Linux), the working folder otherwise. */
export function defaultPinning(): Pinning {
  return existsSync('/proc/self/fd') ? 'proc' : 'cwd';
}

/** A path the kernel resolves through an open folder handle (Linux). */
export function fdPath(fd: number, name?: string): string {
  return name === undefined ? `/proc/self/fd/${fd}` : `/proc/self/fd/${fd}/${name}`;
}

export function lstatOrNull(path: string): BigIntStats | null {
  try {
    return lstatSync(path, { bigint: true });
  } catch {
    return null;
  }
}

export const lexists = (path: string): boolean => lstatOrNull(path) !== null;

export const euid = (): number => process.geteuid?.() ?? 0;

/**
 * fchown that tolerates running unprivileged (tests): only root can give a
 * file away, and there the owner is already the test user.
 */
export function fchownIfRoot(fd: number, uid: number, gid: number): void {
  try {
    fchownSync(fd, uid, gid);
  } catch (err) {
    if (euid() === 0) throw err;
  }
}

export function fstatBig(fd: number): BigIntStats {
  return fstatSync(fd, { bigint: true });
}

/** A folder held so that later steps happen in it, whatever its path comes to name. */
export interface Pin {
  /** A path the kernel resolves inside the pinned folder. */
  at(name: string): string;
  /** Where the pinned folder is now, as the kernel reports it. */
  where(): string | null;
  /** The pinned folder, then each folder above it, as the kernel finds them through "..". */
  chain(): BigIntStats[];
  /** Move the pin into a folder just made inside it, refusing a link put there instead. */
  enter(name: string): void;
  /** The open handle on the folder, where there is one (Linux). */
  readonly fd: number | undefined;
  release(): void;
}

function moved(dir: string): ActionError {
  return new ActionError('refused', `${dir} has moved or is not a folder; nothing was moved`);
}

function walkUp(start: string): BigIntStats[] {
  const out: BigIntStats[] = [];
  let p = start;
  for (let i = 0; i < 512; i++) {
    const st = statSync(p, { bigint: true });
    // "/.." is "/" again.
    if (out.length && sameId(st, out[out.length - 1]!)) break;
    out.push(st);
    p += '/..';
  }
  return out;
}

class ProcPin implements Pin {
  fd: number;

  constructor(dir: string) {
    try {
      this.fd = openSync(dir, O_FOLDER);
    } catch {
      throw moved(dir);
    }
    if (this.where() !== dir) {
      closeSync(this.fd);
      throw moved(dir);
    }
  }

  at(name: string): string {
    return fdPath(this.fd, name);
  }

  where(): string | null {
    try {
      return readlinkSync(fdPath(this.fd));
    } catch {
      return null;
    }
  }

  chain(): BigIntStats[] {
    return walkUp(fdPath(this.fd));
  }

  enter(name: string): void {
    let fd: number;
    try {
      fd = openSync(this.at(name), O_FOLDER);
    } catch {
      throw moved(name);
    }
    closeSync(this.fd);
    this.fd = fd;
  }

  release(): void {
    closeSync(this.fd);
  }
}

class CwdPin implements Pin {
  readonly fd = undefined;
  private readonly saved: string;

  constructor(dir: string) {
    let saved = '/';
    try {
      saved = process.cwd();
    } catch {
      // The old working folder is gone; go back to / afterwards.
    }
    this.saved = saved;
    try {
      process.chdir(dir);
    } catch {
      throw moved(dir);
    }
    if (this.where() !== dir) {
      this.release();
      throw moved(dir);
    }
  }

  at(name: string): string {
    return name;
  }

  where(): string | null {
    // realpath of "." asks the kernel (getcwd), unlike process.cwd(), which
    // Node caches until the next chdir.
    try {
      return realpathSync.native('.');
    } catch {
      return null;
    }
  }

  chain(): BigIntStats[] {
    return walkUp('.');
  }

  enter(name: string): void {
    let fd: number;
    try {
      fd = openSync(name, O_FOLDER);
    } catch {
      throw moved(name);
    }
    try {
      const want = fstatBig(fd);
      process.chdir(name);
      if (!sameId(lstatSync('.', { bigint: true }), want)) throw moved(name);
    } finally {
      closeSync(fd);
    }
  }

  release(): void {
    try {
      process.chdir(this.saved);
    } catch {
      process.chdir('/');
    }
  }
}

/** Pin `dir`, which must be exactly where the kernel finds the folder now. */
export function pinFolder(dir: string, how: Pinning = defaultPinning()): Pin {
  return how === 'proc' ? new ProcPin(dir) : new CwdPin(dir);
}

/** Run fn with a handle on the pinned folder itself. */
export function withFolderFd<T>(pin: Pin, fn: (fd: number) => T): T {
  if (pin.fd !== undefined) return fn(pin.fd);
  const fd = openSync('.', constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    return fn(fd);
  } finally {
    closeSync(fd);
  }
}
