// sha256 of programs osquery reports launching on Linux. Santa hashes every
// launch on macOS; osquery's eBPF events don't, and the block-this-program
// action (a fapolicyd rule by hash) needs one. Only untrusted programs are
// hashed (package files are trusted already), only up to a size cap, and each
// file once per change, so a busy build directory costs a stat per launch.

import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';

export interface FileHasherOptions {
  /** Larger files are not hashed (their launches still go to the rules, without sha256). */
  maxBytes?: number;
  maxEntries?: number;
}

/**
 * Open `path` for reading without ever blocking: O_NONBLOCK, so a FIFO or a
 * device opens at once (and is then refused by the caller's fstat), and
 * O_NOFOLLOW when `nofollow` is set, so a symlink there fails to open.
 * Undefined when it can't be opened.
 */
export function openNonBlocking(path: string, nofollow = false): number | undefined {
  try {
    return openSync(
      path,
      constants.O_RDONLY | constants.O_NONBLOCK | (nofollow ? constants.O_NOFOLLOW : 0),
    );
  } catch {
    return undefined;
  }
}

/**
 * The sha256 of what the open descriptor `fd` holds, read from its start
 * with positioned reads, so it hashes exactly the file that was opened and
 * fstat'ed. Undefined when it isn't a regular file or is larger than `maxBytes`.
 */
export function sha256OfFd(fd: number, maxBytes = Number.MAX_SAFE_INTEGER): string | undefined {
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > maxBytes) return undefined;
    const hash = createHash('sha256');
    const buf = Buffer.allocUnsafe(1024 * 1024);
    let pos = 0;
    let n: number;
    while ((n = readSync(fd, buf, 0, buf.length, pos)) > 0) {
      pos += n;
      if (pos > maxBytes) return undefined;
      hash.update(buf.subarray(0, n));
    }
    return hash.digest('hex');
  } catch {
    return undefined;
  }
}

export class FileHasher {
  private readonly cache = new Map<string, { key: string; sha256: string }>();
  private readonly maxBytes: number;
  private readonly maxEntries: number;

  constructor(opts: FileHasherOptions = {}) {
    this.maxBytes = opts.maxBytes ?? 32 * 1024 * 1024;
    this.maxEntries = opts.maxEntries ?? 2048;
  }

  /**
   * The file's sha256, or undefined when it is gone, too big or not a
   * regular file. Opened without blocking, so a FIFO swapped in at the path
   * is refused at once instead of waiting for a writer.
   */
  sha256(path: string): string | undefined {
    const fd = openNonBlocking(path);
    if (fd === undefined) return undefined;
    try {
      // fstat on the open file, so the stat and the bytes are the same file.
      const st = fstatSync(fd);
      if (!st.isFile() || st.size > this.maxBytes) return undefined;
      const key = `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}`;
      const hit = this.cache.get(path);
      if (hit?.key === key) return hit.sha256;
      const sha256 = sha256OfFd(fd, this.maxBytes);
      if (!sha256) return undefined;
      this.cache.delete(path);
      this.cache.set(path, { key, sha256 });
      if (this.cache.size > this.maxEntries) {
        const oldest = this.cache.keys().next().value;
        if (oldest !== undefined) this.cache.delete(oldest);
      }
      return sha256;
    } catch {
      return undefined;
    } finally {
      closeSync(fd);
    }
  }
}
