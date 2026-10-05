// sha256 of programs osquery reports launching on Linux. Santa hashes every
// launch on macOS; osquery's eBPF events don't, and the block-this-program
// action (a fapolicyd rule by hash) needs one. Only untrusted programs are
// hashed (package files are trusted already), only up to a size cap, and each
// file once per change, so a busy build directory costs a stat per launch.

import { createHash } from 'node:crypto';
import { closeSync, fstatSync, openSync, readSync } from 'node:fs';

export interface FileHasherOptions {
  /** Larger files are not hashed (their launches still go to the rules, without sha256). */
  maxBytes?: number;
  maxEntries?: number;
}

export class FileHasher {
  private readonly cache = new Map<string, { key: string; sha256: string }>();
  private readonly maxBytes: number;
  private readonly maxEntries: number;

  constructor(opts: FileHasherOptions = {}) {
    this.maxBytes = opts.maxBytes ?? 32 * 1024 * 1024;
    this.maxEntries = opts.maxEntries ?? 2048;
  }

  /** The file's sha256, or undefined when it is gone, too big or not a regular file. */
  sha256(path: string): string | undefined {
    let fd: number;
    try {
      fd = openSync(path, 'r');
    } catch {
      return undefined;
    }
    try {
      // fstat on the open file, so the stat and the bytes are the same file.
      const st = fstatSync(fd);
      if (!st.isFile() || st.size > this.maxBytes) return undefined;
      const key = `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}`;
      const hit = this.cache.get(path);
      if (hit?.key === key) return hit.sha256;
      const hash = createHash('sha256');
      const buf = Buffer.allocUnsafe(1024 * 1024);
      let n: number;
      while ((n = readSync(fd, buf, 0, buf.length, null)) > 0) hash.update(buf.subarray(0, n));
      const sha256 = hash.digest('hex');
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
