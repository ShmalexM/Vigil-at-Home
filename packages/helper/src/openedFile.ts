// A file the helper holds open while it decides about it. Everything it
// learns (device and inode, ctime, size, contents, the code signature) comes
// from this one descriptor, never from looking the path up again, so the
// facts can't come from different files when the path is swapped meanwhile.

import { closeSync, fstatSync, readSync } from 'node:fs';
import { fileId } from '@vigil/core/self';
import { openNonBlocking, sha256OfFd } from '@vigil/sensors';
import type { FileStat } from './system.js';

/** Largest file the helper hashes for a pin (an AppImage or Electron binary). */
export const PIN_MAX_BYTES = 4 * 1024 ** 3;

export interface OpenedFile {
  /** fstat of the descriptor when it was opened. */
  readonly stat: FileStat;
  /** fstat of the same descriptor now; undefined if it can't be read. */
  restat(): FileStat | undefined;
  /** `len` bytes at `pos` (fewer at the end). */
  read(pos: number, len: number): Buffer;
  /** The sha256 of the whole file, read through the descriptor. */
  sha256(): string | undefined;
  close(): void;
}

export interface OpenOptions {
  /** Refuse a symlink at the path itself (O_NOFOLLOW). */
  nofollow?: boolean;
}

function regularStat(fd: number): FileStat | undefined {
  const st = fstatSync(fd, { bigint: true });
  if (!st.isFile()) return undefined;
  return { id: fileId(st.dev, st.ino), ctime: st.ctimeNs.toString(), size: Number(st.size) };
}

/**
 * Open `path` once, read-only and without blocking (O_NONBLOCK, plus
 * O_NOFOLLOW when asked), and keep it only if fstat says it is a regular
 * file: a FIFO, device, socket or directory is refused at once.
 */
export function openRegularFile(path: string, opts: OpenOptions = {}): OpenedFile | undefined {
  const fd = openNonBlocking(path, opts.nofollow);
  if (fd === undefined) return undefined;
  let stat: FileStat | undefined;
  try {
    stat = regularStat(fd);
  } catch {
    stat = undefined;
  }
  if (!stat) {
    closeSync(fd);
    return undefined;
  }
  return {
    stat,
    restat() {
      try {
        return regularStat(fd);
      } catch {
        return undefined;
      }
    },
    read(pos, len) {
      const buf = Buffer.alloc(len);
      let got = 0;
      while (got < len) {
        const n = readSync(fd, buf, got, len - got, pos + got);
        if (n <= 0) break;
        got += n;
      }
      return buf.subarray(0, got);
    },
    sha256: () => sha256OfFd(fd, PIN_MAX_BYTES),
    close: () => closeSync(fd),
  };
}

/** Whether two stats are of the same, unchanged file. */
export const sameStat = (a: FileStat, b: FileStat | undefined): boolean =>
  !!b && a.id === b.id && a.ctime === b.ctime && a.size === b.size;
