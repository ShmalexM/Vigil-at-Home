import { createHash } from 'node:crypto';
import type { OpenedFile, OpenOptions } from '../openedFile.js';

/** One file's contents and metadata, by its id (`<device>:<inode>`). */
export interface FakeInode {
  kind?: 'file' | 'fifo' | 'dir';
  data?: Buffer;
  /** Defaults to "1". */
  ctime?: string;
  /** Defaults to the data's length, or 1. */
  size?: number;
  /** The file's sha256; defaults to the hash of `data`, or of the id. */
  sha256?: string;
}

/**
 * Paths to file ids, file ids to contents, and symlinks: enough for openFile.
 * An open file stays bound to the inode it opened, whatever later happens
 * to the path, the way a real descriptor does.
 */
export class FakeFs {
  /** Path → file id. */
  readonly paths = new Map<string, string>();
  readonly inodes = new Map<string, FakeInode>();
  /** Path → target, for symlinks. */
  readonly links = new Map<string, string>();
  /** Runs inside every hash, to stand in for something changing meanwhile. */
  duringHash: (() => void) | undefined;
  /** Every file opened, by path. */
  readonly opened: string[] = [];

  open(path: string, opts: OpenOptions = {}): OpenedFile | undefined {
    this.opened.push(path);
    let target = path;
    for (let hops = 0; this.links.has(target); hops++) {
      if (opts.nofollow && hops === 0) return undefined;
      if (hops > 8) return undefined;
      target = this.links.get(target)!;
    }
    const id = this.paths.get(target);
    if (id === undefined) return undefined;
    const statOf = () => {
      const ino = this.inodes.get(id) ?? {};
      if (ino.kind && ino.kind !== 'file') return undefined;
      return { id, ctime: ino.ctime ?? '1', size: ino.size ?? ino.data?.length ?? 1 };
    };
    const stat = statOf();
    if (!stat) return undefined;
    return {
      stat,
      restat: statOf,
      read: (pos, len) => (this.inodes.get(id)?.data ?? Buffer.alloc(0)).subarray(pos, pos + len),
      sha256: () => {
        this.duringHash?.();
        const ino = this.inodes.get(id) ?? {};
        return (
          ino.sha256 ??
          createHash('sha256')
            .update(ino.data ?? id)
            .digest('hex')
        );
      },
      close: () => undefined,
    };
  }
}
