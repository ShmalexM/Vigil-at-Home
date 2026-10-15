// The hashes of the programs blocking must never reach: the helper's own
// launcher and runtime, Santa's and osquery's programs, and the installed
// Vigil app's executables. Santa (and fapolicyd on Linux) blocks a program by
// hash everywhere at once, so a block rule naming one of these would stop the
// helper from starting again, blind the sensors, or keep Vigil from opening.
//
// The helper works these out itself, from the places it knows those programs
// live (ownProgramRoots in config.ts), never from anything a client sends:
// every executable file there is hashed (sha256, and on macOS the CDHash of
// each slice, as Santa's CDHASH rules name it). The set is built off the event
// loop at startup and refreshed now and then, rehashing only files whose
// identity, ctime or size changed, so an install or update of Santa or
// osquery after the helper started is picked up.
//
// Only what root owns and only root can change counts: the file, every
// folder walked to reach it, and a root that is a link. Some of these places
// can be written by the user's account (/usr/local/bin with Homebrew, or
// /Applications/Santa.app before Santa is installed), and a program put there
// must not become one no rule may block.

import { lstat, readdir, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { fileId } from '@vigil/core/self';
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64, readCodeIdentity } from './codeDirectory.js';
import { openRegularFile } from './openedFile.js';

export interface OwnHashesOptions {
  /** Files or folders whose executables are protected. */
  roots: readonly string[];
  /** Read CDHashes too (macOS). */
  cdhashes: boolean;
  log?: (msg: string) => void;
  /** Most files looked at in one pass. */
  maxFiles?: number;
  /** Deepest folder level walked below a root. */
  maxDepth?: number;
  /** Who must own what counts (root); tests use their own uid. */
  ownerUid?: number;
}

const MAX_FILES = 4096;
const MAX_DEPTH = 12;

interface Cached {
  key: string;
  hashes: string[];
}

export class OwnHashes {
  /** Hash (lower case) → the program it is the hash of. */
  private byHash = new Map<string, string>();
  /** Path → what it hashed to, keyed by its identity, ctime and size. */
  private cache = new Map<string, Cached>();
  private pass: Promise<void> | undefined;
  private readonly first: Promise<void>;
  private settleFirst!: () => void;

  constructor(private readonly opts: OwnHashesOptions) {
    this.first = new Promise((resolve) => (this.settleFirst = resolve));
  }

  /** Resolves once the first pass is done (at once with no roots). */
  ready(): Promise<void> {
    return this.first;
  }

  /** The program `identifier` is the sha256 or CDHash of, if it is one of them. */
  owner(identifier: string): string | undefined {
    return this.byHash.get(identifier.toLowerCase());
  }

  get size(): number {
    return this.byHash.size;
  }

  /** Walk the roots again. One pass at a time; a call during a pass waits for it. */
  refresh(): Promise<void> {
    this.pass ??= this.walk()
      .catch((err: Error) => this.opts.log?.(`own program hashes: ${err.message}`))
      .finally(() => {
        this.pass = undefined;
        this.settleFirst();
      });
    return this.pass;
  }

  private async walk(): Promise<void> {
    /** Path → the device:inode the walk found there. */
    const files = new Map<string, string>();
    const max = this.opts.maxFiles ?? MAX_FILES;
    let capped = false;
    const uid = BigInt(this.opts.ownerUid ?? 0);
    // Owned by root and writable by nobody else.
    const rootOnly = (st: { uid: bigint; mode: bigint }) =>
      st.uid === uid && (st.mode & 0o022n) === 0n;
    const visit = async (path: string, depth: number): Promise<void> => {
      if (files.size >= max) {
        capped = true;
        return;
      }
      let st;
      try {
        st = await lstat(path, { bigint: true });
      } catch {
        return;
      }
      // Links inside a folder are not followed: what they point at is either
      // walked anyway (a bundle's Versions/Current) or not Vigil's to protect.
      if (st.isSymbolicLink() || !rootOnly(st)) return;
      if (st.isFile()) {
        if (st.mode & 0o111n) files.set(path, fileId(st.dev, st.ino));
        return;
      }
      if (!st.isDirectory() || depth > (this.opts.maxDepth ?? MAX_DEPTH)) return;
      let names: string[];
      try {
        names = await readdir(path);
      } catch {
        return;
      }
      for (const n of names.sort()) await visit(join(path, n), depth + 1);
    };
    for (const root of this.opts.roots) {
      // A root may itself be a link (/usr/local/bin/osqueryd into /opt/osquery).
      let real: string;
      try {
        const link = await lstat(root, { bigint: true });
        // A link's own mode means nothing; who owns it decides where it points.
        if (link.isSymbolicLink() && link.uid !== uid) continue;
        real = await realpath(root);
      } catch {
        continue;
      }
      await visit(real, 0);
    }
    if (capped) this.opts.log?.(`own program hashes: stopped after ${max} files`);

    const byHash = new Map<string, string>();
    const cache = new Map<string, Cached>();
    for (const [path, id] of files) {
      const got = await this.hashesOf(path, id);
      if (!got) continue;
      cache.set(path, got);
      for (const h of got.hashes) byHash.set(h, path);
    }
    this.cache = cache;
    this.byHash = byHash;
  }

  /** The hashes of one file, from the cache while it is unchanged. */
  private async hashesOf(path: string, id: string): Promise<Cached | undefined> {
    const f = openRegularFile(path, { nofollow: true });
    if (!f) return undefined;
    try {
      // The file the walk found root owns, not one put in its place since.
      if (f.stat.id !== id) return undefined;
      const key = `${f.stat.id}|${f.stat.ctime}|${f.stat.size}`;
      const cached = this.cache.get(path);
      if (cached?.key === key) return cached;
      const sha = await f.sha256Async();
      if (!sha) return undefined;
      const hashes = [sha];
      if (this.opts.cdhashes) {
        for (const cpu of [CPU_TYPE_ARM64, CPU_TYPE_X86_64]) {
          try {
            const cd = readCodeIdentity((pos, len) => f.read(pos, len), cpu)?.cdhash;
            if (cd && !hashes.includes(cd)) hashes.push(cd);
          } catch {
            // Not Mach-O, or a damaged one: its sha256 still counts.
          }
        }
      }
      return { key, hashes };
    } finally {
      f.close();
    }
  }
}
