// Linux has no code signing, so Vigil's trust model there is the package
// manager: a program dpkg or rpm installed counts as trusted (`package`),
// anything else (a download, a build, something dropped in ~/.local/bin)
// as `unsigned`. Rules then treat untrusted programs on Linux the way they
// treat unsigned ones on macOS.
//
//   exec /usr/bin/curl          ─► owned by dpkg "curl"   ─► signing: package, signingId pkg:curl
//   exec ~/.cache/x/miner       ─► owned by nothing       ─► signing: unsigned
//   exec /snap/firefox/123/...  ─► read-only snap image   ─► signing: package, signingId snap:firefox
//
// Rules need the answer while the launch is being checked, so the index is
// held in memory and looked up synchronously. Only paths a program could run
// from are kept (documentation, headers, icons and libraries are skipped),
// which is a few tens of thousands of strings even on a full desktop. The
// index reloads when the package database changes.
//
// Package files belong to root, so changing one already takes root; the
// index does not hash files.

import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { SignatureInfo } from '../enrich.js';

export const DPKG_INFO_DIR = '/var/lib/dpkg/info';
export const DPKG_STATUS = '/var/lib/dpkg/status';
export const RPM_DB_DIRS = ['/var/lib/rpm', '/usr/lib/sysimage/rpm'];

/** Folders nothing is run from directly. */
const SKIP_PREFIXES = [
  '/usr/share/',
  '/usr/include/',
  '/usr/src/',
  '/etc/',
  '/var/',
  '/boot/',
  '/usr/lib/debug/',
];
const SKIP_EXT =
  /\.(so(\.[\d.]+)?|a|o|h|hpp|py|pyc|pm|rb|js|json|xml|html?|txt|md|gz|xz|bz2|zst|png|svg|jpg|mo|po|conf|cfg|ini|desktop|service|socket|timer|rules|pc|cmake|la|typelib|gir|ko|ko\.zst|ko\.xz)$/i;

/** Whether a package file could be a program someone runs. */
export function runnable(path: string): boolean {
  return (
    path.startsWith('/') && !SKIP_PREFIXES.some((p) => path.startsWith(p)) && !SKIP_EXT.test(path)
  );
}

/**
 * The other spelling of a path on merged-/usr systems, where /bin, /sbin and
 * /lib are links into /usr. The kernel reports one, the package database may
 * record the other.
 */
export function usrAlias(path: string): string | undefined {
  const m = /^\/(bin|sbin|lib|lib32|lib64|libx32)\//.exec(path);
  if (m) return '/usr' + path;
  const u = /^\/usr\/(bin|sbin|lib|lib32|lib64|libx32)\//.exec(path);
  return u ? path.slice(4) : undefined;
}

/** Programs inside a snap's read-only image, or a system-wide Flatpak. */
export function sandboxedPackage(path: string): string | undefined {
  const snap = /^\/snap\/([a-z0-9][a-z0-9-]{0,39})\/(\d+|current)\//.exec(path);
  if (snap) return `snap:${snap[1]}`;
  // Only the system installation: ~/.local/share/flatpak belongs to the user and they can edit it.
  const flat = /^\/var\/lib\/flatpak\/app\/([A-Za-z0-9._-]{1,255})\//.exec(path);
  return flat ? `flatpak:${flat[1]}` : undefined;
}

export interface PackageSource {
  /** Changes whenever the package database does (an mtime, a revision). */
  version(): string | undefined;
  /** Every file each package owns. */
  load(): Iterable<[path: string, pkg: string]>;
}

/** dpkg (Debian, Ubuntu, Mint, Pop!_OS): one `<pkg>.list` per package. */
export function dpkgSource(infoDir = DPKG_INFO_DIR, status = DPKG_STATUS): PackageSource {
  return {
    version() {
      try {
        return `dpkg:${statSync(status).mtimeMs}`;
      } catch {
        return undefined;
      }
    },
    *load() {
      let names: string[];
      try {
        names = readdirSync(infoDir);
      } catch {
        return;
      }
      for (const name of names) {
        if (!name.endsWith('.list')) continue;
        // "libc6:amd64.list" → "libc6"
        const pkg = name.slice(0, -'.list'.length).split(':')[0]!;
        let text: string;
        try {
          text = readFileSync(join(infoDir, name), 'utf8');
        } catch {
          continue;
        }
        for (const line of text.split('\n')) if (line) yield [line, pkg];
      }
    },
  };
}

/**
 * rpm (Fedora, RHEL, openSUSE). Its database is binary, so the listing comes
 * from `rpm -qa --qf '[%{FILENAMES}\t%{NAME}\n]'`, run by the caller (the
 * helper owns process execution).
 */
export function rpmSource(
  list: () => string | undefined,
  dbDirs: string[] = RPM_DB_DIRS,
): PackageSource {
  return {
    version() {
      for (const d of dbDirs) {
        try {
          return `rpm:${statSync(d).mtimeMs}`;
        } catch {
          // try the next location
        }
      }
      return undefined;
    },
    *load() {
      const text = list();
      if (!text) return;
      for (const line of text.split('\n')) {
        const tab = line.indexOf('\t');
        if (tab > 0) yield [line.slice(0, tab), line.slice(tab + 1)];
      }
    },
  };
}

export interface PackageIndexOptions {
  sources: PackageSource[];
  /** Least time between checks of whether the database changed. */
  recheckMs?: number;
  now?: () => number;
}

export class PackageIndex {
  private owners = new Map<string, string>();
  private versions = '';
  private checkedAt = -Infinity;
  private readonly now: () => number;

  constructor(private readonly opts: PackageIndexOptions) {
    this.now = opts.now ?? Date.now;
  }

  /** Number of runnable files indexed. */
  get size(): number {
    return this.owners.size;
  }

  /** Reload if the package database changed since the last load. */
  refresh(): boolean {
    this.checkedAt = this.now();
    const v = this.opts.sources.map((s) => s.version() ?? '-').join('|');
    if (v === this.versions) return false;
    const owners = new Map<string, string>();
    for (const s of this.opts.sources) {
      if (s.version() === undefined) continue;
      for (const [path, pkg] of s.load()) if (runnable(path)) owners.set(path, pkg);
    }
    this.owners = owners;
    this.versions = v;
    return true;
  }

  /** The package that installed `path`, if any. */
  owner(path: string): string | undefined {
    if (this.now() - this.checkedAt >= (this.opts.recheckMs ?? 30_000)) this.refresh();
    const own = this.owners.get(path);
    if (own) return `pkg:${own}`;
    const alias = usrAlias(path);
    const viaAlias = alias ? this.owners.get(alias) : undefined;
    return viaAlias ? `pkg:${viaAlias}` : sandboxedPackage(path);
  }

  /** The trust answer for a program path, in the shape rules read. */
  trust(path: string): SignatureInfo | undefined {
    if (!path.startsWith('/')) return undefined;
    const owner = this.owner(path);
    return owner ? { signing: 'package', signingId: owner } : { signing: 'unsigned' };
  }
}
