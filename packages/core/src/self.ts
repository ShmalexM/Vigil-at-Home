// What counts as Vigil itself, for the safety floor in the app and in the
// helper. Both use these functions, so they agree on what Vigil never pauses,
// kills or blocks.
//
// A packaged install is a folder (the macOS .app bundle, /opt/Vigil at Home
// on Linux) and anything inside it is Vigil. A Linux AppImage instead runs
// from a read-only FUSE mount the image's runtime makes on every launch. A
// program there is Vigil only when that mount is the one served for the
// approved image, which is checked against the kernel's mount table and the
// image's device and inode, never against the mount's folder name. Programs
// Vigil starts from elsewhere, such as connectors, are not Vigil.
//
// Pure functions only: the app and the helper each read /proc themselves.

/**
 * macOS disks ignore case by default, so `/Applications/vigil at home.app` is
 * Vigil too. Linux paths that differ only in case are different files.
 */
const CASELESS = typeof process !== 'undefined' && process.platform === 'darwin';

/**
 * Vigil's own paths without a trailing slash (lower-cased on macOS). A path
 * with fewer than two parts (`/`, `/opt`) is dropped: it would cover every
 * program on the machine, so nothing could ever be paused, killed or
 * quarantined.
 */
export function selfRoots(paths: readonly string[], caseless = CASELESS): string[] {
  return paths
    .map((p) => selfKey(p, caseless))
    .filter(
      (p) => p.split('/').filter((part) => part && part !== '.' && part !== '..').length >= 2,
    );
}

/** A path without trailing slashes (lower-cased on macOS), for comparing against {@link selfRoots}. */
export function selfKey(path: string, caseless = CASELESS): string {
  let end = path.length;
  while (end > 0 && path[end - 1] === '/') end--;
  const p = path.slice(0, end);
  return caseless ? p.toLowerCase() : p;
}

/** Whether `path` is one of `roots` (from {@link selfRoots}) or inside one. */
export function underSelfRoot(
  roots: readonly string[],
  path: string,
  caseless = CASELESS,
): boolean {
  const p = caseless ? path.toLowerCase() : path;
  return roots.some((s) => p === s || p.startsWith(`${s}/`));
}

/** A file's identity, `<device>:<inode>`. It stays the same when the file is renamed. */
export function fileId(dev: bigint | number, ino: bigint | number): string {
  return `${dev}:${ino}`;
}

/** The AppImage Vigil runs from, as the user approved it in the helper. */
export interface SelfImage {
  /** Where it was when approved; shown in the password prompt. */
  path: string;
  /** Its {@link fileId}, which is what the helper matches. */
  id: string;
}

/** One line of /proc/<pid>/mountinfo. */
export interface MountEntry {
  /** Unique per mount for as long as it stays mounted. */
  id: number;
  /** `major:minor` of the mounted filesystem. */
  dev: string;
  mountPoint: string;
  /** `fuse.<subtype>` for FUSE mounts. */
  fsType: string;
  readOnly: boolean;
}

/** mountinfo escapes space, tab, newline and backslash as `\ooo`. */
function unescapeMount(s: string): string {
  return s.replace(/\\([0-7]{3})/g, (_, oct: string) => String.fromCharCode(parseInt(oct, 8)));
}

/** Parse /proc/<pid>/mountinfo (see proc(5)). Lines that don't parse are skipped. */
export function parseMountInfo(text: string): MountEntry[] {
  const out: MountEntry[] = [];
  for (const line of text.split('\n')) {
    const [left, right] = line.split(' - ');
    if (!left || !right) continue;
    const f = left.split(' ');
    const id = Number(f[0]);
    if (!Number.isInteger(id) || f.length < 6) continue;
    const fsType = right.split(' ')[0] ?? '';
    out.push({
      id,
      dev: f[2]!,
      mountPoint: unescapeMount(f[4]!),
      fsType,
      readOnly: f[5]!.split(',').includes('ro'),
    });
  }
  return out;
}

/**
 * The mount `path` lives on: the one with the longest mount point containing
 * it, and of those the last mounted (it hides the ones beneath).
 */
export function mountContaining(
  mounts: readonly MountEntry[],
  path: string,
): MountEntry | undefined {
  let best: MountEntry | undefined;
  for (const m of mounts) {
    const mp = m.mountPoint;
    const inside = mp === '/' ? path.startsWith('/') : path === mp || path.startsWith(`${mp}/`);
    if (inside && (!best || mp.length >= best.mountPoint.length)) best = m;
  }
  return best;
}

/** A read-only FUSE mount, which is how an AppImage's runtime serves the image. */
export function isImageMount(m: MountEntry | undefined): m is MountEntry {
  return !!m && m.readOnly && (m.fsType === 'fuse' || m.fsType.startsWith('fuse.'));
}

/**
 * The mount an AppImage-launched Vigil runs from: the read-only FUSE mount
 * holding its executable, from the process's own mountinfo. Undefined when
 * Vigil runs from anything else (a .deb install, an extracted image).
 */
export function selfMount(mountinfo: string, execPath: string): MountEntry | undefined {
  const m = mountContaining(parseMountInfo(mountinfo), execPath);
  return isImageMount(m) && m.mountPoint !== '/' ? m : undefined;
}

/** Whether `exe` runs from `mount` (the one {@link selfMount} or the helper verified). */
export function runsFromMount(
  mounts: readonly MountEntry[],
  exe: string,
  mount: MountEntry,
): boolean {
  return mountContaining(mounts, exe)?.id === mount.id;
}

/** Most programs inside an image the app hashes at startup. */
export const SELF_HASH_MAX_FILES = 64;
/** Largest program it hashes (Electron's binary is about 200 MB). */
export const SELF_HASH_MAX_BYTES = 320 * 1024 * 1024;
