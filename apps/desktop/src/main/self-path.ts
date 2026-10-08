import { createReadStream, readFileSync, realpathSync, statSync } from 'node:fs';
import { lstat, readdir } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import {
  SELF_HASH_MAX_BYTES,
  SELF_HASH_MAX_FILES,
  fileId,
  selfMount,
  type SelfImage,
} from '@vigil/core/self';

/** What the helper is told is Vigil's own. */
export interface HelperSelf {
  paths: string[];
  /** Linux AppImage: the image by device and inode, so a rename while it runs still matches. */
  images: SelfImage[];
  /** sha256 of the programs inside the image, which no rule may block. Filled in after start-up. */
  hashes: string[];
}

/** Where Vigil's own programs live, for the safety floor. */
export interface SelfPaths {
  /** What the app's own engine never pauses, kills or quarantines. */
  app: string[];
  /** What the helper is told: stable across launches, since anything new asks for the password. */
  helper: HelperSelf;
  /** Linux AppImage: the mount Vigil runs from, whose programs {@link hashSelf} hashes. */
  mount?: string;
}

export interface SelfDeps {
  realpath: (p: string) => string;
  /** /proc/self/mountinfo. */
  mountInfo: () => string | undefined;
  fileId: (p: string) => string | undefined;
}

const realDeps: SelfDeps = {
  realpath: realpathSync,
  mountInfo: () => {
    try {
      return readFileSync('/proc/self/mountinfo', 'utf8');
    } catch {
      return undefined;
    }
  },
  fileId: (p) => {
    try {
      const st = statSync(p, { bigint: true });
      return fileId(st.dev, st.ino);
    } catch {
      return undefined;
    }
  },
};

/**
 * The installed app's own folder. On macOS the binary is
 * `X.app/Contents/MacOS/X`, so the bundle is three levels up; on Linux the
 * binary sits directly in its folder (`/opt/Vigil at Home/vigil-at-home`). An
 * AppImage runs from a fresh read-only FUSE mount under /tmp on every launch:
 * the app protects that mount, found in the kernel's mount table, and the
 * helper is told the image file by its device and inode, which it checks
 * every process against (packages/helper/src/commands/selfImage.ts).
 */
export function selfPaths(
  execPath: string,
  platform: NodeJS.Platform,
  packaged: boolean,
  env: NodeJS.ProcessEnv = {},
  deps: Partial<SelfDeps> = {},
): SelfPaths {
  const d = { ...realDeps, ...deps };
  const plain = (paths: string[]): SelfPaths => ({
    app: paths,
    helper: { paths, images: [], hashes: [] },
  });
  if (!packaged) return plain([execPath]);
  if (platform === 'darwin') return plain([join(execPath, '../../..')]);
  const dir = dirname(execPath);
  // The kernel names the running image by its real path.
  let image = env['APPIMAGE'];
  if (!image) return plain([dir]);
  try {
    image = d.realpath(image);
  } catch {
    // Gone or unreadable: keep the name the runtime gave.
  }
  const mount = selfMount(d.mountInfo() ?? '', execPath)?.mountPoint;
  const id = d.fileId(image);
  return {
    app: [mount ?? dir, image],
    helper: { paths: [image], images: id ? [{ path: image, id }] : [], hashes: [] },
    ...(mount ? { mount } : {}),
  };
}

/** Most entries {@link hashSelf} looks at, so a huge mount can't stall start-up. */
const WALK_MAX = 20_000;

/**
 * The sha256 of the programs (files with an execute bit) inside Vigil's
 * mount, so no rule blocks one by hash: blocking by hash stops that program
 * everywhere, Vigil included. Bounded: at most SELF_HASH_MAX_FILES programs,
 * none larger than SELF_HASH_MAX_BYTES, links not followed. Read in the
 * background after start-up.
 */
export async function hashSelf(root: string): Promise<string[]> {
  const found: string[] = [];
  const queue = [root];
  let seen = 0;
  while (queue.length && found.length < SELF_HASH_MAX_FILES && seen < WALK_MAX) {
    const dir = queue.shift()!;
    let names: string[];
    try {
      names = await readdir(dir);
    } catch {
      continue;
    }
    for (const name of names.sort()) {
      if (++seen > WALK_MAX || found.length >= SELF_HASH_MAX_FILES) break;
      const path = join(dir, name);
      const st = await lstat(path).catch(() => undefined);
      if (st?.isDirectory()) queue.push(path);
      else if (st?.isFile() && st.mode & 0o111 && st.size <= SELF_HASH_MAX_BYTES) found.push(path);
    }
  }
  const hashes = new Set<string>();
  for (const path of found) {
    const h = await sha256(path).catch(() => undefined);
    if (h) hashes.add(h);
  }
  return [...hashes].sort();
}

function sha256(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(path)
      .on('data', (chunk) => hash.update(chunk))
      .on('error', reject)
      .on('end', () => resolve(hash.digest('hex')));
  });
}
