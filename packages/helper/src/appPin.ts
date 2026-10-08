// The app the helper was installed for, pinned by root.
//
// Until the user approves a self grant (fastpath.ts), an app running from
// outside the installer's folder is an ordinary program to the helper's
// rules. What keeps them off it is this pin: install.sh runs as root, behind
// the admin password, and records the identity of the app that asked for
// the install. Whenever the helper is about to pause, stop or block a
// program by hash, it checks the target against the pin itself:
//
//   macOS  the cdhash of the code the kernel loaded for the target pid
//          (codesign on the pid), against the cdhash of the app's main
//          executable recorded at install.
//   Linux  whether the target runs from the pinned AppImage, by device and
//          inode, checked the way the self floor checks it
//          (commands/selfImage.ts).
//
// A match is refused, and so is a hash block naming the pinned program's
// sha256 (or, on macOS, its cdhash). Nothing a client says is part of the
// check, and any process running the pinned code is the app, so a copy of it
// gains nothing it couldn't already be. Nothing else gets weaker. Without a
// pin, or when the pin doesn't match (another app, or an app updated since),
// there is no protection.
//
// Only an app outside the installer's folder (/Applications/Vigil at
// Home.app, /opt/Vigil at Home) is pinned: one inside it is protected by
// path already, so it has no pin, an update in place asks for nothing, and
// no target is ever looked up. An AppImage is never inside it, wherever it
// sits: Vigil runs from the image's own mount, which the folder's protection
// doesn't reach. An app outside it is re-pinned by the next
// self grant the password approves that covers it (repinFromGrant), or else
// by a helper update.

import {
  chmodSync,
  closeSync,
  constants,
  fstatSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { isAbsolute } from 'node:path';
import { z } from 'zod';
import { FileHasher } from '@vigil/sensors';
import { insideInstalledRoot, looksLikeAppImage, type SelfImage } from '@vigil/core/self';
import type { System } from './system.js';
import type { ProcessIdentity } from './commands/process.js';
import { runsFromSelfImage } from './commands/selfImage.js';

const SHA256 = /^[0-9a-f]{64}$/;
/** Santa's CDHASH identifiers: the first 20 bytes of the CodeDirectory hash. */
const CDHASH = /^[0-9a-f]{40}$/;

export const AppPin = z.discriminatedUnion('platform', [
  z.object({
    platform: z.literal('darwin'),
    /** The main executable, as pinned. For people reading the file. */
    path: z.string(),
    cdhash: z.string().regex(CDHASH),
    sha256: z.string().regex(SHA256),
  }),
  z.object({
    platform: z.literal('linux'),
    path: z.string(),
    /** The AppImage's `fileId`, device and inode. */
    image: z.string().regex(/^\d+:\d+$/),
    /** The AppImage file's own sha256, which a program block would name. */
    sha256: z.string().regex(SHA256),
  }),
]);
export type AppPin = z.infer<typeof AppPin>;

/** The pinned app, or undefined when there is none or the file doesn't parse. */
export function readPin(file: string): AppPin | undefined {
  try {
    const parsed = AppPin.safeParse(JSON.parse(readFileSync(file, 'utf8')));
    return parsed.success ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}

/** Replace the pin; undefined removes it. Readable by all, so the app can tell it is pinned. */
export function writePin(file: string, pin: AppPin | undefined): void {
  if (!pin) {
    rmSync(file, { force: true });
    return;
  }
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, JSON.stringify(pin) + '\n', { mode: 0o644 });
  chmodSync(tmp, 0o644);
  renameSync(tmp, file);
}

/** The CDHash and Executable lines of `codesign -d -vvv` (written to stderr). */
export function parseCodesignIdentity(
  output: string,
): { cdhash: string; executable?: string } | undefined {
  const cdhash = /^CDHash=([0-9a-f]{40})$/m.exec(output)?.[1];
  if (!cdhash) return undefined;
  const executable = /^Executable=(\/.+)$/m.exec(output)?.[1];
  return executable ? { cdhash, executable } : { cdhash };
}

/**
 * What `target` runs, by codesign: a path (an app bundle or executable), or
 * a pid, for which codesign reads the code the kernel loaded for that
 * process rather than whatever file sits at its path now.
 */
async function codesign(
  sys: System,
  target: string,
): Promise<{ cdhash: string; executable?: string } | undefined> {
  const r = await sys.run('codesign', ['-d', '-vvv', target], { timeoutMs: 10_000 });
  return r.code === 0 ? parseCodesignIdentity(`${r.stderr}\n${r.stdout}`) : undefined;
}

const sha256Of = (p: string) => new FileHasher({ maxBytes: 4 * 1024 ** 3 }).sha256(p);

/**
 * Whether `path` is inside the installer's own folder, which the helper
 * already protects by path: an app there is never pinned. An AppImage never
 * is, wherever it sits (insideInstalledRoot).
 */
function inInstalled(
  sys: System,
  installed: readonly string[],
  path: string,
  appImage: boolean,
): boolean {
  return insideInstalledRoot(path, sys.platform ?? 'darwin', { roots: installed, appImage });
}

/** Linux: whether the file at `path` is an AppImage, by its name or its first bytes. */
function isAppImage(sys: System, path: string): boolean {
  if (sys.platform !== 'linux') return false;
  if (looksLikeAppImage(path)) return true;
  let fd: number | undefined;
  try {
    // Non-blocking, and only a regular file is read, so a FIFO never stalls the helper.
    fd = openSync(path, constants.O_RDONLY | constants.O_NONBLOCK);
    if (!fstatSync(fd).isFile()) return false;
    const head = Buffer.alloc(16);
    const n = readSync(fd, head, 0, head.length, 0);
    return looksLikeAppImage(path, head.subarray(0, n));
  } catch {
    return false;
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

export interface PinOptions {
  /** The installer's own folders (config installedSelf); an app there needs no pin. */
  installed: readonly string[];
  sha256?: (path: string) => string | undefined;
  /** Linux: whether the path is an AppImage. Read from the file when not given. */
  appImage?: boolean;
}

/**
 * Root: the pin for the app at `path` (its bundle or main executable on
 * macOS, its AppImage on Linux). Undefined when the app needs none (inside
 * the installer's folder). Throws when the file can't be pinned.
 */
export async function pinFor(
  sys: System,
  path: string,
  opts: PinOptions,
): Promise<AppPin | undefined> {
  if (!isAbsolute(path)) throw new Error(`${path} is not an absolute path`);
  const hash = opts.sha256 ?? sha256Of;
  const appImage = opts.appImage ?? isAppImage(sys, path);
  if (inInstalled(sys, opts.installed, path, appImage)) return undefined;
  if (sys.platform === 'linux') {
    const image = sys.fileId?.(path);
    const sha256 = hash(path);
    if (!image || !sha256) throw new Error(`${path} is not a file Vigil can pin`);
    return { platform: 'linux', path, image, sha256 };
  }
  const id = await codesign(sys, path);
  const exe = id?.executable ?? path;
  if (!id || inInstalled(sys, opts.installed, exe, false))
    throw new Error(`${path} has no code signature to pin`);
  const sha256 = hash(exe);
  if (!sha256) throw new Error(`${exe} can't be read`);
  return { platform: 'darwin', path: exe, cdhash: id.cdhash, sha256 };
}

export interface RepinOptions extends PinOptions {
  pinFile: string;
}

/**
 * After the admin password approved a self grant: pin the app it covers, so
 * an app updated outside the installer's folder is re-pinned with the
 * grant's one prompt instead of a helper update's. What the password just
 * approved is what gets pinned: on macOS the first of the grant's paths
 * outside the installer's folder that is signed code (the app bundle; its
 * cdhash and main executable come from codesign on disk, and a path that
 * isn't code is skipped), on Linux the
 * first of its AppImages that is still the file at its path. Anything else
 * leaves the pin as it was. Returns the new pin, if any.
 */
export async function repinFromGrant(
  sys: System,
  grant: { selfPaths: readonly string[]; selfImages?: readonly SelfImage[] | undefined },
  opts: RepinOptions,
): Promise<AppPin | undefined> {
  const candidates =
    sys.platform === 'linux'
      ? (grant.selfImages ?? []).filter((i) => sys.fileId?.(i.path) === i.id).map((i) => i.path)
      : grant.selfPaths;
  // A grant's images are AppImages, wherever they sit.
  const appImage = sys.platform === 'linux';
  for (const path of candidates) {
    if (inInstalled(sys, opts.installed, path, appImage)) continue;
    let pin: AppPin | undefined;
    try {
      pin = await pinFor(sys, path, { ...opts, appImage });
    } catch {
      continue;
    }
    if (!pin) continue;
    writePin(opts.pinFile, pin);
    return pin;
  }
  return undefined;
}

/** The pinned program's hashes, which no hash block may name. Reads only the pin. */
export function pinnedHashes(pinFile: string): string[] {
  const pin = readPin(pinFile);
  if (!pin) return [];
  return pin.platform === 'darwin' ? [pin.cdhash, pin.sha256] : [pin.sha256];
}

/**
 * Whether the identified process runs the pinned app. Nothing runs without
 * a pin. On macOS the pid's cdhash is read once codesign is done, the
 * process is identified again: `recheck` says whether it is still the same
 * one, and if not the answer is 'changed', so a pid reused while codesign
 * ran is neither spared nor hit.
 */
export async function runsPinnedApp(
  sys: System,
  pinFile: string,
  id: ProcessIdentity,
  recheck: () => Promise<ProcessIdentity | undefined>,
): Promise<boolean | 'changed'> {
  const pin = readPin(pinFile);
  if (!pin || pin.platform !== (sys.platform ?? 'darwin')) return false;
  if (pin.platform === 'linux') return runsFromSelfImage(sys, id.pid, [pin.image]);
  const running = await codesign(sys, String(id.pid));
  const after = await recheck();
  if (!after || after.started !== id.started || after.path !== id.path) return 'changed';
  return running?.cdhash === pin.cdhash;
}
