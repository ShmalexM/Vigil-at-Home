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
//          (commands/selfImage.ts), and whether that image still has the
//          pinned contents: unchanged ctime and size, or else its sha256.
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
// by a helper update. The grant's approval is bound to the code on disk
// when the password was asked for (pinCandidate), and on macOS only code
// signed with Vigil's bundle id is pinned at all.
//
// The pin is kept by pinStore.ts: signed with a root-only key, held in
// memory, and flagged immutable on disk, so only the helper can set it.

import { isAbsolute } from 'node:path';
import { z } from 'zod';
import { insideInstalledRoot, looksLikeAppImage, type SelfImage } from '@vigil/core/self';
import { readCodeIdentity } from './codeDirectory.js';
import { VIGIL_BUNDLE_ID } from './config.js';
import { sameStat } from './openedFile.js';
import type { AppPinStore } from './pinStore.js';
import type { System } from './system.js';
import type { ProcessIdentity } from './commands/process.js';
import { selfImageOf } from './commands/selfImage.js';

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
    /**
     * The AppImage's ctime (ns) and size when pinned. An inode can be
     * rewritten in place; while these are unchanged it wasn't, and once
     * they change the image's contents must still hash to `sha256`. A pin
     * without them is checked by contents every time.
     */
    ctime: z
      .string()
      .regex(/^\d{1,30}$/)
      .optional(),
    size: z.number().int().nonnegative().optional(),
    /** The AppImage file's own sha256, which a program block would name. */
    sha256: z.string().regex(SHA256),
  }),
]);
export type AppPin = z.infer<typeof AppPin>;

/** The CDHash and Executable lines of `codesign -d -vvv` (written to stderr). */
export function parseCodesignIdentity(output: string): CodeIdentity | undefined {
  const cdhash = /^CDHash=([0-9a-f]{40})$/m.exec(output)?.[1];
  if (!cdhash) return undefined;
  const id: CodeIdentity = { cdhash };
  const executable = /^Executable=(\/.+)$/m.exec(output)?.[1];
  if (executable) id.executable = executable;
  const identifier = /^Identifier=(\S+)$/m.exec(output)?.[1];
  if (identifier) id.identifier = identifier;
  return id;
}

/** What codesign says about a piece of code. */
export interface CodeIdentity {
  cdhash: string;
  executable?: string;
  /** The signing identifier: the bundle id for an app bundle. */
  identifier?: string;
}

/**
 * What `target` runs, by codesign: a path (an app bundle or executable), or
 * a pid, for which codesign reads the code the kernel loaded for that
 * process rather than whatever file sits at its path now.
 */
async function codesign(sys: System, target: string): Promise<CodeIdentity | undefined> {
  const r = await sys.run('codesign', ['-d', '-vvv', target], { timeoutMs: 10_000 });
  return r.code === 0 ? parseCodesignIdentity(`${r.stderr}\n${r.stdout}`) : undefined;
}

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

export interface PinOptions {
  /** The installer's own folders (config installedSelf); an app there needs no pin. */
  installed: readonly string[];
  /** Linux: the path is known to be an AppImage. Otherwise its first bytes tell. */
  appImage?: boolean;
  /** Linux: the device and inode the file must have (a grant's image), checked on the open file. */
  expectId?: string;
}

/**
 * macOS: the main executable of the bundle at `bundle`, from its Info.plist.
 * Only a name is taken from it; the executable itself is then opened once
 * and everything pinned is read from that descriptor.
 */
async function bundleExecutable(sys: System, bundle: string): Promise<string> {
  const plist = `${bundle}/Contents/Info.plist`;
  const r = await sys.run('plutil', ['-extract', 'CFBundleExecutable', 'raw', '-o', '-', plist]);
  const name = r.stdout.trim();
  if (r.code !== 0 || !name || name.includes('/') || name === '.' || name === '..')
    throw new Error(`${bundle} names no main executable`);
  return `${bundle}/Contents/MacOS/${name}`;
}

/**
 * Root: the pin for the app at `path` (its bundle or main executable on
 * macOS, its AppImage on Linux). Undefined when the app needs none (inside
 * the installer's folder). Throws when the file can't be pinned.
 *
 * The file is opened once (O_NONBLOCK and O_NOFOLLOW: a FIFO, device,
 * folder or symlink there is refused at once), and its device, inode,
 * ctime and size come from fstat on that descriptor, its sha256 from
 * reading it, and on macOS its CDHash and signing identifier from the code
 * signature in those same bytes (codeDirectory.ts). The path is never looked
 * up again, so a file swapped in meanwhile can't lend its metadata or hash
 * to another. The file must be unchanged (fstat again) once it is hashed.
 *
 * On macOS codesign is also asked about the path afterwards, and must
 * report the same CDHash: a cross-check of the reading above (codesign is
 * what the kernel and Santa agree with), which can only refuse a pin, never
 * supply one.
 */
export async function pinFor(
  sys: System,
  path: string,
  opts: PinOptions,
): Promise<AppPin | undefined> {
  if (!isAbsolute(path)) throw new Error(`${path} is not an absolute path`);
  if (sys.platform === 'linux') return pinImage(sys, path, opts);
  if (inInstalled(sys, opts.installed, path, false)) return undefined;
  const exe = /\.app$/i.test(path) ? await bundleExecutable(sys, path) : path;
  if (inInstalled(sys, opts.installed, exe, false))
    throw new Error(`${path} has no code signature to pin`);
  const f = sys.openFile?.(exe, { nofollow: true });
  if (!f) throw new Error(`${exe} is not a regular file Vigil can pin`);
  try {
    const code = readCodeIdentity((pos, len) => f.read(pos, len));
    if (!code) throw new Error(`${exe} has no code signature to pin`);
    // Only Vigil's own code is ever pinned, by the identifier it is signed with.
    if (code.identifier !== VIGIL_BUNDLE_ID)
      throw new Error(`${exe} is not signed as ${VIGIL_BUNDLE_ID}`);
    const sha256 = await f.sha256Async();
    if (!sha256 || !sameStat(f.stat, f.restat())) throw new Error(`${exe} changed while read`);
    const checked = await codesign(sys, exe);
    if (checked?.cdhash !== code.cdhash || !sameStat(f.stat, f.restat()))
      throw new Error(`${exe} changed while read`);
    return { platform: 'darwin', path: exe, cdhash: code.cdhash, sha256 };
  } finally {
    f.close();
  }
}

/** Linux: the pin for the AppImage at `path`, all read from one descriptor (see pinFor). */
async function pinImage(sys: System, path: string, opts: PinOptions): Promise<AppPin | undefined> {
  const inside = inInstalled(sys, opts.installed, path, false);
  const f = sys.openFile?.(path, { nofollow: true });
  if (!f) {
    if (inside) return undefined;
    throw new Error(`${path} is not a regular file Vigil can pin`);
  }
  try {
    // An AppImage is never inside the installer's folder, wherever it sits.
    const appImage = opts.appImage ?? looksLikeAppImage(path, f.read(0, 16));
    if (inside && !appImage) return undefined;
    const { id: image, ctime, size } = f.stat;
    if (opts.expectId !== undefined && image !== opts.expectId)
      throw new Error(`${path} is no longer the file that was named`);
    const sha256 = await f.sha256Async();
    if (!sha256 || !sameStat(f.stat, f.restat())) throw new Error(`${path} changed while read`);
    return { platform: 'linux', path, image, ctime, size, sha256 };
  } finally {
    f.close();
  }
}

export interface RepinOptions extends PinOptions {
  /** Where the new pin is kept (pinStore.ts). */
  store: AppPinStore;
}

/** The app a self grant would pin: the grant path it came from, and its pin as computed then. */
export interface PinCandidate {
  source: string;
  pin: AppPin;
}

/**
 * When a self grant asks for the password, before the dialog appears: the
 * app the grant covers, with the identity of its code on disk right now.
 * The approval is bound to it, so what gets pinned is the code that was on
 * disk when the user was asked (repinFromGrant). That is, on macOS the first
 * of the grant's paths outside the installer's folder that is code signed
 * as Vigil (the app bundle; its main executable is read through one
 * descriptor, see pinFor, and a path that isn't such code is skipped), on
 * Linux the first of its AppImages whose open file is still the device and
 * inode the grant names. Code replaced before the request is out of scope.
 * Undefined when there is none.
 */
export async function pinCandidate(
  sys: System,
  grant: { selfPaths: readonly string[]; selfImages?: readonly SelfImage[] | undefined },
  opts: PinOptions,
): Promise<PinCandidate | undefined> {
  const candidates: { source: string; expectId?: string }[] =
    sys.platform === 'linux'
      ? (grant.selfImages ?? []).map((i) => ({ source: i.path, expectId: i.id }))
      : grant.selfPaths.map((source) => ({ source }));
  // A grant's images are AppImages, wherever they sit.
  const appImage = sys.platform === 'linux';
  for (const { source, expectId } of candidates) {
    if (inInstalled(sys, opts.installed, source, appImage)) continue;
    try {
      const pin = await pinFor(sys, source, {
        ...opts,
        appImage,
        ...(expectId ? { expectId } : {}),
      });
      if (pin) return { source, pin };
    } catch {
      // Not code Vigil can pin: try the next.
    }
  }
  return undefined;
}

/** Whether two pins name the same code: same file, and the same hashes. */
function sameCode(a: AppPin, b: AppPin): boolean {
  if (a.platform === 'darwin' && b.platform === 'darwin')
    return a.path === b.path && a.cdhash === b.cdhash && a.sha256 === b.sha256;
  if (a.platform === 'linux' && b.platform === 'linux')
    return a.path === b.path && a.image === b.image && a.sha256 === b.sha256;
  return false;
}

/**
 * After the admin password approved a self grant: pin the app bound to the
 * approval (pinCandidate), so an app updated outside the installer's folder
 * is re-pinned with the grant's one prompt instead of a helper update's.
 * The code on disk is read again and must still be the bound code, or
 * nothing is pinned and the pin stays as it was. Returns the new pin, if any.
 */
export async function repinFromGrant(
  sys: System,
  bound: PinCandidate,
  opts: RepinOptions,
): Promise<AppPin | undefined> {
  let pin: AppPin | undefined;
  try {
    pin = await pinFor(sys, bound.source, { ...opts, appImage: sys.platform === 'linux' });
  } catch {
    return undefined;
  }
  if (!pin || !sameCode(pin, bound.pin)) return undefined;
  await opts.store.write(pin);
  return pin;
}

/** The pinned program's hashes, which no hash block may name. */
export function pinnedHashes(pin: AppPin | undefined): string[] {
  if (!pin) return [];
  return pin.platform === 'darwin' ? [pin.cdhash, pin.sha256] : [pin.sha256];
}

/**
 * Whether the identified process runs the pinned app. Nothing runs without
 * a pin. On macOS the pid's cdhash is read once codesign is done, the
 * process is identified again: `recheck` says whether it is still the same
 * one, and if not the answer is 'changed', so a pid reused while codesign
 * ran is neither spared nor hit.
 *
 * On Linux the process must run the pinned image by device and inode, and
 * the image must still be what was pinned: while its ctime and size are as
 * pinned it hasn't been written to; once they changed, the image the process
 * runs (through /proc, so whatever its name now) must hash to the pinned
 * sha256, or there is no exemption.
 *
 * Accepted, in both directions: exec keeps the pid and start time, so the
 * recheck sees the same process whichever code it runs.
 *  - Into the pinned code: a process that execs the pinned program is the
 *    pinned program from then on, and is spared.
 *  - Away from it: a process running the pinned code can exec other code at
 *    the same path while the check runs, after codesign read the old
 *    cdhash, and is spared once on that old answer (on Linux, the image
 *    checked can likewise be the one it ran a moment before).
 * Only a process that can already run code of its choosing can make either
 * exec, so sparing it spares a program its author already controls; the
 * real app, a separate process, is untouched either way, and stopping that
 * process was never what keeps the app safe.
 */
export async function runsPinnedApp(
  sys: System,
  pin: AppPin | undefined,
  id: ProcessIdentity,
  recheck: () => Promise<ProcessIdentity | undefined>,
): Promise<boolean | 'changed'> {
  if (!pin || pin.platform !== (sys.platform ?? 'darwin')) return false;
  if (pin.platform === 'linux') return runsPinnedImage(sys, pin, id.pid);
  const running = await codesign(sys, String(id.pid));
  const after = await recheck();
  if (!after || after.started !== id.started || after.path !== id.path) return 'changed';
  return running?.cdhash === pin.cdhash;
}

type LinuxPin = Extract<AppPin, { platform: 'linux' }>;

/** Images whose contents were found to match their pin after a change, by pin and stat. */
const rehashed = new Set<string>();

/**
 * Linux: whether `pid` runs the pinned image, unchanged. The image the
 * process runs is opened once through /proc (selfImageOf names the link:
 * the process's own exe, or its mount server's), and its device, inode,
 * ctime, size and, when needed, contents all come from that descriptor.
 */
function runsPinnedImage(sys: System, pin: LinuxPin, pid: number): boolean {
  const via = selfImageOf(sys, pid, [pin.image]);
  if (!via) return false;
  const f = sys.openFile?.(via);
  if (!f) return false;
  try {
    const now = f.stat;
    if (now.id !== pin.image) return false;
    if (now.ctime === pin.ctime && now.size === pin.size) return true;
    // Written to since it was pinned (or a pin without a ctime): the contents decide.
    const key = `${pin.image}|${pin.sha256}|${now.ctime}|${now.size}`;
    if (rehashed.has(key)) return true;
    if (f.sha256() !== pin.sha256 || !sameStat(now, f.restat())) return false;
    if (rehashed.size >= 16) rehashed.clear();
    rehashed.add(key);
    return true;
  } finally {
    f.close();
  }
}
