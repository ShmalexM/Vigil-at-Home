// The app the helper was installed for, pinned by root at install time.
//
// Until the user approves a self grant (fastpath.ts), an app running from
// outside the installer's folder is an ordinary program to the helper's
// rules. What keeps those rules off the app that is talking to the helper is
// this pin: install.sh runs as root, behind the admin password, and records
// the identity of the app that asked for the install. A connection to the
// helper's socket counts as that app only when the kernel says who the peer
// is (peer.ts) and that process's running code matches the pin:
//
//   macOS  the cdhash of the app's main executable, as the kernel loaded it
//          for the running process (codesign on the pid), against the
//          cdhash codesign read from the file at install time.
//   Linux  the AppImage by device and inode, checked the way the self floor
//          checks it (commands/selfImage.ts). A .deb or .rpm install lives in
//          the installer's root-owned folder, which is protected already.
//
// What a verified peer gets is narrow: the helper will not pause or stop that
// one process, or block its program's hashes (the pinned sha256, and on macOS
// the cdhash), for as long as it stays connected. Nothing the client says is
// part of the check, and nothing else gets weaker. Without a pin, or when
// the pin doesn't match (another app, or an app updated since the install),
// there is no protection.
//
// Only an app outside the installer's folder (/Applications/Vigil at
// Home.app, /opt/Vigil at Home) is pinned: one inside it is protected by
// path already, so it has no pin, an update in place asks for nothing, and
// no connection is looked up. An app outside it is re-pinned by the next
// self grant the password approves (repinFromGrant), or else by a helper
// update.

import { chmodSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { z } from 'zod';
import { FileHasher } from '@vigil/sensors';
import { selfRoots, underSelfRoot, type SelfImage } from '@vigil/core/self';
import type { System } from './system.js';
import { identifyProcess } from './commands/process.js';
import { runsFromSelfImage } from './commands/selfImage.js';
import { peerPid } from './peer.js';

const SHA256 = /^[0-9a-f]{64}$/;
/** Santa's CDHASH identifiers: the first 20 bytes of the CodeDirectory hash. */
const CDHASH = /^[0-9a-f]{40}$/;

export const AppPin = z.discriminatedUnion('platform', [
  z.object({
    platform: z.literal('darwin'),
    /** The main executable, as install.sh was given it. For people reading the file. */
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

/** The CDHash line of `codesign -d -vvv` (written to stderr). */
export function parseCdhash(output: string): string | undefined {
  return /^CDHash=([0-9a-f]{40})$/m.exec(output)?.[1];
}

/**
 * The cdhash of what `target` runs: a path, or a pid, for which codesign
 * reads the code the kernel loaded for that process rather than whatever
 * file sits at its path now.
 */
async function cdhash(sys: System, target: string): Promise<string | undefined> {
  const r = await sys.run('codesign', ['-d', '-vvv', target], { timeoutMs: 10_000 });
  return r.code === 0 ? parseCdhash(`${r.stderr}\n${r.stdout}`) : undefined;
}

export interface PinOptions {
  /** The installer's own folders (config installedSelf); an app there needs no pin. */
  installed: readonly string[];
  sha256?: (path: string) => string | undefined;
}

/**
 * Root, at install: the pin for the app at `path` (its main executable on
 * macOS, its AppImage on Linux). Undefined when the app needs none (Linux,
 * installed in the installer's folder). Throws when the file can't be pinned.
 */
export async function pinFor(
  sys: System,
  path: string,
  opts: PinOptions,
): Promise<AppPin | undefined> {
  if (!isAbsolute(path)) throw new Error(`${path} is not an absolute path`);
  const hash = opts.sha256 ?? sha256Of;
  if (inInstalled(sys, opts.installed, path)) return undefined;
  if (sys.platform === 'linux') {
    const image = sys.fileId?.(path);
    const sha256 = hash(path);
    if (!image || !sha256) throw new Error(`${path} is not a file Vigil can pin`);
    return { platform: 'linux', path, image, sha256 };
  }
  const cd = await cdhash(sys, path);
  const sha256 = hash(path);
  if (!cd || !sha256) throw new Error(`${path} has no code signature to pin`);
  return { platform: 'darwin', path, cdhash: cd, sha256 };
}

const sha256Of = (p: string) => new FileHasher({ maxBytes: 4 * 1024 ** 3 }).sha256(p);

/**
 * Whether `path` is inside the installer's own folder, which the helper
 * already protects by path: an app there is never pinned, so an update in
 * place asks for nothing and connections cost nothing to check.
 */
function inInstalled(sys: System, installed: readonly string[], path: string): boolean {
  const caseless = sys.platform !== 'linux';
  return underSelfRoot(selfRoots(installed, caseless), path, caseless);
}

export interface RepinOptions extends PinOptions {
  socketPath: string;
  pinFile: string;
  /** For tests: the helper's own pid. */
  self?: number;
}

/**
 * After the admin password approved a self grant: pin the app that asked
 * for it, so an app updated outside the installer's folder is re-pinned
 * with the grant's one prompt instead of a helper update's. Only the
 * process the kernel names on the connection the grant came from counts,
 * and only when what it runs is inside what the password just approved:
 *
 *   macOS  its executable is inside one of the grant's paths, and the
 *          file there has the cdhash the running process has (so the
 *          sha256 pinned is of the code that runs).
 *   Linux  it runs from one of the grant's AppImages (device and inode).
 *
 * Anything else leaves the pin as it was. Returns the new pin, if any.
 */
export async function repinFromGrant(
  sys: System,
  fd: number,
  grant: { selfPaths: readonly string[]; selfImages?: readonly SelfImage[] | undefined },
  opts: RepinOptions,
): Promise<AppPin | undefined> {
  const pid = await peerPid(sys, fd, opts.socketPath, opts.self);
  if (pid === undefined) return undefined;
  const id = await identifyProcess(sys, pid);
  if (!id || inInstalled(sys, opts.installed, id.path)) return undefined;
  const hash = opts.sha256 ?? sha256Of;
  let pin: AppPin | undefined;
  if (sys.platform === 'linux') {
    const image = (grant.selfImages ?? []).find(
      (i) => sys.fileId?.(i.path) === i.id && runsFromSelfImage(sys, pid, [i.id]),
    );
    const sha256 = image && hash(image.path);
    if (image && sha256) pin = { platform: 'linux', path: image.path, image: image.id, sha256 };
  } else {
    const caseless = true;
    if (!underSelfRoot(selfRoots(grant.selfPaths, caseless), id.path, caseless)) return undefined;
    const running = await cdhash(sys, String(pid));
    const onDisk = await cdhash(sys, id.path);
    const sha256 = running && running === onDisk ? hash(id.path) : undefined;
    if (running && sha256) pin = { platform: 'darwin', path: id.path, cdhash: running, sha256 };
  }
  if (!pin) return undefined;
  // Still the same process.
  const after = await identifyProcess(sys, pid);
  if (!after || after.started !== id.started) return undefined;
  writePin(opts.pinFile, pin);
  return pin;
}

/** A connected process verified as the pinned app, and the program hashes it runs. */
export interface ProtectedPeer {
  pid: number;
  /** Its start time as ps prints it, so a reused pid is never mistaken for it. */
  started: string;
  hashes: readonly string[];
}

export interface PeerCheckOptions {
  socketPath: string;
  pinFile: string;
  /** For tests: the helper's own pid. */
  self?: number;
}

/**
 * The process on the other end of the connection on `fd`, if it is the
 * pinned app. Anything less than a match gives undefined.
 */
export async function verifyPeer(
  sys: System,
  fd: number,
  opts: PeerCheckOptions,
): Promise<ProtectedPeer | undefined> {
  const pin = readPin(opts.pinFile);
  if (!pin || pin.platform !== (sys.platform ?? 'darwin')) return undefined;
  const pid = await peerPid(sys, fd, opts.socketPath, opts.self);
  if (pid === undefined) return undefined;
  const before = await identifyProcess(sys, pid);
  if (!before) return undefined;
  const matches =
    pin.platform === 'darwin'
      ? (await cdhash(sys, String(pid))) === pin.cdhash
      : runsFromSelfImage(sys, pid, [pin.image]);
  if (!matches) return undefined;
  // Still the same process: not gone and its pid reused while checking.
  const after = await identifyProcess(sys, pid);
  if (!after || after.started !== before.started || after.path !== before.path) return undefined;
  return {
    pid,
    started: before.started,
    hashes: pin.platform === 'darwin' ? [pin.cdhash, pin.sha256] : [pin.sha256],
  };
}
