// Where the app pin (appPin.ts) is kept, so that nothing but the helper can
// make a file the pin, and the pin doesn't depend on the file staying put.
//
//   Root-only   The pin and its key live in their own folder (config
//               appPinDir, 0700, root's). File commands act on user paths
//               only as that user (commands/transfer.ts), so none of them
//               can reach it.
//   Signed      The pin file carries an HMAC-SHA256 over its contents, keyed
//               by a random key only root can read (app-pin.key, 0600, made
//               on first use). A file without a valid signature is never
//               the pin, whatever put it there: a planted file, an old one
//               restored, or one edited. It is reported in helper.status.
//               What is signed includes the device and inode the helper
//               wrote the file as, so a copy, or a backup put back, is not
//               the pin either, and a generation the running helper only
//               ever raises, so an older pin of its own can't come back.
//               The highest generation written is also kept in a signed
//               counter beside them (app-pin.gen), read at start, so an
//               older pin put back while the helper was stopped is refused
//               too.
//               Having no pin is itself signed, so a missing file is never
//               taken to mean "no pin".
//   In memory   The helper keeps the pin and key it loaded, and checks pins
//               only with that key from then on. A pin file that vanishes
//               or stops verifying changes nothing until the helper itself
//               writes a new one (or a signed one appears). A key with no
//               pin file beside it at start is reported.
//   Immutable   Both files carry the immutable flag (chflags uchg on macOS,
//               chattr +i on Linux where the filesystem has it). The helper
//               clears it only around its own writes.
//   One queue   Writes, repairs and the tripwire run one at a time, in
//               order. The pin in memory changes only once a write is
//               complete and flagged, and a repair writes what is in memory
//               when its turn comes, never something read before.
//   Tripwire    intact() says whether the files are still the device and
//               inode the helper left (as it wrote or loaded them; reading
//               the pin for status never moves the wire); file commands
//               check it before and after every move, and refuse and log
//               when it is not. It never moves or rewrites anything.
//
// A readable copy of the pin (config appPin) is written beside the state for
// the app to see what is pinned. It is never read here.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { join } from 'node:path';
import { fileId } from '@vigil/core/self';
import { openNonBlocking } from '@vigil/sensors';
import { AppPin } from './appPin.js';
import type { System } from './system.js';

const DOMAIN = 'vigil-app-pin-v1\n';
const GEN_DOMAIN = 'vigil-app-pin-gen-v1\n';

/** The files in the pin folder. */
export const PIN_FILES = ['app-pin.json', 'app-pin.key', 'app-pin.gen'] as const;
const MAX_FILE = 64 * 1024;

export interface PinStoreOptions {
  /** The root-only folder holding the pin and its key (config appPinDir). */
  dir: string;
  /** The readable copy for the app (config appPin). */
  publicFile?: string;
  /** uid that must own the folder and key. 0 in production; the test's own uid in tests. */
  ownerUid?: number;
  log?: (msg: string) => void;
}

export interface PinStatus {
  pinned: boolean;
  path?: string;
  /** Why the file on disk is not being used, when it isn't. */
  problem?: string;
}

/** The file at `path`, read through one non-blocking, no-follow descriptor; undefined unless a small regular file. */
function readSmall(
  path: string,
): { text: string; uid: number; mode: number; id: string } | undefined {
  const fd = openNonBlocking(path, true);
  if (fd === undefined) return undefined;
  try {
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile() || st.size > MAX_FILE) return undefined;
    const buf = Buffer.alloc(Number(st.size));
    let got = 0;
    while (got < buf.length) {
      const n = readSync(fd, buf, got, buf.length - got, got);
      if (n <= 0) break;
      got += n;
    }
    return {
      text: buf.subarray(0, got).toString('utf8'),
      uid: Number(st.uid),
      mode: Number(st.mode),
      id: fileId(st.dev, st.ino),
    };
  } catch {
    return undefined;
  } finally {
    closeSync(fd);
  }
}

/** `<dev>:<ino>` of what is at `path` (not following a link), or undefined. */
export function lstatId(path: string): string | undefined {
  try {
    const st = lstatSync(path, { bigint: true });
    return fileId(st.dev, st.ino);
  } catch {
    return undefined;
  }
}

function stamp(path: string): string {
  try {
    const st = lstatSync(path, { bigint: true });
    return `${st.dev}:${st.ino}:${st.ctimeNs}:${st.size}`;
  } catch {
    return 'missing';
  }
}

/** The signed fields as one string: sorted keys, `mac` left out. */
function canonical(body: Record<string, unknown>): string {
  const keys = Object.keys(body)
    .filter((k) => k !== 'mac')
    .sort();
  return JSON.stringify(Object.fromEntries(keys.map((k) => [k, body[k]])));
}

export class AppPinStore {
  readonly file: string;
  readonly keyFile: string;
  /** The signed high-water generation. */
  readonly genFile: string;
  private key: Buffer | undefined;
  private pin: AppPin | undefined;
  private seen: string | undefined;
  private problem: string | undefined;
  /** The generation of the pin in memory; a file signed with a lower one is old. */
  private gen = 0;
  /** Device and inode of each file as the helper last left it. */
  private readonly ids = new Map<string, string>();
  private tail: Promise<unknown> = Promise.resolve();
  private writing = 0;

  constructor(
    private readonly sys: System,
    private readonly opts: PinStoreOptions,
  ) {
    this.file = join(opts.dir, 'app-pin.json');
    this.keyFile = join(opts.dir, 'app-pin.key');
    this.genFile = join(opts.dir, 'app-pin.gen');
  }

  /** Run `fn` after everything queued before it. */
  private enqueue<T>(fn: () => Promise<T> | T): Promise<T> {
    const run = this.tail.then(fn);
    this.tail = run.catch(() => undefined);
    return run;
  }

  /** At start: the folder, the key (made if there is none) and the pin, if the file verifies. */
  load(): Promise<void> {
    return this.enqueue(async () => {
      this.ensureDir();
      this.key = this.readKey();
      const hadKey = !!this.key;
      if (!this.key && lstatId(this.keyFile) === undefined) await this.writeKey();
      this.gen = Math.max(this.gen, this.readGen());
      this.refresh(true);
      if (hadKey && lstatId(this.file) === undefined) {
        this.problem = 'the pin file is missing; no app is pinned until the helper writes one';
        this.opts.log?.(`app pin: ${this.problem}`);
      }
    });
  }

  /** The folder must be a real folder, the owner's alone; made so if it is new. */
  private ensureDir(): void {
    const owner = this.opts.ownerUid ?? 0;
    mkdirSync(this.opts.dir, { recursive: true, mode: 0o700 });
    const st = lstatSync(this.opts.dir);
    if (!st.isDirectory() || st.uid !== owner)
      throw new Error(`${this.opts.dir} is not a folder only the helper owns`);
    if ((st.mode & 0o077) !== 0) {
      // Opened without following a link, so the mode lands on this very folder.
      const fd = openSync(
        this.opts.dir,
        constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_DIRECTORY,
      );
      try {
        fchmodSync(fd, 0o700);
      } finally {
        closeSync(fd);
      }
    }
  }

  /** The pin in force: the signed file on disk if it changed, else the one in memory. */
  current(): AppPin | undefined {
    this.refresh();
    return this.pin;
  }

  status(): PinStatus {
    this.refresh();
    const s: PinStatus = { pinned: !!this.pin };
    if (this.pin) s.path = this.pin.path;
    if (this.problem) s.problem = this.problem;
    return s;
  }

  /**
   * The tripwire: whether the pin and key files are still the device and
   * inode the helper left them as. Waits for writes queued before it.
   */
  intact(): Promise<boolean> {
    return this.enqueue(() => [...this.ids].every(([path, id]) => lstatId(path) === id));
  }

  /** Replace the pin (undefined: no pin), signed, and flagged immutable again. */
  write(pin: AppPin | undefined): Promise<void> {
    return this.enqueue(() => this.commit(pin));
  }

  /**
   * Put back what the helper keeps, from memory, when a file is no longer
   * the one it left (replaced, moved away or gone). Writes the pin in force
   * when its turn in the queue comes, after reading the file again: a valid
   * signed pin there that is newer than memory is adopted instead.
   */
  repair(): Promise<void> {
    return this.enqueue(async () => {
      // A newer pin the helper signed (pin-app, say) is adopted, never overwritten.
      this.seen = undefined;
      this.refresh(true);
      const keyId = this.ids.get(this.keyFile);
      if (this.key && keyId !== undefined && lstatId(this.keyFile) !== keyId) {
        const key = this.key;
        await this.writeFile(this.keyFile, 0o600, () => key.toString('hex') + '\n');
      }
      const pinId = this.ids.get(this.file);
      if (pinId !== undefined && lstatId(this.file) !== pinId) await this.commit(this.pin);
      const genId = this.ids.get(this.genFile);
      if (genId !== undefined && lstatId(this.genFile) !== genId) await this.writeGen();
    });
  }

  /** Write `pin`, then, once the file is in place and flagged, make it the pin in memory. */
  private async commit(pin: AppPin | undefined): Promise<void> {
    if (!this.key) await this.writeKey();
    const key = this.key!;
    const gen = Math.max(this.gen + 1, this.sys.now());
    await this.writeFile(this.file, 0o644, (file) => {
      const body: Record<string, unknown> = pin ? { ...pin } : { none: true };
      Object.assign(body, { file, gen });
      body.mac = this.sign(key, body);
      return JSON.stringify(body) + '\n';
    });
    this.pin = pin;
    this.gen = gen;
    this.problem = undefined;
    this.seen = stamp(this.file);
    await this.writeGen();
    this.writePublic(pin);
  }

  /** Record the generation in force as the lowest any pin may have from now on. */
  private async writeGen(): Promise<void> {
    const key = this.key;
    if (!key) return;
    const gen = this.gen;
    await this.writeFile(this.genFile, 0o600, (file) => {
      const body: Record<string, unknown> = { gen, file };
      body.mac = createHmac('sha256', key)
        .update(GEN_DOMAIN + canonical(body))
        .digest('hex');
      return JSON.stringify(body) + '\n';
    });
  }

  /** The signed high-water generation, or 0 when there is none that verifies. */
  private readGen(): number {
    const read = readSmall(this.genFile);
    if (!read || !this.key) return 0;
    try {
      const body = JSON.parse(read.text) as Record<string, unknown>;
      if (body.file !== read.id || typeof body.gen !== 'number' || typeof body.mac !== 'string')
        throw new Error('unreadable');
      const want = createHmac('sha256', this.key)
        .update(GEN_DOMAIN + canonical(body))
        .digest();
      const got = Buffer.from(body.mac, 'hex');
      if (got.length !== want.length || !timingSafeEqual(got, want)) throw new Error('unsigned');
      const id = lstatId(this.genFile);
      if (id) this.ids.set(this.genFile, id);
      return body.gen;
    } catch {
      this.opts.log?.('app pin: the generation file is not the one this helper signed');
      return 0;
    }
  }

  /** The app's readable copy; a failure only means the app may ask to set the helper up again. */
  private writePublic(pin: AppPin | undefined): void {
    const path = this.opts.publicFile;
    if (!path) return;
    try {
      const tmp = `${path}.tmp`;
      rmSync(tmp, { force: true });
      const fd = openSync(
        tmp,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        0o644,
      );
      try {
        fchmodSync(fd, 0o644);
        writeSync(fd, JSON.stringify(pin ?? {}) + '\n');
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, path);
    } catch (err) {
      this.opts.log?.(`could not write ${path}: ${(err as Error).message}`);
    }
  }

  private sign(key: Buffer, body: Record<string, unknown>): string {
    return createHmac('sha256', key)
      .update(DOMAIN + canonical(body))
      .digest('hex');
  }

  /** Re-read the pin file when it changed since last looked at; keep memory unless it verifies. */
  /** Read the pin file again if it changed; `adopt` (load, repair) also moves the tripwire to it. */
  private refresh(adopt = false): void {
    // A write in progress is not the pin until it is committed.
    if (this.writing) return;
    const now = stamp(this.file);
    if (now === this.seen) return;
    this.seen = now;
    const verified = this.verify();
    if (verified === 'invalid') {
      // Never pinned and nothing there: nothing is wrong.
      if (now === 'missing' && !this.pin && !this.ids.has(this.file)) return;
      this.problem =
        now === 'missing'
          ? 'the pin file is missing; the helper keeps the pin it loaded'
          : 'the pin file is not the one this helper signed; it is ignored';
      this.opts.log?.(`app pin: ${this.problem}`);
      return;
    }
    this.pin = verified.pin;
    this.gen = verified.gen;
    this.problem = undefined;
    if (!adopt) return;
    const id = lstatId(this.file);
    if (id) this.ids.set(this.file, id);
  }

  private verify(): { pin: AppPin | undefined; gen: number } | 'invalid' {
    const read = readSmall(this.file);
    if (!read) return 'invalid';
    let body: Record<string, unknown>;
    try {
      body = JSON.parse(read.text) as Record<string, unknown>;
    } catch {
      return 'invalid';
    }
    if (typeof body !== 'object' || body === null || typeof body.mac !== 'string') return 'invalid';
    // Signed as written to this very file (not a copy), and not older than what is in force.
    const { file, gen, none, mac: _mac, ...rest } = body;
    if (file !== read.id || typeof gen !== 'number' || gen < this.gen) return 'invalid';
    // Only the key loaded at start (or written since) signs a pin.
    const key = this.key;
    if (!key) return 'invalid';
    const want = createHmac('sha256', key)
      .update(DOMAIN + canonical(body))
      .digest();
    const got = Buffer.from(body.mac, 'hex');
    if (got.length !== want.length || !timingSafeEqual(got, want)) return 'invalid';
    if (none === true && Object.keys(rest).length === 0) return { pin: undefined, gen };
    if (none !== undefined) return 'invalid';
    const parsed = AppPin.safeParse(rest);
    return parsed.success ? { pin: parsed.data, gen } : 'invalid';
  }

  /** The key, if the key file is a 0600 file of the owner's holding one. */
  private readKey(): Buffer | undefined {
    const read = readSmall(this.keyFile);
    if (!read) return undefined;
    const owner = this.opts.ownerUid ?? 0;
    if (read.uid !== owner || (read.mode & 0o077) !== 0) return undefined;
    const m = /^([0-9a-f]{64})\n?$/.exec(read.text);
    if (!m) return undefined;
    const id = lstatId(this.keyFile);
    if (id) this.ids.set(this.keyFile, id);
    return Buffer.from(m[1]!, 'hex');
  }

  private async writeKey(): Promise<void> {
    const key = randomBytes(32);
    await this.writeFile(this.keyFile, 0o600, () => key.toString('hex') + '\n');
    this.key = key;
  }

  /**
   * Write `path` whole: clear its immutable flag, write a new file beside
   * it (never following a link, never reusing one), rename it into place,
   * and flag it again. The flag is cleared only here. `text` gets the new
   * file's device and inode, which the rename keeps.
   */
  private async writeFile(path: string, mode: number, text: (id: string) => string): Promise<void> {
    this.writing++;
    try {
      if (lstatId(path) !== undefined) await this.flag(path, false);
      const tmp = `${path}.tmp`;
      rmSync(tmp, { force: true });
      const fd = openSync(
        tmp,
        constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW,
        mode,
      );
      try {
        fchmodSync(fd, mode);
        const st = fstatSync(fd, { bigint: true });
        writeSync(fd, text(fileId(st.dev, st.ino)));
      } finally {
        closeSync(fd);
      }
      renameSync(tmp, path);
      await this.flag(path, true);
      const id = lstatId(path);
      if (id) this.ids.set(path, id);
    } finally {
      this.writing--;
    }
  }

  /** Set or clear the immutable flag; a filesystem without it is left as it is. */
  private async flag(path: string, on: boolean): Promise<void> {
    const r = await setImmutable(this.sys, path, on);
    if (r.code !== 0 && on) this.opts.log?.(`could not make ${path} immutable: ${r.stderr.trim()}`);
  }
}

function setImmutable(sys: System, path: string, on: boolean) {
  return sys.platform === 'linux'
    ? sys.run('chattr', [on ? '+i' : '-i', path])
    : sys.run('chflags', [on ? 'uchg' : 'nouchg', path]);
}

/**
 * Remove the pin folder and the readable copy (uninstall, `vigil-helper
 * pin-remove`): clear the immutable flag on each file in it, then remove it.
 */
export async function removePinStore(sys: System, dir: string, publicFile?: string): Promise<void> {
  for (const name of PIN_FILES) {
    const path = join(dir, name);
    if (lstatId(path) !== undefined) await setImmutable(sys, path, false);
  }
  rmSync(dir, { recursive: true, force: true });
  if (publicFile) {
    rmSync(publicFile, { force: true });
    rmSync(`${publicFile}.tmp`, { force: true });
  }
}
