// Where the app pin (appPin.ts) is kept, so that nothing but the helper can
// make a file the pin, and the pin doesn't depend on the file staying put.
//
//   Signed      The pin file carries an HMAC-SHA256 over its contents, keyed
//               by a random key only root can read (app-pin.key, 0600, made
//               on first use). A file without a valid signature is never
//               the pin, whatever put it there: a planted file, an old one
//               restored, or one edited. It is reported in helper.status.
//               What is signed includes the device and inode the helper
//               wrote the file as, so a copy, or a backup put back, is not
//               the pin either, and a generation the running helper only
//               ever raises, so an older pin of its own can't come back.
//               Having no pin is itself signed, so a missing file is never
//               taken to mean "no pin".
//   In memory   The helper keeps the pin and key it loaded. A pin file that
//               vanishes or stops verifying changes nothing until the helper
//               itself writes a new one (or a signed one appears).
//   Immutable   Both files carry the immutable flag (chflags uchg on macOS,
//               chattr +i on Linux where the filesystem has it), which
//               stops any rename, unlink or write, even root's. The helper
//               clears it only around its own writes. The state folder
//               itself is not flagged: the journal, rules and approvals are
//               written there all the time.
//   Watched     The files' device and inode are known (guarded), so a file
//               command whose move ends up taking one of them is undone
//               (commands/quarantine.ts); that also covers filesystems
//               without the flag.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants,
  fchmodSync,
  fstatSync,
  lstatSync,
  openSync,
  readSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { fileId } from '@vigil/core/self';
import { openNonBlocking } from '@vigil/sensors';
import { AppPin } from './appPin.js';
import type { System } from './system.js';
import type { GuardedFile } from './commands/quarantine.js';

const DOMAIN = 'vigil-app-pin-v1\n';
const MAX_FILE = 64 * 1024;

export interface PinStoreOptions {
  /** The pin file (config appPin). */
  file: string;
  /** The key file (config appPinKey). */
  keyFile: string;
  /** uid that must own the key file. 0 in production; the test's own uid in tests. */
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
  private key: Buffer | undefined;
  private pin: AppPin | undefined;
  private seen: string | undefined;
  private problem: string | undefined;
  /** The generation of the pin in memory; a file signed with a lower one is old. */
  private gen = 0;
  private readonly ids = new Map<string, string>();

  constructor(
    private readonly sys: System,
    private readonly opts: PinStoreOptions,
  ) {}

  /** At start: the key (made if there is none) and the pin, if the file verifies. */
  async load(): Promise<void> {
    this.key = this.readKey();
    if (!this.key && lstatId(this.opts.keyFile) === undefined) await this.writeKey();
    this.refresh();
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

  /** The pin and key files with the device and inode the helper last left them with. */
  guarded(): GuardedFile[] {
    return [...this.ids].map(([path, id]) => ({ path, id }));
  }

  /** Replace the pin (undefined: no pin), signed, and flagged immutable again. */
  async write(pin: AppPin | undefined): Promise<void> {
    if (!this.key) await this.writeKey();
    const gen = Math.max(this.gen + 1, this.sys.now());
    await this.writeFile(this.opts.file, 0o644, (file) => {
      const body: Record<string, unknown> = pin ? { ...pin } : { none: true };
      Object.assign(body, { file, gen });
      body.mac = this.sign(body);
      return JSON.stringify(body) + '\n';
    });
    this.pin = pin;
    this.gen = gen;
    this.problem = undefined;
    this.seen = stamp(this.opts.file);
  }

  /**
   * Put back what the helper keeps, from memory, when a file is no longer
   * the one it left (replaced, moved away or gone).
   */
  async repair(): Promise<void> {
    const keyId = this.ids.get(this.opts.keyFile);
    if (this.key && keyId !== undefined && lstatId(this.opts.keyFile) !== keyId)
      await this.writeFile(this.opts.keyFile, 0o600, () => this.key!.toString('hex') + '\n');
    const pinId = this.ids.get(this.opts.file);
    if (pinId !== undefined && lstatId(this.opts.file) !== pinId) await this.write(this.pin);
  }

  private sign(body: Record<string, unknown>): string {
    return createHmac('sha256', this.key!)
      .update(DOMAIN + canonical(body))
      .digest('hex');
  }

  /** Re-read the pin file when it changed since last looked at; keep memory unless it verifies. */
  private refresh(): void {
    const now = stamp(this.opts.file);
    if (now === this.seen) return;
    this.seen = now;
    const verified = this.verify();
    if (verified === 'invalid') {
      // Never pinned and nothing there: nothing is wrong.
      if (now === 'missing' && !this.pin && !this.ids.has(this.opts.file)) return;
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
    const id = lstatId(this.opts.file);
    if (id) this.ids.set(this.opts.file, id);
  }

  private verify(): { pin: AppPin | undefined; gen: number } | 'invalid' {
    const read = readSmall(this.opts.file);
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
    // A key changed by the helper in another process (pin-app) is picked up once.
    for (const key of [this.key, this.readKey()]) {
      if (!key) continue;
      const want = createHmac('sha256', key)
        .update(DOMAIN + canonical(body))
        .digest();
      const got = Buffer.from(body.mac, 'hex');
      if (got.length !== want.length || !timingSafeEqual(got, want)) continue;
      this.key = key;
      if (none === true && Object.keys(rest).length === 0) return { pin: undefined, gen };
      if (none !== undefined) return 'invalid';
      const parsed = AppPin.safeParse(rest);
      return parsed.success ? { pin: parsed.data, gen } : 'invalid';
    }
    return 'invalid';
  }

  /** The key, if the key file is a root-owned 0600 file holding one. */
  private readKey(): Buffer | undefined {
    const read = readSmall(this.opts.keyFile);
    if (!read) return undefined;
    const owner = this.opts.ownerUid ?? 0;
    if (read.uid !== owner || (read.mode & 0o077) !== 0) return undefined;
    const m = /^([0-9a-f]{64})\n?$/.exec(read.text);
    if (!m) return undefined;
    const id = lstatId(this.opts.keyFile);
    if (id) this.ids.set(this.opts.keyFile, id);
    return Buffer.from(m[1]!, 'hex');
  }

  private async writeKey(): Promise<void> {
    const key = randomBytes(32);
    await this.writeFile(this.opts.keyFile, 0o600, () => key.toString('hex') + '\n');
    this.key = key;
  }

  /**
   * Write `path` whole: clear its immutable flag, write a new file beside
   * it (never following a link, never reusing one), rename it into place,
   * and flag it again. The flag is cleared only here. `text` gets the new
   * file's device and inode, which the rename keeps.
   */
  private async writeFile(path: string, mode: number, text: (id: string) => string): Promise<void> {
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
  }

  /** Set or clear the immutable flag; a filesystem without it is left as it is. */
  private async flag(path: string, on: boolean): Promise<void> {
    const r =
      this.sys.platform === 'linux'
        ? await this.sys.run('chattr', [on ? '+i' : '-i', path])
        : await this.sys.run('chflags', [on ? 'uchg' : 'nouchg', path]);
    if (r.code !== 0 && on) this.opts.log?.(`could not make ${path} immutable: ${r.stderr.trim()}`);
  }
}
