// Certificates for the local Santa sync server, and the store that keeps them.
//
// A small private CA (pinned in Santa through ServerAuthRootsFile) signs a
// short-lived server certificate for 127.0.0.1/localhost. Apple's TLS stack
// rejects server certificates valid for more than 825 days, and wants the
// serverAuth EKU plus a subjectAltName, so the leaf gets 397 days and is
// renewed by the helper well before it expires.
//
// The same CA signs a client certificate that Santa presents on every sync
// (ClientAuthCertificateFile in the profile). The helper's server requires it
// and pins its SHA-256, so other local programs can't sync in Santa's place.
// Santa opens that file again on every sync: santasyncservice builds a new
// MOLAuthenticatingURLSession per sync, which reads ClientAuthCertificateFile
// with SecPKCS12Import when the server asks for a certificate. So renewing it
// under the same path and password needs no new profile. The pin of the
// certificate a renewal replaced is still taken for 30 days, for a sync that
// was already under way or a Santa that cached the old identity.
//
// Everything that makes up the identity (CA, server and client certificates
// and keys, the PKCS#12 Santa reads, its password, the pin, the previous pin,
// the pins a recovery revoked and whether the certificate is required) is one
// version, written whole into its own folder and never changed afterwards:
//
//   santa-sync/                  0755 root
//     versions/<id>/             0750 root:nobody
//       ca.pem server.pem client.pem          0644
//       client.p12                            0440 root:nobody
//       ca.key server.key client.key client.p12.pass identity.json   0600 root
//     current -> versions/<id>   switched by one atomic rename
//     ca.pem -> current/ca.pem          the paths Santa's profile names
//     client.p12 -> current/client.p12
//     installed                  written last on the first start
//
// A crash at any point leaves `current` on a complete version, the old one or
// the new one. Every change runs through one lock (SyncIdentityStore), so two
// changes never start from the same version and lose each other's work.
//
// Who reads client.p12: santasyncservice drops from root to the user nobody
// before syncing. This assumes it takes nobody's primary group as well
// (macOS: uid -2, gid -2 "nobody"), as Santa's DropRootPrivileges does with
// getpwnam("nobody")->pw_gid; nothing in this repository names another group.
// Root owns the file and its folder, with group nobody and no write bit, so a
// process running as nobody can read the identity but can't replace,
// truncate or chmod it. Accepted: code running as nobody, working with a
// process of the user's, could still copy the identity out and sync in
// Santa's place. Moving the identity into the System keychain, where only
// Santa could use it, is left for later.
//
// Uses /usr/bin/openssl (LibreSSL on macOS), driven only with config files so
// it works on LibreSSL versions without -addext.

import { execFile } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  closeSync,
  existsSync,
  fsyncSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  rmSync,
  symlinkSync,
  writeFileSync,
  writeSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, createPrivateKey, randomBytes, X509Certificate } from 'node:crypto';

/** The files of one identity version, by role. */
export const IDENTITY_FILES = {
  caKey: 'ca.key',
  caCert: 'ca.pem',
  serverKey: 'server.key',
  serverCert: 'server.pem',
  clientKey: 'client.key',
  clientCert: 'client.pem',
  clientP12: 'client.p12',
  clientP12Password: 'client.p12.pass',
  state: 'identity.json',
} as const;
export type IdentityFile = keyof typeof IDENTITY_FILES;

/** Written in this order; identity.json last. */
const FILE_ORDER: IdentityFile[] = [
  'caKey',
  'caCert',
  'serverKey',
  'serverCert',
  'clientKey',
  'clientCert',
  'clientP12Password',
  'clientP12',
  'state',
];

const FILE_MODE: Record<IdentityFile, number> = {
  caKey: 0o600,
  caCert: 0o644,
  serverKey: 0o600,
  serverCert: 0o644,
  clientKey: 0o600,
  clientCert: 0o644,
  clientP12: 0o440,
  clientP12Password: 0o600,
  state: 0o600,
};

/** A version folder: root and group nobody may enter and read, nobody may not write. */
export const VERSION_DIR_MODE = 0o750;

export interface SyncTlsPaths {
  dir: string;
  versions: string;
  /** The link to the version in use. */
  current: string;
  /** Written last on the first start; its absence means the first start never finished. */
  installed: string;
  /** Through `current`. */
  caKey: string;
  caCert: string;
  serverKey: string;
  serverCert: string;
  clientKey: string;
  clientCert: string;
  /** The path Santa's profile names (a link into `current`). */
  clientP12: string;
  clientP12Password: string;
  state: string;
  /** The CA path Santa's profile names (a link into `current`). */
  caCertLink: string;
}

export function syncTlsPaths(dir: string): SyncTlsPaths {
  const current = join(dir, 'current');
  return {
    dir,
    versions: join(dir, 'versions'),
    current,
    installed: join(dir, 'installed'),
    caKey: join(current, IDENTITY_FILES.caKey),
    caCert: join(current, IDENTITY_FILES.caCert),
    serverKey: join(current, IDENTITY_FILES.serverKey),
    serverCert: join(current, IDENTITY_FILES.serverCert),
    clientKey: join(current, IDENTITY_FILES.clientKey),
    clientCert: join(current, IDENTITY_FILES.clientCert),
    clientP12: join(dir, IDENTITY_FILES.clientP12),
    clientP12Password: join(current, IDENTITY_FILES.clientP12Password),
    state: join(current, IDENTITY_FILES.state),
    caCertLink: join(dir, IDENTITY_FILES.caCert),
  };
}

/** The flat layout earlier versions wrote straight into santa-sync/. */
const LEGACY = {
  caKey: 'ca.key',
  caCert: 'ca.pem',
  serverKey: 'server.key',
  serverCert: 'server.pem',
  clientKey: 'client.key',
  clientCert: 'client.pem',
  clientP12: 'client.p12',
  clientP12Password: 'client.p12.pass',
  prevPin: 'client.prev.json',
  required: 'client-auth-required',
} as const;

function openssl(bin: string, args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: 30_000 }, (err, stdout, stderr) => {
      if (err) reject(new Error(`openssl ${args[0]} failed: ${stderr || err.message}`));
      else resolve(stdout);
    });
  });
}

const RENEW_BEFORE_MS = 30 * 24 * 3600 * 1000;
/** How long the replaced client certificate is still taken after a renewal. */
export const CLIENT_PIN_OVERLAP_MS = 30 * 24 * 3600 * 1000;
/** Revoked pins kept, newest last. */
const MAX_REVOKED = 16;

/** SHA-256 of a PEM certificate's DER encoding, as lowercase hex. */
export function certFingerprint(pem: string | Buffer): string {
  return createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');
}

function expiresAt(pem: Buffer | undefined): number | null {
  try {
    return pem ? Date.parse(new X509Certificate(pem).validTo) : null;
  } catch {
    return null;
  }
}

function needsRenewal(pem: Buffer | undefined, now: number): boolean {
  const at = expiresAt(pem);
  return at === null || at - now < RENEW_BEFORE_MS;
}

/** Whether cert is issued by ca and belongs to key. */
function pairOk(key: Buffer | undefined, cert: Buffer | undefined, ca?: Buffer): boolean {
  if (!key || !cert) return false;
  try {
    const x = new X509Certificate(cert);
    if (!x.checkPrivateKey(createPrivateKey(key))) return false;
    return ca
      ? x.checkIssued(new X509Certificate(ca)) && x.verify(new X509Certificate(ca).publicKey)
      : true;
  } catch {
    return false;
  }
}

/**
 * The SHA-256 pin of the certificate inside a PKCS#12 file, read with openssl
 * the way Santa will read it, or null when it doesn't open.
 */
export async function p12Fingerprint(
  p12: string,
  passwordFile: string,
  opensslBin = '/usr/bin/openssl',
): Promise<string | null> {
  try {
    const out = await openssl(opensslBin, [
      'pkcs12',
      '-in',
      p12,
      '-nokeys',
      '-clcerts',
      '-passin',
      `file:${passwordFile}`,
    ]);
    const pem = /-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/.exec(out);
    return pem ? certFingerprint(pem[0]) : null;
  } catch {
    return null;
  }
}

/**
 * macOS's nobody (uid -2), the user santasyncservice drops to before syncing.
 */
export const SANTA_SYNC_UID = 0xfffffffe;
/** nobody's primary group on macOS (gid -2); see the note at the top. */
export const SANTA_SYNC_GID = 0xfffffffe;

export interface Owner {
  uid: number;
  gid: number;
}

/** root:nobody when running as root on macOS; left as is otherwise (tests, Linux). */
function defaultOwner(): Owner | false {
  return process.platform === 'darwin' && process.getuid?.() === 0
    ? { uid: 0, gid: SANTA_SYNC_GID }
    : false;
}

/** Everything a version records besides its certificate files. */
export interface IdentityState {
  v: 1;
  /** SHA-256 of client.pem, which client.p12 holds. */
  pin: string;
  /** The certificate a renewal replaced, taken until `until`. */
  previous: { fingerprint: string; until: number } | null;
  /** Pins a recovery dropped. Never taken again, never brought back as `previous`. */
  revoked: string[];
  /** Whether the sync port takes only Santa's certificate. */
  required: boolean;
}

const PIN_RE = /^[a-f0-9]{64}$/;

function parseState(raw: string): IdentityState | null {
  try {
    const s = JSON.parse(raw) as Partial<IdentityState>;
    if (s.v !== 1 || typeof s.pin !== 'string' || !PIN_RE.test(s.pin)) return null;
    const prev = s.previous;
    const previous =
      prev &&
      typeof prev.fingerprint === 'string' &&
      PIN_RE.test(prev.fingerprint) &&
      typeof prev.until === 'number'
        ? { fingerprint: prev.fingerprint, until: prev.until }
        : null;
    const revoked = Array.isArray(s.revoked)
      ? s.revoked.filter((p): p is string => typeof p === 'string' && PIN_RE.test(p))
      : [];
    return { v: 1, pin: s.pin, previous, revoked, required: s.required === true };
  } catch {
    return null;
  }
}

type Contents = Record<Exclude<IdentityFile, 'state'>, Buffer>;

/** A step of writing a version, for tests that stop it partway. */
export type IdentityStep = IdentityFile | 'swap' | 'links' | 'installed';

/** A change that would let Santa sync without its certificate, asked for without the admin password. */
export class IdentityApprovalNeeded extends Error {
  constructor() {
    super('lowering the sync certificate requirement needs the admin password');
    this.name = 'IdentityApprovalNeeded';
  }
}

export interface IdentityStoreOptions {
  opensslBin?: string;
  /** Who owns client.p12 and the version folders; see defaultOwner. */
  owner?: Owner | false;
  now?: () => number;
  log?: (msg: string) => void;
  /** Tests: called before each step of writing a version. Throwing stands in for a crash there. */
  beforeStep?: (step: IdentityStep) => void;
  /** How long to wait before writing the required flag again after it failed. */
  retryMs?: number;
}

/** What helper.status reports about the identity. */
export interface IdentityStatus {
  /** A complete identity is in place. */
  issued: boolean;
  /** Whether the sync port takes only Santa's certificate (in force now). */
  required: boolean;
  /** Whether client.p12 held the pinned certificate when last read; null before the first check. */
  p12Valid: boolean | null;
  /** When the client certificate expires. */
  expiresAt: number | null;
  /** When the first start finished (the `installed` marker). */
  installedAt: number | null;
  /** Something about the identity that needs attention, or null. */
  problem: string | null;
}

/**
 * Santa's sync identity on disk, changed only through one lock: first start,
 * renewal, recovery (reissue) and setting the required flag each write a
 * whole new version and switch `current` to it. In memory, `required` only
 * ever rises outside an approved reissue: a failed write keeps it raised and
 * tries again.
 */
export class SyncIdentityStore {
  readonly paths: SyncTlsPaths;
  private queue: Promise<unknown> = Promise.resolve();
  private state: IdentityState | null = null;
  private requiredNow = false;
  private persistError: string | null = null;
  private p12Valid: boolean | null = null;
  private clientExpiresAt: number | null = null;
  private installedAt: number | null = null;
  private retry: NodeJS.Timeout | undefined;
  private closed = false;
  private readonly bin: string;
  private readonly owner: Owner | false;
  private readonly now: () => number;
  private readonly log: (msg: string) => void;

  constructor(
    dir: string,
    private readonly o: IdentityStoreOptions = {},
  ) {
    this.paths = syncTlsPaths(dir);
    this.bin = o.opensslBin ?? '/usr/bin/openssl';
    this.owner = o.owner ?? defaultOwner();
    this.now = o.now ?? Date.now;
    this.log = o.log ?? (() => {});
  }

  /** Runs fn once every change asked for before it has ended; later ones wait for it. */
  private locked<T>(fn: () => Promise<T>): Promise<T> {
    const run = this.queue.then(fn);
    this.queue = run.catch(() => {});
    return run;
  }

  /** Resolves once every change asked for so far has ended. */
  idle(): Promise<void> {
    return this.locked(async () => {});
  }

  /** Stops retrying a failed write. */
  close(): void {
    this.closed = true;
    clearTimeout(this.retry);
  }

  get required(): boolean {
    return this.requiredNow;
  }

  /** The version in use, as last written. */
  get current(): Readonly<IdentityState> | null {
    return this.state;
  }

  /** Whether a client certificate with this SHA-256 (hex, of the DER) is Santa's. */
  accepts(fingerprint: string, now = this.now()): boolean {
    const s = this.state;
    if (!s || s.revoked.includes(fingerprint)) return false;
    if (fingerprint === s.pin) return true;
    return !!s.previous && fingerprint === s.previous.fingerprint && now < s.previous.until;
  }

  status(): IdentityStatus {
    return {
      issued: this.state !== null,
      required: this.requiredNow,
      p12Valid: this.p12Valid,
      expiresAt: this.clientExpiresAt,
      installedAt: this.installedAt,
      problem:
        this.persistError ??
        (this.p12Valid === false ? 'Santa’s certificate file doesn’t match its pin' : null),
    };
  }

  /**
   * First start, or any later one: finishes or repairs whatever an earlier
   * run left. With no `installed` marker and no flat layout from an earlier
   * version, this is a new install, even if a first start was cut short:
   * the certificate is required from the start.
   */
  start(): Promise<void> {
    return this.locked(async () => {
      const p = this.paths;
      mkdirSync(p.dir, { recursive: true, mode: 0o755 });
      chmodSync(p.dir, 0o755);
      mkdirSync(p.versions, { recursive: true, mode: 0o755 });
      chmodSync(p.versions, 0o755);
      const installedAt = readTime(p.installed);
      const loaded = this.readVersion();
      if (installedAt !== null && loaded) {
        this.state = loaded.state;
        this.requiredNow = loaded.state.required;
        await this.check(this.now());
      } else if (this.isLegacy()) {
        await this.migrate();
      } else {
        // A new install, or one whose first start never finished. If the
        // marker is there but the version isn't, keep it strict too.
        await this.create();
      }
      this.ensureLinks();
      if (installedAt === null) {
        // Last: until this exists, a restart starts over in the strict state.
        this.step('installed');
        writeAtomic(p.installed, `${new Date(this.now()).toISOString()}\n`, 0o600);
      }
      // Only once the marker is down, so a cut-short move starts over from them.
      this.removeLegacy();
      this.installedAt = readTime(p.installed);
      this.prune();
    });
  }

  /**
   * Daily (and hourly) upkeep: renews certificates near expiry and repairs a
   * client.p12 that doesn't hold the pinned certificate. Never lowers
   * `required`. True when a new version was written.
   */
  renew(now = this.now()): Promise<boolean> {
    return this.locked(() => this.check(now));
  }

  /**
   * Recovery: a new client identity that owes nothing to the old one. The old
   * pins are revoked and the requirement drops, so a Santa whose profile
   * lacks the certificate syncs again until it presents the new one. That
   * loosens the port, so unless `approved`, it is refused with
   * IdentityApprovalNeeded whenever the certificate is required at the moment
   * the new version would take over.
   */
  reissue(o: { approved: boolean }): Promise<void> {
    return this.locked(async () => {
      const s = this.state;
      const cur = this.readVersion();
      if (!s || !cur) throw new Error('Santa’s sync identity isn’t set up');
      const mayLower = () => {
        if (!o.approved && (this.requiredNow || this.state?.required))
          throw new IdentityApprovalNeeded();
      };
      mayLower();
      const client = await this.withWork((work) =>
        makeClient(work, this.bin, cur.files, cur.files.clientP12Password),
      );
      const revoked = [...s.revoked, s.pin, ...(s.previous ? [s.previous.fingerprint] : [])];
      const next: IdentityState = {
        v: 1,
        pin: certFingerprint(client.clientCert),
        previous: null,
        revoked: [...new Set(revoked)].slice(-MAX_REVOKED),
        required: false,
      };
      await this.commit(
        next,
        { ...cur.files, ...client },
        {
          lower: true,
          // Decided again as the new version takes over, not only when the
          // command came in: Santa may have presented its certificate meanwhile.
          check: mayLower,
        },
      );
      this.p12Valid = true;
    });
  }

  /**
   * Santa presented this certificate. If it is the pinned one and the port
   * didn't require it yet, it does from now on: at once in memory, and on
   * disk under the lock. True when that raised the requirement.
   */
  presented(fingerprint: string): boolean {
    if (this.requiredNow || !this.accepts(fingerprint)) return false;
    this.requiredNow = true;
    void this.persistRequired();
    return true;
  }

  private persistRequired(): Promise<void> {
    return this.locked(async () => {
      clearTimeout(this.retry);
      this.retry = undefined;
      const s = this.state;
      // An approved reissue lowered it again meanwhile, or it is on disk already.
      if (!s || !this.requiredNow || s.required) {
        this.persistError = null;
        return;
      }
      try {
        const cur = this.readVersion();
        if (!cur) throw new Error('the identity in use can’t be read');
        await this.commit({ ...s, required: true }, cur.files, { lower: false });
        this.persistError = null;
      } catch (err) {
        // Still required for as long as this helper runs; say so, and try again.
        this.persistError = `Couldn’t save that Santa’s certificate is required: ${(err as Error).message}`;
        this.log(`Santa sync: ${this.persistError}; retrying`);
        if (!this.closed) {
          this.retry = setTimeout(() => void this.persistRequired(), this.o.retryMs ?? 30_000);
          this.retry.unref?.();
        }
      }
    });
  }

  /** Checks the version in use and writes a renewed or repaired one when needed. */
  private async check(now: number): Promise<boolean> {
    const s = this.state;
    const cur = this.readVersion();
    if (!s || !cur) {
      await this.create();
      return true;
    }
    const f = cur.files;
    this.fixModes();
    const caOk = pairOk(f.caKey, f.caCert) && !needsRenewal(f.caCert, now);
    if (!caOk) {
      // A CA that is gone or lapsing: start over, in the strict state.
      await this.create();
      return true;
    }
    const serverOk =
      pairOk(f.serverKey, f.serverCert, f.caCert) && !needsRenewal(f.serverCert, now);
    const p12Pin = await p12Fingerprint(
      join(this.paths.current, IDENTITY_FILES.clientP12),
      join(this.paths.current, IDENTITY_FILES.clientP12Password),
      this.bin,
    );
    const pemPin = safeFingerprint(f.clientCert);
    const matches =
      p12Pin === s.pin && pemPin === s.pin && pairOk(f.clientKey, f.clientCert, f.caCert);
    this.p12Valid = matches;
    this.clientExpiresAt = expiresAt(f.clientCert);
    const clientOk = matches && !needsRenewal(f.clientCert, now);
    if (serverOk && clientOk) return false;

    const fresh = await this.withWork(async (work) => ({
      ...(serverOk ? {} : await makeServer(work, this.bin, f)),
      ...(clientOk ? {} : await makeClient(work, this.bin, f, f.clientP12Password)),
    }));
    const next: IdentityState = { ...s, required: s.required || this.requiredNow };
    if (!clientOk) {
      next.pin = certFingerprint(fresh.clientCert!);
      // A renewal keeps taking the certificate it replaced for a while. A
      // repair doesn't: the file never held that certificate.
      if (matches) {
        const until = Math.min(expiresAt(f.clientCert) ?? 0, now + CLIENT_PIN_OVERLAP_MS);
        next.previous =
          until > now && !s.revoked.includes(s.pin) ? { fingerprint: s.pin, until } : null;
      } else {
        this.log('Santa sync: client.p12 didn’t hold the pinned certificate; issued a new one');
      }
    }
    await this.commit(next, { ...f, ...fresh }, { lower: false });
    this.p12Valid = true;
    return true;
  }

  /** A whole new identity: new CA, server and client, and the certificate required. */
  private async create(): Promise<void> {
    const old = this.readVersion();
    const files = await this.withWork(async (work) => {
      const ca = await makeCa(work, this.bin);
      const password = old?.files.clientP12Password ?? newPassword();
      const server = await makeServer(work, this.bin, ca);
      const client = await makeClient(work, this.bin, ca, password);
      return { ...ca, ...server, ...client };
    });
    await this.commit(
      {
        v: 1,
        pin: certFingerprint(files.clientCert),
        previous: null,
        revoked: this.state?.revoked ?? [],
        required: true,
      },
      files,
      { lower: false },
    );
    this.p12Valid = true;
  }

  /** Whether santa-sync/ still has the flat layout of an earlier version. */
  private isLegacy(): boolean {
    return isFile(join(this.paths.dir, LEGACY.caKey));
  }

  /**
   * Moves the flat layout of an earlier version into a version, keeping the
   * CA, certificates and password Santa already has. Whether the certificate
   * is required comes from the earlier marker: a profile from before the
   * client certificate keeps syncing until Santa first presents it.
   */
  private async migrate(): Promise<void> {
    const d = this.paths.dir;
    const read = (name: string): Buffer | undefined => {
      try {
        return readFileSync(join(d, name));
      } catch {
        return undefined;
      }
    };
    const now = this.now();
    const files = await this.withWork(async (work) => {
      const caKey = read(LEGACY.caKey);
      const caCert = read(LEGACY.caCert);
      const ca =
        caKey && caCert && pairOk(caKey, caCert) && !needsRenewal(caCert, now)
          ? { caKey, caCert }
          : await makeCa(work, this.bin);
      const serverKey = read(LEGACY.serverKey);
      const serverCert = read(LEGACY.serverCert);
      const server =
        serverKey &&
        serverCert &&
        pairOk(serverKey, serverCert, ca.caCert) &&
        !needsRenewal(serverCert, now)
          ? { serverKey, serverCert }
          : await makeServer(work, this.bin, ca);
      const password = read(LEGACY.clientP12Password) ?? newPassword();
      const clientKey = read(LEGACY.clientKey);
      const clientCert = read(LEGACY.clientCert);
      const clientP12 = read(LEGACY.clientP12);
      let keep = false;
      if (clientKey && clientCert && clientP12 && pairOk(clientKey, clientCert, ca.caCert)) {
        writeFileSync(join(work, 'old.p12'), clientP12, { mode: 0o600 });
        writeFileSync(join(work, 'old.pass'), password, { mode: 0o600 });
        const inside = await p12Fingerprint(
          join(work, 'old.p12'),
          join(work, 'old.pass'),
          this.bin,
        );
        keep = inside === safeFingerprint(clientCert) && !needsRenewal(clientCert, now);
      }
      const client = keep
        ? {
            clientKey: clientKey!,
            clientCert: clientCert!,
            clientP12: clientP12!,
            clientP12Password: password,
          }
        : await makeClient(work, this.bin, ca, password);
      return { ...ca, ...server, ...client };
    });
    let previous: IdentityState['previous'] = null;
    try {
      const p = JSON.parse(read(LEGACY.prevPin)?.toString('utf8') ?? 'null') as {
        fingerprint?: unknown;
        until?: unknown;
      } | null;
      if (
        p &&
        typeof p.fingerprint === 'string' &&
        PIN_RE.test(p.fingerprint) &&
        typeof p.until === 'number' &&
        p.until > now
      )
        previous = { fingerprint: p.fingerprint, until: p.until };
    } catch {
      // No previous pin.
    }
    await this.commit(
      {
        v: 1,
        pin: certFingerprint(files.clientCert),
        previous,
        revoked: [],
        required: existsSync(join(d, LEGACY.required)),
      },
      files,
      { lower: false },
    );
    this.p12Valid = true;
  }

  /** The flat layout's files, once the move is complete; the two links stay. */
  private removeLegacy(): void {
    for (const name of [
      LEGACY.caKey,
      LEGACY.serverKey,
      LEGACY.serverCert,
      LEGACY.clientKey,
      LEGACY.clientCert,
      LEGACY.clientP12Password,
      LEGACY.prevPin,
      LEGACY.required,
      `${LEGACY.clientP12}.new`,
    ]) {
      const path = join(this.paths.dir, name);
      if (isFile(path)) rmSync(path, { force: true });
    }
  }

  /**
   * Writes a whole version and switches `current` to it. `check` runs last,
   * right before the switch, with nothing awaited in between. Unless
   * `lower`, the requirement in memory never drops.
   */
  private async commit(
    next: IdentityState,
    files: Contents,
    o: { lower: boolean; check?: () => void },
  ): Promise<void> {
    const p = this.paths;
    const id = `${this.now().toString(36)}-${randomBytes(4).toString('hex')}`;
    const dir = join(p.versions, id);
    const link = join(p.dir, `.current-${id}`);
    let replaced: string | undefined;
    mkdirSync(dir, { mode: VERSION_DIR_MODE });
    try {
      chmodSync(dir, VERSION_DIR_MODE);
      if (this.owner) chownSync(dir, this.owner.uid, this.owner.gid);
      for (const f of FILE_ORDER) {
        this.step(f);
        const path = join(dir, IDENTITY_FILES[f]);
        writeDurable(
          path,
          f === 'state' ? JSON.stringify(next) + '\n' : files[f as Exclude<IdentityFile, 'state'>],
          FILE_MODE[f],
        );
        if (f === 'clientP12' && this.owner) chownSync(path, this.owner.uid, this.owner.gid);
      }
      syncDir(dir);
      o.check?.();
      this.step('swap');
      replaced = this.linkTarget();
      symlinkSync(join('versions', id), link);
      renameSync(link, p.current);
    } catch (err) {
      rmSync(link, { force: true });
      rmSync(dir, { recursive: true, force: true });
      throw err;
    }
    // On disk now; memory follows before anything else can fail.
    this.state = next;
    this.requiredNow = o.lower ? next.required : this.requiredNow || next.required;
    this.clientExpiresAt = expiresAt(files.clientCert);
    syncDir(p.dir);
    this.step('links');
    this.ensureLinks();
    this.prune(replaced);
  }

  /** The version `current` points at, or null when it is missing or incomplete. */
  private readVersion(): { state: IdentityState; files: Contents } | null {
    try {
      const state = parseState(readFileSync(this.paths.state, 'utf8'));
      if (!state) return null;
      const files = {} as Contents;
      for (const f of FILE_ORDER) {
        if (f === 'state') continue;
        files[f] = readFileSync(join(this.paths.current, IDENTITY_FILES[f]));
      }
      return { state, files };
    } catch {
      return null;
    }
  }

  /** The two paths Santa's profile names, as links into `current`. */
  private ensureLinks(): void {
    for (const name of [IDENTITY_FILES.caCert, IDENTITY_FILES.clientP12]) {
      const path = join(this.paths.dir, name);
      const target = join('current', name);
      try {
        if (readlinkSync(path) === target) continue;
      } catch {
        // Missing, or a file from the flat layout: replaced below in one rename.
      }
      const tmp = join(this.paths.dir, `.${name}-${randomBytes(4).toString('hex')}`);
      symlinkSync(target, tmp);
      renameSync(tmp, path);
    }
  }

  /** Puts back the owner and modes of the version in use. */
  private fixModes(): void {
    try {
      const dir = join(this.paths.dir, readlinkSync(this.paths.current));
      chmodSync(dir, VERSION_DIR_MODE);
      if (this.owner) chownSync(dir, this.owner.uid, this.owner.gid);
      for (const f of FILE_ORDER) chmodSync(join(dir, IDENTITY_FILES[f]), FILE_MODE[f]);
      if (this.owner)
        chownSync(join(dir, IDENTITY_FILES.clientP12), this.owner.uid, this.owner.gid);
    } catch (err) {
      this.log(`Santa sync: could not check the identity's file modes: ${(err as Error).message}`);
    }
  }

  /**
   * Removes versions other than the one in use and `replaced` (the one it
   * just took over from, for a reader still on it), and stray temporary links.
   */
  private prune(replaced?: string): void {
    try {
      const keep = new Set<string>();
      for (const target of [this.linkTarget(), replaced]) {
        if (target) keep.add(target.replace(/^versions\//, ''));
      }
      for (const id of readdirSync(this.paths.versions)) {
        if (!keep.has(id)) rmSync(join(this.paths.versions, id), { recursive: true, force: true });
      }
      for (const name of readdirSync(this.paths.dir)) {
        if (/^\.(current-|ca\.pem-|client\.p12-)|^installed\..*\.tmp$/.test(name))
          rmSync(join(this.paths.dir, name), { force: true });
      }
    } catch (err) {
      this.log(`Santa sync: could not prune old identities: ${(err as Error).message}`);
    }
  }

  private linkTarget(): string | undefined {
    try {
      return readlinkSync(this.paths.current);
    } catch {
      return undefined;
    }
  }

  private step(step: IdentityStep): void {
    this.o.beforeStep?.(step);
  }

  private async withWork<T>(fn: (work: string) => Promise<T>): Promise<T> {
    const work = mkdtempSync(join(tmpdir(), 'vigil-tls-'));
    try {
      return await fn(work);
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
}

function safeFingerprint(pem: Buffer | undefined): string | null {
  try {
    return pem ? certFingerprint(pem) : null;
  } catch {
    return null;
  }
}

function isFile(path: string): boolean {
  try {
    return lstatSync(path).isFile();
  } catch {
    return false;
  }
}

/** A time written as an ISO string, or null. */
function readTime(path: string): number | null {
  try {
    const t = Date.parse(readFileSync(path, 'utf8').trim());
    return Number.isFinite(t) ? t : null;
  } catch {
    return null;
  }
}

/** Writes a new file and flushes it to disk before returning. */
function writeDurable(path: string, data: string | Buffer, mode: number): void {
  const buf = typeof data === 'string' ? Buffer.from(data) : data;
  const fd = openSync(path, 'wx', mode);
  try {
    let off = 0;
    while (off < buf.length) off += writeSync(fd, buf, off, buf.length - off);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  chmodSync(path, mode);
}

/** Replaces a file in one rename. */
function writeAtomic(path: string, data: string, mode: number): void {
  const tmp = `${path}.${randomBytes(4).toString('hex')}.tmp`;
  try {
    writeDurable(tmp, data, mode);
    renameSync(tmp, path);
  } catch (err) {
    rmSync(tmp, { force: true });
    throw err;
  }
}

function syncDir(dir: string): void {
  try {
    const fd = openSync(dir, 'r');
    try {
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
  } catch {
    // Not every file system lets a folder be flushed.
  }
}

function newPassword(): Buffer {
  return Buffer.from(randomBytes(24).toString('hex') + '\n');
}

function conf(work: string, name: string, lines: string[]): string {
  const path = join(work, name);
  writeFileSync(path, [...lines, ''].join('\n'));
  return path;
}

async function makeCa(work: string, bin: string): Promise<{ caKey: Buffer; caCert: Buffer }> {
  const caConf = conf(work, 'ca.cnf', [
    '[req]',
    'distinguished_name = dn',
    'x509_extensions = v3_ca',
    'prompt = no',
    '[dn]',
    'CN = Vigil local Santa sync CA',
    '[v3_ca]',
    'basicConstraints = critical,CA:TRUE,pathlen:0',
    'keyUsage = critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier = hash',
  ]);
  const key = join(work, 'ca.key');
  const cert = join(work, 'ca.pem');
  await openssl(bin, ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', key]);
  await openssl(bin, [
    'req',
    '-new',
    '-x509',
    '-sha256',
    '-days',
    '3650',
    '-key',
    key,
    '-out',
    cert,
    '-config',
    caConf,
  ]);
  return { caKey: readFileSync(key), caCert: readFileSync(cert) };
}

/** Writes the CA into the work folder for openssl to sign with. */
function caFiles(
  work: string,
  ca: { caKey: Buffer; caCert: Buffer },
): { key: string; cert: string } {
  const key = join(work, 'sign-ca.key');
  const cert = join(work, 'sign-ca.pem');
  writeFileSync(key, ca.caKey, { mode: 0o600 });
  writeFileSync(cert, ca.caCert, { mode: 0o600 });
  return { key, cert };
}

let serial = 0;
function nextSerial(): string {
  serial = (serial + 1) % 0x1000;
  return '0x' + (Date.now() * 0x1000 + serial).toString(16);
}

async function makeServer(
  work: string,
  bin: string,
  ca: { caKey: Buffer; caCert: Buffer },
): Promise<{ serverKey: Buffer; serverCert: Buffer }> {
  const leafConf = conf(work, 'leaf.cnf', [
    '[req]',
    'distinguished_name = dn',
    'prompt = no',
    '[dn]',
    'CN = localhost',
    '[v3_leaf]',
    'basicConstraints = critical,CA:FALSE',
    'keyUsage = critical,digitalSignature,keyEncipherment',
    'extendedKeyUsage = serverAuth',
    'subjectAltName = DNS:localhost,IP:127.0.0.1,IP:::1',
    'authorityKeyIdentifier = keyid',
  ]);
  const signer = caFiles(work, ca);
  const key = join(work, 'server.key');
  const csr = join(work, 'server.csr');
  const cert = join(work, 'server.pem');
  await openssl(bin, ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', key]);
  await openssl(bin, ['req', '-new', '-sha256', '-key', key, '-out', csr, '-config', leafConf]);
  await openssl(bin, [
    'x509',
    '-req',
    '-sha256',
    '-days',
    '397',
    '-in',
    csr,
    '-CA',
    signer.cert,
    '-CAkey',
    signer.key,
    '-set_serial',
    nextSerial(),
    '-extfile',
    leafConf,
    '-extensions',
    'v3_leaf',
    '-out',
    cert,
  ]);
  return { serverKey: readFileSync(key), serverCert: readFileSync(cert) };
}

/** A new key and certificate for Santa, and the PKCS#12 copy Santa reads. */
async function makeClient(
  work: string,
  bin: string,
  ca: { caKey: Buffer; caCert: Buffer },
  password: Buffer,
): Promise<{
  clientKey: Buffer;
  clientCert: Buffer;
  clientP12: Buffer;
  clientP12Password: Buffer;
}> {
  const clientConf = conf(work, 'client.cnf', [
    '[req]',
    'distinguished_name = dn',
    'prompt = no',
    '[dn]',
    'CN = Vigil Santa sync client',
    '[v3_client]',
    'basicConstraints = critical,CA:FALSE',
    'keyUsage = critical,digitalSignature',
    'extendedKeyUsage = clientAuth',
    'authorityKeyIdentifier = keyid',
  ]);
  const signer = caFiles(work, ca);
  const key = join(work, 'client.key');
  const csr = join(work, 'client.csr');
  const cert = join(work, 'client.pem');
  const p12 = join(work, 'client.p12');
  const pass = join(work, 'client.p12.pass');
  await openssl(bin, ['ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', key]);
  await openssl(bin, ['req', '-new', '-sha256', '-key', key, '-out', csr, '-config', clientConf]);
  await openssl(bin, [
    'x509',
    '-req',
    '-sha256',
    '-days',
    '397',
    '-in',
    csr,
    '-CA',
    signer.cert,
    '-CAkey',
    signer.key,
    '-set_serial',
    nextSerial(),
    '-extfile',
    clientConf,
    '-extensions',
    'v3_client',
    '-out',
    cert,
  ]);
  // The password is kept so a renewed file opens with the profile already
  // installed. It protects nothing by itself: the file's owner and mode do.
  writeFileSync(pass, password, { mode: 0o600 });
  // 3DES and a SHA-1 MAC: what both LibreSSL and Apple's SecPKCS12Import read
  // on every macOS Santa supports. OpenSSL 3 would default to AES and PBKDF2.
  await openssl(bin, [
    'pkcs12',
    '-export',
    '-inkey',
    key,
    '-in',
    cert,
    '-name',
    'Vigil Santa sync client',
    '-passout',
    `file:${pass}`,
    '-keypbe',
    'PBE-SHA1-3DES',
    '-certpbe',
    'PBE-SHA1-3DES',
    '-macalg',
    'sha1',
    '-out',
    p12,
  ]);
  return {
    clientKey: readFileSync(key),
    clientCert: readFileSync(cert),
    clientP12: readFileSync(p12),
    clientP12Password: password,
  };
}

/**
 * Tests: another client certificate from the same CA (not the pinned one),
 * or from a new CA when none is given.
 */
export async function issueClientCertificate(
  ca: { key: Buffer; cert: Buffer } | null,
  opensslBin = 'openssl',
): Promise<{ key: Buffer; cert: Buffer }> {
  const work = mkdtempSync(join(tmpdir(), 'vigil-tls-'));
  try {
    const signer = ca ? { caKey: ca.key, caCert: ca.cert } : await makeCa(work, opensslBin);
    const c = await makeClient(work, opensslBin, signer, newPassword());
    return { key: c.clientKey, cert: c.clientCert };
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}
