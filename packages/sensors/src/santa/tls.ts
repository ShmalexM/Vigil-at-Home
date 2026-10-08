// Certificates for the local Santa sync server.
//
// A small private CA (pinned in Santa through ServerAuthRootsFile) signs a
// short-lived server certificate for 127.0.0.1/localhost. Apple's TLS stack
// rejects server certificates valid for more than 825 days, and wants the
// serverAuth EKU plus a subjectAltName, so the leaf gets 397 days and is
// renewed by the helper well before it expires. Keys are written 0600 and
// the helper runs as root, so nothing running as the user can read them.
// The folder and the certificates stay world-readable: santasyncservice runs
// as nobody and must read ca.pem, or every sync fails with a TLS error.
//
// The same CA signs a client certificate that Santa presents on every sync
// (ClientAuthCertificateFile in the profile). The helper's server requires it
// and pins its SHA-256, so other local programs can't sync in Santa's place.
// Its key stays root-only in client.key; Santa reads the PKCS#12 copy, which
// is owned by nobody (the user santasyncservice drops to) and mode 0600.
//
// Santa opens that file again on every sync: santasyncservice builds a new
// MOLAuthenticatingURLSession per sync, which reads ClientAuthCertificateFile
// with SecPKCS12Import when the server asks for a certificate. So renewing it
// in place (same path, same password) needs no new profile. The pin of the
// certificate it replaced is kept for 30 days (client.prev.json) for a sync
// that was already under way, or a Santa that cached the old identity.
//
// Uses /usr/bin/openssl (LibreSSL on macOS), driven only with config files so
// it works on LibreSSL versions without -addext.

import { execFile } from 'node:child_process';
import {
  chmodSync,
  chownSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash, randomBytes, X509Certificate } from 'node:crypto';

export interface SyncTlsPaths {
  dir: string;
  caKey: string;
  caCert: string;
  serverKey: string;
  serverCert: string;
  /** Santa's client identity: key (root-only), certificate, and the PKCS#12 Santa reads. */
  clientKey: string;
  clientCert: string;
  clientP12: string;
  /** Password of clientP12, root-only. Santa gets it through the profile. */
  clientP12Password: string;
  /** The pin of the client certificate a renewal replaced, and until when it is still taken. */
  clientPrevPin: string;
}

export function syncTlsPaths(dir: string): SyncTlsPaths {
  return {
    dir,
    caKey: join(dir, 'ca.key'),
    caCert: join(dir, 'ca.pem'),
    serverKey: join(dir, 'server.key'),
    serverCert: join(dir, 'server.pem'),
    clientKey: join(dir, 'client.key'),
    clientCert: join(dir, 'client.pem'),
    clientP12: join(dir, 'client.p12'),
    clientP12Password: join(dir, 'client.p12.pass'),
    clientPrevPin: join(dir, 'client.prev.json'),
  };
}

function openssl(bin: string, args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { timeout: 30_000 }, (err, _stdout, stderr) => {
      if (err) reject(new Error(`openssl ${args[0]} failed: ${stderr || err.message}`));
      else resolve();
    });
  });
}

const RENEW_BEFORE_MS = 30 * 24 * 3600 * 1000;
/** How long the replaced client certificate is still taken after a renewal. */
export const CLIENT_PIN_OVERLAP_MS = 30 * 24 * 3600 * 1000;

function certNeedsRenewal(path: string, now: number): boolean {
  try {
    const cert = new X509Certificate(readFileSync(path));
    return Date.parse(cert.validTo) - now < RENEW_BEFORE_MS;
  } catch {
    return true;
  }
}

/** True when the server certificate is missing, unreadable or expires within 30 days. */
export function serverCertNeedsRenewal(paths: SyncTlsPaths, now = Date.now()): boolean {
  return certNeedsRenewal(paths.serverCert, now);
}

/** True when any part of Santa's client identity is missing or the certificate expires within 30 days. */
export function clientCertNeedsRenewal(paths: SyncTlsPaths, now = Date.now()): boolean {
  return (
    !existsSync(paths.clientKey) ||
    !existsSync(paths.clientP12) ||
    !existsSync(paths.clientP12Password) ||
    certNeedsRenewal(paths.clientCert, now)
  );
}

/** When Santa's client certificate expires (ms since epoch), or null when it can't be read. */
export function clientCertExpiresAt(paths: SyncTlsPaths): number | null {
  try {
    return Date.parse(new X509Certificate(readFileSync(paths.clientCert)).validTo);
  } catch {
    return null;
  }
}

/**
 * The pin of the client certificate the last renewal replaced, while it is
 * still taken: up to 30 days after the renewal and never past its own expiry.
 */
export function previousClientPin(
  paths: SyncTlsPaths,
  now = Date.now(),
): { fingerprint: string; until: number } | null {
  try {
    const p = JSON.parse(readFileSync(paths.clientPrevPin, 'utf8')) as {
      fingerprint?: unknown;
      until?: unknown;
    };
    if (typeof p.fingerprint !== 'string' || !/^[a-f0-9]{64}$/.test(p.fingerprint)) return null;
    if (typeof p.until !== 'number' || p.until <= now) return null;
    return { fingerprint: p.fingerprint, until: p.until };
  } catch {
    return null;
  }
}

/** SHA-256 of a PEM certificate's DER encoding, as lowercase hex. */
export function certFingerprint(pem: string | Buffer): string {
  return createHash('sha256').update(new X509Certificate(pem).raw).digest('hex');
}

/**
 * macOS's nobody (uid -2). santasyncservice drops to it before syncing and
 * must read the PKCS#12 file.
 */
export const SANTA_SYNC_UID = 0xfffffffe;

export interface SyncTlsOptions {
  /**
   * Who owns client.p12. Defaults to nobody when running as root on macOS,
   * and to the current user otherwise (tests, Linux).
   */
  clientP12Owner?: { uid: number; gid: number } | false;
}

function defaultP12Owner(): { uid: number; gid: number } | false {
  return process.platform === 'darwin' && process.getuid?.() === 0
    ? { uid: SANTA_SYNC_UID, gid: 0 }
    : false;
}

/**
 * Create the CA (once) and a fresh server certificate when needed.
 * Returns true if anything was (re)generated.
 */
export async function ensureSyncTls(
  paths: SyncTlsPaths,
  opensslBin = '/usr/bin/openssl',
  opts: SyncTlsOptions = {},
): Promise<boolean> {
  const p12Owner = opts.clientP12Owner ?? defaultP12Owner();
  mkdirSync(paths.dir, { recursive: true, mode: 0o755 });
  chmodSync(paths.dir, 0o755);
  let changed = false;
  const work = mkdtempSync(join(tmpdir(), 'vigil-tls-'));
  try {
    if (!existsSync(paths.caKey) || !existsSync(paths.caCert)) {
      const caConf = join(work, 'ca.cnf');
      writeFileSync(
        caConf,
        [
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
          '',
        ].join('\n'),
      );
      await openssl(opensslBin, [
        'ecparam',
        '-name',
        'prime256v1',
        '-genkey',
        '-noout',
        '-out',
        paths.caKey,
      ]);
      chmodSync(paths.caKey, 0o600);
      await openssl(opensslBin, [
        'req',
        '-new',
        '-x509',
        '-sha256',
        '-days',
        '3650',
        '-key',
        paths.caKey,
        '-out',
        paths.caCert,
        '-config',
        caConf,
      ]);
      // Santa must be able to read the CA certificate; it is public anyway.
      chmodSync(paths.caCert, 0o644);
      changed = true;
    }

    const caChanged = changed;
    if (caChanged || serverCertNeedsRenewal(paths)) {
      const leafConf = join(work, 'leaf.cnf');
      writeFileSync(
        leafConf,
        [
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
          '',
        ].join('\n'),
      );
      const csr = join(work, 'server.csr');
      const newKey = join(work, 'server.key');
      const newCert = join(work, 'server.pem');
      await openssl(opensslBin, [
        'ecparam',
        '-name',
        'prime256v1',
        '-genkey',
        '-noout',
        '-out',
        newKey,
      ]);
      await openssl(opensslBin, [
        'req',
        '-new',
        '-sha256',
        '-key',
        newKey,
        '-out',
        csr,
        '-config',
        leafConf,
      ]);
      await openssl(opensslBin, [
        'x509',
        '-req',
        '-sha256',
        '-days',
        '397',
        '-in',
        csr,
        '-CA',
        paths.caCert,
        '-CAkey',
        paths.caKey,
        '-set_serial',
        '0x' + Date.now().toString(16),
        '-extfile',
        leafConf,
        '-extensions',
        'v3_leaf',
        '-out',
        newCert,
      ]);
      writeFileSync(paths.serverKey, readFileSync(newKey), { mode: 0o600 });
      chmodSync(paths.serverKey, 0o600);
      writeFileSync(paths.serverCert, readFileSync(newCert), { mode: 0o644 });
      changed = true;
    }

    if (caChanged || clientCertNeedsRenewal(paths)) {
      // A renewal under the same CA: Santa may still present the old
      // certificate for a while, so keep taking it.
      if (!caChanged) keepPreviousPin(paths);
      await issueClientIdentity(paths, opensslBin, work, p12Owner);
      changed = true;
    }
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  // Also repairs folders written by earlier versions, which were 0700.
  chmodSync(paths.caCert, 0o644);
  chmodSync(paths.serverCert, 0o644);
  chmodSync(paths.caKey, 0o600);
  chmodSync(paths.serverKey, 0o600);
  chmodSync(paths.clientKey, 0o600);
  chmodSync(paths.clientCert, 0o644);
  chmodSync(paths.clientP12Password, 0o600);
  chmodSync(paths.clientP12, 0o600);
  if (p12Owner) chownSync(paths.clientP12, p12Owner.uid, p12Owner.gid);
  return changed;
}

/** Records the current client certificate's pin before it is replaced. */
function keepPreviousPin(paths: SyncTlsPaths, now = Date.now()): void {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(readFileSync(paths.clientCert));
  } catch {
    return;
  }
  const until = Math.min(Date.parse(cert.validTo), now + CLIENT_PIN_OVERLAP_MS);
  if (!(until > now)) return;
  const fingerprint = createHash('sha256').update(cert.raw).digest('hex');
  writeFileSync(paths.clientPrevPin, JSON.stringify({ fingerprint, until }) + '\n', {
    mode: 0o600,
  });
  chmodSync(paths.clientPrevPin, 0o600);
}

/**
 * Recovery: a new client identity for Santa that owes nothing to the old one.
 * Same file and password, so the installed profile keeps working once Santa
 * opens the file again; the old certificate's pin is dropped, not kept.
 */
export async function reissueClientIdentity(
  paths: SyncTlsPaths,
  opensslBin = '/usr/bin/openssl',
  opts: SyncTlsOptions = {},
): Promise<void> {
  const p12Owner = opts.clientP12Owner ?? defaultP12Owner();
  const work = mkdtempSync(join(tmpdir(), 'vigil-tls-'));
  try {
    rmSync(paths.clientPrevPin, { force: true });
    await issueClientIdentity(paths, opensslBin, work, p12Owner);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

/** A new key and certificate for Santa, and the PKCS#12 copy Santa reads. */
async function issueClientIdentity(
  paths: SyncTlsPaths,
  opensslBin: string,
  work: string,
  p12Owner: { uid: number; gid: number } | false,
): Promise<void> {
  const conf = join(work, 'client.cnf');
  writeFileSync(
    conf,
    [
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
      '',
    ].join('\n'),
  );
  const newKey = join(work, 'client.key');
  const csr = join(work, 'client.csr');
  const newCert = join(work, 'client.pem');
  const newP12 = join(work, 'client.p12');
  await openssl(opensslBin, [
    'ecparam',
    '-name',
    'prime256v1',
    '-genkey',
    '-noout',
    '-out',
    newKey,
  ]);
  await openssl(opensslBin, [
    'req',
    '-new',
    '-sha256',
    '-key',
    newKey,
    '-out',
    csr,
    '-config',
    conf,
  ]);
  await openssl(opensslBin, [
    'x509',
    '-req',
    '-sha256',
    '-days',
    '397',
    '-in',
    csr,
    '-CA',
    paths.caCert,
    '-CAkey',
    paths.caKey,
    '-set_serial',
    '0x' + (Date.now() + 1).toString(16),
    '-extfile',
    conf,
    '-extensions',
    'v3_client',
    '-out',
    newCert,
  ]);
  // The password is kept so a renewed file opens with the profile already
  // installed. It protects nothing by itself: the file's owner and mode do.
  if (!existsSync(paths.clientP12Password)) {
    writeFileSync(paths.clientP12Password, randomBytes(24).toString('hex') + '\n', {
      mode: 0o600,
    });
  }
  chmodSync(paths.clientP12Password, 0o600);
  // 3DES and a SHA-1 MAC: what both LibreSSL and Apple's SecPKCS12Import read
  // on every macOS Santa supports. OpenSSL 3 would default to AES and PBKDF2.
  await openssl(opensslBin, [
    'pkcs12',
    '-export',
    '-inkey',
    newKey,
    '-in',
    newCert,
    '-name',
    'Vigil Santa sync client',
    '-passout',
    `file:${paths.clientP12Password}`,
    '-keypbe',
    'PBE-SHA1-3DES',
    '-certpbe',
    'PBE-SHA1-3DES',
    '-macalg',
    'sha1',
    '-out',
    newP12,
  ]);
  writeFileSync(paths.clientKey, readFileSync(newKey), { mode: 0o600 });
  chmodSync(paths.clientKey, 0o600);
  writeFileSync(paths.clientCert, readFileSync(newCert), { mode: 0o644 });
  chmodSync(paths.clientCert, 0o644);
  // Santa may read the file mid-sync, so swap the whole file in at once.
  const staged = `${paths.clientP12}.new`;
  writeFileSync(staged, readFileSync(newP12), { mode: 0o600 });
  chmodSync(staged, 0o600);
  if (p12Owner) chownSync(staged, p12Owner.uid, p12Owner.gid);
  renameSync(staged, paths.clientP12);
}
