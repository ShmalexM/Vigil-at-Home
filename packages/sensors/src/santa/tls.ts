// Certificates for the local Santa sync server.
//
// A small private CA (pinned in Santa through ServerAuthRootsFile) signs a
// short-lived server certificate for 127.0.0.1/localhost. Apple's TLS stack
// rejects server certificates valid for more than 825 days, and wants the
// serverAuth EKU plus a subjectAltName, so the leaf gets 397 days and is
// renewed by the helper well before it expires. Keys are written 0600 and
// the helper runs as root, so nothing running as the user can read them.
//
// Uses /usr/bin/openssl (LibreSSL on macOS), driven only with config files so
// it works on LibreSSL versions without -addext.

import { execFile } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';

export interface SyncTlsPaths {
  dir: string;
  caKey: string;
  caCert: string;
  serverKey: string;
  serverCert: string;
}

export function syncTlsPaths(dir: string): SyncTlsPaths {
  return {
    dir,
    caKey: join(dir, 'ca.key'),
    caCert: join(dir, 'ca.pem'),
    serverKey: join(dir, 'server.key'),
    serverCert: join(dir, 'server.pem'),
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

/** True when the server certificate is missing, unreadable or expires within 30 days. */
export function serverCertNeedsRenewal(paths: SyncTlsPaths, now = Date.now()): boolean {
  try {
    const cert = new X509Certificate(readFileSync(paths.serverCert));
    return Date.parse(cert.validTo) - now < RENEW_BEFORE_MS;
  } catch {
    return true;
  }
}

/**
 * Create the CA (once) and a fresh server certificate when needed.
 * Returns true if anything was (re)generated.
 */
export async function ensureSyncTls(
  paths: SyncTlsPaths,
  opensslBin = '/usr/bin/openssl',
): Promise<boolean> {
  mkdirSync(paths.dir, { recursive: true, mode: 0o700 });
  chmodSync(paths.dir, 0o700);
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

    if (changed || serverCertNeedsRenewal(paths)) {
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
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
  return changed;
}
