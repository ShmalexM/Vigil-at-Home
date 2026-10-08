// Real-Mac checks for Santa's client identity (santa/tls.ts): macOS's own
// openssl (LibreSSL) makes it, santasyncservice's user (nobody) can read the
// PKCS#12 file but not change it, nobody else can read it, and Apple's
// Security framework opens it with the password the profile carries. Santa
// itself is not installed on the runners, so the handshake with the real
// santasyncservice still needs a Mac with Santa. Runs only on macOS with
// VIGIL_MAC_INTEGRATION=1, as root (`pnpm --filter @vigil/sensors test:mac`).

import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createSecureContext } from 'node:tls';
import { SANTA_SYNC_GID, SyncIdentityStore } from './santa/tls.js';

const enabled =
  process.platform === 'darwin' &&
  process.env.VIGIL_MAC_INTEGRATION === '1' &&
  process.getuid?.() === 0;

let root: string;

describe.skipIf(!enabled)("Santa's client identity on a real Mac", () => {
  // Under /private/tmp, which nobody can pass through; the runner's own
  // temporary folder is private to the runner user.
  beforeAll(() => {
    root = mkdtempSync('/private/tmp/vigil-tls-');
    chmodSync(root, 0o755);
  });
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it('is made with /usr/bin/openssl, readable by root and nobody, writable by neither but root', async () => {
    const store = new SyncIdentityStore(join(root, 'santa-sync'));
    await store.start();
    const tls = store.paths;
    const p12 = realpathSync(tls.clientP12);
    const st = statSync(p12);
    expect(st.uid).toBe(0);
    expect(st.gid >>> 0).toBe(SANTA_SYNC_GID);
    expect(st.mode & 0o777).toBe(0o440);
    const dir = statSync(dirname(p12));
    expect(dir.uid).toBe(0);
    expect(dir.gid >>> 0).toBe(SANTA_SYNC_GID);
    expect(dir.mode & 0o777).toBe(0o750);
    expect(statSync(tls.clientKey).uid).toBe(0);
    expect(statSync(tls.clientKey).mode & 0o777).toBe(0o600);
    expect(statSync(tls.clientP12Password).mode & 0o777).toBe(0o600);
    expect(store.status().p12Valid).toBe(true);

    const asUser = (user: string, ...cmd: string[]) =>
      execFileSync('/usr/bin/sudo', ['-n', '-u', user, ...cmd], { stdio: 'pipe' });
    // Through the path the profile names, as santasyncservice opens it.
    expect(asUser('nobody', '/bin/cat', tls.clientP12).equals(readFileSync(p12))).toBe(true);
    expect(asUser('nobody', '/bin/cat', tls.caCertLink).length).toBeGreaterThan(0);
    // nobody can't truncate, chmod or replace it.
    expect(() => asUser('nobody', '/bin/sh', '-c', `: > '${p12}'`)).toThrow();
    expect(() => asUser('nobody', '/bin/chmod', '666', p12)).toThrow();
    expect(() => asUser('nobody', '/bin/mv', p12, `${p12}.x`)).toThrow();
    expect(statSync(p12).size).toBe(st.size);
    const runner = process.env.SUDO_USER;
    if (runner && runner !== 'root') expect(() => asUser(runner, '/bin/cat', p12)).toThrow();
  });

  it("opens with Apple's Security framework and with node", () => {
    const tls = new SyncIdentityStore(join(root, 'santa-sync')).paths;
    const password = readFileSync(tls.clientP12Password, 'utf8').trim();
    expect(() =>
      createSecureContext({ pfx: readFileSync(tls.clientP12), passphrase: password }),
    ).not.toThrow();
    // A throwaway keychain: `security import` decodes the file the way
    // SecPKCS12Import does, which is what Santa calls.
    const keychain = join(root, 'check.keychain');
    execFileSync('/usr/bin/security', ['create-keychain', '-p', 'vigil-check', keychain]);
    try {
      execFileSync('/usr/bin/security', [
        'import',
        tls.clientP12,
        '-k',
        keychain,
        '-f',
        'pkcs12',
        '-P',
        password,
      ]);
      const ids = execFileSync('/usr/bin/security', ['find-identity', keychain], {
        encoding: 'utf8',
      });
      expect(ids).toContain('Vigil Santa sync client');
    } finally {
      execFileSync('/usr/bin/security', ['delete-keychain', keychain]);
    }
  });
});
