// Santa's sync identity store (santa/tls.ts): one lock for every change, each
// change a whole new version behind one atomic switch.

import { afterAll, describe, expect, it } from 'vitest';
import {
  chmodSync,
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import { createSecureContext } from 'node:tls';
import {
  CLIENT_PIN_OVERLAP_MS,
  IDENTITY_FILES,
  IdentityApprovalNeeded,
  type IdentityState,
  type IdentityStep,
  type IdentityStoreOptions,
  SyncIdentityStore,
  certFingerprint,
  p12Fingerprint,
} from './santa/tls.js';

const root = mkdtempSync(join(tmpdir(), 'vigil-identity-'));
afterAll(() => rmSync(root, { recursive: true, force: true }));
let n = 0;
const newDir = () => join(root, `s${n++}`, 'santa-sync');

const DAY = 86_400_000;
/** Some tests make dozens of keys and certificates with openssl. */
const OPENSSL_TIMEOUT_MS = 120_000;
const WRITE_STEPS: IdentityStep[] = [
  ...(Object.keys(IDENTITY_FILES) as IdentityStep[]),
  'swap',
  'links',
];

function store(dir: string, o: IdentityStoreOptions = {}): SyncIdentityStore {
  return new SyncIdentityStore(dir, { opensslBin: 'openssl', ...o });
}

async function started(dir = newDir(), o: IdentityStoreOptions = {}): Promise<SyncIdentityStore> {
  const s = store(dir, o);
  await s.start();
  return s;
}

/** Throws when `step` comes up while `armed` says so. */
function crashAt(step: IdentityStep, armed: () => boolean = () => true) {
  return (s: IdentityStep) => {
    if (s === step && armed()) throw new Error(`crash at ${s}`);
  };
}

/**
 * What is on disk, read without starting a store (which would repair it), and
 * checked to be one consistent identity.
 */
async function onDisk(dir: string): Promise<IdentityState> {
  const cur = join(dir, 'current');
  const read = (f: keyof typeof IDENTITY_FILES) => readFileSync(join(cur, IDENTITY_FILES[f]));
  const state = JSON.parse(read('state').toString('utf8')) as IdentityState;
  expect(certFingerprint(read('clientCert'))).toBe(state.pin);
  expect(
    await p12Fingerprint(
      join(dir, IDENTITY_FILES.clientP12),
      join(cur, IDENTITY_FILES.clientP12Password),
      'openssl',
    ),
  ).toBe(state.pin);
  const ca = new X509Certificate(read('caCert'));
  expect(new X509Certificate(read('clientCert')).checkIssued(ca)).toBe(true);
  expect(new X509Certificate(read('serverCert')).checkIssued(ca)).toBe(true);
  // The profile's paths lead into the same version.
  expect(readFileSync(join(dir, 'ca.pem')).equals(read('caCert'))).toBe(true);
  return state;
}

/** A store whose certificate is not required (as after an approved recovery). */
async function notRequired(dir = newDir(), o: IdentityStoreOptions = {}) {
  const s = await started(dir, o);
  await s.reissue({ approved: true });
  expect(s.required).toBe(false);
  return s;
}

/** santa-sync/ as an earlier version left it: everything flat in the folder. */
async function legacyLayout(o: { clientAuth: boolean; required: boolean }): Promise<string> {
  const src = await started();
  const dir = newDir();
  mkdirSync(dir, { recursive: true });
  const names = Object.values(IDENTITY_FILES).filter(
    (f) => f !== IDENTITY_FILES.state && (o.clientAuth || !f.startsWith('client')),
  );
  for (const f of names) {
    writeFileSync(join(dir, f), readFileSync(join(src.paths.current, f)), { mode: 0o600 });
  }
  if (o.required) writeFileSync(join(dir, 'client-auth-required'), 'x\n');
  return dir;
}

describe("Santa's sync identity on a new install", { timeout: OPENSSL_TIMEOUT_MS }, () => {
  it('writes one complete version, private except what Santa reads, and requires the certificate', async () => {
    const s = await started();
    const t = s.paths;
    expect(s.required).toBe(true);
    expect(s.current?.required).toBe(true);
    expect(existsSync(t.installed)).toBe(true);
    expect(s.status()).toMatchObject({
      issued: true,
      required: true,
      p12Valid: true,
      problem: null,
      installedAt: expect.any(Number),
    });
    expect(s.status().expiresAt! - Date.now()).toBeGreaterThan(396 * DAY);
    // The profile's paths are links into `current`, which names one version.
    expect(readlinkSync(t.clientP12)).toBe(join('current', 'client.p12'));
    expect(readlinkSync(t.caCertLink)).toBe(join('current', 'ca.pem'));
    expect(readlinkSync(t.current)).toMatch(/^versions\//);
    // Root (here: the test user) and group nobody may read; nobody may not write.
    const p12 = realpathSync(t.clientP12);
    expect(statSync(p12).mode & 0o777).toBe(0o440);
    expect(statSync(dirname(p12)).mode & 0o777).toBe(0o750);
    for (const key of [t.caKey, t.serverKey, t.clientKey, t.clientP12Password, t.state])
      expect(statSync(key).mode & 0o777).toBe(0o600);
    expect(statSync(t.dir).mode & 0o777).toBe(0o755);
    expect(statSync(t.caCert).mode & 0o777).toBe(0o644);
    const password = readFileSync(t.clientP12Password, 'utf8').trim();
    expect(() =>
      createSecureContext({ pfx: readFileSync(t.clientP12), passphrase: password }),
    ).not.toThrow();
    await onDisk(t.dir);

    // A second start changes nothing.
    const version = readlinkSync(t.current);
    const again = await started(t.dir);
    expect(readlinkSync(t.current)).toBe(version);
    expect(again.required).toBe(true);
    expect(again.current).toEqual(s.current);
  });

  it('stays strict when the first start was cut short at any step', async () => {
    for (const step of [...WRITE_STEPS, 'installed'] as IdentityStep[]) {
      const dir = newDir();
      await expect(store(dir, { beforeStep: crashAt(step) }).start()).rejects.toThrow(/crash/);
      expect(existsSync(join(dir, 'installed'))).toBe(false);
      // ca.pem may already be there; that is no sign of an earlier version.
      const s = await started(dir);
      expect(s.required).toBe(true);
      expect((await onDisk(dir)).required).toBe(true);
      expect(existsSync(join(dir, 'installed'))).toBe(true);
    }
  });
});

describe("Santa's sync identity over time", { timeout: OPENSSL_TIMEOUT_MS }, () => {
  it('keeps taking the replaced certificate for 30 days after a renewal, under the same password', async () => {
    const s = await started();
    const old = s.current!.pin;
    const password = readFileSync(s.paths.clientP12Password, 'utf8');
    expect(await s.renew()).toBe(false);
    // 380 days on, the 397-day certificate is within 30 days of expiring.
    const later = Date.now() + 380 * DAY;
    expect(await s.renew(later)).toBe(true);
    const cur = s.current!;
    expect(cur.pin).not.toBe(old);
    expect(cur.previous?.fingerprint).toBe(old);
    expect(cur.previous!.until).toBeLessThanOrEqual(later + CLIENT_PIN_OVERLAP_MS);
    expect(s.accepts(old, later)).toBe(true);
    expect(s.accepts(old, cur.previous!.until + 1)).toBe(false);
    expect(readFileSync(s.paths.clientP12Password, 'utf8')).toBe(password);
    // Renewal never lowers the requirement.
    expect(s.required).toBe(true);
    expect((await onDisk(s.paths.dir)).required).toBe(true);
  });

  it('issues a new identity on recovery, revoking the old pins, same file and password', async () => {
    const s = await started();
    const first = s.current!.pin;
    await s.renew(Date.now() + 380 * DAY);
    const second = s.current!.pin;
    const password = readFileSync(s.paths.clientP12Password, 'utf8');
    await s.reissue({ approved: true });
    const cur = s.current!;
    expect(cur.previous).toBeNull();
    expect(cur.revoked).toEqual(expect.arrayContaining([first, second]));
    expect(s.accepts(first)).toBe(false);
    expect(s.accepts(second)).toBe(false);
    expect(s.accepts(cur.pin)).toBe(true);
    expect(s.required).toBe(false);
    expect(readFileSync(s.paths.clientP12Password, 'utf8')).toBe(password);
    await onDisk(s.paths.dir);
  });

  it('repairs a client.p12 that does not hold the pinned certificate, at start and hourly', async () => {
    const s = await started();
    const pin = s.current!.pin;
    const tamper = () => {
      const p12 = realpathSync(s.paths.clientP12);
      chmodSync(p12, 0o640);
      writeFileSync(p12, 'not a pkcs12 file');
    };
    tamper();
    // Hourly check: read back with openssl, not just found to exist.
    expect(await s.renew()).toBe(true);
    expect(s.status()).toMatchObject({ p12Valid: true, problem: null, required: true });
    expect(s.current!.pin).not.toBe(pin);
    // A file that never held the pin is no reason to keep taking it.
    expect(s.current!.previous).toBeNull();
    await onDisk(s.paths.dir);

    tamper();
    const restarted = await started(s.paths.dir);
    expect(restarted.status().p12Valid).toBe(true);
    expect(restarted.required).toBe(true);
    await onDisk(s.paths.dir);
  });
});

describe('changes to the identity, one at a time', { timeout: OPENSSL_TIMEOUT_MS }, () => {
  it('never lowers the requirement without approval when Santa presents its certificate during reissues', async () => {
    const s = await notRequired();
    const pin = s.current!.pin;
    const a = s.reissue({ approved: false });
    const b = s.reissue({ approved: false });
    // Santa, with the new profile, presents the pinned certificate meanwhile.
    expect(s.presented(pin)).toBe(true);
    const results = await Promise.allSettled([a, b]);
    for (const r of results) {
      expect(r.status).toBe('rejected');
      expect((r as PromiseRejectedResult).reason).toBeInstanceOf(IdentityApprovalNeeded);
    }
    await s.idle();
    expect(s.required).toBe(true);
    expect(s.accepts(pin)).toBe(true);
    expect((await onDisk(s.paths.dir)).required).toBe(true);
    expect((await started(s.paths.dir)).required).toBe(true);

    // With the password it goes through.
    await s.reissue({ approved: true });
    expect(s.required).toBe(false);
    expect(s.accepts(pin)).toBe(false);
  });

  it('decides again as the new identity takes over, after the certificates were made', async () => {
    let onWrite: (() => void) | undefined;
    const s = await notRequired(newDir(), {
      beforeStep: (step) => {
        if (step === 'caKey') onWrite?.();
      },
    });
    const pin = s.current!.pin;
    // Santa presents while the reissue is already writing its version.
    onWrite = () => {
      onWrite = undefined;
      expect(s.presented(pin)).toBe(true);
    };
    await expect(s.reissue({ approved: false })).rejects.toBeInstanceOf(IdentityApprovalNeeded);
    await s.idle();
    expect(s.required).toBe(true);
    expect(s.current).toMatchObject({ pin, required: true });
    expect((await onDisk(s.paths.dir)).required).toBe(true);
  });

  it('refuses an unapproved reissue once Santa presented the certificate one before it issued', async () => {
    const s = await notRequired();
    // Nothing required: no password needed.
    await s.reissue({ approved: false });
    const pin = s.current!.pin;
    const next = s.reissue({ approved: false });
    expect(s.presented(pin)).toBe(true);
    await expect(next).rejects.toBeInstanceOf(IdentityApprovalNeeded);
    await s.idle();
    expect(s.required).toBe(true);
    expect(s.current).toMatchObject({ pin, required: true });
  });

  it('ignores a presentation of a pin a recovery revoked', async () => {
    const s = await notRequired();
    const old = s.current!.pin;
    await s.reissue({ approved: false });
    expect(s.presented(old)).toBe(false);
    expect(s.required).toBe(false);
  });

  it('never lets a renewal bring back a pin a recovery revoked, in either order', async () => {
    const later = Date.now() + 380 * DAY;
    const s = await started();
    const a = s.current!.pin;
    await Promise.all([s.renew(later), s.reissue({ approved: true })]);
    expect(s.current!.previous).toBeNull();
    expect(s.current!.revoked).toContain(a);
    expect(s.accepts(a, later)).toBe(false);

    const b = s.current!.pin;
    await Promise.all([s.reissue({ approved: true }), s.renew(later)]);
    const cur = s.current!;
    expect(cur.revoked).toContain(b);
    expect(s.accepts(b, later)).toBe(false);
    // The renewal kept the reissued certificate as previous, never a revoked one.
    expect(cur.previous).not.toBeNull();
    expect(cur.revoked).not.toContain(cur.previous!.fingerprint);
    await onDisk(s.paths.dir);
  });

  it('leaves one consistent identity when a reissue or renewal stops at any write', async () => {
    const base = await notRequired();
    await base.idle();
    const before = await onDisk(base.paths.dir);
    for (const step of WRITE_STEPS) {
      for (const change of ['reissue', 'renew'] as const) {
        const dir = newDir();
        mkdirSync(dirname(dir), { recursive: true });
        cpSync(base.paths.dir, dir, { recursive: true, verbatimSymlinks: true });
        let armed = false;
        const s = await started(dir, { beforeStep: crashAt(step, () => armed) });
        armed = true;
        const run =
          change === 'reissue' ? s.reissue({ approved: true }) : s.renew(Date.now() + 380 * DAY);
        await expect(run).rejects.toThrow(/crash/);
        const after = await onDisk(dir);
        // Before the switch, the old identity; after it, the new one, whole.
        const switched = step === 'links';
        expect(after.pin === before.pin).toBe(!switched);
        expect(s.current?.pin).toBe(after.pin);
        expect(after.required).toBe(false);
        // A restart finds nothing to repair.
        const version = readlinkSync(join(dir, 'current'));
        await started(dir);
        expect(readlinkSync(join(dir, 'current'))).toBe(version);
      }
    }
  });

  it('keeps the requirement and says so when it cannot be written down, and writes it later', async () => {
    let failing = false;
    const logs: string[] = [];
    const s = await notRequired(newDir(), {
      beforeStep: crashAt('state', () => failing),
      retryMs: 20,
      log: (m) => logs.push(m),
    });
    failing = true;
    expect(s.presented(s.current!.pin)).toBe(true);
    await s.idle();
    expect(s.required).toBe(true);
    expect(s.status().problem).toMatch(/Couldn’t save that Santa’s certificate is required/);
    expect(logs.some((l) => l.includes('retrying'))).toBe(true);
    expect((await onDisk(s.paths.dir)).required).toBe(false);
    // Still required: a reissue without the password is refused.
    await expect(s.reissue({ approved: false })).rejects.toBeInstanceOf(IdentityApprovalNeeded);

    failing = false;
    for (let i = 0; i < 100 && s.status().problem; i++) await new Promise((r) => setTimeout(r, 20));
    expect(s.status().problem).toBeNull();
    expect((await onDisk(s.paths.dir)).required).toBe(true);
    s.close();
  });
});

describe('moving from the flat layout of earlier versions', { timeout: OPENSSL_TIMEOUT_MS }, () => {
  it('keeps the CA and identity, and serves an old profile until Santa presents the certificate', async () => {
    const dir = await legacyLayout({ clientAuth: true, required: false });
    const ca = readFileSync(join(dir, 'ca.pem'));
    const pin = certFingerprint(readFileSync(join(dir, 'client.pem')));
    const s = await started(dir);
    expect(s.required).toBe(false);
    expect(s.current!.pin).toBe(pin);
    expect(readFileSync(s.paths.caCertLink).equals(ca)).toBe(true);
    // The flat files are gone; the two the profile names are links now.
    for (const f of ['ca.key', 'client.key', 'client.p12.pass', 'server.key'])
      expect(existsSync(join(dir, f))).toBe(false);
    expect(readlinkSync(join(dir, 'client.p12'))).toBe(join('current', 'client.p12'));
    await onDisk(dir);
    expect(s.presented(pin)).toBe(true);
    await s.idle();
    expect((await started(dir)).required).toBe(true);
  });

  it('keeps an earlier required marker, and makes a client identity for a CA-only folder', async () => {
    const required = await started(await legacyLayout({ clientAuth: true, required: true }));
    expect(required.required).toBe(true);
    const caOnly = await started(await legacyLayout({ clientAuth: false, required: false }));
    expect(caOnly.required).toBe(false);
    expect(caOnly.status().p12Valid).toBe(true);
    await onDisk(caOnly.paths.dir);
  });

  it('stays in the upgrade fallback when the move is cut short', async () => {
    for (const step of [...WRITE_STEPS, 'installed'] as IdentityStep[]) {
      const dir = await legacyLayout({ clientAuth: true, required: false });
      await expect(store(dir, { beforeStep: crashAt(step) }).start()).rejects.toThrow(/crash/);
      const s = await started(dir);
      expect(s.required).toBe(false);
      await onDisk(dir);
    }
  });
});
