import { describe, expect, it } from 'vitest';
import { execFileSync } from 'node:child_process';
import { fileAccessPolicy, santaProfile } from './santa/profile.js';
import { toPlist } from './plist.js';

// Parse with Python's plistlib as an independent check that the XML is valid.
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- test helper over arbitrary plist JSON
function parsePlist(xml: string): any {
  const out = execFileSync(
    'python3',
    [
      '-c',
      'import plistlib,sys,json; print(json.dumps(plistlib.loads(sys.stdin.buffer.read()), default=str))',
    ],
    { input: xml },
  );
  return JSON.parse(out.toString());
}

describe('Santa profile', () => {
  it('produces a valid profile pointing Santa at the local server', () => {
    let n = 0;
    const p = parsePlist(
      santaProfile({
        syncPort: 8443,
        uuid: () => `UUID-${++n}`,
        eventDetailUrl: 'vigil://santa/%file_sha%',
      }),
    );
    const payload = p.PayloadContent[0];
    expect(payload.PayloadType).toBe('com.northpolesec.santa');
    expect(payload.SyncBaseURL).toBe('https://127.0.0.1:8443/');
    expect(payload.ClientMode).toBe(1);
    expect(payload.ServerAuthRootsFile).toMatch(/ca\.pem$/);
    expect(payload.EventDetailURL).toBe('vigil://santa/%file_sha%');
    expect(p.PayloadType).toBe('Configuration');
    expect(p.PayloadRemovalDisallowed).toBe(false);
  });

  it("has Santa present Vigil's client certificate when given its password", () => {
    const without = parsePlist(santaProfile({ syncPort: 8443 })).PayloadContent[0];
    expect(without.ClientAuthCertificateFile).toBeUndefined();
    const payload = parsePlist(santaProfile({ syncPort: 8443, clientCertPassword: 'pw' }))
      .PayloadContent[0];
    expect(payload.ClientAuthCertificateFile).toBe(
      '/Library/Application Support/Vigil/santa-sync/client.p12',
    );
    expect(payload.ClientAuthCertificatePassword).toBe('pw');
    // Keychain lookups are not used: they would need an import into a keychain.
    expect(payload.ClientAuthCertificateCN).toBeUndefined();
    expect(payload.ClientAuthCertificateIssuerCN).toBeUndefined();
  });

  it('rejects bad ports', () => {
    expect(() => santaProfile({ syncPort: 0 })).toThrow();
  });

  it('file access policy starts audit-only and can enforce', () => {
    type Item = {
      Paths: { Path: string; IsPrefix: boolean }[];
      Options: { AuditOnly: boolean; RuleType: string; AllowReadAccess: boolean };
      Processes: Record<string, unknown>[];
    };
    const audit = parsePlist(fileAccessPolicy()) as { WatchItems: Record<string, Item> };
    const items = audit.WatchItems;
    expect(Object.keys(items)).toEqual([
      'ChromeCookies',
      'BraveCookies',
      'EdgeCookies',
      'ArcCookies',
      'FirefoxCookies',
      'SafariCookies',
      'CryptoWallets',
      'SSHKeys',
      'UserKeychains',
      'ScriptToolsReadingSecrets',
      'TCCDatabaseWrites',
    ]);
    for (const [name, item] of Object.entries(items)) {
      expect(name).toMatch(/^[A-Za-z0-9._:-]{1,64}$/);
      expect(item.Options.AuditOnly).toBe(true);
      // Santa's globs are glob(3): no globstar.
      for (const p of item.Paths) expect(p.Path).not.toContain('**');
      // A signing ID alone matches nothing; Santa wants a team ID or PlatformBinary with it.
      for (const proc of item.Processes)
        if ('SigningID' in proc)
          expect('TeamID' in proc || proc.PlatformBinary === true).toBe(true);
    }
    // Only OpenSSH may read private keys, so curl or python3 reading one is reported.
    expect(items.SSHKeys!.Processes).toEqual([
      { PlatformBinary: true, SigningID: 'com.apple.ssh*' },
    ]);
    expect(items.ScriptToolsReadingSecrets!.Options.RuleType).toBe('ProcessesWithDeniedPaths');
    expect(items.ScriptToolsReadingSecrets!.Processes).toContainEqual({
      PlatformBinary: true,
      SigningID: 'com.apple.curl',
    });
    expect(items.ChromeCookies!.Paths.map((p) => p.Path)).toContain(
      '/Users/*/Library/Application Support/Google/Chrome/*/Network/Cookies',
    );
    expect(items.TCCDatabaseWrites!.Options.AllowReadAccess).toBe(true);

    const enforce = parsePlist(fileAccessPolicy({ enforce: true })) as typeof audit;
    expect(enforce.WatchItems.SSHKeys!.Options.AuditOnly).toBe(false);
    // Items whose owning app isn't confirmed yet never block it.
    expect(enforce.WatchItems.ArcCookies!.Options.AuditOnly).toBe(true);
    expect(enforce.WatchItems.CryptoWallets!.Options.AuditOnly).toBe(true);
  });

  it('watches Documents and Desktop only when asked', () => {
    const on = parsePlist(fileAccessPolicy({ watchDocuments: true })) as {
      WatchItems: Record<string, { Options: { AllowReadAccess: boolean; AuditOnly: boolean } }>;
    };
    expect(on.WatchItems.UserDocuments!.Options).toMatchObject({
      AllowReadAccess: false,
      AuditOnly: true,
    });
    expect(fileAccessPolicy()).not.toContain('UserDocuments');
  });

  it('escapes XML', () => {
    expect(parsePlist(toPlist({ a: '<&"\'>' })).a).toBe('<&"\'>');
  });
});
