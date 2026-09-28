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

  it('rejects bad ports', () => {
    expect(() => santaProfile({ syncPort: 0 })).toThrow();
  });

  it('file access policy starts audit-only and can enforce', () => {
    const audit = parsePlist(fileAccessPolicy());
    expect(Object.keys(audit.WatchItems)).toEqual([
      'ChromeCookies',
      'FirefoxCookies',
      'SSHKeys',
      'UserKeychains',
    ]);
    for (const item of Object.values<{ Options: { AuditOnly: boolean; RuleType: string } }>(
      audit.WatchItems,
    )) {
      expect(item.Options.AuditOnly).toBe(true);
      expect(item.Options.RuleType).toBe('PathsWithAllowedProcesses');
    }
    for (const name of Object.keys(audit.WatchItems))
      expect(name).toMatch(/^[A-Za-z0-9._:-]{1,64}$/);
    const enforce = parsePlist(fileAccessPolicy({ enforce: true }));
    expect(enforce.WatchItems.SSHKeys.Options.AuditOnly).toBe(false);
  });

  it('escapes XML', () => {
    expect(parsePlist(toPlist({ a: '<&"\'>' })).a).toBe('<&"\'>');
  });
});
