import { describe, expect, it } from 'vitest';
import { SafetyFloor, selfKey, selfRoots, underSelfRoot } from '../safety.js';

const proc = (path: string) => ({ pid: 4242, ppid: 900, path });

describe('safety floor: Vigil’s own paths', () => {
  it('ignores a self path that would cover the whole machine', () => {
    expect(selfRoots(['/', '', '/opt', '/opt/', '/x/..'])).toEqual([]);
    const floor = new SafetyFloor({ selfPaths: ['/'] });
    expect(floor.processProtection(proc('/tmp/payload'))).toBeUndefined();
  });

  it('protects only what is inside a real install folder', () => {
    const floor = new SafetyFloor({ selfPaths: ['/opt/Vigil at Home/'] });
    expect(floor.processProtection(proc('/opt/Vigil at Home/vigil-at-home'))).toBe(
      'it is Vigil itself',
    );
    expect(floor.processProtection(proc('/opt/Vigil at Home2/x'))).toBeUndefined();
  });

  it('ignores case only where the disk does (macOS)', () => {
    const roots = selfRoots(['/Applications/Vigil at Home.app'], true);
    expect(underSelfRoot(roots, '/applications/vigil at home.app/x', true)).toBe(true);
    const linux = selfRoots(['/home/alex/Apps/Vigil.AppImage'], false);
    expect(underSelfRoot(linux, selfKey('/home/alex/Apps/vigil.appimage', false), false)).toBe(
      false,
    );
    expect(underSelfRoot(linux, '/home/alex/Apps/Vigil.AppImage', false)).toBe(true);
  });
});

describe('safety floor: Vigil’s own programs by hash', () => {
  const own = 'a'.repeat(64);
  const block = (identifier: string) =>
    ({ kind: 'santa.rule.set', ruleType: 'binary', identifier, policy: 'block' }) as const;
  const event = (sha256: string) =>
    ({
      id: 'e',
      ts: 0,
      source: 'osquery',
      kind: 'process.exec',
      process: { pid: 4242, ppid: 900, path: '/tmp/copy', sha256 },
    }) as const;

  it('never blocks a program inside Vigil’s image, wherever a copy runs', () => {
    const floor = new SafetyFloor({ selfHashes: [own.toUpperCase()] });
    expect(floor.check(block(own), event(own))).toBe('it would block Vigil itself');
    expect(floor.check(block('b'.repeat(64)), event('b'.repeat(64)))).toBeUndefined();
    // A copy elsewhere is not Vigil: it can still be stopped, just not blocked by hash.
    expect(floor.processProtection(event(own).process)).toBeUndefined();
  });

  it('takes the hashes once the app has computed them', () => {
    const floor = new SafetyFloor();
    expect(floor.check(block(own), event(own))).toBeUndefined();
    floor.setSelfHashes([own]);
    expect(floor.check(block(own), event(own))).toBe('it would block Vigil itself');
  });
});

// Review of #189: a self-signed certificate can be named "Software Signing",
// and Santa's log and osquery report the leaf's name, so `signing: 'apple'`
// alone must not make a program one that can't be stopped or blocked.
describe('safety floor: what counts as part of macOS', () => {
  const floor = new SafetyFloor();
  const p = (path: string, extra: Record<string, string> = {}) => ({
    pid: 4242,
    ppid: 900,
    path,
    signing: 'apple' as const,
    ...extra,
  });

  it('takes no certificate name on its own word', () => {
    expect(floor.processProtection(p('/tmp/evil'))).toBeUndefined();
    expect(floor.blockProtection(p('/tmp/evil'))).toBeUndefined();
  });

  it('takes a path the OS protects, or a platform signing ID', () => {
    expect(floor.blockProtection(p('/usr/libexec/xpcproxy'))).toContain('part of macOS');
    const platform = p('/tmp/copy', { signingId: 'platform:com.apple.curl' });
    expect(floor.blockProtection(platform)).toContain('part of macOS');
  });
});
