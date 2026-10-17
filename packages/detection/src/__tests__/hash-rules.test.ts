import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { matchesProgramHash } from '../safety.js';
import { memoryStores } from '../state/stores.js';
import type { DetectionEvent } from '../types.js';

const SH = 'a5'.repeat(32);

const exec = (path: string, sha256 = SH): DetectionEvent =>
  ({
    id: `e-${path}`,
    ts: 1,
    source: 'santa',
    kind: 'process.exec',
    // Santa's log names no signer, and a shell's parent is rarely launchd.
    process: { pid: 4242, ppid: 900, path, sha256, signing: 'unknown' },
  }) as DetectionEvent;

function engine(): DetectionEngine {
  const stores = memoryStores();
  stores.lists.replace('user_blocked_sha256', [SH], { source: 'app', updatedAt: 0 });
  stores.lists.replace('known_bad_sha256', [SH], { source: 'app', updatedAt: 0 });
  return new DetectionEngine(macosCoreRules, stores, { recordHistory: false });
}

describe('rules that pick a program by its hash', () => {
  it('are told apart from rules that only read the hash', () => {
    const inList = { inList: { list: 'user_blocked_sha256', field: 'process.sha256' } };
    expect(matchesProgramHash(inList)).toBe(true);
    expect(matchesProgramHash({ field: 'process.cdhash', op: 'eq', value: 'x' })).toBe(true);
    expect(
      matchesProgramHash({ all: [{ field: 'process.path', op: 'eq', value: '/x' }, inList] }),
    ).toBe(true);
    expect(matchesProgramHash({ not: inList })).toBe(false);
    expect(matchesProgramHash({ field: 'process.sha256', op: 'exists' })).toBe(false);
    expect(matchesProgramHash({ inList: { list: 'known_bad_ips', field: 'remoteAddress' } })).toBe(
      false,
    );
  });

  it('never stop or block the macOS shell, even when its hash is on the user’s list', () => {
    // 2026-10-10: a "malicious" verdict put /bin/sh's hash on user_blocked_sha256.
    const ds = engine().evaluate(exec('/bin/sh'));
    const hit = ds.filter(
      (d) => d.match.ruleId === 'user-blocked-hash' || d.match.ruleId === 'known-bad-hash',
    );
    expect(hit.length).toBeGreaterThan(0);
    for (const d of hit) {
      expect(d.execute).toEqual([]);
      expect(d.propose).toEqual([]);
      expect(d.downgrades.join(' ')).toContain('matches the program by its hash');
    }
  });

  it('leave other Apple tools alone too, but not a copy elsewhere', () => {
    for (const d of engine().evaluate(exec('/usr/bin/curl'))) expect(d.execute).toEqual([]);
    const copy = engine()
      .evaluate(exec('/tmp/sh'))
      .find((d) => d.match.ruleId === 'user-blocked-hash')!;
    expect(copy.execute.map((a) => a.kind)).toEqual(['process.kill', 'santa.rule.set']);
  });

  // Review of #189: folders the user's account can write are not the OS's.
  it('stop and block a known-bad hash under Homebrew, /usr/local or Nix', () => {
    for (const path of [
      '/opt/homebrew/bin/fish',
      '/opt/homebrew/Cellar/x/1/bin/bash',
      '/usr/local/bin/sh',
      '/nix/store/abc-bash/bin/bash',
    ]) {
      const d = engine()
        .evaluate(exec(path))
        .find((x) => x.match.ruleId === 'known-bad-hash')!;
      expect(
        d.execute.map((a) => a.kind),
        path,
      ).toEqual(['process.kill', 'santa.rule.set']);
    }
  });
});
