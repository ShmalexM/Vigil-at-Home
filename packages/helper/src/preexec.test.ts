import { describe, expect, it } from 'vitest';
import { DetectionRule, macosCoreRules } from '@vigil/detection';
import { RuleStore } from '@vigil/sensors';
import {
  PREEXEC_REASON,
  PreexecSync,
  parsePlatformSigningId,
  parseSantaVersion,
  supportsCel,
} from './preexec.js';
import type { BinaryName, RunResult, System } from './system.js';

const OSASCRIPT_CODESIGN = [
  'Executable=/usr/bin/osascript',
  'Identifier=com.apple.osascript',
  'Format=Mach-O universal (x86_64 arm64e)',
  'CodeDirectory v=20400 size=1234 flags=0x0(none) hashes=29+7 location=embedded',
  'Platform identifier=16',
  'Signature size=4442',
].join('\n');

function fakeSys(version = 'santad | 2026.8 (build 123)', codesign = OSASCRIPT_CODESIGN) {
  const runs: { bin: BinaryName; args: string[] }[] = [];
  const sys = {
    async run(bin: BinaryName, args: string[]): Promise<RunResult> {
      runs.push({ bin, args });
      if (bin === 'santactl') return { code: 0, stdout: version + '\n', stderr: '' };
      if (bin === 'codesign') return { code: 0, stdout: '', stderr: codesign };
      return { code: 1, stdout: '', stderr: 'unexpected' };
    },
  } as unknown as System;
  return { sys, runs };
}

const fake = DetectionRule.parse(macosCoreRules.find((r) => r.id === 'fake-password-prompt')!);
const exists = (p: string) => p === '/usr/bin/osascript';

describe('parsing', () => {
  it('reads Santa versions and knows which have CEL', () => {
    expect(parseSantaVersion('santad | 2026.8 (build 1)')).toEqual([2026, 8]);
    expect(supportsCel([2025, 8])).toBe(true);
    expect(supportsCel([2025, 7])).toBe(false);
    expect(supportsCel([2026, 1])).toBe(true);
    expect(supportsCel(undefined)).toBe(false);
  });

  it('only gives signing IDs for platform binaries', () => {
    expect(parsePlatformSigningId(OSASCRIPT_CODESIGN)).toBe('platform:com.apple.osascript');
    expect(
      parsePlatformSigningId('Identifier=com.example.tool\nTeamIdentifier=ABCDE12345\n'),
    ).toBeUndefined();
  });
});

describe('PreexecSync', () => {
  it('installs a CEL rule for osascript, then removes it when the rule goes', async () => {
    const { sys } = fakeSys();
    const store = new RuleStore();
    const sync = new PreexecSync(sys, store, exists);
    const out = await sync.apply([fake]);
    expect(out.santaSupportsCel).toBe(true);
    expect(out.installed).toEqual([
      {
        program: 'osascript',
        identifier: 'platform:com.apple.osascript',
        ruleIds: ['fake-password-prompt'],
      },
    ]);
    const stored = store.get('SIGNINGID', 'platform:com.apple.osascript')!;
    expect(stored.reason).toBe(PREEXEC_REASON);
    expect(stored.rule.policy).toBe('CEL');
    expect(stored.rule.cel_expr).toMatch(/\? BLOCKLIST : ALLOWLIST$/);

    // Same rules again: nothing changes, so Santa has nothing new to fetch.
    const rev = store.rev;
    await sync.apply([fake]);
    expect(store.rev).toBe(rev);

    await sync.apply([]);
    expect(store.get('SIGNINGID', 'platform:com.apple.osascript')).toBeUndefined();
  });

  it('does nothing on a Santa without CEL', async () => {
    const { sys } = fakeSys('santad | 2025.6 (build 1)');
    const store = new RuleStore();
    const out = await new PreexecSync(sys, store, exists).apply([fake]);
    expect(out.santaSupportsCel).toBe(false);
    expect(store.active()).toEqual([]);
  });

  it('never targets programs that are not Apple platform binaries', async () => {
    const { sys } = fakeSys(undefined, 'Identifier=osascript\nTeamIdentifier=not set\n');
    const store = new RuleStore();
    const out = await new PreexecSync(sys, store, exists).apply([fake]);
    expect(out.installed).toEqual([]);
    expect(out.skipped.at(-1)?.program).toBe('osascript');
    expect(store.active()).toEqual([]);
  });

  it('keeps a rule someone else set on the same program', async () => {
    const { sys } = fakeSys();
    const store = new RuleStore();
    store.upsert({
      ruleType: 'SIGNINGID',
      identifier: 'platform:com.apple.osascript',
      policy: 'BLOCKLIST',
    });
    const out = await new PreexecSync(sys, store, exists).apply([fake]);
    expect(out.installed).toEqual([]);
    expect(store.get('SIGNINGID', 'platform:com.apple.osascript')!.rule.policy).toBe('BLOCKLIST');
  });
});
