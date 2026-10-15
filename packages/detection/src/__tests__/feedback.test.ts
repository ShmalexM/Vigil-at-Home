import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { assertExceptionScope, Feedback, USER_BLOCKED_HASHES } from '../feedback.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { memoryStores } from '../state/stores.js';
import { userOrigin } from '../user.js';
import { exec, proc, T0, testRule } from './fixtures.js';

const me = userOrigin('test');
const noisy = testRule({
  id: 'noisy-rule',
  mode: 'block',
  condition: { field: 'process.path', op: 'startsWith', value: '/opt/' },
  response: [{ kind: 'process.suspend', pid: '{{process.pid}}' }],
  dedupe: { key: ['process.path'], windowSec: 0 },
});
const tool = (n: number, extra = {}) =>
  proc({ path: `/opt/tools/t${n}`, sha256: String(n).repeat(64).slice(0, 64), ...extra });
const benign = { at: T0, verdict: 'benign', remember: false } as const;

describe('user decisions', () => {
  it('"allow this binary" adds a narrow exception so it stops firing', () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    const d = eng.evaluate(exec(tool(1)))[0]!;
    const res = fb.recordDecision(d, { ...benign, remember: true, scope: 'this_binary' }, me);
    expect(res.exception).toMatchObject({
      ruleId: 'noisy-rule',
      match: { 'process.sha256': '1'.repeat(64) },
    });
    expect(eng.evaluate(exec(tool(1)))).toEqual([]);
    expect(eng.evaluate(exec(tool(2)))).toHaveLength(1);
  });

  it('"allow this signer" needs a team ID, since ad-hoc signatures can claim any signing ID', () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    const adhoc = eng.evaluate(exec(tool(3, { signingId: 'com.google.Chrome' })))[0]!;
    expect(
      fb.recordDecision(adhoc, { ...benign, remember: true, scope: 'this_signer' }, me).exception,
    ).toBeUndefined();
    const signed = eng.evaluate(
      exec(tool(4, { signingId: 'com.acme.tool', teamId: 'ACME123456' })),
    )[0]!;
    const res = fb.recordDecision(signed, { ...benign, remember: true, scope: 'this_signer' }, me);
    expect(res.exception?.match).toEqual({
      'process.teamId': 'ACME123456',
      'process.signingId': 'com.acme.tool',
    });
    // Same signing ID from another team still fires.
    expect(
      eng.evaluate(exec(tool(5, { signingId: 'com.acme.tool', teamId: 'EVIL999999' }))),
    ).toHaveLength(1);
  });

  it('suggests a quieter mode after repeated false positives, and never changes it itself', () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    const results = [1, 2, 3].map((n) =>
      fb.recordDecision(eng.evaluate(exec(tool(n)))[0]!, benign, me),
    );
    expect(results[1]!.suggestDemotion).toBeUndefined();
    expect(results[2]!.suggestDemotion).toMatchObject({ from: 'block', to: 'alert' });
    expect(results[2]!.suggestDemotion!.message).toMatch(/Move it from Block to Alert\?/);
    // Still blocking: only the user can turn it down.
    expect(eng.modeOf(eng.getRule('noisy-rule')!)).toBe('block');
    expect(eng.evaluate(exec(tool(9)))[0]!.execute).not.toEqual([]);
    eng._setMode('noisy-rule', 'alert');
    const more = [4, 5, 6].map((n) =>
      fb.recordDecision(eng.evaluate(exec(tool(n)))[0]!, benign, me),
    );
    expect(more.find((r) => r.suggestDemotion)?.suggestDemotion).toMatchObject({
      from: 'alert',
      to: 'shadow',
    });
    expect(eng.modeOf(eng.getRule('noisy-rule')!)).toBe('alert');
  });

  it('confirming a threat blocks that program from then on and returns a Santa rule', () => {
    const eng = new DetectionEngine(macosCoreRules, memoryStores());
    const bad = proc({ path: '/private/tmp/x', sha256: 'f'.repeat(64), signing: 'unsigned' });
    const d = eng.evaluate(exec(bad)).find((x) => x.match.ruleId === 'exec-from-shared-temp')!;
    expect(d.mode).toBe('alert');
    const res = new Feedback(eng).recordDecision(
      d,
      { at: T0, verdict: 'malicious', remember: false },
      me,
    );
    expect(res.santa).toMatchObject({
      ruleType: 'binary',
      identifier: 'f'.repeat(64),
      policy: 'block',
    });
    const next = eng.evaluate(exec(bad)).find((x) => x.match.ruleId === 'user-blocked-hash');
    expect(next?.mode).toBe('block');
    expect(next?.execute.map((a) => a.kind)).toEqual(['process.kill', 'santa.rule.set']);
  });

  // 2026-10-10, a real Mac: Santa's log reported `/bin/sh -c security
  // find-generic-password ...` with `signing: "unknown"`, the user marked the
  // alert malicious, and /bin/sh's hash was blocked for the whole Mac.
  const anyExec = testRule({
    id: 'any-exec',
    mode: 'alert',
    condition: { field: 'process.path', op: 'exists' },
    dedupe: { key: ['process.pid'], windowSec: 0 },
  });
  const malicious = { at: T0, verdict: 'malicious', remember: false } as const;
  const santaLogShell = proc({
    path: '/bin/sh',
    sha256: 'c0eaf44f9242d5bbc2e14f4e8b7dccc1eff7f2976d64dc18914d5ef9f373e100',
    signing: 'unknown',
    // Santa's log splits the command on spaces.
    args: [
      '/bin/sh',
      '-c',
      'security',
      'find-generic-password',
      '-a',
      'alex',
      '-w',
      '-s',
      '"Claude',
      'Code-credentials"',
    ],
  });

  it('never blocks the macOS shell a confirmed threat ran through, and says what to block', () => {
    const eng = new DetectionEngine([anyExec, ...macosCoreRules], memoryStores());
    const d = eng.evaluate(exec(santaLogShell)).find((x) => x.match.ruleId === 'any-exec')!;
    const res = new Feedback(eng, undefined, () => T0).recordDecision(d, malicious, me);
    expect(res.santa).toBeUndefined();
    expect(res.blockRefused?.message).toMatch(/did not block \/bin\/sh: .*macOS shell/);
    expect(res.blockRefused?.message).toMatch(/shell that ran `security find-generic-password/);
    expect(res.blockRefused?.message).toMatch(
      /If security is the threat, block it from its own alert/,
    );
    expect(eng.stores.lists.size(USER_BLOCKED_HASHES)).toBe(0);
    // The next shell runs as before.
    expect(
      eng.evaluate(exec(santaLogShell)).find((x) => x.match.ruleId === 'user-blocked-hash'),
    ).toBeUndefined();
  });

  it.each([
    ['/usr/bin/python3', 'part of macOS'],
    ['/usr/libexec/xpcproxy', 'part of macOS'],
    ['/sbin/launchd', 'part of macOS'],
    ['/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder', 'part of macOS'],
    ['/Library/Apple/usr/bin/x', 'part of macOS'],
    ['/opt/homebrew/bin/zsh', 'installed shell'],
    ['/usr/local/bin/bash', 'installed shell'],
  ])('refuses to block %s whatever its signing field says', (path, why) => {
    const eng = new DetectionEngine([anyExec], memoryStores());
    const p = proc({ path, sha256: 'a'.repeat(64), signing: 'unknown' });
    const d = eng.evaluate(exec(p))[0]!;
    const res = new Feedback(eng, undefined, () => T0).recordDecision(d, malicious, me);
    expect(res.santa).toBeUndefined();
    expect(res.blockRefused?.message).toContain(why);
    expect(eng.stores.lists.has(USER_BLOCKED_HASHES, 'a'.repeat(64))).toBe(false);
  });

  it('still blocks a program that only calls itself sh, outside where shells are installed', () => {
    const eng = new DetectionEngine([anyExec], memoryStores());
    const p = proc({ path: '/private/tmp/.x/sh', sha256: 'b'.repeat(64), signing: 'unsigned' });
    const res = new Feedback(eng, undefined, () => T0).recordDecision(
      eng.evaluate(exec(p))[0]!,
      malicious,
      me,
    );
    expect(res.blockRefused).toBeUndefined();
    expect(res.santa).toMatchObject({ identifier: 'b'.repeat(64), policy: 'block' });
  });

  it('undoing a malicious verdict takes the program off the list and returns the Santa rule to remove', () => {
    const eng = new DetectionEngine(macosCoreRules, memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    const bad = proc({ path: '/private/tmp/x', sha256: 'f'.repeat(64), signing: 'unsigned' });
    const d = eng.evaluate(exec(bad)).find((x) => x.match.ruleId === 'exec-from-shared-temp')!;
    expect(fb.recordDecision(d, malicious, me).santa).toBeDefined();
    expect(eng.stores.lists.has(USER_BLOCKED_HASHES, 'f'.repeat(64))).toBe(true);

    expect(() => fb.undoBlock(d, { kind: 'user', via: 'agent', at: 0 } as never)).toThrow(
      /approval/,
    );
    expect(fb.undoBlock(d, me)).toEqual({
      unlisted: 'f'.repeat(64),
      santa: { kind: 'santa.rule.remove', ruleType: 'binary', identifier: 'f'.repeat(64) },
    });
    expect(eng.stores.lists.has(USER_BLOCKED_HASHES, 'f'.repeat(64))).toBe(false);
    expect(
      eng.evaluate(exec(bad)).find((x) => x.match.ruleId === 'user-blocked-hash'),
    ).toBeUndefined();
    // Nothing left to undo.
    expect(fb.undoBlock(d, me)).toEqual({});
  });

  it('refuses anything without a real user origin', () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng);
    const d = eng.evaluate(exec(tool(1)))[0]!;
    const forged = { kind: 'user', via: 'agent', at: 0 } as never;
    expect(() => fb.recordDecision(d, benign, forged)).toThrow(/approval/);
    expect(() => fb.setMode('noisy-rule', 'block', forged)).toThrow(/approval/);
    fb.setMode('noisy-rule', 'shadow', me);
    expect(eng.modeOf(eng.getRule('noisy-rule')!)).toBe('shadow');
  });

  it("clearing the user's override puts a rule back on its own mode, keeping its count", () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    eng.evaluate(exec(tool(1)));
    fb.setMode('noisy-rule', 'shadow', me);
    expect(eng.modeOverride('noisy-rule')).toBe('shadow');
    expect(() => fb.clearMode('noisy-rule', { kind: 'user', via: 'x', at: 0 } as never)).toThrow(
      /approval/,
    );
    fb.clearMode('noisy-rule', me);
    expect(eng.modeOverride('noisy-rule')).toBeUndefined();
    expect(eng.modeOf(eng.getRule('noisy-rule')!)).toBe('block');
    expect(eng.stores.ruleState.get('noisy-rule')?.fired).toBe(1);
    fb.clearMode('noisy-rule', me); // nothing to clear
    expect(eng.modeOverride('noisy-rule')).toBeUndefined();
  });

  it("counts every change to a rule or its mode in the rule's revision", () => {
    const eng = new DetectionEngine([noisy], memoryStores());
    const fb = new Feedback(eng, undefined, () => T0);
    const start = eng.revision('noisy-rule');
    fb.setMode('noisy-rule', 'shadow', me);
    fb.setMode('noisy-rule', 'shadow', me); // the same value still counts
    expect(eng.revision('noisy-rule')).toBe(start + 2);
    fb.clearMode('noisy-rule', me);
    fb.clearMode('noisy-rule', me); // nothing to clear: no change
    expect(eng.revision('noisy-rule')).toBe(start + 3);
    eng.upsertRule({ ...eng.getRule('noisy-rule')!, version: 2 });
    expect(eng.revision('noisy-rule')).toBe(start + 4);
  });
});

describe('exception scope', () => {
  it('refuses an exception that only names an agent', () => {
    expect(() => assertExceptionScope({ 'process.agent.id': 'claude-code' })).toThrow(/too broad/);
    expect(() => assertExceptionScope({ 'agent.id': 'claude-code', tool: 'Bash' })).toThrow(
      /too broad/,
    );
    expect(() => assertExceptionScope({})).toThrow(/too broad/);
    expect(() =>
      assertExceptionScope({ 'process.agent.id': 'claude-code', 'process.sha256': 'a'.repeat(64) }),
    ).not.toThrow();
  });
});
