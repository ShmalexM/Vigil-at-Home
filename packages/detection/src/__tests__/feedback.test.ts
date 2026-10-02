import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { Feedback } from '../feedback.js';
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
});
