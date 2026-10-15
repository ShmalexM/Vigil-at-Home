import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  admitSavedRules,
  compileRule,
  DetectionEngine,
  RuleCompileError,
  SLOW_RULE_BUDGET_MS,
} from '../engine.js';
import { forgetLegacyPatterns } from '../rules/legacy.js';
import { lintRule } from '../rules/lint.js';
import { memoryStores } from '../state/stores.js';
import { DetectionRule } from '../types.js';
import { exec, proc, testRule } from './fixtures.js';

afterEach(() => {
  forgetLegacyPatterns();
  vi.restoreAllMocks();
});

const regexRule = (id: string, value: string, field = 'process.commandLine') =>
  testRule({ id, condition: { field, op: 'regex', value } });
const run = (args: string[]) => exec(proc({ path: '/bin/sh', pid: 800, args }));
const at = (path: string) => exec(proc({ path, pid: 801 }));

// Saved before rule patterns moved to the linear-time engine: each compiled then.
const LOOKAHEAD = 'curl(?=\\s)';
const NESTED_COUNT = '^(?:[0-9a-f]{10}){4}$';

describe('rules saved before the linear-time engine', () => {
  it('keep running exactly as before, marked legacy, and only the ones that need it', () => {
    const saved = [
      regexRule('r-look', LOOKAHEAD),
      regexRule('r-nested', NESTED_COUNT, 'process.path'),
      regexRule('r-sha1', '^[0-9a-f]{40}$', 'process.path'),
      testRule({
        id: 'r-glob',
        condition: { field: 'process.path', op: 'glob', value: `/tmp/*${'?'.repeat(20)}` },
      }),
      // Refused before too (a nested quantifier): still left out, with the reason.
      regexRule('r-broken', '(a+)+$'),
    ];
    const { rules, dropped } = admitSavedRules(saved);
    expect(rules.map((r) => r.id)).toEqual(['r-look', 'r-nested', 'r-sha1', 'r-glob']);
    expect(dropped).toEqual([{ id: 'r-broken', error: expect.stringMatching(/nested/) }]);

    const eng = new DetectionEngine(rules, memoryStores());
    expect(eng.legacyRules().sort()).toEqual(['r-look', 'r-nested']);
    const fired = (e: ReturnType<typeof run>) => eng.evaluate(e).map((d) => d.match.ruleId);
    expect(fired(run(['curl -s x']))).toEqual(['r-look']);
    expect(fired(run(['curlx']))).toEqual([]);
    expect(fired(at('0123456789'.repeat(4)))).toEqual(['r-nested', 'r-sha1']);
    expect(fired(at('0123456789'.repeat(4).slice(1)))).toEqual([]);
    expect(fired(at(`/tmp/${'x'.repeat(20)}`))).toEqual(['r-glob']);
  });

  it('can still be edited, keeping the pattern, but not given a new one', () => {
    admitSavedRules([regexRule('r-look', LOOKAHEAD)]);
    const edited = DetectionRule.parse({
      ...(regexRule('r-look', LOOKAHEAD) as object),
      name: 'Renamed',
    });
    expect(compileRule(edited).legacy).toEqual([
      { field: 'process.commandLine', nocase: false, pattern: LOOKAHEAD },
    ]);
    expect(lintRule(edited).errors).toEqual([]);
    expect(() => compileRule(regexRule('r-look', 'wget(?=\\s)'))).toThrow(/lookahead/);
  });

  it('a new rule, AI draft or import with the same pattern is refused with the reason', () => {
    admitSavedRules([regexRule('r-look', LOOKAHEAD)]);
    for (const id of ['r-new', 'ai-r-look'])
      expect(() => compileRule(regexRule(id, LOOKAHEAD))).toThrow(RuleCompileError);
    expect(() => compileRule(regexRule('r-new', LOOKAHEAD))).toThrow(/linear-time.*lookahead/);
    expect(lintRule(DetectionRule.parse(regexRule('r-new', LOOKAHEAD))).errors.join()).toMatch(
      /lookahead/,
    );
  });

  it('are still timed by the watchdog', () => {
    const { rules } = admitSavedRules([regexRule('r-look', LOOKAHEAD)]);
    const slow: string[] = [];
    const eng = new DetectionEngine(rules, memoryStores(), { onSlowRule: (r) => slow.push(r.id) });
    let t = 0;
    let calls = 0;
    vi.spyOn(performance, 'now').mockImplementation(() =>
      calls++ % 2 ? (t += SLOW_RULE_BUDGET_MS) : t,
    );
    for (let i = 0; i < 2; i++) eng.evaluate(run(['ls']));
    expect(slow).toEqual(['r-look']);
  });
});

describe('a legacy permission', () => {
  const withCase = (id: string, value: string, field: string, nocase: boolean) =>
    testRule({ id, condition: { field, op: 'regex', value, nocase } });

  it('is bound to the rule id, field, case setting and text together', () => {
    admitSavedRules([regexRule('r-look', LOOKAHEAD)]);
    expect(() => compileRule(regexRule('r-look', LOOKAHEAD))).not.toThrow();
    expect(() => compileRule(withCase('r-look', LOOKAHEAD, 'process.commandLine', true))).toThrow(
      /lookahead/,
    );
    expect(() => compileRule(regexRule('r-look', LOOKAHEAD, 'process.path'))).toThrow(/lookahead/);
  });

  it('is revoked when the rule in force is removed, so the same rule cannot come back', () => {
    const { rules } = admitSavedRules([regexRule('r-look', LOOKAHEAD)]);
    const eng = new DetectionEngine(rules, memoryStores(), { holdsLegacy: true });
    expect(eng.legacyRules()).toEqual(['r-look']);
    eng.removeRule('r-look');
    for (const again of [
      regexRule('r-look', LOOKAHEAD),
      withCase('r-look', LOOKAHEAD, 'process.commandLine', true),
      regexRule('r-look', LOOKAHEAD, 'process.path'),
    ]) {
      expect(() => compileRule(again)).toThrow(/lookahead/);
      expect(() => eng.upsertRule(again)).toThrow(/lookahead/);
    }
  });

  it('is revoked when an edit stops using the test, and not by a replay of the edit', () => {
    const { rules } = admitSavedRules([regexRule('r-look', LOOKAHEAD)]);
    const eng = new DetectionEngine(rules, memoryStores(), { holdsLegacy: true });
    // A replay or preview builds its own engine: that changes nothing.
    new DetectionEngine([regexRule('r-look', 'curl\\s')], memoryStores());
    expect(() => compileRule(regexRule('r-look', LOOKAHEAD))).not.toThrow();
    eng.upsertRule(regexRule('r-look', 'curl\\s'));
    expect(eng.legacyRules()).toEqual([]);
    expect(() => eng.upsertRule(regexRule('r-look', LOOKAHEAD))).toThrow(/lookahead/);
  });
});
