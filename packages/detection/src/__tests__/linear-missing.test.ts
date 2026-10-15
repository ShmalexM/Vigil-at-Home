import { afterEach, describe, expect, it } from 'vitest';
import { compileAgentMatchers } from '../agents/match.js';
import { admitSavedRules, compileRule, DetectionEngine } from '../engine.js';
import { builtinRulesFor } from '../packs/agent-preflight.js';
import { globMatcher, globProblem, globToRegExp, MAX_SUBJECT_LENGTH } from '../rules/compile.js';
import { forgetLegacyPatterns } from '../rules/legacy.js';
import { linearEngine, linearProblem, simulateLinearEngine } from '../rules/linear.js';
import { lintRule } from '../rules/lint.js';
import { SafetyFloor } from '../safety.js';
import { memoryStores } from '../state/stores.js';
import { DetectionRule } from '../types.js';
import { exec, proc, testRule } from './fixtures.js';

afterEach(() => {
  simulateLinearEngine(undefined);
  forgetLegacyPatterns();
});

const regexRule = (id: string, value: string, field = 'process.commandLine') =>
  testRule({ id, condition: { field, op: 'regex', value } });
const at = (path: string) => exec(proc({ path, pid: 801 }));

describe('without the linear-time engine', () => {
  it('is on in this runtime unless simulated off', () => {
    expect(linearEngine()).toBe(true);
    simulateLinearEngine(false);
    expect(linearEngine()).toBe(false);
  });

  it('refuses a new rule regex with the reason, never falling back to backtracking', () => {
    simulateLinearEngine(false);
    expect(linearProblem('^/tmp/x$')).toMatch(/can't run the linear-time matcher/);
    expect(() => compileRule(regexRule('r-new', '^/tmp/x$', 'process.path'))).toThrow(
      /can't run the linear-time matcher/,
    );
    expect(lintRule(DetectionRule.parse(regexRule('r-new', 'x'))).errors.join()).toMatch(
      /linear-time matcher/,
    );
  });

  it('keeps built-in rules as they ship and saved rules as legacy', () => {
    simulateLinearEngine(false);
    for (const r of builtinRulesFor('darwin')) expect(() => compileRule(r), r.id).not.toThrow();
    const { rules, dropped } = admitSavedRules([
      regexRule('r-own', '^/tmp/x[0-9]+$', 'process.path'),
    ]);
    expect(dropped).toEqual([]);
    const eng = new DetectionEngine(rules, memoryStores());
    expect(eng.legacyRules()).toEqual(['r-own']);
    expect(eng.evaluate(at('/tmp/x12'))).toHaveLength(1);
  });

  it('still matches globs in rules, agent identities and protected paths', () => {
    simulateLinearEngine(false);
    const glob = testRule({
      id: 'r-glob',
      condition: { field: 'process.path', op: 'glob', value: '/Users/*/Downloads/**' },
    });
    const eng = new DetectionEngine([glob], memoryStores());
    expect(eng.evaluate(at('/Users/alex/downloads/x/evil'))).toHaveLength(1);
    expect(eng.evaluate(at('/Users/alex/Documents/evil'))).toEqual([]);
    const m = compileAgentMatchers([
      {
        id: 'mine',
        name: 'Mine',
        kind: 'cli',
        match: [{ paths: ['/opt/**/a**b'] }],
        watch: true,
        origin: 'user',
        status: 'active',
        createdAt: 0,
        updatedAt: 0,
      },
    ]);
    expect(m.match({ path: '/opt/x/y/axxb' })?.id).toBe('mine');
    expect(m.match({ path: '/opt/x/y/axx' })).toBeUndefined();
    const floor = new SafetyFloor({ protectedPathGlobs: ['/opt/**/a**b'] });
    expect(floor.processProtection({ pid: 50, path: '/opt/q/aZb', signing: 'unsigned' })).toMatch(
      /protected/,
    );
  });
});

describe('globMatcher', () => {
  const globs = [
    '/usr/bin/*',
    '/opt/**/a**b',
    '/opt/**/**/a***b',
    '~/Library/Application Support/Google/Chrome/**/Cookies',
    '~/.ssh/id_*',
    '/a/(b)+.c',
    '/a/*?*?',
    '/tmp/*????',
    '**/x',
    '/a/**',
    '/a/**/b/*',
    '?',
    '/Ä/ß*',
  ];
  const paths = [
    '/usr/bin/git',
    '/usr/bin/sub/x',
    '/opt/a/b/axb',
    '/opt/ab',
    '/opt/x/aQb',
    '/opt/x/a/b',
    '/opt/x/a\nb',
    '/Users/alex/Library/Application Support/Google/Chrome/Default/Cookies',
    '/home/alex/Library/Application Support/Google/Chrome/Cookies',
    '/root/.ssh/ID_ed25519',
    '/srv/home/alex/.ssh/id_rsa',
    '/Users//.ssh/id_rsa',
    '/a/(b)+.c',
    '/a/bb.c',
    '/a/xy',
    '/a/x',
    '/tmp/abcd',
    '/tmp/abc',
    'x',
    '/q/x',
    '/a/',
    '/a/c/b/d',
    '/a/b/d/e',
    'Q',
    '/ä/SS',
    '/ä/ßx',
  ];
  it('matches exactly what globToRegExp matches, either case setting', () => {
    for (const g of globs)
      for (const ic of [true, false]) {
        const re = globToRegExp(g, ic);
        const fits = globMatcher(g, ic);
        for (const p of paths)
          expect(fits(p), `${g} ${ic} on ${JSON.stringify(p)}`).toBe(re.test(p));
      }
  });

  it('runs a glob with two open wildcards on a crafted path in linear time', () => {
    const g = '/opt/**/a**b';
    expect(globProblem(g)).toBeUndefined();
    // Collapsed: repeats of ** are one wildcard.
    expect(globMatcher('/opt/**/**/a***b')('/opt/x/axb')).toBe(true);
    const fits = globMatcher(g);
    const crafted = `/opt/${'a/'.repeat(MAX_SUBJECT_LENGTH)}`.slice(0, MAX_SUBJECT_LENGTH);
    for (const on of [undefined, false]) {
      simulateLinearEngine(on);
      const t0 = performance.now();
      for (let i = 0; i < 10; i++) expect(fits(crafted)).toBe(false);
      expect((performance.now() - t0) / 10).toBeLessThan(25);
      const m = compileAgentMatchers([
        {
          id: 'mine',
          name: 'Mine',
          kind: 'cli',
          match: [{ paths: [g] }],
          watch: true,
          origin: 'user',
          status: 'active',
          createdAt: 0,
          updatedAt: 0,
        },
      ]);
      const t1 = performance.now();
      expect(m.match({ path: crafted })).toBeUndefined();
      expect(
        new SafetyFloor({ protectedPathGlobs: [g] }).processProtection({
          pid: 50,
          path: crafted,
          signing: 'unsigned',
        }),
      ).toBeUndefined();
      expect(performance.now() - t1).toBeLessThan(50);
    }
  });
});
