import { describe, expect, it } from 'vitest';
import { compileCondition } from '../rules/compile.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { celProgram, celString, preexecRules } from '../preexec.js';
import { DetectionRule, type DetectionRuleInput } from '../types.js';
import { exec, osascriptTool } from './fixtures.js';

const KILL = {
  kind: 'process.kill',
  pid: '{{process.pid}}',
  startTime: '{{process.startTime}}',
  path: '{{process.path}}',
} as const;

function rule(r: Partial<DetectionRuleInput> & Pick<DetectionRuleInput, 'id' | 'condition'>) {
  return DetectionRule.parse({
    version: 1,
    origin: 'user',
    createdAt: 1,
    updatedAt: 1,
    name: r.id,
    description: 'test',
    mode: 'block',
    severity: 'high',
    fidelity: 'high',
    eventKinds: ['process.exec'],
    response: [KILL],
    reasons: ['test reason'],
    ...r,
  });
}

/**
 * Evaluates the CEL subset preexec emits, by rewriting it into JavaScript.
 * Lets the tests check Santa would decide exactly as Vigil's engine does.
 */
function celEval(program: string, args: string[]): string {
  const js = program
    .replace(/\.lowerAscii\(\)/g, '.toLowerCase()')
    .replace(/\.contains\(/g, '.includes(')
    .replace(/args\.exists\(a, /g, 'args.some((a) => ')
    .replace(/((?:args\.join\(" "\)|a)(?:\.toLowerCase\(\))?) in (\[[^\]]*\])/g, '$2.includes($1)')
    .replace(/\bBLOCKLIST\b/g, '"BLOCKLIST"')
    .replace(/\bALLOWLIST\b/g, '"ALLOWLIST"');
  return new Function('args', `return ${js};`)(args) as string;
}

describe('preexecRules', () => {
  it('turns the fake password dialog rule into an osascript CEL rule', () => {
    const fake = macosCoreRules.find((r) => r.id === 'fake-password-prompt')!;
    const out = preexecRules([{ rule: DetectionRule.parse(fake), mode: 'block' }]);
    expect(out.rules).toHaveLength(1);
    const r = out.rules[0]!;
    expect(r.program).toBe('osascript');
    expect(r.ruleIds).toEqual(['fake-password-prompt']);
    expect(r.tests[0]).toBe(
      '(args.join(" ").lowerAscii().contains("display dialog") && ' +
        'args.join(" ").lowerAscii().contains("hidden answer"))',
    );
  });

  it('decides the same as the engine on matching and harmless launches', () => {
    const fake = DetectionRule.parse(macosCoreRules.find((r) => r.id === 'fake-password-prompt')!);
    const program = celProgram(preexecRules([{ rule: fake, mode: 'block' }]).rules[0]!.tests);
    const engine = compileCondition(fake.condition);
    const cases = [
      ['-e', 'display dialog "Update" default answer "" with Hidden Answer'],
      ['-e', 'display dialog "Hello"'],
      ['-e', 'tell application "Music" to play'],
      ['-e', 'DISPLAY DIALOG "x" with hidden answer'],
    ];
    const state = { baselineHas: () => false, listHas: () => false };
    for (const args of cases) {
      const e = exec(osascriptTool(args));
      const argv = (e as { process: { args: string[] } }).process.args;
      expect(celEval(program, argv)).toBe(engine.test(e, state) ? 'BLOCKLIST' : 'ALLOWLIST');
    }
  });

  it('leaves alert and shadow rules, and rules that only pause, to the engine', () => {
    const cond = {
      all: [
        { field: 'process.name', op: 'eq' as const, value: 'security' },
        { field: 'process.args', op: 'eq' as const, value: 'dump-keychain' },
      ],
    };
    const out = preexecRules([
      { rule: rule({ id: 'a', condition: cond }), mode: 'alert' },
      {
        rule: rule({
          id: 'pause',
          condition: cond,
          response: [{ ...KILL, kind: 'process.suspend' }],
        }),
        mode: 'block',
      },
    ]);
    expect(out.rules).toEqual([]);
    expect(out.skipped).toEqual([{ ruleId: 'pause', reason: 'does not kill the program' }]);
  });

  it('skips rules that need what Santa cannot see', () => {
    const out = preexecRules([
      {
        rule: rule({
          id: 'parent',
          condition: {
            all: [
              { field: 'process.name', op: 'eq', value: 'curl' },
              { field: 'process.parentName', op: 'eq', value: 'zsh' },
            ],
          },
        }),
        mode: 'block',
      },
      {
        rule: rule({
          id: 'everything',
          condition: { field: 'process.name', op: 'eq', value: 'curl' },
        }),
        mode: 'block',
      },
      {
        rule: rule({
          id: 'anywhere',
          condition: {
            all: [
              { field: 'process.path', op: 'eq', value: '/tmp/x' },
              { field: 'process.args', op: 'eq', value: '-y' },
            ],
          },
        }),
        mode: 'block',
      },
    ]);
    expect(out.rules).toEqual([]);
    expect(out.skipped.map((s) => s.ruleId)).toEqual(['parent', 'everything', 'anywhere']);
  });

  it('groups rules by program, negates exclusions, and names programs by system path', () => {
    const out = preexecRules([
      {
        rule: rule({
          id: 'one',
          condition: {
            all: [
              { field: 'process.path', op: 'eq', value: '/usr/sbin/spctl' },
              { field: 'process.args', op: 'in', value: ['--master-disable', '--global-disable'] },
            ],
          },
        }),
        mode: 'block',
      },
      {
        rule: rule({
          id: 'two',
          condition: {
            all: [
              { field: 'process.name', op: 'eq', value: 'spctl' },
              { field: 'process.args', op: 'eq', value: '--disable' },
            ],
          },
          exclusions: [{ field: 'process.commandLine', op: 'contains', value: '--label' }],
        }),
        mode: 'block',
      },
    ]);
    expect(out.rules).toHaveLength(1);
    const r = out.rules[0]!;
    expect(r.program).toBe('spctl');
    expect(r.ruleIds).toEqual(['one', 'two']);
    const program = celProgram(r.tests);
    expect(celEval(program, ['spctl', '--master-disable'])).toBe('BLOCKLIST');
    expect(celEval(program, ['spctl', '--disable'])).toBe('BLOCKLIST');
    expect(celEval(program, ['spctl', '--disable', '--label', 'x'])).toBe('ALLOWLIST');
    expect(celEval(program, ['spctl', '--status'])).toBe('ALLOWLIST');
  });

  it('escapes text safely and refuses control characters', () => {
    expect(celString('say "hi" \\ bye')).toBe('"say \\"hi\\" \\\\ bye"');
    expect(() => celString('a\nb')).toThrow();
    const out = preexecRules([
      {
        rule: rule({
          id: 'quote',
          condition: {
            all: [
              { field: 'process.name', op: 'eq', value: 'osascript' },
              { field: 'process.commandLine', op: 'contains', value: 'x") || true || ("' },
            ],
          },
        }),
        mode: 'block',
      },
    ]);
    const program = celProgram(out.rules[0]!.tests);
    expect(celEval(program, ['osascript', '-e', 'harmless'])).toBe('ALLOWLIST');
    expect(celEval(program, ['osascript', 'x") || true || ("'])).toBe('BLOCKLIST');
  });

  it('only accepts plain program names', () => {
    const out = preexecRules([
      {
        rule: rule({
          id: 'odd',
          condition: {
            all: [
              { field: 'process.name', op: 'eq', value: '../evil' },
              { field: 'process.args', op: 'eq', value: '-x' },
            ],
          },
        }),
        mode: 'block',
      },
    ]);
    expect(out.rules).toEqual([]);
  });
});
