import { describe, expect, it } from 'vitest';
import {
  compileCondition,
  globProblem,
  globToRegExp,
  MAX_SUBJECT_LENGTH,
  regexProblem,
  renderTemplate,
  resolveTemplateValue,
  type EvalState,
} from '../rules/compile.js';
import { connect, exec, proc } from './fixtures.js';

const none: EvalState = { baselineHas: () => false, listHas: () => false };

describe('globToRegExp', () => {
  it("expands ~ to any user's home and handles ** and *", () => {
    const r = globToRegExp('~/Library/Application Support/Google/Chrome/**/Cookies');
    expect(r.test('/Users/alex/Library/Application Support/Google/Chrome/Default/Cookies')).toBe(
      true,
    );
    expect(
      r.test('/Users/alex/Library/Application Support/Google/Chrome/Profile 2/Network/Cookies'),
    ).toBe(true);
    expect(r.test('/Users/alex/Library/Application Support/Google/Chrome/Cookies')).toBe(true);
    expect(
      r.test('/Users/alex/Library/Application Support/Google/Chrome/Default/Cookies-journal'),
    ).toBe(false);
    expect(globToRegExp('/usr/bin/*').test('/usr/bin/sub/x')).toBe(false);
  });
  it('is case-insensitive by default, like APFS', () => {
    expect(globToRegExp('~/.ssh/id_*').test('/Users/alex/.SSH/ID_ed25519')).toBe(true);
    expect(globToRegExp('~/.ssh/id_*', false).test('/Users/alex/.SSH/ID_ed25519')).toBe(false);
  });
  it('escapes regex characters', () => {
    expect(globToRegExp('/a/(b)+.c').test('/a/(b)+.c')).toBe(true);
    expect(globToRegExp('/a/(b)+.c').test('/a/bb.c')).toBe(false);
  });
  it('merges runs of wildcards without changing what they match', () => {
    expect(globToRegExp('/a/***/b').source).toBe(globToRegExp('/a/**/b').source);
    expect(globToRegExp('/a/**/**/b').source).toBe(globToRegExp('/a/**/b').source);
    expect(globToRegExp('/a/**/**').source).toBe(globToRegExp('/a/**').source);
    const r = globToRegExp('/a/*?*?');
    expect(r.test('/a/xy')).toBe(true);
    expect(r.test('/a/x')).toBe(false);
    expect(r.test('/a/x/y')).toBe(false);
  });
});

describe('globProblem', () => {
  it('accepts every glob the built-in rules use', () => {
    for (const g of [
      '/private/var/folders/**/AppTranslocation/*/d/Claude.app/**',
      '/Users/*/Library/Application Support/Google/Chrome/*/Local Extension Settings/**',
      '~/Library/Application Support/Google/Chrome/**/Local Extension Settings/**',
      '**/.claude/settings*.json',
      '~/.ssh/id_*',
    ])
      expect(globProblem(g), g).toBeUndefined();
  });
  it('refuses globs that can take too long to match', () => {
    expect(globProblem('**a**a**a**a**a**a!')).toMatch(/more than 4/);
    expect(globProblem('/*/*/*/*/*')).toMatch(/more than 4/);
    expect(globProblem('**a**a**a!')).toMatch(/can stop anywhere/);
    expect(globProblem('*a*a*a!')).toMatch(/can stop anywhere/);
    expect(globProblem('**/x/**/*.js')).toMatch(/can stop anywhere/);
  });
  it('lets the slowest glob it accepts fail on a long path in well under a second', () => {
    const subjects = [
      'a'.repeat(MAX_SUBJECT_LENGTH - 1) + '!',
      '/a'.repeat(MAX_SUBJECT_LENGTH / 2 - 1) + '!!',
    ];
    for (const g of ['*a**/a/', '*a**a', '/*a*a', '**a**/', '/**/a/*a?/*a']) {
      expect(globProblem(g), g).toBeUndefined();
      const r = globToRegExp(g);
      for (const s of subjects) {
        const t0 = performance.now();
        expect(r.test(s)).toBe(false);
        expect(performance.now() - t0, g).toBeLessThan(250);
      }
    }
  });
});

// Known-bad patterns, joined at run time so code scanning doesn't mistake
// these test inputs for regexes the app runs.
const bad = (...parts: string[]) => parts.join('');

describe('regexProblem', () => {
  it('rejects catastrophic patterns and backreferences', () => {
    expect(regexProblem('(a+)+$')).toMatch(/nested/);
    expect(regexProblem('(.*)*x')).toMatch(/nested/);
    expect(regexProblem('(a|b+){2,}')).toMatch(/nested/);
    expect(regexProblem('(a)\\1')).toMatch(/backreference/);
    expect(regexProblem('x'.repeat(300))).toMatch(/longer/);
    expect(regexProblem('([')).toMatch(/compile/);
  });
  it('rejects nested quantifiers through any depth of groups', () => {
    expect(regexProblem(bad('((a', '+))+$'))).toMatch(/nested/);
    expect(regexProblem('(?:x(?:y+)z)*$')).toMatch(/nested/);
    expect(regexProblem('(?:a{2,})+b')).toMatch(/nested/);
  });
  it('rejects repeated groups with alternatives', () => {
    expect(regexProblem(bad('(a|', 'a)*$'))).toMatch(/alternatives/);
    expect(regexProblem(bad('(?:x|', 'x)+y'))).toMatch(/alternatives/);
    expect(regexProblem('(?:(a|b)c){2,}d')).toMatch(/alternatives/);
  });
  it('rejects more than three open-ended wildcards', () => {
    expect(regexProblem('.*a.*b.*c.*d')).toMatch(/open-ended/);
    expect(regexProblem('[^x]*a[^y]+b.*c(?:[^z])*d')).toMatch(/open-ended/);
    // A lookaround is matched on its own, so it counts on its own.
    expect(regexProblem('^(?=.*a.*b)(?=.*c.*d)')).toBeUndefined();
  });
  it('accepts ordinary patterns, including optional groups', () => {
    expect(regexProblem('(curl|wget)\\s[^|]*\\|\\s*(ba|z)?sh\\b')).toBeUndefined();
    expect(regexProblem('\\|\\s*(sudo\\s+)?sh')).toBeUndefined();
    // A tempered token: the alternatives in the lookahead never backtrack.
    expect(regexProblem('(?:(?!a|b)[^;])*c')).toBeUndefined();
    expect(regexProblem('(sudo\\s+-\\S+)?(a|b){2}')).toBeUndefined();
  });
});

describe('operators', () => {
  const e = connect(
    proc({ path: '/opt/x/agent', args: ['agent', '--Mode', 'fast'] }),
    '10.1.2.3',
    'a.example.test',
  );
  const t = (c: Parameters<typeof compileCondition>[0]) => compileCondition(c).test(e, none);

  it('matches array fields element-wise', () => {
    expect(t({ field: 'process.args', op: 'eq', value: '--Mode' })).toBe(true);
    expect(t({ field: 'process.args', op: 'eq', value: '--mode' })).toBe(false);
    expect(t({ field: 'process.args', op: 'eq', value: '--mode', nocase: true })).toBe(true);
  });
  it('handles computed fields', () => {
    expect(t({ field: 'process.name', op: 'eq', value: 'agent' })).toBe(true);
    expect(t({ field: 'process.commandLine', op: 'contains', value: '--Mode fast' })).toBe(true);
  });
  it('handles cidr, numbers and exists', () => {
    expect(t({ field: 'remoteAddress', op: 'cidr', value: ['10.0.0.0/8'] })).toBe(true);
    expect(t({ field: 'remoteAddress', op: 'cidr', value: ['192.168.0.0/16'] })).toBe(false);
    expect(t({ field: 'remotePort', op: 'gt', value: 400 })).toBe(true);
    expect(t({ field: 'process.quarantine', op: 'exists' })).toBe(false);
    expect(t({ field: 'process.quarantine', op: 'exists', value: false })).toBe(true);
  });
  it('neq and notIn do not match a missing field', () => {
    expect(t({ field: 'process.signing', op: 'neq', value: 'apple' })).toBe(false);
    expect(t({ field: 'process.signing', op: 'notIn', value: ['apple'] })).toBe(false);
  });
  it('combines all, any and not', () => {
    expect(
      t({
        all: [
          { field: 'remotePort', op: 'eq', value: 443 },
          { not: { field: 'remoteHost', op: 'endsWith', value: '.apple.com' } },
          {
            any: [
              { field: 'process.name', op: 'eq', value: 'nope' },
              { field: 'process.name', op: 'startsWith', value: 'ag' },
            ],
          },
        ],
      }),
    ).toBe(true);
  });
});

describe('templates', () => {
  const e = exec(proc({ path: '/tmp/x', pid: 77 }));
  it('fills reasons and marks missing fields', () => {
    expect(renderTemplate('{{process.name}} from {{process.path}} via {{remoteHost}}', e)).toBe(
      'x from /tmp/x via unknown',
    );
  });
  it('tries alternatives in order, with quoted literals as the last resort', () => {
    expect(
      renderTemplate("{{remoteHost|process.name}} by {{process.parentName|'a program'}}", e),
    ).toBe('x by a program');
  });
  it('keeps a whole-field template typed and refuses missing values', () => {
    expect(resolveTemplateValue('{{process.pid}}', e)).toBe(77);
    expect(resolveTemplateValue('pid {{process.pid}}', e)).toBe('pid 77');
    expect(resolveTemplateValue('{{process.sha256}}', e)).toBeUndefined();
  });
});
