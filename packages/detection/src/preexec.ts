// Turns rules that block a program as it starts into Santa CEL rules, so
// Santa stops the program before it runs instead of Vigil killing it a few
// milliseconds after.
//
//   rule (mode block, kills on process.exec, osascript + args test)
//     ─► { program: 'osascript', test: 'args.join(" ").lowerAscii().contains("hidden answer")' }
//     ─► helper resolves /usr/bin/osascript to platform:com.apple.osascript
//     ─► Santa SIGNINGID rule, policy CEL: (tests) ? BLOCKLIST : ALLOWLIST
//
// Only rules Santa can evaluate exactly are compiled: the program must be
// named by process.name or process.path at the top of the rule, and every
// other test must read only the program's arguments (CEL v1 sees args, cwd,
// envs, euid and path, not the parent or the signature). Everything else
// stays with Vigil's own engine, which also keeps running the compiled rules
// as a backstop for older Santa versions.
//
// The helper only accepts Apple platform binaries as targets: the CEL rule's
// "otherwise" answer is ALLOWLIST, which is harmless for programs macOS ships
// (Santa allows them anyway) and must never be applied to anything else.

import type { Condition, DetectionRule, FieldTest, RuleMode } from './types.js';

/** One Apple program and the argument tests that block it. */
export interface PreexecRule {
  /** Program name, e.g. "osascript". The helper finds it under the system folders. */
  program: string;
  /** CEL boolean expressions; any one true blocks the launch. */
  tests: string[];
  /** The Vigil rules the tests came from. */
  ruleIds: string[];
  /** Shown in Santa's block dialog. */
  message: string;
}

export interface PreexecResult {
  rules: PreexecRule[];
  /** Block rules left to Vigil's engine, with why. */
  skipped: { ruleId: string; reason: string }[];
}

const PROGRAM_NAME = /^[A-Za-z0-9_.+-]{1,64}$/;
const SYSTEM_DIRS = ['/usr/bin/', '/bin/', '/usr/sbin/', '/sbin/', '/usr/libexec/'];
const MAX_LITERAL = 512;
const MAX_TESTS_PER_PROGRAM = 32;

class NotCompilable extends Error {}

/** A CEL string literal. Refuses anything that isn't plain printable text. */
export function celString(s: string): string {
  if (s.length > MAX_LITERAL) throw new NotCompilable(`text longer than ${MAX_LITERAL}`);
  // eslint-disable-next-line no-control-regex
  if (/[\u0000-\u001f\u007f]/.test(s)) throw new NotCompilable('text with control characters');
  return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
}

function values(t: FieldTest): string[] {
  const v = t.value;
  if (Array.isArray(v)) return v.map(String);
  if (v === undefined || typeof v === 'boolean') throw new NotCompilable(`${t.op} without text`);
  return [String(v)];
}

/** A test on one string (`s` is a CEL expression for it). */
function stringTest(s: string, t: FieldTest): string {
  const ic = t.nocase === true;
  const subject = ic ? `${s}.lowerAscii()` : s;
  const lits = values(t).map((v) => celString(ic ? v.toLowerCase() : v));
  const one = (op: string): string => {
    const parts = lits.map((l) => `${subject}.${op}(${l})`);
    return parts.length === 1 ? parts[0]! : `(${parts.join(' || ')})`;
  };
  switch (t.op) {
    case 'eq':
      return `${subject} == ${lits[0]}`;
    case 'in':
      return `${subject} in [${lits.join(', ')}]`;
    case 'contains':
      return one('contains');
    case 'startsWith':
      return one('startsWith');
    case 'endsWith':
      return one('endsWith');
    default:
      throw new NotCompilable(`op ${t.op} on arguments`);
  }
}

function leaf(t: FieldTest): string {
  if (t.field === 'process.commandLine') return stringTest('args.join(" ")', t);
  if (t.field === 'process.args') return `args.exists(a, ${stringTest('a', t)})`;
  throw new NotCompilable(`field ${t.field} is not visible to Santa`);
}

function expr(c: Condition): string {
  if ('all' in c) return `(${c.all.map(expr).join(' && ')})`;
  if ('any' in c) return `(${c.any.map(expr).join(' || ')})`;
  if ('not' in c) return `!${expr(c.not)}`;
  if ('field' in c) return leaf(c);
  throw new NotCompilable('first-seen and list conditions need Vigil');
}

function programsOf(t: FieldTest): string[] {
  if (t.op !== 'eq' && t.op !== 'in') throw new NotCompilable(`program named with ${t.op}`);
  const names = values(t).map((v) => {
    if (t.field === 'process.name') return v;
    const dir = SYSTEM_DIRS.find((d) => v.startsWith(d));
    if (!dir) throw new NotCompilable('program outside the system folders');
    return v.slice(dir.length);
  });
  for (const n of names) if (!PROGRAM_NAME.test(n)) throw new NotCompilable(`program name ${n}`);
  return names;
}

/** Splits a rule's condition into the programs it names and the argument tests. */
function split(rule: DetectionRule): { programs: string[]; test: string } {
  const top = 'all' in rule.condition ? rule.condition.all : [rule.condition];
  let programs: string[] | undefined;
  const rest: string[] = [];
  for (const c of top) {
    if ('field' in c && (c.field === 'process.name' || c.field === 'process.path')) {
      if (programs) throw new NotCompilable('program named twice');
      programs = programsOf(c);
    } else {
      rest.push(expr(c));
    }
  }
  if (!programs) throw new NotCompilable('no program named');
  if (rest.length === 0) throw new NotCompilable('would block every launch of the program');
  for (const ex of rule.exclusions) rest.push(`!${expr(ex)}`);
  return { programs, test: rest.length === 1 ? rest[0]! : `(${rest.join(' && ')})` };
}

/**
 * The Santa CEL rules for every rule that blocks on launch.
 * @param rules each rule with the mode actually applied to it
 */
export function preexecRules(rules: { rule: DetectionRule; mode: RuleMode }[]): PreexecResult {
  const byProgram = new Map<string, PreexecRule>();
  const skipped: PreexecResult['skipped'] = [];
  for (const { rule, mode } of rules) {
    if (mode !== 'block') continue;
    if (rule.eventKinds.length !== 1 || rule.eventKinds[0] !== 'process.exec') continue;
    // Stopping the launch matches a rule that kills; a rule that only pauses
    // leaves the user able to let the program carry on, so it stays in Vigil.
    if (!rule.response?.some((a) => a.kind === 'process.kill')) {
      skipped.push({ ruleId: rule.id, reason: 'does not kill the program' });
      continue;
    }
    try {
      const { programs, test } = split(rule);
      for (const program of programs) {
        const entry = byProgram.get(program) ?? {
          program,
          tests: [],
          ruleIds: [],
          message: rule.name,
        };
        if (entry.tests.length >= MAX_TESTS_PER_PROGRAM) {
          skipped.push({ ruleId: rule.id, reason: `too many rules for ${program}` });
          continue;
        }
        entry.tests.push(test);
        if (!entry.ruleIds.includes(rule.id)) entry.ruleIds.push(rule.id);
        if (entry.ruleIds.length > 1) entry.message = 'Vigil stopped this command.';
        byProgram.set(program, entry);
      }
    } catch (err) {
      if (!(err instanceof NotCompilable)) throw err;
      skipped.push({ ruleId: rule.id, reason: err.message });
    }
  }
  return { rules: [...byProgram.values()], skipped };
}

/** The full CEL program Santa runs for one target. */
export function celProgram(tests: string[]): string {
  return `(${tests.join(') || (')}) ? BLOCKLIST : ALLOWLIST`;
}
