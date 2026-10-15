import { describe, expect, it } from 'vitest';
import { AGENT_CATALOG } from '../agents/catalog.js';
import { builtinRulesFor } from '../packs/agent-preflight.js';
import { globMatcher, globToRegExp } from '../rules/compile.js';
import {
  APPLE_TOOL_GLOBS,
  DEFAULT_PROTECTED_PATH_GLOBS,
  PROTECTED_FILE_GLOBS,
  SYSTEM_PERSISTENCE_GLOBS,
} from '../safety.js';

/** Every glob Vigil ships: in built-in rules, the agent catalogue and the safety floor. */
function shippedGlobs(): string[] {
  const out = new Set<string>([
    ...DEFAULT_PROTECTED_PATH_GLOBS,
    ...PROTECTED_FILE_GLOBS,
    ...APPLE_TOOL_GLOBS,
    ...SYSTEM_PERSISTENCE_GLOBS,
    ...AGENT_CATALOG.flatMap((a) => a.match.flatMap((m) => m.paths ?? [])),
  ]);
  const walk = (c: unknown): void => {
    if (!c || typeof c !== 'object') return;
    const o = c as Record<string, unknown>;
    if (o.op === 'glob') for (const v of [o.value].flat()) out.add(String(v));
    for (const v of Object.values(o)) walk(v);
  };
  for (const r of [...builtinRulesFor('darwin'), ...builtinRulesFor('linux')]) walk(r);
  return [...out];
}

/** A small deterministic generator, so a failure names the same paths every run. */
function rng(seed: number) {
  let x = seed;
  return (n: number) => {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    return x % n;
  };
}

const FILL = {
  home: ['/Users/alex/', '/home/bob/', '/root/', '/srv/home/x/', '/Users//', '/USERS/Alex/'],
  dirs: ['', 'a/', 'a/b/', 'a\nb/', 'Ä/', '/'],
  any: ['', 'x', 'x/y', 'x\ny', 'X.App/Contents', ' '],
  star: ['', 'z', 'ZZ', 'z/z', 'z\nz', 'ß', 'ſ'],
  one: ['q', '', 'qq', '/', '\n', 'K'],
};

/** Paths a glob should match, by filling its wildcards, then near misses of each. */
function corpus(glob: string, pick: (n: number) => number): string[] {
  const one = <T>(xs: readonly T[]) => xs[pick(xs.length)]!;
  const out: string[] = [];
  for (let i = 0; i < 40; i++) {
    let p = '';
    let g = glob;
    if (g.startsWith('~/')) {
      p += one(FILL.home);
      g = g.slice(2);
    }
    for (let j = 0; j < g.length; j++) {
      if (g.startsWith('**/', j)) {
        p += one(FILL.dirs);
        j += 2;
      } else if (g.startsWith('**', j)) {
        p += one(FILL.any);
        j += 1;
      } else if (g[j] === '*') p += one(FILL.star);
      else if (g[j] === '?') p += one(FILL.one);
      else p += g[j];
    }
    const at = pick(p.length + 1);
    out.push(
      p,
      p.toUpperCase(),
      p.toLowerCase(),
      `${p}x`,
      `${p}\n`,
      `${p}/`,
      p.slice(0, -1),
      `${p.slice(0, at)}\n${p.slice(at)}`,
      `${p.slice(0, at)}/${p.slice(at)}`,
      `x${p}`,
    );
  }
  return out;
}

describe('every glob Vigil ships', () => {
  const globs = shippedGlobs();

  it('is found', () => {
    expect(globs.length).toBeGreaterThan(20);
    expect(globs.some((g) => g.startsWith('~/'))).toBe(true);
    expect(globs.some((g) => g.includes('**/'))).toBe(true);
  });

  it('matches with globMatcher exactly what its regex matched, with and without case', () => {
    const pick = rng(7);
    const wrong: string[] = [];
    let checked = 0;
    let matched = 0;
    for (const g of globs) {
      const paths = [...corpus(g, pick), ...globs.flatMap((h) => corpus(h, pick).slice(0, 2))];
      for (const ic of [true, false]) {
        const re = globToRegExp(g, ic);
        const fits = globMatcher(g, ic);
        for (const p of paths) {
          checked++;
          if (re.test(p)) matched++;
          if (fits(p) !== re.test(p)) wrong.push(`${g} ${ic} ${JSON.stringify(p)}`);
        }
      }
    }
    expect(wrong).toEqual([]);
    expect(checked).toBeGreaterThan(10_000);
    // Both answers come up often, so the comparison means something.
    expect(matched).toBeGreaterThan(checked / 20);
    expect(matched).toBeLessThan(checked - checked / 20);
  });
});
