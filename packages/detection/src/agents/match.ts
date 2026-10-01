import type { AgentIdentity } from '@vigil/core';
import { globToRegExp } from '../rules/compile.js';

/** What matching sees of a program. Sensors give all four; a `ps` seed gives path and args. */
export interface AgentProc {
  path: string;
  args?: string[] | undefined;
  teamId?: string | undefined;
  signingId?: string | undefined;
}

export interface CompiledAgentMatcher {
  /**
   * The first identity, in list order, with a matcher that fits. Suggestions
   * are left out (they tag nothing until accepted). Ignored identities and
   * runtimes still match, so a program the user ignored is not mistaken for
   * an unknown one, but they come back with `watch: false`.
   */
  match(p: AgentProc): AgentIdentity | undefined;
  /** The identity with this id, with the same `watch` that `match` reports. */
  byId(id: string): AgentIdentity | undefined;
  /** True when this program's command line could decide a match, so it is worth keeping. */
  wantsArgs(p: AgentProc): boolean;
}

/** Longest command line an argument glob is tested against. */
const MAX_ARGS = 1024;

interface Clause {
  order: number;
  identity: AgentIdentity;
  teamIds?: Set<string>;
  signingIds?: Set<string>;
  names?: Set<string>;
  paths?: RegExp[];
  /** Lower case; all must match. */
  argGlobs?: string[];
}

function basename(p: string): string {
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

/**
 * `*` matches any run of characters (spaces and slashes included) and `?`
 * one character. Iterative with one backtrack point, so it stays linear in
 * practice and never worse than pattern × text, whatever the pattern.
 */
export function argGlobMatch(pattern: string, text: string): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    const c = pattern[p];
    if (c !== undefined && c !== '*' && (c === '?' || c === text[t])) {
      p++;
      t++;
    } else if (c === '*') {
      star = p++;
      mark = t;
    } else if (star !== -1) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (pattern[p] === '*') p++;
  return p === pattern.length;
}

function joinedArgs(p: AgentProc): string | undefined {
  if (!p.args?.length) return undefined;
  const s = p.args.join(' ');
  return (s.length > MAX_ARGS ? s.slice(0, MAX_ARGS) : s).toLowerCase();
}

/** Everything but the argument globs: does the clause name this program? */
function namesProgram(c: Clause, p: AgentProc, name: string): boolean {
  if (c.teamIds && !(p.teamId !== undefined && c.teamIds.has(p.teamId))) return false;
  if (c.signingIds && !(p.signingId !== undefined && c.signingIds.has(p.signingId))) return false;
  if (c.names && !c.names.has(name)) return false;
  if (c.paths && !c.paths.some((re) => re.test(p.path))) return false;
  return true;
}

/** A matcher's effective watch: only an active, watched agent that is not a runtime tags anything. */
function effective(id: AgentIdentity): AgentIdentity {
  const watch = id.status === 'active' && id.watch && id.kind !== 'runtime';
  return watch === id.watch ? id : { ...id, watch };
}

/**
 * Compile identities for the per-launch check. Matchers are indexed by team
 * ID, signing ID or name (whichever each names first), so most launches cost
 * a few map lookups; matchers with only path globs are tried last. When two
 * identities match, the earlier one in `ids` wins.
 */
export function compileAgentMatchers(ids: readonly AgentIdentity[]): CompiledAgentMatcher {
  const byTeam = new Map<string, Clause[]>();
  const bySigning = new Map<string, Clause[]>();
  const byName = new Map<string, Clause[]>();
  const globOnly: Clause[] = [];
  const byId = new Map<string, AgentIdentity>();
  const push = (m: Map<string, Clause[]>, k: string, c: Clause) => {
    const list = m.get(k);
    if (list) list.push(c);
    else m.set(k, [c]);
  };

  ids.forEach((raw, order) => {
    if (raw.status === 'suggested' || byId.has(raw.id)) return;
    const identity = effective(raw);
    byId.set(identity.id, identity);
    for (const m of identity.match) {
      const c: Clause = { order, identity };
      if (m.teamIds?.length) c.teamIds = new Set(m.teamIds);
      if (m.signingIds?.length) c.signingIds = new Set(m.signingIds);
      if (m.names?.length) c.names = new Set(m.names);
      if (m.paths?.length) c.paths = m.paths.map((g) => globToRegExp(g));
      if (m.argGlobs?.length) c.argGlobs = m.argGlobs.map((g) => g.toLowerCase());
      if (c.teamIds) for (const k of c.teamIds) push(byTeam, k, c);
      else if (c.signingIds) for (const k of c.signingIds) push(bySigning, k, c);
      else if (c.names) for (const k of c.names) push(byName, k, c);
      else if (c.paths) globOnly.push(c);
    }
  });

  // One pass over the path decides whether any glob-only clause is worth trying.
  const anyGlob = globOnly.length
    ? new RegExp(globOnly.flatMap((c) => c.paths!.map((re) => `(?:${re.source})`)).join('|'), 'i')
    : undefined;

  /** Clause lists that could fit p, cheapest first; the glob-only ones last. */
  const candidates = (p: AgentProc, name: string): Array<Clause[] | undefined> => [
    p.teamId !== undefined ? byTeam.get(p.teamId) : undefined,
    p.signingId !== undefined ? bySigning.get(p.signingId) : undefined,
    byName.get(name),
    anyGlob?.test(p.path) ? globOnly : undefined,
  ];

  return {
    match(p) {
      const name = basename(p.path);
      let args: string | undefined | null = null; // null: not joined yet
      let best: Clause | undefined;
      for (const list of candidates(p, name)) {
        if (!list) continue;
        for (const c of list) {
          if (best && c.order >= best.order) continue;
          if (!namesProgram(c, p, name)) continue;
          if (c.argGlobs) {
            if (args === null) args = joinedArgs(p);
            const a = args;
            if (a === undefined || !c.argGlobs.every((g) => argGlobMatch(g, a))) continue;
          }
          best = c;
        }
      }
      return best?.identity;
    },
    byId: (id) => byId.get(id),
    wantsArgs(p) {
      const name = basename(p.path);
      for (const list of candidates(p, name)) {
        for (const c of list ?? []) if (c.argGlobs && namesProgram(c, p, name)) return true;
      }
      return false;
    },
  };
}
