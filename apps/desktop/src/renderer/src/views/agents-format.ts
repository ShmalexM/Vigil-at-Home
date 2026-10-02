import type { AgentMatcherView, AgentView, TreeNode } from '../../../shared/agents';

// Plain helpers for the Agents page: routes, the process tree's order, and the
// matcher form. No React here, so they can be tested on their own.

/** Vigil's own AI helpers run under this tag; it is never a watched agent. */
export const VIGIL_SELF = 'vigil-self';
/** An MCP server Vigil started for the pack. Same id as VIGIL_CONNECTOR in @vigil/detection. */
export const VIGIL_CONNECTOR = 'vigil-connector';

// ---------------------------------------------------------------- routes

const SESSION = /^[0-9a-f]{16}$/;
const AGENT = /^[a-z0-9][a-z0-9-]{0,39}$/;

/**
 * `agents/<id>` opens an agent and `agents/<id>_<session>` one of its
 * sessions. Agent ids never contain `_`, so the split is unambiguous, and
 * both fit the route pattern main accepts (`[A-Za-z0-9_-]+`).
 */
export function agentRoute(id: string, session?: string): string {
  return session ? `agents/${id}_${session}` : `agents/${id}`;
}

export function parseAgentParam(param: string | undefined): { id?: string; session?: string } {
  if (!param) return {};
  const [id = '', session] = param.split('_');
  if (!AGENT.test(id)) return {};
  return session && SESSION.test(session) ? { id, session } : { id };
}

/** Activity's feed narrowed to one agent (`activity/agent-<id>`) or one session (`activity/session-<hex>`). */
export function activityRoute(filter: { agent: string } | { session: string }): string {
  return 'agent' in filter
    ? `activity/agent-${filter.agent}`
    : `activity/session-${filter.session}`;
}

export function parseActivityParam(param: string | undefined): {
  agent?: string;
  session?: string;
} {
  if (param?.startsWith('agent-')) {
    const id = param.slice('agent-'.length);
    return AGENT.test(id) ? { agent: id } : {};
  }
  if (param?.startsWith('session-')) {
    const id = param.slice('session-'.length);
    return SESSION.test(id) ? { session: id } : {};
  }
  return {};
}

// ---------------------------------------------------------------- labels

/**
 * Where an agent came from, as its card's chip: found by Vigil (a built-in it
 * has seen, or a suggestion you accepted), in Vigil's list only, yours, or a
 * suggestion still waiting on you.
 */
export function originLabel(a: Pick<AgentView, 'origin' | 'status' | 'presence'>): {
  label: string;
  tone?: 'accent';
} {
  if (a.origin === 'user') return { label: 'Added by you' };
  if (a.origin === 'suggested') {
    return a.status === 'suggested'
      ? { label: 'Suggested', tone: 'accent' }
      : { label: 'Detected' };
  }
  return { label: a.presence === 'not-found' ? 'Built-in' : 'Detected' };
}

/**
 * Whether Vigil tags what this agent starts, as the matcher decides it
 * (`effective` in @vigil/detection): an active agent whose switch is on, and
 * never a model runtime. The stored switch stays as it was while an agent is
 * ignored, so it comes back when you watch the agent again.
 */
export function watching(a: Pick<AgentView, 'status' | 'watch' | 'kind'>): boolean {
  return a.status === 'active' && a.watch && a.kind !== 'runtime';
}

/** An agent's Sessions list when it has none. */
export function noSessionsText(a: Pick<AgentView, 'status' | 'watch' | 'kind'>): string {
  if (watching(a)) return 'No sessions yet. One starts the next time it runs.';
  if (a.status === 'ignored')
    return 'No sessions: this agent is ignored, so Vigil tags nothing it runs.';
  return 'No sessions: Vigil starts sessions only for agents it watches.';
}

/** "3 asks", "1 ask". */
export function plural(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}

// ---------------------------------------------------------------- sessions

/** The sessions listed: the live first page, then the older ones loaded, each once. */
export function mergeSessions<S extends { id: string }>(
  first: readonly S[],
  older: readonly S[],
): S[] {
  const all = new Map<string, S>();
  for (const s of [...first, ...older]) if (!all.has(s.id)) all.set(s.id, s);
  return [...all.values()];
}

/**
 * The page before the oldest session shown, added to a copy of everything
 * shown. The copy matters: the first page reloads as new sessions start, and
 * a session that drops off its end would otherwise vanish. `fetch(before)`
 * returns up to `pageSize` sessions that started strictly before `before`,
 * newest first, so it is asked from one past the oldest start: sessions that
 * started in that same millisecond come back too, and the ones shown are
 * dropped. Only when a whole page started in that millisecond does it step
 * past them, so paging always moves on; a tie larger than a page can then
 * lose some (only a cursor on start time and id, in main, would close that).
 */
export async function loadOlderSessions<S extends { id: string; startedAt: number }>(
  shown: readonly S[],
  fetch: (before: number) => Promise<S[]>,
  pageSize: number,
): Promise<{ rows: S[]; more: boolean } | undefined> {
  const last = shown.at(-1);
  if (!last) return undefined;
  const seen = new Set(shown.map((s) => s.id));
  let rows = await fetch(last.startedAt + 1);
  if (rows.length === pageSize && rows.every((s) => seen.has(s.id))) {
    rows = await fetch(last.startedAt);
  }
  return {
    rows: [...shown, ...rows.filter((s) => !seen.has(s.id))],
    more: rows.length === pageSize,
  };
}

// ---------------------------------------------------------------- process tree

/**
 * A session's processes in tree order: each program right under the one that
 * started it, siblings oldest first. A process whose parent Vigil never saw
 * (a shell that forked without a launch of its own, say) goes under the agent
 * itself and keeps the depth the tracker gave it, so the gap stays visible.
 * The first node is the agent; the rest may come in any order.
 */
export function treeOrder(nodes: readonly TreeNode[]): TreeNode[] {
  return treeRows(nodes).map((r) => r.node);
}

/**
 * The same order as treeOrder, each node with the one it hangs under (none
 * for the agent), so a screen reader can say which program started which.
 */
export function treeRows(nodes: readonly TreeNode[]): { node: TreeNode; parent?: TreeNode }[] {
  const [root, ...rest] = nodes;
  if (!root) return [];
  const children = new Map<TreeNode, TreeNode[]>();
  const parentOf = new Map<TreeNode, TreeNode>();
  // The newest process seen with each pid so far, since pids get reused.
  const byPid = new Map<number, TreeNode>([[root.pid, root]]);
  for (const n of [...rest].sort((a, b) => a.ts - b.ts)) {
    const parent = byPid.get(n.ppid) ?? root;
    parentOf.set(n, parent);
    const list = children.get(parent);
    if (list) list.push(n);
    else children.set(parent, [n]);
    byPid.set(n.pid, n);
  }
  // Parents always come before their children above, so this walk can't loop.
  const out: { node: TreeNode; parent?: TreeNode }[] = [];
  const stack: TreeNode[] = [root];
  while (stack.length) {
    const n = stack.pop()!;
    const parent = parentOf.get(n);
    out.push(parent ? { node: n, parent } : { node: n });
    const kids = children.get(n);
    if (kids) for (let i = kids.length - 1; i >= 0; i--) stack.push(kids[i]!);
  }
  return out;
}

// ---------------------------------------------------------------- matchers

export type MatcherField = 'names' | 'paths' | 'teamIds' | 'signingIds';

/** One way to recognise an agent's program, as the form edits it. */
export interface MatcherRow {
  field: MatcherField;
  /** Comma-separated: any one of them matches. */
  value: string;
  /** Optional comma-separated command-line globs; one of them must match too. */
  args: string;
}

export const MATCHER_FIELDS: { value: MatcherField; label: string; placeholder: string }[] = [
  { value: 'names', label: 'Program name is', placeholder: 'goose' },
  { value: 'paths', label: 'Path matches', placeholder: '~/.local/bin/goose' },
  { value: 'teamIds', label: 'Developer team ID is', placeholder: 'ABCDE12345' },
  { value: 'signingIds', label: 'Signing ID is', placeholder: 'com.example.agent' },
];

const FIELDS: readonly MatcherField[] = ['names', 'paths', 'teamIds', 'signingIds'];

/** The most matchers an agent has, and values in one list (core's AgentMatcher). */
export const MAX_MATCHERS = 4;
const MAX_VALUES = 8;
const MAX_ARG_GLOBS = 4;

export const emptyRow = (): MatcherRow => ({ field: 'names', value: '', args: '' });

const split = (s: string) =>
  s
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean);

/**
 * An agent's matchers as form rows. A matcher that tests more than one kind
 * of identity at once (a team ID and a path, say) has no row shape; it is
 * kept as it is and shown read-only.
 */
export function rowsFromMatchers(match: readonly AgentMatcherView[]): {
  rows: MatcherRow[];
  kept: AgentMatcherView[];
} {
  const rows: MatcherRow[] = [];
  const kept: AgentMatcherView[] = [];
  for (const m of match) {
    const used = FIELDS.filter((f) => m[f]?.length);
    const field = used[0];
    if (used.length !== 1 || !field) {
      kept.push(m);
      continue;
    }
    rows.push({ field, value: m[field]!.join(', '), args: (m.argGlobs ?? []).join(', ') });
  }
  return { rows, kept };
}

/**
 * The form's rows as matchers, checked against the same limits main checks,
 * so a slip shows up as a sentence instead of a refused call. Empty rows are
 * skipped.
 */
export function matchersFromRows(
  rows: readonly MatcherRow[],
  kept: readonly AgentMatcherView[] = [],
): { match: AgentMatcherView[]; errors: string[] } {
  const errors: string[] = [];
  const match: AgentMatcherView[] = [...kept];
  for (const r of rows) {
    const values = split(r.value);
    const args = split(r.args);
    if (values.length === 0) {
      if (args.length) errors.push('A command-line pattern needs a program name or path with it.');
      continue;
    }
    const label = MATCHER_FIELDS.find((f) => f.value === r.field)!.label;
    if (values.length > MAX_VALUES) errors.push(`${label}: at most ${MAX_VALUES} values.`);
    for (const v of values) {
      const problem = valueProblem(r.field, v);
      if (problem) errors.push(problem);
    }
    if (args.length > MAX_ARG_GLOBS) {
      errors.push(`At most ${MAX_ARG_GLOBS} command-line patterns per row.`);
    }
    for (const a of args) {
      if (a.length < 3 || a.length > 256) {
        errors.push(`Command-line pattern "${a}" should be 3 to 256 characters, like *codex*.`);
      }
    }
    const m: AgentMatcherView = {};
    m[r.field] = r.field === 'teamIds' ? values.map(upper) : values;
    if (args.length) m.argGlobs = args;
    match.push(m);
  }
  if (match.length === 0) errors.push('Add at least one way to recognise the program.');
  if (match.length > MAX_MATCHERS) errors.push(`At most ${MAX_MATCHERS} ways per agent.`);
  return { match, errors };
}

const upper = (s: string) => s.toUpperCase();

function valueProblem(field: MatcherField, v: string): string | undefined {
  switch (field) {
    case 'names':
      if (v.length > 64) return `Program name "${v}" is longer than 64 characters.`;
      if (v.includes('/')) return `"${v}" is a path. Use "Path matches" for it, or just the name.`;
      return undefined;
    case 'paths':
      if (v.length < 3 || v.length > 256) return `Path "${v}" should be 3 to 256 characters.`;
      return undefined;
    case 'teamIds':
      return /^[A-Z0-9]{10}$/.test(upper(v))
        ? undefined
        : `Team ID "${v}" should be 10 letters and digits, like ABCDE12345.`;
    case 'signingIds':
      return v.length > 128 ? `Signing ID "${v}" is longer than 128 characters.` : undefined;
  }
}

/** One matcher in plain words, e.g. `named node, command line *@openai/codex*`. */
export function describeMatcher(m: AgentMatcherView): string {
  const parts: string[] = [];
  const list = (vs: string[]) => vs.join(' or ');
  if (m.names?.length) parts.push(`named ${list(m.names)}`);
  if (m.paths?.length) parts.push(`at ${list(m.paths)}`);
  if (m.teamIds?.length) parts.push(`from developer team ${list(m.teamIds)}`);
  if (m.signingIds?.length) parts.push(`signed as ${list(m.signingIds)}`);
  if (m.argGlobs?.length) parts.push(`with a command line like ${list(m.argGlobs)}`);
  return parts.join(', ');
}

/** A new agent's id from its name: lowercase words joined by dashes, unique among `taken`. */
export function agentIdFor(name: string, taken: ReadonlySet<string>): string {
  const slug =
    name
      .toLowerCase()
      .normalize('NFKD')
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+/, '')
      .slice(0, 32)
      .replace(/-+$/, '') || 'agent';
  let id = slug;
  for (let i = 2; taken.has(id) || id === VIGIL_SELF || id === VIGIL_CONNECTOR; i++)
    id = `${slug}-${i}`;
  return id;
}
