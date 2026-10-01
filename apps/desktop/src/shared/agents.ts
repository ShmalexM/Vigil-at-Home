/**
 * The Agents page's data, shared by main and the renderer. Types and labels
 * only, with no runtime imports, so the renderer stays free of zod. The
 * schemas main checks the renderer's input with live in ipc.ts.
 *
 * Two meanings of "agent" share the page: watched agents are the AI tools on
 * this Mac (Claude Code, Codex, Cursor and the MCP servers they start), and
 * Vigil's AI helpers are its own explainer, labeller and rule reviewer.
 */

/** Same ids as `AgentKind` in @vigil/core. */
export type AgentKind = 'cli' | 'app' | 'ide' | 'runtime';
/** builtin: Vigil's catalogue; user: added by you; suggested: Vigil's heuristic. */
export type AgentOrigin = 'builtin' | 'user' | 'suggested';
export type AgentStatus = 'active' | 'suggested' | 'ignored';
/**
 * - running: running now, or active in the last few minutes;
 * - seen: Vigil has seen it run before;
 * - installed: found where it installs, not seen running yet;
 * - not-found: none of the above.
 */
export type AgentPresence = 'running' | 'seen' | 'installed' | 'not-found';

/** Same shape as `AgentMatcher` in @vigil/core. Every list given must match. */
export interface AgentMatcherView {
  teamIds?: string[];
  signingIds?: string[];
  /** Path globs; `~/` means any user's home folder. */
  paths?: string[];
  /** Exact program names. */
  names?: string[];
  /** Globs on the command line, e.g. `*@openai/codex*`; they only narrow a match. */
  argGlobs?: string[];
}

export interface AgentView {
  id: string;
  name: string;
  kind: AgentKind;
  origin: AgentOrigin;
  status: AgentStatus;
  /** Programs it starts are tagged for the agent rules. */
  watch: boolean;
  presence: AgentPresence;
  lastSeenAt?: number;
  /** Today since midnight. */
  sessionsToday: number;
  matchesToday: number;
  asksToday: number;
  deniesToday: number;
  /** Its hook can ask Vigil before each tool call. */
  preflightHost?: 'claude-code';
  /** From Vigil's catalogue: it can be reset or ignored, not removed. */
  builtin: boolean;
  /** A built-in whose matchers you changed. */
  edited: boolean;
}

export interface AgentDetail extends AgentView {
  match: AgentMatcherView[];
  note?: string;
  /** The agent-watch rules, and the pre-flight rules when it has a hook. */
  rules: { id: string; name: string; mode: 'disabled' | 'shadow' | 'alert' | 'block' }[];
}

export type SaveAgentResult = { ok: true; agent: AgentView } | { ok: false; errors: string[] };

/** What a draft agent's matchers would have caught over the last 14 days. */
export interface AgentMatchPreview {
  /** Program launches that match. */
  execs: number;
  /** Of those, how many started a tree of their own (their parent did not match). */
  trees: number;
  /** Up to 10 distinct matching programs or command lines. */
  samples: string[];
  /** The scan stopped at its row limit, so the counts are lower bounds. */
  truncated: boolean;
}

/** A program seen recently, offered when adding an agent by hand. */
export interface AgentCandidate {
  path: string;
  name: string;
  teamId?: string;
  signingId?: string;
  lastSeen: number;
  /** Launches seen in the window. */
  count: number;
}

/** One run of an agent: its own program and everything it started. */
export interface AgentSessionView {
  /** 16 hex chars. */
  id: string;
  agentId: string;
  rootPid: number;
  rootPath: string;
  startedAt: number;
  /** The newest event of the session, or its start. */
  lastAt: number;
  events: number;
  matches: number;
  asks: number;
  denies: number;
  /** The enclosing agent's session, when one agent started another. */
  parentSession?: string;
  /** Found running by `ps` rather than seen launching. */
  seeded: boolean;
}

/** One process of a session's tree, from its launch event. */
export interface TreeNode {
  pid: number;
  ppid: number;
  name: string;
  path: string;
  ts: number;
  /** 0 for the agent itself. */
  depth: number;
  /** One of its events matched a rule. */
  matched: boolean;
}

export interface AgentPrefs {
  /** Vigil answers the pre-flight hook (the socket is open). Off by default. */
  preflightEnabled: boolean;
  /** When Vigil can't answer: ask you, or let Claude Code decide as if Vigil weren't there. */
  onUnavailable: 'ask' | 'defer';
  /** Suggest programs that behave like agents (at most one a day). */
  suggestions: boolean;
}

export const DEFAULT_AGENT_PREFS: AgentPrefs = {
  preflightEnabled: false,
  onUnavailable: 'ask',
  suggestions: true,
};

export interface PreflightStatus {
  endpoint: 'off' | 'listening' | 'error';
  error?: string;
  socketPath: string;
  /** The hooks to paste into Claude Code's settings. Empty when this build has no hook. */
  snippet: string;
  lastHelloAt?: number;
  lastRequestAt?: number;
  /** Answers in the last 24 hours that were stored. */
  counts24h: { deny: number; ask: number; none: number };
  /** Requests over the recording cap since Vigil started: answered, not stored. */
  notRecorded: number;
}

export type VigilHelperId = 'explainer' | 'labeller' | 'rule-reviewer';

/** One of Vigil's own AI helpers. They read and propose; they never act. */
export interface VigilHelperView {
  id: VigilHelperId;
  name: string;
  /** The AI apps it can use. */
  providers: string[];
  /** Vigil's read-only tools it may call. */
  tools: string[];
  lastRunAt?: number;
  runs7d: number;
}

/** The hook counts as connected while it was heard from this recently. */
export const HOOK_CONNECTED_MS = 7 * 24 * 60 * 60 * 1000;

export const AGENT_KIND_LABEL: Record<AgentKind, string> = {
  cli: 'Command-line agent',
  app: 'Agent app',
  ide: 'Editor with an agent',
  runtime: 'Model runtime',
};

export const PRESENCE_LABEL: Record<AgentPresence, string> = {
  running: 'Running',
  seen: 'Seen before',
  installed: 'Installed',
  'not-found': 'Not found',
};

/** Whether the hook was heard from recently enough to call it connected. */
export function hookConnected(
  s: { lastHelloAt?: number | undefined; lastRequestAt?: number | undefined },
  now: number,
): boolean {
  const last = Math.max(s.lastHelloAt ?? 0, s.lastRequestAt ?? 0);
  return last > 0 && now - last < HOOK_CONNECTED_MS;
}
