// The Agents page and the pre-flight bridge in the main process.
//
// Watched agents are the AI tools on this Mac (Claude Code, Codex, Cursor and
// the MCP servers they start). The process tracker inside the Detector tags
// what they run; this service turns that into sessions, counts and views,
// seeds the tracker from `ps`, stats install paths once a day, and keeps the
// registry's changes behind a UserOrigin from the Agents screen.
//
// Pre-flight: Claude Code's PreToolUse hook asks over a socket in Vigil's own
// folder before a tool runs. Rules answer, synchronously, deny, ask or
// nothing, never allow. The answer goes out first; storing the request,
// alerting on a deny and counting repeated denies happen after it. Nothing on
// the answer path reaches the AI or the scheduler.
//
// Vigil's tools for agents (opt-in): the user's own agents, through the hook
// package's MCP server, read alerts, events and agent sessions over the same
// socket (tools.ts). Read-only and redacted; while they're off, every call is
// refused before anything is read.

import { EventEmitter } from 'node:events';
import { existsSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { join } from 'node:path';
import { z } from 'zod';
import {
  AgentIdentityInput,
  newId,
  type AgentIdentity,
  type AgentMatcher,
  type AgentToolRequestEvent,
  type HelloReply,
  type PreflightReply,
  type PreflightRequest,
  type ToolsReply,
} from '@vigil/core';
import {
  PREFLIGHT_PROBING_RULE_ID,
  PREFLIGHT_SOCKET_RULE_ID,
  PREFLIGHT_SOCKET_TOOL,
  compileAgentMatchers,
  type AgentRecord,
  type Detection,
  type PsRow,
  type SessionStart,
} from '@vigil/detection';
import { userOrigin } from '@vigil/detection/user';
import {
  DEFAULT_AGENT_PREFS,
  VIGIL_TOOLS,
  hookConnected,
  type AgentCandidate,
  type AgentDetail,
  type AgentMatcherView,
  type AgentMatchPreview,
  type AgentPresence,
  type AgentSessionView,
  type AgentToolsStatus,
  type AgentView,
  type PreflightStatus,
  type SaveAgentResult,
  type TreeNode,
  type VigilHelperView,
} from '../../shared/agents.js';
import {
  AgentPrefs,
  AgentPrefsPatch,
  type AgentSessionDetail,
  type EventView,
  type StatusView,
} from '../../shared/ipc.js';
import type { AlertService } from '../alerts.js';
import type { AgentSessionRow, AgentStats, Store } from '../db/store.js';
import { coreRule, type Detector, type PreflightResult } from '../detection.js';
import { helperBundleDir } from '../helper-install.js';
import type { Scheduler } from '../scheduler.js';
import {
  AgentEndpoint,
  TOOLS_OFF,
  socketPathFor,
  type EndpointRequest,
  type SocketTamper,
  type ToolsRequest,
} from './endpoint.js';
import { hookFiles, hookSnippet, mcpSnippet } from './hook-snippet.js';
import { processTableReader } from './ps.js';
import { VigilTools, type RuleFacts, type StatusFacts, type VigilToolsSource } from './tools.js';

const KEY_PREFS = 'agents.prefs';
const KEY_HOOK = 'agents.hook';
const KEY_SUGGESTED = 'agents.suggestedAt';
const KEY_TOOLS = 'agents.tools';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** New sessions are written in one batch this long after the first arrives. */
const SESSION_FLUSH_MS = 1000;
/**
 * `ps` runs again on a miss at most this often. While reading it again finds
 * none of the processes that missed, the wait doubles, up to MAX_RESEED_MS.
 */
const RESEED_MS = 30_000;
const MAX_RESEED_MS = 30 * MINUTE;
/**
 * A request from a process Vigil doesn't know yet reads `ps` again, at most
 * this often, so it can be filed under its agent's session.
 */
const LATE_ATTRIBUTION_MS = 5_000;
/** Processes that missed since `ps` last ran, remembered at most. */
const MAX_MISSED = 256;
/** Pages hear about background changes (requests, sessions) at most this often. */
const CHANGED_MS = 2000;
/** The hook's last request is saved at most this often; a hello is saved at once. */
const HOOK_SAVE_MS = MINUTE;
/** Tool requests stored per agent session (or hook session) and in all, per hour. */
export const RECORD_PER_KEY_PER_HOUR = 600;
export const RECORD_PER_HOUR = 3000;
/**
 * Stopped steps stored per hour, apart from the limits above, so a flood of
 * other requests can't push them out. Denies are rare by design.
 */
export const DENY_RECORD_PER_HOUR = 300;
/** One alert per rule and agent session for stopped steps in this long. */
export const DENY_ALERT_MS = 10 * MINUTE;
/** This many stopped steps in one session within PROBE_WINDOW_MS looks like probing. */
export const PROBE_DENIES = 5;
/** Twice that over all sessions together, spread so no one session reaches it. */
export const PROBE_DENIES_ALL = 2 * PROBE_DENIES;
const PROBE_WINDOW_MS = 10 * MINUTE;
const PROBE_ALERT_MS = HOUR;
/**
 * Alerts and probing count by the session Vigil attributed a request to.
 * The client sends its hook session and parent pid itself, so requests Vigil
 * can't attribute count together, and changing those can't spread denies thin.
 */
const UNATTRIBUTED = 'unattributed';
/** Every session at once, for probing spread over several. */
const EVERY_SESSION = '*';
/** Another program taking the agent socket raises an alert at most this often. */
const TAMPER_ALERT_MS = HOUR;
/** Sessions, denies and alert times are remembered for this many keys at most. */
const MAX_KEYS = 1024;
/** An agent active this recently counts as running. */
const RUNNING_MS = 15 * MINUTE;
/** A draft agent is previewed over this much history, and at most this many launches. */
const PREVIEW_DAYS = 14;
const PREVIEW_MAX_ROWS = 200_000;
const MAX_SAMPLES = 10;
const MAX_CANDIDATES = 50;
const MAX_TREE = 200;
const MAX_SESSION_EVENTS = 500;
const SESSIONS_PAGE = 100;

/** The hook's heartbeat, setting `agents.hook`. */
const HookState = z.object({
  lastHelloAt: z.number().int().optional(),
  lastRequestAt: z.number().int().optional(),
  hookVersion: z.string().max(32).optional(),
});
type HookState = z.infer<typeof HookState>;

/** How Vigil's tools for agents have been used, setting `agents.tools`. */
const ToolUse = z.object({
  calls: z.number().int().nonnegative(),
  lastCallAt: z.number().int().optional(),
  lastTool: z.string().max(64).optional(),
});
type ToolUse = z.infer<typeof ToolUse>;

/** Vigil's own AI helpers, for the read-only tab. Provider ids as on the Usage page. */
const HELPERS: ReadonlyArray<
  Omit<VigilHelperView, 'lastRunAt' | 'runs7d'> & { purpose: 'explain' | 'classify' | 'analyze' }
> = [
  {
    id: 'explainer',
    name: 'Alert explainer',
    purpose: 'explain',
    providers: ['claude', 'codex', 'api', 'ollama'],
    tools: [],
  },
  {
    id: 'labeller',
    name: 'Event labeller',
    purpose: 'classify',
    providers: ['claude', 'jev', 'ollama'],
    tools: [],
  },
  {
    id: 'rule-reviewer',
    name: 'Rule reviewer',
    purpose: 'analyze',
    providers: ['claude', 'codex', 'api'],
    tools: ['get_telemetry_summary', 'get_rule_language'],
  },
];

export interface AgentServiceDeps {
  detector: Detector;
  store: Store;
  alerts: AlertService;
  scheduler: Scheduler;
  /** The app's Resources folder; the hook ships in its helper folder. */
  resourcesPath: string;
  /** Vigil's data folder; the socket lives in it. */
  userData: string;
  /** The app's protection status, for the vigil_status tool. */
  status?: () => StatusView;
  now?: () => number;
  /** A development build's helper folder (build/helper/dev-<arch>). */
  devHelperDir?: string;
  /** The process table. Defaults to `ps` on macOS, nothing elsewhere. */
  readPs?: () => Promise<PsRow[]>;
  /** Whether an install path exists (the daily discovery). */
  statInstall?: (path: string) => boolean;
  home?: string;
  socketPath?: string;
  log?: (msg: string) => void;
}

/** Remember `value` under `key`, most recent last, forgetting the oldest past MAX_KEYS. */
function remember<V>(m: Map<string, V>, key: string, value: V): void {
  m.delete(key);
  m.set(key, value);
  if (m.size > MAX_KEYS) m.delete(m.keys().next().value!);
}

function sameSet(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  return a.size === b.size && [...a].every((x) => b.has(x));
}

function basename(p: string): string {
  return p.slice(p.lastIndexOf('/') + 1);
}

function matcherView(m: AgentMatcher): AgentMatcherView {
  const v: AgentMatcherView = {};
  if (m.teamIds) v.teamIds = m.teamIds;
  if (m.signingIds) v.signingIds = m.signingIds;
  if (m.paths) v.paths = m.paths;
  if (m.names) v.names = m.names;
  if (m.argGlobs) v.argGlobs = m.argGlobs;
  return v;
}

/**
 * `changed`: something setup, the menu bar or the Agents page's state depends
 * on (an agent, a setting, the hook connecting). `activity`: a request,
 * session or tools call was recorded, for the views that show those.
 */
export class AgentService extends EventEmitter<{ changed: []; activity: [] }> {
  private readonly now: () => number;
  private readonly endpoint: AgentEndpoint;
  private readonly readPs: () => Promise<PsRow[]>;
  private readonly statInstall: (path: string) => boolean;
  private readonly home: string;
  private readonly log: (msg: string) => void;
  private started = false;
  private cachedPrefs: AgentPrefs | undefined;
  private hook: HookState;
  private hookSavedAt = 0;
  /** Over MCP, for the user's own agents. */
  private readonly tools: VigilTools;
  /** For the pack, which also sees Vigil's answers to tool requests. */
  private readonly packView: VigilTools;
  private toolUse: ToolUse;
  private toolUseSavedAt = 0;
  /** Tools calls refused because the tools were off, since start. */
  private toolsRefused = 0;

  private pendingSessions: AgentSessionRow[] = [];
  private sessionTimer: ReturnType<typeof setTimeout> | undefined;
  private readonly timers: Partial<Record<'changed' | 'activity', ReturnType<typeof setTimeout>>> =
    {};

  private seeding: Promise<void> | undefined;
  private lastSeedAt = Number.NEGATIVE_INFINITY;
  /** The wait between `ps` runs on a miss; it grows while they find nothing. */
  private reseedMs = RESEED_MS;
  /** Pids the last `ps` listed: a miss on one of them is not fixed by reading it again. */
  private psPids = new Set<number>();
  /** Pids that missed since `ps` last ran. */
  private missed = new Set<number>();
  /** Agents the last `ps` found running, and when that `ps` ran. */
  private running = new Set<string>();
  private runningAt = Number.NEGATIVE_INFINITY;
  /** Agents the last discovery found installed. */
  private installed = new Set<string>();

  /** Tool requests admitted for storage this hour: in all, per key, and denies. */
  private caps = { hour: -1, total: 0, perKey: new Map<string, number>(), denies: 0 };
  private notRecorded = 0;
  private tamperAlertAt = Number.NEGATIVE_INFINITY;
  private readonly denyAlertAt = new Map<string, number>();
  private readonly denyTimes = new Map<string, number[]>();
  private readonly probeAlertAt = new Map<string, number>();

  constructor(private readonly o: AgentServiceDeps) {
    super();
    this.now = o.now ?? Date.now;
    this.readPs = o.readPs ?? processTableReader();
    this.statInstall = o.statInstall ?? existsSync;
    this.home = o.home ?? homedir();
    this.log = o.log ?? ((msg) => console.warn(`[agents] ${msg}`));
    this.hook = o.store.getSetting(KEY_HOOK, HookState, {});
    this.toolUse = o.store.getSetting(KEY_TOOLS, ToolUse, { calls: 0 });
    this.endpoint = new AgentEndpoint({
      socketPath: o.socketPath ?? socketPathFor(o.userData, tmpdir(), process.getuid?.() ?? 0),
      handle: (req) => this.fromSocket(req),
      tools: (req) => this.handleTools(req),
      // Later: it can arrive from inside status().
      onTamper: (why) => setImmediate(() => this.socketTampered(why)),
      log: this.log,
    });
    const source: VigilToolsSource = {
      now: this.now,
      status: () => this.statusFacts(),
      alerts: (opts) => o.store.listAlerts(opts),
      alert: (id) => o.store.getAlert(id),
      events: (ids) => o.store.getEventViews(ids),
      ruleName: (id) => o.detector.engine.getRule(id)?.name ?? o.store.getRule(id)?.name,
      searchEvents: (q) => o.store.searchEvents(q),
      rules: () => this.ruleFacts(),
      ruleHits: (since) => o.store.ruleMatchCounts(since),
      actions: (limit) => o.store.listActions({ limit }),
      agents: () => this.listAgents(),
      agentSessions: (id, limit) => o.store.listAgentSessions(id, undefined, limit),
      agentSession: (id, rows) => this.sessionDetail(id, rows, rows),
    };
    this.tools = new VigilTools(source);
    this.packView = new VigilTools(source, { verdicts: true });
  }

  /**
   * Read the process table, start the daily discovery, and open the socket if
   * pre-flight or Vigil's tools are on.
   */
  async start(): Promise<void> {
    if (this.started) return;
    this.started = true;
    this.o.scheduler.every('agent-discovery', DAY, () => this.discover(), true);
    await this.seed();
    if (this.socketWanted()) await this.endpoint.start();
    this.emit('changed');
  }

  async stop(): Promise<void> {
    this.started = false;
    this.flushSessions();
    for (const t of Object.values(this.timers)) clearTimeout(t);
    delete this.timers.changed;
    delete this.timers.activity;
    this.saveHook();
    this.saveToolUse();
    await this.endpoint.stop();
  }

  // ---------------------------------------------------------------- views

  listAgents(): AgentView[] {
    const since = this.startOfDay();
    const stats = this.o.store.agentStats(since);
    const host = this.hostCounts(since);
    const active = this.preflightActive();
    return this.o.detector.registry.list().map((r) => this.view(r, stats.get(r.id), host, active));
  }

  /**
   * Each agent's id, name and status, from the registry alone: for the
   * sidebar's suggestion count and agent names on other pages, which would
   * otherwise run listAgents' stats queries on every change.
   */
  listAgentNames(): Pick<AgentView, 'id' | 'name' | 'status'>[] {
    return this.o.detector.registry
      .list()
      .map((r) => ({ id: r.id, name: r.name, status: r.status }));
  }

  getAgent(id: string): AgentDetail | null {
    const r = this.agentRecord(id);
    if (!r) return null;
    const since = this.startOfDay();
    const view = this.view(
      r,
      this.o.store.agentStats(since).get(id),
      this.hostCounts(since),
      this.preflightActive(),
    );
    const rules = this.o.detector
      .rules()
      .filter(
        ({ rule }) =>
          rule.tags.includes('agent-watch') ||
          (r.preflightHost !== undefined && rule.tags.includes('agent-preflight')),
      )
      .map(({ rule, mode }) => ({ id: rule.id, name: rule.name, mode }));
    return {
      ...view,
      match: r.match.map(matcherView),
      ...(r.note !== undefined ? { note: r.note } : {}),
      rules,
    };
  }

  /** Add an agent, or change one (a built-in keeps the user's copy until reset). */
  saveAgent(input: AgentIdentityInput): SaveAgentResult {
    const parsed = AgentIdentityInput.safeParse(input);
    if (!parsed.success) {
      return {
        ok: false,
        errors: parsed.error.issues.map((i) =>
          i.path.length ? `${i.path.join('.')}: ${i.message}` : i.message,
        ),
      };
    }
    try {
      this.o.detector.registry.save(parsed.data, userOrigin('agents-screen'));
    } catch (err) {
      return { ok: false, errors: [(err as Error).message] };
    }
    this.emit('changed');
    const r = this.agentRecord(parsed.data.id)!;
    const since = this.startOfDay();
    return {
      ok: true,
      agent: this.view(
        r,
        this.o.store.agentStats(since).get(r.id),
        this.hostCounts(since),
        this.preflightActive(),
      ),
    };
  }

  setAgentWatch(id: string, on: boolean): void {
    this.o.detector.registry.setWatch(id, on, userOrigin('agents-screen'));
    this.emit('changed');
  }

  /** Accepting a suggestion is `active` (it then watches); "not an agent" is `ignored`. */
  setAgentStatus(id: string, status: 'active' | 'ignored'): void {
    this.o.detector.registry.setStatus(id, status, userOrigin('agents-screen'));
    this.emit('changed');
  }

  removeAgent(id: string): void {
    this.o.detector.registry.remove(id, userOrigin('agents-screen'));
    this.emit('changed');
  }

  resetAgent(id: string): void {
    this.o.detector.registry.reset(id, userOrigin('agents-screen'));
    this.emit('changed');
  }

  /** What these matchers would have caught over the last 14 days of program launches. */
  previewAgentMatch(match: AgentMatcher[]): AgentMatchPreview {
    const at = this.now();
    const draft: AgentIdentity = {
      id: 'preview',
      name: 'Preview',
      kind: 'cli',
      origin: 'user',
      status: 'active',
      watch: true,
      match,
      createdAt: at,
      updatedAt: at,
    };
    const m = compileAgentMatchers([draft]);
    const hits: Array<{ pid: number; ppid?: number }> = [];
    const samples = new Set<string>();
    let rows = 0;
    let truncated = false;
    for (const r of this.o.store.iterateExecEvents(at - PREVIEW_DAYS * DAY, PREVIEW_MAX_ROWS + 1)) {
      if (++rows > PREVIEW_MAX_ROWS) {
        truncated = true;
        break;
      }
      if (!m.match(r)) continue;
      hits.push(r.ppid === undefined ? { pid: r.pid } : { pid: r.pid, ppid: r.ppid });
      if (samples.size < MAX_SAMPLES) {
        samples.add(r.args?.length ? r.args.join(' ').slice(0, 200) : r.path);
      }
    }
    const pids = new Set(hits.map((h) => h.pid));
    const roots = new Set(
      hits.filter((h) => h.ppid === undefined || !pids.has(h.ppid)).map((h) => h.pid),
    );
    return { execs: hits.length, trees: roots.size, samples: [...samples], truncated };
  }

  /** Programs seen in the last day that no agent covers, for "Add an agent". */
  listAgentCandidates(): AgentCandidate[] {
    const m = this.o.detector.registry.matcher();
    return this.o.store
      .recentExecPrograms(this.now() - DAY, MAX_CANDIDATES * 4)
      .filter((c) => !m.match(c))
      .slice(0, MAX_CANDIDATES);
  }

  listAgentSessions(id: string, before?: number): AgentSessionView[] {
    return this.o.store.listAgentSessions(id, before, SESSIONS_PAGE);
  }

  /** One session: its process tree (from launches, oldest first) and its newest events. */
  getAgentSession(id: string): AgentSessionDetail | null {
    return this.sessionDetail(id, MAX_TREE, MAX_SESSION_EVENTS);
  }

  private sessionDetail(id: string, maxTree: number, maxEvents: number): AgentSessionDetail | null {
    const session = this.o.store.getAgentSession(id);
    if (!session) return null;
    const matched = this.o.store.sessionMatchedPids(id);
    const execs = this.o.store.sessionEvents(id, maxTree, {
      kind: 'process.exec',
      oldestFirst: true,
    });
    return {
      session,
      tree: sessionTree(session, execs, matched, maxTree),
      events: this.o.store.sessionEvents(id, maxEvents),
    };
  }

  // ---------------------------------------------------------------- prefs and status

  prefs(): AgentPrefs {
    if (this.cachedPrefs) return this.cachedPrefs;
    // Prefs saved by an older Vigil lack newer switches; those take their defaults.
    const saved = this.o.store.getSetting(KEY_PREFS, AgentPrefs.partial(), {});
    const defined = Object.fromEntries(Object.entries(saved).filter(([, v]) => v !== undefined));
    this.cachedPrefs = AgentPrefs.parse({ ...DEFAULT_AGENT_PREFS, ...defined });
    return this.cachedPrefs;
  }

  setPrefs(raw: AgentPrefsPatch): AgentPrefs {
    const patch = AgentPrefsPatch.parse(raw);
    const before = this.prefs();
    const defined = Object.fromEntries(Object.entries(patch).filter(([, v]) => v !== undefined));
    this.o.store.setSetting(KEY_PREFS, AgentPrefs.parse({ ...before, ...defined }));
    this.cachedPrefs = undefined;
    const next = this.prefs();
    if (
      next.preflightEnabled !== before.preflightEnabled ||
      next.toolsEnabled !== before.toolsEnabled
    ) {
      void this.syncEndpoint();
    }
    this.emit('changed');
    return next;
  }

  /** Vigil's tools for agents: the switch, what to paste, and how they've been used. */
  toolsStatus(): AgentToolsStatus {
    const ep = this.endpoint.status();
    const files = this.hookFiles();
    return {
      enabled: this.prefs().toolsEnabled,
      endpoint: ep.state,
      ...(ep.error ? { error: ep.error } : {}),
      snippets: files ? mcpSnippet({ ...files, socketPath: ep.socketPath }) : null,
      tools: VIGIL_TOOLS.filter((t) => !t.packOnly),
      calls: this.toolUse.calls,
      ...(this.toolUse.lastCallAt !== undefined ? { lastCallAt: this.toolUse.lastCallAt } : {}),
      ...(this.toolUse.lastTool !== undefined ? { lastTool: this.toolUse.lastTool } : {}),
      refused: this.toolsRefused,
    };
  }

  preflightStatus(): PreflightStatus {
    const ep = this.endpoint.status();
    return {
      endpoint: ep.state,
      ...(ep.error ? { error: ep.error } : {}),
      socketPath: ep.socketPath,
      snippet: this.snippet(ep.socketPath),
      ...(this.hook.lastHelloAt !== undefined ? { lastHelloAt: this.hook.lastHelloAt } : {}),
      ...(this.hook.lastRequestAt !== undefined ? { lastRequestAt: this.hook.lastRequestAt } : {}),
      counts24h: this.o.store.toolRequestCounts(this.now() - DAY),
      notRecorded: this.notRecorded,
    };
  }

  listVigilHelpers(): VigilHelperView[] {
    const stats = this.o.store.aiRunStats(this.now() - 7 * DAY);
    return HELPERS.map(({ purpose, ...h }) => {
      const s = stats.get(purpose);
      return {
        ...h,
        providers: [...h.providers],
        tools: [...h.tools],
        ...(s ? { lastRunAt: s.lastAt } : {}),
        runs7d: s?.runs ?? 0,
      };
    });
  }

  /**
   * Vigil's read-only tools, for the pack's own dogs (pack.ts). Same tools,
   * redaction and caps as the user's agents get over MCP, plus Vigil's answer
   * to each tool request; this path doesn't depend on that opt-in, because
   * the pack runs inside Vigil.
   */
  packTools(): {
    list: () => ReturnType<VigilTools['list']>;
    call: (name: string, args: Record<string, unknown>) => ToolsReply;
  } {
    return {
      list: () => this.packView.list({ pack: true }),
      call: (n, a) => this.packView.call(n, a, { pack: true }),
    };
  }

  /**
   * Asks Vigil's rules about a pack dog's tool call, as they'd answer a
   * watched agent's hook: deny, ask or none. Nothing is recorded, and the
   * answer can only make the gate stricter.
   */
  packPreflight(req: PreflightRequest): PreflightReply {
    return this.o.detector.preflight(req).reply;
  }

  /**
   * For setup's Claude Code pre-flight step: shown once Claude Code is
   * installed or has been seen, done while pre-flight is on and the hook is
   * connected. `off`: the hook was heard from, but pre-flight is off, so
   * Vigil answers nothing and Claude Code asks about every step.
   */
  claudePreflightStep(): { connected: boolean; off?: true } | undefined {
    const heard = hookConnected(this.hook, this.now());
    const on = this.prefs().preflightEnabled;
    const claude = 'claude-code';
    const known =
      this.hook.lastHelloAt !== undefined ||
      this.hook.lastRequestAt !== undefined ||
      this.installed.has(claude) ||
      this.running.has(claude) ||
      this.o.store.hasAgentSessions(claude);
    if (!known) return undefined;
    return heard && !on ? { connected: false, off: true } : { connected: heard && on };
  }

  // ---------------------------------------------------------------- the bridge

  /**
   * One request from the hook, answered synchronously from rules. A hello
   * only says the hook is installed. Recording happens after the reply.
   */
  handleBridge(req: EndpointRequest): PreflightReply | HelloReply {
    if (req.method === 'hello') {
      const at = this.now();
      setImmediate(() => this.heard({ lastHelloAt: at, hookVersion: req.hookVersion }));
      return { v: 1, ok: true };
    }
    const result = this.o.detector.preflight(req);
    // The hook can ask before the sensors report the agent running it (a
    // `claude -p` that calls a tool at once). Then `ps` says which agent it
    // is, and the request is recorded once that is known. The answer never waits.
    const late = req.ppid !== undefined && !result.event.agent.session ? req.ppid : undefined;
    const lookup = late !== undefined ? this.lateLookup(late) : undefined;
    if (lookup) void lookup.then(() => this.recordLate(result, late!));
    else setImmediate(() => this.record(result));
    return result.reply;
  }

  /** A `ps` read under way, or a new one when the last was long enough ago. */
  private lateLookup(pid: number): Promise<void> | undefined {
    if (!this.started || this.psPids.has(pid)) return undefined;
    if (this.seeding) return this.seeding;
    if (this.o.scheduler.isPaused || this.now() - this.lastSeedAt < LATE_ATTRIBUTION_MS) {
      return undefined;
    }
    return this.seed();
  }

  private recordLate(r: PreflightResult, pid: number): void {
    if (!this.started) return;
    const tag = this.o.detector.agentOf(pid);
    if (tag) {
      r.event.agent.id = tag.id;
      r.event.agent.session = tag.session;
    }
    this.record(r);
  }

  /**
   * What the socket answers. While it is open for Vigil's tools alone, a tool
   * request gets what the hook does when Vigil isn't there, and nothing is
   * checked or stored.
   */
  private fromSocket(req: EndpointRequest): PreflightReply | HelloReply {
    const p = this.prefs();
    if (req.method !== 'preflight.check' || p.preflightEnabled) return this.handleBridge(req);
    return p.onUnavailable === 'defer'
      ? { v: 1, decision: 'none' }
      : { v: 1, decision: 'ask', reason: "Vigil's pre-flight checks are off" };
  }

  /**
   * A call to Vigil's read-only tools from the user's own agent. While the
   * tools are off it is refused before anything is read. The call is counted
   * after the answer.
   */
  handleTools(req: ToolsRequest): ToolsReply {
    if (!this.prefs().toolsEnabled) {
      this.toolsRefused++;
      this.soon('activity');
      return TOOLS_OFF;
    }
    if (req.method === 'tools.list')
      return { v: 1, ok: true, result: { tools: this.tools.list() } };
    const at = this.now();
    const reply = this.tools.call(req.tool, req.args);
    setImmediate(() => this.calledTool(req.tool, at));
    return reply;
  }

  private calledTool(tool: string, at: number): void {
    this.toolUse = { calls: this.toolUse.calls + 1, lastCallAt: at, lastTool: tool };
    if (this.now() - this.toolUseSavedAt >= HOOK_SAVE_MS) this.saveToolUse();
    this.soon('activity');
  }

  private saveToolUse(): void {
    this.o.store.setSetting(KEY_TOOLS, this.toolUse);
    this.toolUseSavedAt = this.now();
  }

  /** The rules detection runs, for list_rules and get_rule: no conditions, exclusions counted. */
  private ruleFacts(): RuleFacts[] {
    const exceptions = this.o.detector.stores.exceptions;
    return this.o.detector.engine.listRules().map((r) => ({
      id: r.id,
      name: r.name,
      description: r.description,
      mode: r.effectiveMode,
      severity: r.severity,
      exclusions:
        r.exclusions.length + exceptions.forRule(r.id).filter((x) => x.ruleId === r.id).length,
    }));
  }

  /** What vigil_status reports. */
  private statusFacts(): StatusFacts {
    const rules: StatusFacts['rules'] = { disabled: 0, shadow: 0, alert: 0, block: 0 };
    for (const r of this.o.detector.engine.listRules()) rules[r.effectiveMode]++;
    const s = this.o.status?.();
    const last = Math.max(this.hook.lastHelloAt ?? 0, this.hook.lastRequestAt ?? 0);
    return {
      ...(s
        ? {
            protection: {
              level: s.level,
              reasons: s.reasons,
              needsYou: s.needsYou,
              sensors: s.sensors,
              simulated: s.dryRun,
            },
          }
        : {}),
      rules,
      preflight: {
        on: this.prefs().preflightEnabled,
        hookConnected: hookConnected(this.hook, this.now()),
        ...(last > 0 ? { lastHookAt: last } : {}),
        last24h: this.o.store.toolRequestCounts(this.now() - DAY),
      },
    };
  }

  /**
   * After the answer: alert on a deny, watch for probing, and store the
   * request within the hourly limits. Alerting comes first and has bounds of
   * its own, so a busy session or a flood of other requests never silences it.
   */
  private record(r: PreflightResult): void {
    // When it was asked, not when this runs: a burst is recorded together.
    const at = r.event.ts;
    this.heard({ lastRequestAt: at });
    const deny = r.reply.decision === 'deny';
    const who = r.event.agent.session ?? UNATTRIBUTED;
    const alerted = new Set<string>();
    if (deny) {
      for (const d of r.detections) {
        if (d.mode === 'block' && this.alertDeny(d, r.event, who, at)) alerted.add(d.match.ruleId);
      }
      this.countDeny(r.event, who, at);
    }
    // Storage is shared out per session, or per hook session when Vigil can't
    // tell which agent asked. A request an alert points to is kept regardless.
    const key = r.event.agent.session ?? r.event.agent.hookSession ?? 'unknown';
    if (this.admit(key, at, deny) || alerted.size > 0) {
      this.o.detector.recordToolRequest(r.event, r.detections, alerted);
    } else {
      this.notRecorded++;
    }
    this.soon('activity');
  }

  /**
   * Room to store one more request from `key` this hour. Denies have their
   * own room, so they never wait behind other requests.
   */
  private admit(key: string, at: number, deny: boolean): boolean {
    const hour = Math.floor(at / HOUR);
    if (hour !== this.caps.hour) this.caps = { hour, total: 0, perKey: new Map(), denies: 0 };
    if (deny) {
      if (this.caps.denies >= DENY_RECORD_PER_HOUR) return false;
      this.caps.denies++;
      return true;
    }
    const n = this.caps.perKey.get(key) ?? 0;
    if (this.caps.total >= RECORD_PER_HOUR || n >= RECORD_PER_KEY_PER_HOUR) return false;
    this.caps.total++;
    this.caps.perKey.set(key, n + 1);
    return true;
  }

  /**
   * A stopped step raises a badge-level alert, once per rule and session
   * every 10 minutes. Asks raise nothing: Claude Code is already asking.
   */
  private alertDeny(d: Detection, event: AgentToolRequestEvent, key: string, at: number): boolean {
    const rule = this.o.detector.engine.getRule(d.match.ruleId);
    if (!rule) return false;
    const k = `${rule.id}\n${key}`;
    const last = this.denyAlertAt.get(k);
    if (last !== undefined && at - last < DENY_ALERT_MS) return false;
    remember(this.denyAlertAt, k, at);
    const summary = d.alert?.summary ?? d.reasons.join(' ');
    void this.o.alerts
      .raise({
        rule: { ...coreRule(rule), mode: 'alert' },
        events: [event],
        actions: [],
        title: `Stopped: ${rule.name}`,
        ...(summary ? { summary } : {}),
        ...(d.alert?.subject ? { subject: d.alert.subject } : {}),
        notify: 'badge',
      })
      .catch((err: unknown) => this.log(`deny alert failed: ${(err as Error).message}`));
    return true;
  }

  /**
   * Five stopped steps in one session within 10 minutes raise
   * preflight-probing, once an hour per session; so do ten over all
   * sessions together, when no one session got to five.
   */
  private countDeny(event: AgentToolRequestEvent, who: string, at: number): void {
    const mine = this.denied(who, at);
    const all = this.denied(EVERY_SESSION, at);
    const key = mine >= PROBE_DENIES ? who : all >= PROBE_DENIES_ALL ? EVERY_SESSION : undefined;
    if (key === undefined) return;
    const last = this.probeAlertAt.get(key);
    if (last !== undefined && at - last < PROBE_ALERT_MS) return;
    const engine = this.o.detector.engine;
    const rule = engine.getRule(PREFLIGHT_PROBING_RULE_ID);
    if (!rule) return;
    // The user can turn it off (or to shadow) on the Rules page.
    const mode = engine.modeOf(rule);
    if (mode !== 'alert' && mode !== 'block') return;
    remember(this.probeAlertAt, key, at);
    void this.o.alerts
      .raise({
        rule: { ...coreRule(rule), mode },
        events: [event],
        actions: [],
        summary: rule.reasons.join(' '),
      })
      .catch((err: unknown) => this.log(`probing alert failed: ${(err as Error).message}`));
  }

  /** Count a stopped step under `key`: how many it has had in the last 10 minutes. */
  private denied(key: string, at: number): number {
    const times = (this.denyTimes.get(key) ?? []).filter((t) => at - t < PROBE_WINDOW_MS);
    times.push(at);
    remember(this.denyTimes, key, times);
    return times.length;
  }

  /**
   * Another program took the agent socket: it was listening there before
   * Vigil, or replaced or removed Vigil's socket (which the endpoint then
   * takes back). Raises preflight-socket-tampered, once an hour, in the mode
   * the user set on the Rules page.
   */
  private socketTampered(why: SocketTamper): void {
    const at = this.now();
    if (at - this.tamperAlertAt < TAMPER_ALERT_MS) return;
    const engine = this.o.detector.engine;
    const rule = engine.getRule(PREFLIGHT_SOCKET_RULE_ID);
    if (!rule) return;
    const mode = engine.modeOf(rule);
    if (mode !== 'alert' && mode !== 'block') return;
    this.tamperAlertAt = at;
    // An event for the alert to point to: the socket, as a request no hook can send.
    const event: AgentToolRequestEvent = {
      id: newId(at),
      ts: at,
      source: 'vigil',
      kind: 'agent.tool_request',
      tool: PREFLIGHT_SOCKET_TOOL,
      filePath: this.endpoint.socketPath,
      agent: { host: 'claude-code' },
    };
    const what =
      why === 'taken'
        ? "was already listening on Vigil's socket when Vigil started, so Vigil could not open it. Until it stops, it answers Claude Code's hook in Vigil's place."
        : `${why} Vigil's socket. Vigil took it back, but the program may try again.`;
    void this.o.alerts
      .raise({
        rule: { ...coreRule(rule), mode },
        events: [event],
        actions: [],
        summary: `A program other than Vigil ${what}`,
        subject: { kind: 'file', label: this.endpoint.socketPath },
      })
      .catch((err: unknown) => this.log(`socket alert failed: ${(err as Error).message}`));
    this.emit('changed');
  }

  private heard(patch: Partial<HookState>): void {
    const wasConnected = hookConnected(this.hook, this.now());
    this.hook = { ...this.hook, ...patch };
    if (patch.lastHelloAt !== undefined || this.now() - this.hookSavedAt >= HOOK_SAVE_MS) {
      this.saveHook();
    }
    // Connecting changes the setup step and the Tool policy tab; a later
    // hello only moves "last checked in".
    if (!wasConnected && hookConnected(this.hook, this.now())) this.soon('changed');
    else if (patch.lastHelloAt !== undefined) this.soon('activity');
  }

  private saveHook(): void {
    this.o.store.setSetting(KEY_HOOK, this.hook);
    this.hookSavedAt = this.now();
  }

  /** The socket is open while pre-flight or Vigil's tools are on. */
  private socketWanted(): boolean {
    const p = this.prefs();
    return p.preflightEnabled || p.toolsEnabled;
  }

  private async syncEndpoint(): Promise<void> {
    if (this.started && this.socketWanted()) await this.endpoint.start();
    else await this.endpoint.stop();
    this.emit('changed');
  }

  /** The hooks to paste into Claude Code, or '' when this build has no hook to run. */
  private snippet(socketPath: string): string {
    const files = this.hookFiles();
    if (!files) return '';
    return hookSnippet({ ...files, socketPath, onUnavailable: this.prefs().onUnavailable });
  }

  /** This build's node and hook script, or undefined when it ships no hook. */
  private hookFiles(): { nodePath: string; hookPath: string } | undefined {
    const dir = helperBundleDir(this.o.resourcesPath, this.o.devHelperDir);
    if (!dir) return undefined;
    const files = hookFiles(dir);
    return existsSync(files.hookPath) ? files : undefined;
  }

  // ---------------------------------------------------------------- tracker hooks

  /** A new agent session; written with others in a second. */
  onSession(s: SessionStart): void {
    const row: AgentSessionRow = {
      id: s.id,
      agentId: s.agentId,
      rootPid: s.rootPid,
      rootPath: s.rootPath,
      startedAt: s.startedAt,
      seeded: s.seeded,
    };
    if (s.parentSession) row.parentSession = s.parentSession;
    this.pendingSessions.push(row);
    this.sessionTimer ??= setTimeout(() => this.flushSessions(), SESSION_FLUSH_MS);
  }

  /**
   * The tracker met a process it doesn't know: read `ps` again, at most every
   * 30 s, less often while that finds none of the processes that missed (a
   * process that exited, or one `ps` names differently), on battery 4 times
   * less often still, and not while routine work is paused.
   */
  onMiss(pid: number): void {
    // ps listed it last time, so reading it again tells Vigil nothing new.
    if (this.psPids.has(pid)) return;
    if (this.missed.size < MAX_MISSED) this.missed.add(pid);
    const scheduler = this.o.scheduler;
    if (this.seeding || scheduler.isPaused) return;
    if (this.now() - this.lastSeedAt < this.reseedMs * scheduler.slowdownFactor) return;
    void this.seed();
  }

  /**
   * An unknown program runs shell commands the way agents do. Suggest it
   * (it tags nothing until the user accepts), at most once a day. Later, so
   * the registry never changes while the tracker is mid-event.
   */
  onCandidate(c: { pid: number; path: string; shellChildren: number }): void {
    setImmediate(() => this.suggest(c.path));
  }

  private suggest(path: string): void {
    if (!this.prefs().suggestions) return;
    const at = this.now();
    const last = this.o.store.getSetting(KEY_SUGGESTED, z.number(), 0);
    if (at - last < DAY) return;
    if (!this.o.detector.registry.suggest({ path, at })) return;
    this.o.store.setSetting(KEY_SUGGESTED, at);
    this.emit('changed');
  }

  // ---------------------------------------------------------------- internals

  private flushSessions(): void {
    clearTimeout(this.sessionTimer);
    this.sessionTimer = undefined;
    const rows = this.pendingSessions;
    if (rows.length === 0) return;
    this.pendingSessions = [];
    try {
      this.o.store.insertAgentSessions(rows);
    } catch (err) {
      this.log(`saving sessions failed: ${(err as Error).message}`);
    }
    this.soon('activity');
  }

  /** Tell the pages once things settle, rather than on every request. Armed only by activity. */
  private soon(what: 'changed' | 'activity'): void {
    if (this.timers[what]) return;
    const t = setTimeout(() => {
      delete this.timers[what];
      this.emit(what);
    }, CHANGED_MS);
    t.unref?.();
    this.timers[what] = t;
  }

  private seed(): Promise<void> {
    this.seeding ??= (async () => {
      this.lastSeedAt = this.now();
      const missed = this.missed;
      this.missed = new Set();
      try {
        // Launches seen while ps runs are newer than its rows.
        const since = this.o.detector.processMark();
        const rows = await this.readPs();
        this.o.detector.seedProcesses(rows, since);
        this.psPids = new Set(rows.map((r) => r.pid));
        if (missed.size > 0) {
          const found = [...missed].some((pid) => this.psPids.has(pid));
          this.reseedMs = found ? RESEED_MS : Math.min(MAX_RESEED_MS, this.reseedMs * 2);
        }
        const m = this.o.detector.registry.matcher();
        const running = new Set<string>();
        for (const r of rows) {
          const id = m.match(r)?.id;
          if (id) running.add(id);
        }
        this.runningAt = this.now();
        if (!sameSet(running, this.running)) {
          this.running = running;
          this.soon('changed');
        }
      } catch (err) {
        this.log(`reading the process table failed: ${(err as Error).message}`);
      } finally {
        this.seeding = undefined;
      }
    })();
    return this.seeding;
  }

  /** Which agents are installed: a stat of each one's install paths, once a day. */
  private discover(): void {
    const found = new Set<string>();
    for (const a of this.o.detector.registry.list()) {
      const paths = a.installPaths.map((p) =>
        p.startsWith('~/') ? join(this.home, p.slice(2)) : p,
      );
      if (paths.some((p) => this.statInstall(p))) found.add(a.id);
    }
    if (sameSet(found, this.installed)) return;
    this.installed = found;
    this.emit('changed');
  }

  private agentRecord(id: string): AgentRecord | undefined {
    return this.o.detector.registry.list().find((a) => a.id === id);
  }

  /**
   * Today's pre-flight answers for the host (Claude Code), whether or not
   * Vigil could tie each request to a session: with watch off, or on a
   * tracker miss, a request has the host but no agent.
   */
  private hostCounts(since: number): { ask: number; deny: number } {
    return this.o.store.toolRequestCounts(since);
  }

  /** Pre-flight is on and Claude Code's hook has checked in. */
  private preflightActive(): boolean {
    return this.prefs().preflightEnabled && hookConnected(this.hook, this.now());
  }

  private view(
    r: AgentRecord,
    s: AgentStats | undefined,
    host: { ask: number; deny: number },
    preflightActive: boolean,
  ): AgentView {
    const preflight = r.preflightHost === 'claude-code';
    const v: AgentView = {
      id: r.id,
      name: r.name,
      kind: r.kind,
      origin: r.origin,
      status: r.status,
      watch: r.watch,
      presence: this.presence(r.id, s?.lastSeenAt),
      sessionsToday: s?.sessions ?? 0,
      matchesToday: s?.matches ?? 0,
      asksToday: preflight ? host.ask : (s?.asks ?? 0),
      deniesToday: preflight ? host.deny : (s?.denies ?? 0),
      builtin: r.builtin,
      edited: r.edited,
    };
    if (s?.lastSeenAt !== undefined) v.lastSeenAt = s.lastSeenAt;
    if (preflight) {
      v.preflightHost = 'claude-code';
      v.preflight = preflightActive ? 'active' : 'available';
    }
    return v;
  }

  private presence(id: string, lastSeenAt: number | undefined): AgentPresence {
    // A `ps` that listed it counts as a sighting when it ran, and goes stale like one.
    const psAt = this.running.has(id) ? this.runningAt : Number.NEGATIVE_INFINITY;
    const seen = Math.max(lastSeenAt ?? Number.NEGATIVE_INFINITY, psAt);
    if (this.now() - seen < RUNNING_MS) return 'running';
    if (Number.isFinite(seen)) return 'seen';
    return this.installed.has(id) ? 'installed' : 'not-found';
  }

  /** Midnight today, local time. */
  private startOfDay(): number {
    const d = new Date(this.now());
    d.setHours(0, 0, 0, 0);
    return d.getTime();
  }
}

/** The process tree of one session from its launch events, root first, at most 200 nodes. */
export function sessionTree(
  session: AgentSessionView,
  execs: readonly EventView[],
  matchedPids: ReadonlySet<number>,
  max = MAX_TREE,
): TreeNode[] {
  const root: TreeNode = {
    pid: session.rootPid,
    ppid: 0,
    name: basename(session.rootPath),
    path: session.rootPath,
    ts: session.startedAt,
    depth: 0,
    matched: matchedPids.has(session.rootPid),
  };
  const out: TreeNode[] = [root];
  for (const v of execs) {
    if (v.event.kind !== 'process.exec') continue;
    const p = v.event.process;
    if (p.agent?.session !== session.id) continue;
    const matched = (v.outcome?.matches.length ?? 0) > 0 || matchedPids.has(p.pid);
    if (p.pid === session.rootPid && p.agent.depth === 0) {
      // The root's own launch says who started it.
      root.ppid = p.ppid ?? 0;
      root.matched ||= matched;
      continue;
    }
    if (out.length >= max) break;
    out.push({
      pid: p.pid,
      ppid: p.ppid ?? 0,
      name: basename(p.path),
      path: p.path,
      ts: v.event.ts,
      depth: p.agent.depth,
      matched,
    });
  }
  return out;
}
