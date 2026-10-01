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
  type AgentIdentity,
  type AgentMatcher,
  type AgentToolRequestEvent,
  type HelloReply,
  type PreflightReply,
  type ToolsReply,
} from '@vigil/core';
import {
  PREFLIGHT_PROBING_RULE_ID,
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
  type ToolsRequest,
} from './endpoint.js';
import { hookFiles, hookSnippet, mcpSnippet } from './hook-snippet.js';
import { readProcessTable } from './ps.js';
import { VigilTools, type StatusFacts } from './tools.js';

const KEY_PREFS = 'agents.prefs';
const KEY_HOOK = 'agents.hook';
const KEY_SUGGESTED = 'agents.suggestedAt';
const KEY_TOOLS = 'agents.tools';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** New sessions are written in one batch this long after the first arrives. */
const SESSION_FLUSH_MS = 1000;
/** `ps` runs again on a miss at most this often. */
const RESEED_MS = 30_000;
/** Pages hear about background changes (requests, sessions) at most this often. */
const CHANGED_MS = 2000;
/** The hook's last request is saved at most this often; a hello is saved at once. */
const HOOK_SAVE_MS = MINUTE;
/** Tool requests stored per agent session (or hook session) and in all, per hour. */
export const RECORD_PER_KEY_PER_HOUR = 600;
export const RECORD_PER_HOUR = 3000;
/** One alert per rule and agent session for stopped steps in this long. */
export const DENY_ALERT_MS = 10 * MINUTE;
/** This many stopped steps in one session within PROBE_WINDOW_MS looks like probing. */
export const PROBE_DENIES = 5;
const PROBE_WINDOW_MS = 10 * MINUTE;
const PROBE_ALERT_MS = HOUR;
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

export class AgentService extends EventEmitter<{ changed: [] }> {
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
  private readonly tools: VigilTools;
  private toolUse: ToolUse;
  private toolUseSavedAt = 0;
  /** Tools calls refused because the tools were off, since start. */
  private toolsRefused = 0;

  private pendingSessions: AgentSessionRow[] = [];
  private sessionTimer: ReturnType<typeof setTimeout> | undefined;
  private changedTimer: ReturnType<typeof setTimeout> | undefined;

  private seeding: Promise<void> | undefined;
  private lastSeedAt = Number.NEGATIVE_INFINITY;
  /** Agents the last `ps` found running. */
  private running = new Set<string>();
  /** Agents the last discovery found installed. */
  private installed = new Set<string>();

  /** Tool requests admitted for storage this hour, in all and per key. */
  private caps = { hour: -1, total: 0, perKey: new Map<string, number>() };
  private notRecorded = 0;
  private readonly denyAlertAt = new Map<string, number>();
  private readonly denyTimes = new Map<string, number[]>();
  private readonly probeAlertAt = new Map<string, number>();

  constructor(private readonly o: AgentServiceDeps) {
    super();
    this.now = o.now ?? Date.now;
    this.readPs =
      o.readPs ?? (process.platform === 'darwin' ? () => readProcessTable() : async () => []);
    this.statInstall = o.statInstall ?? existsSync;
    this.home = o.home ?? homedir();
    this.log = o.log ?? ((msg) => console.warn(`[agents] ${msg}`));
    this.hook = o.store.getSetting(KEY_HOOK, HookState, {});
    this.toolUse = o.store.getSetting(KEY_TOOLS, ToolUse, { calls: 0 });
    this.endpoint = new AgentEndpoint({
      socketPath: o.socketPath ?? socketPathFor(o.userData, tmpdir(), process.getuid?.() ?? 0),
      handle: (req) => this.fromSocket(req),
      tools: (req) => this.handleTools(req),
      log: this.log,
    });
    this.tools = new VigilTools({
      now: this.now,
      status: () => this.statusFacts(),
      alerts: (opts) => o.store.listAlerts(opts),
      alert: (id) => o.store.getAlert(id),
      events: (ids) => o.store.getEventViews(ids),
      ruleName: (id) => o.detector.engine.getRule(id)?.name ?? o.store.getRule(id)?.name,
      searchEvents: (q) => o.store.searchEvents(q),
      agents: () => this.listAgents(),
      agentSessions: (id, limit) => o.store.listAgentSessions(id, undefined, limit),
      agentSession: (id, rows) => this.sessionDetail(id, rows, rows),
    });
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
    clearTimeout(this.changedTimer);
    this.changedTimer = undefined;
    this.saveHook();
    this.saveToolUse();
    await this.endpoint.stop();
  }

  // ---------------------------------------------------------------- views

  listAgents(): AgentView[] {
    const stats = this.o.store.agentStats(this.startOfDay());
    return this.o.detector.registry.list().map((r) => this.view(r, stats.get(r.id)));
  }

  getAgent(id: string): AgentDetail | null {
    const r = this.agentRecord(id);
    if (!r) return null;
    const view = this.view(r, this.o.store.agentStats(this.startOfDay()).get(id));
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
    return {
      ok: true,
      agent: this.view(r, this.o.store.agentStats(this.startOfDay()).get(r.id)),
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
      tools: VIGIL_TOOLS,
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
   * For setup's Claude Code pre-flight step: shown once Claude Code is
   * installed or has been seen, done while the hook is connected.
   */
  claudePreflightStep(): { connected: boolean } | undefined {
    const connected = hookConnected(this.hook, this.now());
    const claude = 'claude-code';
    const known =
      this.hook.lastHelloAt !== undefined ||
      this.hook.lastRequestAt !== undefined ||
      this.installed.has(claude) ||
      this.running.has(claude) ||
      this.o.store.listAgentSessions(claude, undefined, 1).length > 0;
    return known ? { connected } : undefined;
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
    setImmediate(() => this.record(result));
    return result.reply;
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
      this.soon();
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
    this.soon();
  }

  private saveToolUse(): void {
    this.o.store.setSetting(KEY_TOOLS, this.toolUse);
    this.toolUseSavedAt = this.now();
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

  /** After the answer: store the request (within caps), alert on a deny, watch for probing. */
  private record(r: PreflightResult): void {
    // When it was asked, not when this runs: a burst is recorded together.
    const at = r.event.ts;
    this.heard({ lastRequestAt: at });
    const key = r.event.agent.session ?? r.event.agent.hookSession ?? 'unknown';
    if (!this.admit(key, at)) {
      this.notRecorded++;
      this.soon();
      return;
    }
    const alerted = new Set<string>();
    for (const d of r.detections) {
      if (d.mode === 'block' && this.alertDeny(d, r.event, key, at)) alerted.add(d.match.ruleId);
    }
    this.o.detector.recordToolRequest(r.event, r.detections, alerted);
    if (r.reply.decision === 'deny') this.countDeny(r.event, key, at);
    this.soon();
  }

  /** Room to store one more request from `key` this hour. */
  private admit(key: string, at: number): boolean {
    const hour = Math.floor(at / HOUR);
    if (hour !== this.caps.hour) this.caps = { hour, total: 0, perKey: new Map() };
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

  /** Five stopped steps in one session within 10 minutes raise preflight-probing, once an hour. */
  private countDeny(event: AgentToolRequestEvent, key: string, at: number): void {
    const times = (this.denyTimes.get(key) ?? []).filter((t) => at - t < PROBE_WINDOW_MS);
    times.push(at);
    remember(this.denyTimes, key, times);
    if (times.length < PROBE_DENIES) return;
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

  private heard(patch: Partial<HookState>): void {
    const wasConnected = hookConnected(this.hook, this.now());
    this.hook = { ...this.hook, ...patch };
    if (patch.lastHelloAt !== undefined || this.now() - this.hookSavedAt >= HOOK_SAVE_MS) {
      this.saveHook();
    }
    if (patch.lastHelloAt !== undefined || !wasConnected) this.soon();
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

  /** The tracker met a process it doesn't know: read `ps` again, at most every 30 s. */
  onMiss(_ppid: number): void {
    if (this.seeding || this.now() - this.lastSeedAt < RESEED_MS) return;
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
    this.soon();
  }

  /** Tell the pages once things settle, rather than on every request. Armed only by activity. */
  private soon(): void {
    if (this.changedTimer) return;
    this.changedTimer = setTimeout(() => {
      this.changedTimer = undefined;
      this.emit('changed');
    }, CHANGED_MS);
    this.changedTimer.unref?.();
  }

  private seed(): Promise<void> {
    this.seeding ??= (async () => {
      this.lastSeedAt = this.now();
      try {
        const rows = await this.readPs();
        this.o.detector.seedProcesses(rows);
        const m = this.o.detector.registry.matcher();
        const running = new Set<string>();
        for (const r of rows) {
          const id = m.match(r)?.id;
          if (id) running.add(id);
        }
        if (!sameSet(running, this.running)) {
          this.running = running;
          this.soon();
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

  private view(r: AgentRecord, s: AgentStats | undefined): AgentView {
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
      asksToday: s?.asks ?? 0,
      deniesToday: s?.denies ?? 0,
      builtin: r.builtin,
      edited: r.edited,
    };
    if (s?.lastSeenAt !== undefined) v.lastSeenAt = s.lastSeenAt;
    if (r.preflightHost === 'claude-code') v.preflightHost = 'claude-code';
    return v;
  }

  private presence(id: string, lastSeenAt: number | undefined): AgentPresence {
    if (this.running.has(id)) return 'running';
    if (lastSeenAt !== undefined && this.now() - lastSeenAt < RUNNING_MS) return 'running';
    if (lastSeenAt !== undefined) return 'seen';
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
