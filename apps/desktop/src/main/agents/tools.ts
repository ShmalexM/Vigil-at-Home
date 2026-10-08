// Vigil's read-only tools for the user's own agents (opt-in, Agents › Tool
// policy). The user adds Vigil as an MCP server to their own Claude Code,
// Codex or Cursor; the hook package's `mcp` command forwards each call over
// the agent socket, and this module answers it from what Vigil has stored.
// No model of Vigil's takes part.
//
// Nothing here can change anything: the source it reads has read methods
// only. Every result goes through the same redaction as the data Vigil's own
// AI gets (home folders, keys, tokens, email addresses), and results are cut
// to 50 rows and 64 KB. Rule conditions and exclusions are never shown (a
// rule's exclusions only as a count), so an agent can't learn how to word its
// commands around them. A model's label on an event is shown, its reason
// isn't: that text was written from what the event's own program wrote.

import {
  AgentId,
  EventKind,
  RuleMode,
  isRelease,
  type Action,
  type ActionRecord,
  type Alert,
  type SensorEvent,
  type Severity,
  type ToolsReply,
} from '@vigil/core';
import { redactValue } from '@vigil/ai/redact';
import { z } from 'zod';
import {
  VIGIL_TOOLS,
  type AgentSessionView,
  type AgentView,
  type TreeNode,
  type VigilToolInfo,
  type VigilToolName,
} from '../../shared/agents.js';
import {
  EVENT_GROUPS,
  EventGroup,
  type AgentSessionDetail,
  type EventLabel,
  type EventOutcome,
  type EventView,
  type SensorView,
} from '../../shared/ipc.js';

/** Rows in any one list of a result. */
export const MAX_ROWS = 50;
/** A result's size as JSON. */
export const MAX_RESULT_BYTES = 64 * 1024;
const DEFAULT_ROWS = 20;
/** search_events looks back this far at most. */
export const EVENT_DAYS = 7;
/**
 * Text is looked for in at most this many of the newest events: about 10 ms
 * of the main thread per search, which the socket's tools budget then limits.
 */
export const SCAN_ROWS = 10_000;
/** Longest string in a result (command lines, summaries). */
const TEXT_CHARS = 1000;
/** Latest sessions shown per agent by list_agents. */
const SESSIONS_PER_AGENT = 3;
/** Rule hits are counted over this many days. */
export const HIT_DAYS = 7;
const DAY = 24 * 60 * 60 * 1000;

/** As Vigil's own AI gets data: no user or host name is configured there either. */
const REDACTION = {};

/** What the tools read. Read methods only: nothing reachable from here writes. */
export interface VigilToolsSource {
  now(): number;
  status(): StatusFacts;
  alerts(opts: { limit: number; status?: 'open' | 'resolved' }): Alert[];
  alert(id: string): Alert | undefined;
  /** Events by id, with what the rules made of them. */
  events(ids: readonly string[]): EventView[];
  ruleName(id: string): string | undefined;
  searchEvents(q: {
    since: number;
    kinds?: readonly EventKind[];
    text?: string;
    agent?: string;
    matchedOnly?: boolean;
    label?: 'unusual' | 'suspicious';
    limit: number;
    scanRows: number;
  }): { views: EventView[]; partial: boolean };
  /** Every rule, without its conditions. */
  rules(): RuleFacts[];
  /** Matches per rule id since `since`. */
  ruleHits(since: number): Map<string, number>;
  /** What Vigil did (blocks, quarantines, releases, undos), newest first. */
  actions(limit: number): ActionRecord[];
  agents(): AgentView[];
  agentSessions(agentId: string, limit: number): AgentSessionView[];
  /** At most `rows` tree nodes and events. */
  agentSession(id: string, rows: number): AgentSessionDetail | null;
}

/** What the rule tools show of one rule: never its conditions or exclusions. */
export interface RuleFacts {
  id: string;
  name: string;
  description: string;
  /** The mode it actually runs in, after the user's choice. */
  mode: RuleMode;
  severity: Severity;
  /** Its own exclusions and the user's exceptions to it, counted. */
  exclusions: number;
}

/** vigil_status's facts, gathered by the agent service. */
export interface StatusFacts {
  /** From the app's status, when it has one (not in some tests). */
  protection?: {
    level: 'good' | 'fair' | 'poor';
    reasons: string[];
    needsYou: number;
    sensors: SensorView[];
    /** Blocks are only recorded: the privileged helper isn't installed. */
    simulated: boolean;
  };
  rules: Record<RuleMode, number>;
  preflight: {
    on: boolean;
    hookConnected: boolean;
    lastHookAt?: number;
    last24h: { deny: number; ask: number; none: number };
  };
}

/** One tool as MCP lists it. */
export interface ToolListing {
  name: VigilToolName;
  title: string;
  description: string;
  inputSchema: Record<string, unknown>;
  annotations: { readOnlyHint: true; destructiveHint: false; openWorldHint: false };
}

/** A refusal whose message the agent may see. Anything else thrown stays inside. */
class ToolError extends Error {}

const Since = z
  .string()
  .min(2)
  .max(40)
  .describe(
    'An ISO 8601 time such as 2026-10-01T09:00:00Z, or a span back from now such as 30m, 24h or 7d.',
  );
const Limit = z
  .number()
  .int()
  .min(1)
  .max(MAX_ROWS)
  .describe(`At most this many rows: ${DEFAULT_ROWS} unless given, ${MAX_ROWS} at most.`);
const KINDS = [...EventKind.options, ...EventGroup.options] as const;

interface ToolDef {
  title: string;
  input: z.ZodObject;
  answer(args: unknown): Record<string, unknown>;
}

/** A tool whose `answer` gets its own parsed arguments. */
function def<S extends z.ZodObject>(
  title: string,
  input: S,
  answer: (args: z.output<S>) => Record<string, unknown>,
): ToolDef {
  return { title, input, answer: (args) => answer(args as z.output<S>) };
}

export class VigilTools {
  private readonly defs: Record<VigilToolName, ToolDef>;

  constructor(private readonly src: VigilToolsSource) {
    this.defs = {
      vigil_status: def('Vigil status', z.object({}), () => this.status()),
      list_alerts: def(
        'List alerts',
        z.object({
          since: Since.optional(),
          status: z
            .enum(['open', 'resolved'])
            .optional()
            .describe('open: still waiting on the user; resolved: decided or closed.'),
          limit: Limit.optional(),
        }),
        (a) => this.listAlerts(a),
      ),
      get_alert: def(
        'Get an alert',
        z.object({ id: z.string().min(1).max(128).describe('An alert id from list_alerts.') }),
        (a) => this.getAlert(a.id),
      ),
      search_events: def(
        'Search events',
        z.object({
          kind: z
            .enum(KINDS)
            .optional()
            .describe(
              'An event kind (process.exec, file, network.connection, agent.tool_request, …) or a group: programs, network, files, startup, system or agents.',
            ),
          text: z
            .string()
            .min(1)
            .max(200)
            .optional()
            .describe('Text anywhere in the event, such as a program name, path or host.'),
          agent: AgentId.optional().describe(
            'Only what one agent did: an agent id from list_agents, such as claude-code.',
          ),
          matched: z.boolean().optional().describe('true: only events that matched a rule.'),
          label: z
            .enum(['unusual', 'suspicious'])
            .optional()
            .describe('Only events the AI labelled unusual or suspicious (no rule matched them).'),
          since: Since.optional(),
          limit: Limit.optional(),
        }),
        (a) => this.searchEvents(a),
      ),
      list_rules: def(
        'List rules',
        z.object({
          mode: RuleMode.optional().describe(
            'Only rules in this mode: disabled, shadow (only logs), alert or block.',
          ),
          limit: Limit.optional(),
        }),
        (a) => this.listRules(a),
      ),
      get_rule: def(
        'Get a rule',
        z.object({
          id: z.string().min(1).max(128).describe('A rule id from list_rules or an alert.'),
        }),
        (a) => this.getRule(a.id),
      ),
      list_actions: def(
        'List actions',
        z.object({ since: Since.optional(), limit: Limit.optional() }),
        (a) => this.listActions(a),
      ),
      list_agents: def('List agents', z.object({}), () => this.listAgents()),
      get_agent_session: def(
        'Get an agent session',
        z.object({
          id: z
            .string()
            .regex(/^[0-9a-f]{16}$/)
            .describe('A session id (16 hex characters) from list_agents or an event.'),
        }),
        (a) => this.getAgentSession(a.id),
      ),
    };
  }

  /** The tools for MCP's tools/list, with JSON Schemas for their arguments. The pack also gets its own. */
  list(o: { pack?: boolean } = {}): ToolListing[] {
    return offered(o).map((t) => {
      const { $schema: _schema, ...inputSchema } = z.toJSONSchema(this.defs[t.name].input, {
        io: 'input',
      }) as Record<string, unknown>;
      return {
        name: t.name,
        title: this.defs[t.name].title,
        description: t.description,
        inputSchema,
        annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
      };
    });
  }

  /** One call, answered as a tools reply: a redacted result within the caps, or why not. */
  call(name: string, args: Record<string, unknown>, o: { pack?: boolean } = {}): ToolsReply {
    const tool = offered(o).find((t) => t.name === name);
    // The name isn't repeated back: an answer carries only Vigil's own words and data.
    if (!tool)
      return fail(
        `Vigil has no such tool. Its tools: ${offered(o)
          .map((t) => t.name)
          .join(', ')}.`,
      );
    const d = this.defs[tool.name];
    const parsed = d.input.safeParse(args);
    if (!parsed.success) {
      const issues = parsed.error.issues.map((i) =>
        i.path.length ? `${i.path.join('.')}: ${i.message}` : i.message,
      );
      return fail(`${name}: ${issues.join('; ')}`);
    }
    try {
      return { v: 1, ok: true, result: fit(d.answer(parsed.data)) };
    } catch (err) {
      return fail(err instanceof ToolError ? err.message : `${name} failed`);
    }
  }

  // ---------------------------------------------------------------- the tools

  private status(): Record<string, unknown> {
    const s = this.src.status();
    const p = s.protection;
    return {
      at: iso(this.src.now()),
      ...(p
        ? {
            protection: p.level,
            reasons: p.reasons,
            needsYou: p.needsYou,
            blocking: p.simulated
              ? 'simulated: the privileged helper is not installed, so blocks are only recorded'
              : 'on',
            sensors: p.sensors.map((x) => ({
              name: x.name,
              state: x.state,
              ...(x.detail ? { detail: clip(x.detail) } : {}),
            })),
          }
        : {}),
      rules: s.rules,
      preflight: {
        on: s.preflight.on,
        hookConnected: s.preflight.hookConnected,
        ...(s.preflight.lastHookAt !== undefined
          ? { lastHookAt: iso(s.preflight.lastHookAt) }
          : {}),
        last24h: s.preflight.last24h,
      },
    };
  }

  private listAlerts(a: {
    since?: string | undefined;
    status?: 'open' | 'resolved' | undefined;
    limit?: number | undefined;
  }): Record<string, unknown> {
    const limit = a.limit ?? DEFAULT_ROWS;
    const since = a.since !== undefined ? parseSince(a.since, this.src.now()) : undefined;
    const found = this.src.alerts({ limit: limit + 1, ...(a.status ? { status: a.status } : {}) });
    // Newest first, so those since a time are the front of the list.
    const recent = since === undefined ? found : found.filter((x) => x.createdAt >= since);
    return {
      alerts: recent.slice(0, limit).map((x) => this.alertRow(x)),
      more: recent.length > limit,
    };
  }

  private getAlert(id: string): Record<string, unknown> {
    const alert = this.src.alert(id);
    if (!alert) throw new ToolError(`No alert ${id}. list_alerts gives the ids.`);
    const events = this.src.events(alert.eventIds.slice(0, MAX_ROWS));
    return {
      alert: {
        ...this.alertRow(alert),
        ...(alert.ai?.details ? { explanationDetails: clip(alert.ai.details) } : {}),
      },
      events: events.map((v) => eventRow(v.event, v.outcome, v.label)),
      ...(alert.eventIds.length > MAX_ROWS ? { more: true } : {}),
    };
  }

  private searchEvents(a: {
    kind?: (typeof KINDS)[number] | undefined;
    text?: string | undefined;
    agent?: string | undefined;
    matched?: boolean | undefined;
    label?: 'unusual' | 'suspicious' | undefined;
    since?: string | undefined;
    limit?: number | undefined;
  }): Record<string, unknown> {
    const now = this.src.now();
    const floor = now - EVENT_DAYS * DAY;
    const since = Math.max(floor, a.since !== undefined ? parseSince(a.since, now) : floor);
    const kinds = a.kind === undefined ? undefined : kindsOf(a.kind);
    const limit = a.limit ?? DEFAULT_ROWS;
    const { views, partial } = this.src.searchEvents({
      since,
      limit,
      scanRows: SCAN_ROWS,
      ...(kinds ? { kinds } : {}),
      ...(a.text ? { text: a.text } : {}),
      ...(a.agent ? { agent: a.agent } : {}),
      ...(a.matched ? { matchedOnly: true } : {}),
      ...(a.label ? { label: a.label } : {}),
    });
    return {
      since: iso(since),
      events: views.map((v) => eventRow(v.event, v.outcome, v.label)),
      ...(partial
        ? { note: `Only the newest ${SCAN_ROWS.toLocaleString('en')} events were searched.` }
        : {}),
    };
  }

  private listRules(a: {
    mode?: RuleMode | undefined;
    limit?: number | undefined;
  }): Record<string, unknown> {
    const limit = a.limit ?? MAX_ROWS;
    const hits = this.src.ruleHits(this.src.now() - HIT_DAYS * DAY);
    // The busiest first, so a cut list keeps the rules that matter today.
    const rules = this.src
      .rules()
      .filter((r) => !a.mode || r.mode === a.mode)
      .map((r) => ({ r, hits: hits.get(r.id) ?? 0 }))
      .sort((x, y) => y.hits - x.hits || x.r.name.localeCompare(y.r.name));
    return {
      rules: rules.slice(0, limit).map(({ r, hits }) => ({
        id: r.id,
        name: clip(r.name),
        mode: r.mode,
        enabled: r.mode !== 'disabled',
        severity: r.severity,
        hits7d: hits,
      })),
      more: rules.length > limit,
    };
  }

  private getRule(id: string): Record<string, unknown> {
    const r = this.src.rules().find((x) => x.id === id);
    if (!r) throw new ToolError(`No rule ${id}. list_rules gives the ids.`);
    return {
      rule: {
        id: r.id,
        name: clip(r.name),
        description: clip(r.description),
        mode: r.mode,
        enabled: r.mode !== 'disabled',
        severity: r.severity,
        hits7d: this.src.ruleHits(this.src.now() - HIT_DAYS * DAY).get(r.id) ?? 0,
        exclusionCount: r.exclusions,
      },
    };
  }

  private listActions(a: {
    since?: string | undefined;
    limit?: number | undefined;
  }): Record<string, unknown> {
    const limit = a.limit ?? DEFAULT_ROWS;
    const since = a.since !== undefined ? parseSince(a.since, this.src.now()) : undefined;
    const found = this.src.actions(limit + 1);
    // Newest first, so those since a time are the front of the list.
    const recent = since === undefined ? found : found.filter((x) => x.requestedAt >= since);
    return {
      actions: recent.slice(0, limit).map((x) => this.actionRow(x)),
      more: recent.length > limit,
    };
  }

  private listAgents(): Record<string, unknown> {
    const agents = this.src.agents().slice(0, MAX_ROWS);
    return {
      agents: agents.map((a) => ({
        id: a.id,
        name: a.name,
        kind: a.kind,
        status: a.status,
        watched: a.watch,
        presence: a.presence,
        ...(a.lastSeenAt !== undefined ? { lastSeenAt: iso(a.lastSeenAt) } : {}),
        today: {
          sessions: a.sessionsToday,
          matches: a.matchesToday,
          asks: a.asksToday,
          denies: a.deniesToday,
        },
        // Only a hook that checked in while pre-flight is on is asked.
        preflightHook: a.preflight === 'active',
        // Only an agent seen running has sessions.
        latestSessions:
          a.lastSeenAt === undefined
            ? []
            : this.src.agentSessions(a.id, SESSIONS_PER_AGENT).map(sessionRow),
      })),
    };
  }

  private getAgentSession(id: string): Record<string, unknown> {
    const d = this.src.agentSession(id, MAX_ROWS + 1);
    if (!d) throw new ToolError(`No agent session ${id}. list_agents gives recent ones.`);
    const cut = d.tree.length > MAX_ROWS || d.events.length > MAX_ROWS;
    return {
      session: sessionRow(d.session),
      tree: d.tree.slice(0, MAX_ROWS).map(treeRow),
      events: d.events.slice(0, MAX_ROWS).map((v) => eventRow(v.event, v.outcome, v.label)),
      ...(cut ? { more: true } : {}),
    };
  }

  private alertRow(a: Alert): Record<string, unknown> {
    return {
      id: a.id,
      at: iso(a.createdAt),
      title: clip(a.title),
      summary: clip(a.summary),
      rule: this.src.ruleName(a.ruleId) ?? a.ruleId,
      ruleId: a.ruleId,
      severity: a.severity,
      status: a.status,
      containment: a.containment,
      ...(a.subject ? { subject: clip(a.subject.label) } : {}),
      ...(a.ai ? { explanation: clip(a.ai.summary), aiVerdict: a.ai.verdict } : {}),
      ...(a.decision ? { userVerdict: a.decision.verdict } : {}),
      events: a.eventIds.length,
    };
  }

  /** What was done, to what, by whom, and how it went; an action's own reason stays out. */
  private actionRow(r: ActionRecord): Record<string, unknown> {
    return {
      id: r.id,
      at: iso(r.requestedAt),
      did: didOf(r.action),
      target: clip(targetOf(r.action)),
      by: r.actor,
      status: r.status,
      // Lifting containment, and undoing an earlier action, are worth seeing at a glance.
      ...(isRelease(r.action) ? { release: true } : {}),
      ...(r.undoes ? { undoes: r.undoes } : {}),
      ...(r.result ? { finishedAt: iso(r.result.at) } : {}),
      ...(r.alertId ? { alertId: r.alertId } : {}),
      ...(r.ruleId ? { rule: this.src.ruleName(r.ruleId) ?? r.ruleId } : {}),
    };
  }
}

// ---------------------------------------------------------------- rows

function fail(error: string): ToolsReply {
  return { v: 1, ok: false, error: clip(error, 300) };
}

function iso(ts: number): string {
  return new Date(ts).toISOString();
}

function clip(s: string, max = TEXT_CHARS): string {
  return s.length <= max ? s : `${s.slice(0, max - 1)}…`;
}

/** `30m`, `24h`, `7d`, or an ISO time. */
export function parseSince(s: string, now: number): number {
  const span = /^(\d{1,5})([mhd])$/.exec(s.trim());
  if (span) {
    const unit = { m: 60_000, h: 3_600_000, d: DAY }[span[2] as 'm' | 'h' | 'd'];
    return now - Number(span[1]) * unit;
  }
  const at = Date.parse(s);
  if (Number.isNaN(at)) {
    throw new ToolError('since: give an ISO time such as 2026-10-01T09:00:00Z, or 30m, 24h or 7d.');
  }
  return at;
}

function kindsOf(k: (typeof KINDS)[number]): EventKind[] {
  const group = EventGroup.safeParse(k);
  return group.success ? EVENT_GROUPS[group.data] : [k as EventKind];
}

function sessionRow(s: AgentSessionView): Record<string, unknown> {
  return {
    id: s.id,
    agent: s.agentId,
    program: s.rootPath,
    pid: s.rootPid,
    startedAt: iso(s.startedAt),
    lastAt: iso(s.lastAt),
    events: s.events,
    matches: s.matches,
    asks: s.asks,
    denies: s.denies,
    ...(s.parentSession ? { parentSession: s.parentSession } : {}),
  };
}

function treeRow(n: TreeNode): Record<string, unknown> {
  return {
    pid: n.pid,
    ppid: n.ppid,
    program: n.path,
    depth: n.depth,
    at: iso(n.ts),
    ...(n.matched ? { matched: true } : {}),
  };
}

/** What an action did, in a few words. A trusted program reads as trusted, nothing more. */
function didOf(a: Action): string {
  switch (a.kind) {
    case 'process.suspend':
      return 'paused a process';
    case 'process.resume':
      return 'resumed a process';
    case 'process.kill':
      return 'stopped a process';
    case 'network.block':
      return 'blocked a connection';
    case 'network.unblock':
      return 'unblocked a connection';
    case 'file.quarantine':
      return 'quarantined a file';
    case 'file.restore':
      return 'restored a quarantined file';
    case 'santa.rule.set':
      return a.policy === 'allow' ? 'trusted a program' : 'blocked a program';
    case 'santa.rule.remove':
      return 'removed a program rule';
    case 'persistence.disable':
      return 'turned off a startup item';
    case 'persistence.enable':
      return 'turned a startup item back on';
  }
}

function targetOf(a: Action): string {
  switch (a.kind) {
    case 'process.suspend':
    case 'process.resume':
    case 'process.kill':
      return a.path ?? `pid ${a.pid}`;
    case 'network.block':
    case 'network.unblock':
      return a.port !== undefined ? `${a.address} port ${a.port}` : a.address;
    case 'file.quarantine':
    case 'persistence.disable':
    case 'persistence.enable':
      return a.path;
    case 'file.restore':
      return `quarantined item ${a.quarantineId}`;
    case 'santa.rule.set':
    case 'santa.rule.remove':
      return `${a.ruleType} ${a.identifier}`;
  }
}

/** What Vigil's answer to a tool request was, from the rules it matched. */
function answerOf(o: EventOutcome): 'deny' | 'ask' | 'none' {
  const modes = new Set(o.matches.map((m) => m.mode));
  return modes.has('block') ? 'deny' : modes.has('alert') ? 'ask' : 'none';
}

/**
 * One event, flat, with the fields a person would look at, and the AI's
 * label when it has one (not its reason: see the top of this file).
 */
export function eventRow(
  e: SensorEvent,
  outcome?: EventOutcome | null,
  label?: EventLabel,
): Record<string, unknown> {
  const r: Record<string, unknown> = { id: e.id, at: iso(e.ts), kind: e.kind };
  const p = 'process' in e ? e.process : undefined;
  // A tool request's process is the shell it would start (pid 0), not a real one.
  if (p && p.pid > 0) {
    r['program'] = p.path;
    r['pid'] = p.pid;
    if (p.args?.length) r['commandLine'] = clip(p.args.join(' '));
    const parent = p.parentPath ?? p.ancestors?.[0];
    if (parent) r['parent'] = parent;
    if (p.ancestors?.length) r['ancestors'] = p.ancestors;
    if (p.signing) r['signing'] = p.signing;
    if (p.agent) r['agent'] = { id: p.agent.id, session: p.agent.session, depth: p.agent.depth };
  }
  switch (e.kind) {
    case 'process.exit':
      if (e.exitCode !== undefined) r['exitCode'] = e.exitCode;
      break;
    case 'file':
      Object.assign(r, { op: e.op, path: e.path }, e.newPath ? { newPath: e.newPath } : {});
      break;
    case 'network.connection':
      Object.assign(r, {
        direction: e.direction,
        protocol: e.protocol,
        remote: e.remoteHost ?? e.remoteAddress,
        ...(e.remotePort !== undefined ? { remotePort: e.remotePort } : {}),
      });
      break;
    case 'network.listen':
      Object.assign(r, { protocol: e.protocol, localPort: e.localPort });
      break;
    case 'persistence':
      Object.assign(r, {
        change: e.change,
        mechanism: e.mechanism,
        path: e.path,
        ...(e.label ? { label: e.label } : {}),
        ...(e.program ? { runs: e.program } : {}),
      });
      break;
    case 'santa.decision':
      // Santa's own words for a launch it let through are left out on purpose:
      // nothing in a tool's answer reads as a permission.
      Object.assign(r, {
        target: e.target,
        santa: e.decision === 'block' ? 'blocked' : e.decision === 'audit_only' ? 'audited' : 'ran',
        ...(e.path ? { path: e.path } : {}),
      });
      break;
    case 'browser.extension':
      Object.assign(r, {
        change: e.change,
        browser: e.browser,
        extensionId: e.extensionId,
        ...(e.name ? { name: clip(e.name) } : {}),
      });
      break;
    case 'system.alert':
      Object.assign(r, { subtype: e.subtype, ...(e.path ? { path: e.path } : {}) });
      break;
    case 'agent.tool_request':
      Object.assign(r, {
        tool: e.tool,
        ...(e.command !== undefined ? { command: clip(e.command) } : {}),
        ...(e.commandBytes !== undefined ? { commandBytes: e.commandBytes } : {}),
        ...(e.filePath ? { filePath: e.filePath } : {}),
        ...(e.url ? { url: clip(e.url) } : {}),
        ...(e.mcpServer ? { mcpServer: e.mcpServer } : {}),
        ...(e.cwd ? { cwd: e.cwd } : {}),
        ...(e.contentBytes !== undefined ? { contentBytes: e.contentBytes } : {}),
        agent: {
          host: e.agent.host,
          ...(e.agent.id ? { id: e.agent.id } : {}),
          ...(e.agent.session ? { session: e.agent.session } : {}),
        },
        // Known once the rules' outcome is stored with it.
        ...(outcome ? { answer: answerOf(outcome) } : {}),
      });
      break;
    case 'process.exec':
      break;
  }
  if (outcome?.matches.length) {
    r['rules'] = outcome.matches.map((m) => ({ rule: m.ruleName, mode: m.mode }));
  }
  if (label) {
    r['aiLabel'] = label.label;
    r['aiScore'] = label.score;
  }
  return r;
}

/**
 * Redacted, then within 64 KB: rows come off the end of the biggest list
 * until it fits, and `truncated` says so.
 */
function fit(result: Record<string, unknown>): Record<string, unknown> {
  const out = redactValue(result, REDACTION) as Record<string, unknown>;
  const bytes = (v: unknown) => Buffer.byteLength(JSON.stringify(v));
  let total = bytes(out);
  if (total <= MAX_RESULT_BYTES) return out;
  out['truncated'] = true;
  total += bytes({ truncated: true });
  const lists = Object.values(out)
    .filter((v): v is unknown[] => Array.isArray(v))
    .map((rows) => ({ rows, sizes: rows.map((r) => bytes(r) + 1) }));
  const left = (l: { sizes: number[] }) => l.sizes.reduce((a, b) => a + b, 0);
  while (total > MAX_RESULT_BYTES) {
    const biggest = lists
      .filter((l) => l.rows.length > 0)
      .reduce<(typeof lists)[number] | undefined>(
        (a, b) => (!a || left(b) > left(a) ? b : a),
        undefined,
      );
    if (!biggest) break;
    biggest.rows.pop();
    total -= biggest.sizes.pop()!;
  }
  if (bytes(out) > MAX_RESULT_BYTES) throw new ToolError('The result is too large to send.');
  return out;
}

/** The tools one caller may use: watched agents never get the pack's own. */
function offered(o: { pack?: boolean }): readonly VigilToolInfo[] {
  return o.pack ? VIGIL_TOOLS : VIGIL_TOOLS.filter((t) => !t.packOnly);
}
