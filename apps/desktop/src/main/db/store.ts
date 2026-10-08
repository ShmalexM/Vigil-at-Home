import type { DatabaseSync, SQLInputValue, StatementSync } from 'node:sqlite';
import {
  ActionProposal,
  ActionRecord,
  Alert,
  Rule,
  RuleMatch,
  SensorEvent,
  type EventKind,
  type RuleMode,
} from '@vigil/core';
import { z } from 'zod';
import {
  EVENT_GROUPS,
  EventLabel,
  EventOutcome,
  TEXT_SEARCH_WINDOW_MS,
  type EventGroup,
  type EventQuery,
  type EventStats,
  type EventView,
} from '../../shared/ipc.js';
import { isNoticed, needsDecision } from '../../shared/attention.js';
import { pileKey, untouched } from '../../shared/piles.js';
import type { AgentCandidate, AgentSessionView } from '../../shared/agents.js';
import type { UsageRun } from '../../shared/usage.js';
import { migrations } from './schema.js';

type Row = { body: string };

/** A new agent session, as the process tracker reports it. */
export interface AgentSessionRow {
  id: string;
  agentId: string;
  rootPid: number;
  rootPath: string;
  startedAt: number;
  parentSession?: string;
  seeded: boolean;
}

const AgentSessionBody = z.object({
  rootPath: z.string(),
  rootName: z.string(),
  parentSession: z.string().optional(),
  seeded: z.boolean(),
});

/** One agent's numbers since a time (see `agentStats`). */
export interface AgentStats {
  /** Sessions active since then. */
  sessions: number;
  /** Events from its sessions that matched a rule. */
  matches: number;
  /** Tool requests Vigil answered with ask, and with deny. */
  asks: number;
  denies: number;
  /** Its newest event or session start, at any time. */
  lastSeenAt?: number;
}

/** What preview matching needs of one stored program launch. */
export interface ExecRow {
  pid: number;
  ppid?: number;
  path: string;
  args?: string[];
  teamId?: string;
  signingId?: string;
}

/** SQL true when a stored tool request was denied (a rule in block mode matched). */
const DENIED = (e: string) =>
  `EXISTS (SELECT 1 FROM json_each(${e}.outcome, '$.matches') m WHERE json_extract(m.value, '$.mode') = 'block')`;
/** ...or asked (alert mode, nothing in block mode). */
const ASKED = (e: string) =>
  `(NOT ${DENIED(e)} AND EXISTS (SELECT 1 FROM json_each(${e}.outcome, '$.matches') m WHERE json_extract(m.value, '$.mode') = 'alert'))`;

function basename(p: string): string {
  return p.slice(p.lastIndexOf('/') + 1);
}

/** Sessions whose counts are kept between reads of the Agents page, at most. */
const MAX_SESSION_COUNTS = 4096;

/**
 * The feed's query for one page. Every filter walks an index on ts: the agent
 * filter goes through events_agent_ts, so a page stops at its limit instead
 * of sorting every event the agent's sessions ever had.
 */
export function eventViewsQuery(
  q: EventQuery,
  now: number,
): { sql: string; args: SQLInputValue[] } {
  const where: string[] = [];
  const args: SQLInputValue[] = [];
  if (q.group) {
    const kinds = EVENT_GROUPS[q.group];
    where.push(`kind IN (${kinds.map(() => '?').join(',')})`);
    args.push(...kinds);
  }
  if (q.matchedOnly) where.push('matched = 1');
  if (q.agentSession) {
    where.push('agent_session = ?');
    args.push(q.agentSession);
  }
  if (q.agent) {
    where.push('agent_id = ?');
    args.push(q.agent);
  }
  if (q.before !== undefined) {
    where.push('ts < ?');
    args.push(q.before);
  }
  if (q.text) {
    where.push('ts >= ?');
    args.push((q.before ?? now) - TEXT_SEARCH_WINDOW_MS);
    where.push(`body LIKE ? ESCAPE '\\'`);
    args.push(`%${q.text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
  }
  const sql = `SELECT body, outcome, label FROM events ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY ts DESC, id DESC LIMIT ?`;
  args.push(q.limit ?? 200);
  return { sql, args };
}

const Tokens = z.number().int().nonnegative();
const UsageRunRow = z.object({
  id: z.string().min(1),
  at: z.number().int(),
  provider: z.enum(['claude', 'codex', 'jev', 'api', 'ollama']),
  purpose: z.enum(['explain', 'analyze', 'classify', 'chat']),
  ok: z.boolean(),
  model: z.string().max(200).optional(),
  inputTokens: Tokens,
  cachedInputTokens: Tokens,
  outputTokens: Tokens,
  costUsd: z.number().nonnegative().nullable(),
  billed: z.boolean().optional(),
}) satisfies z.ZodType<UsageRun>;

type EventRow = { body: string; outcome: string | null; label: string | null };

function eventView(r: EventRow): EventView {
  const label = r.label ? EventLabel.safeParse(JSON.parse(r.label)) : undefined;
  return {
    event: SensorEvent.parse(JSON.parse(r.body)),
    outcome: r.outcome ? EventOutcome.parse(JSON.parse(r.outcome)) : null,
    ...(label?.success ? { label: label.data } : {}),
  };
}

/**
 * Typed access to Vigil's SQLite database. Pure Node (node:sqlite), no Electron,
 * so it runs in tests and in any worker. Every read is validated with zod.
 */
export class Store {
  private readonly statements = new Map<string, StatementSync>();
  /** Per-session counts (see sessionViews), dropped when the session's events change. */
  private readonly sessionCounts = new Map<
    string,
    { events: number; matches: number; lastAt: number; asks: number; denies: number }
  >();
  private txDepth = 0;
  /** Open, undecided alerts: whether each needs a decision, and its pile (openAlertCounts). */
  private attention:
    Map<string, { needs: boolean; pile: string | undefined; clearable: boolean }> | undefined;

  constructor(private readonly db: DatabaseSync) {
    db.exec(`
      PRAGMA journal_mode = WAL;
      -- In WAL mode NORMAL is still crash-safe for the database; it only skips
      -- the fsync per commit (a power cut can lose the last second of events).
      PRAGMA synchronous = NORMAL;
      -- Keep the WAL from staying large after a burst.
      PRAGMA journal_size_limit = ${4 * 1024 * 1024};
      PRAGMA foreign_keys = ON;
      PRAGMA busy_timeout = 3000;
    `);
    this.migrate();
  }

  /** Prepared once and reused: preparing costs more than most of these queries. */
  private stmt(sql: string): StatementSync {
    let s = this.statements.get(sql);
    if (!s) this.statements.set(sql, (s = this.db.prepare(sql)));
    return s;
  }

  private migrate(): void {
    const { user_version: current } = this.db.prepare('PRAGMA user_version').get() as {
      user_version: number;
    };
    for (let v = current; v < migrations.length; v++) {
      this.tx(() => {
        this.db.exec(migrations[v]!);
        this.db.exec(`PRAGMA user_version = ${v + 1}`);
      });
    }
  }

  /**
   * Runs `fn` in a transaction. A call inside another tx becomes a savepoint,
   * so nesting is safe. A transaction left open by code outside tx (a bare
   * BEGIN) is committed and logged first, so one leak can't make every later
   * write fail with "cannot start a transaction within a transaction" and
   * lose alerts. `fn` must be synchronous.
   */
  tx<T>(fn: () => T): T {
    if (this.txDepth === 0 && this.db.isTransaction) {
      console.warn('[store] a transaction was left open outside Store.tx; committing it');
      this.db.exec('COMMIT');
    }
    const name = `tx${this.txDepth}`;
    this.db.exec(`SAVEPOINT ${name}`);
    this.txDepth++;
    try {
      const out = fn();
      if (out instanceof Promise) throw new Error('Store.tx needs a synchronous function');
      this.db.exec(`RELEASE ${name}`);
      return out;
    } catch (err) {
      if (this.db.isTransaction) {
        // Alerts saved inside may be rolled back; count them afresh next time.
        this.attention = undefined;
        this.db.exec(`ROLLBACK TO ${name}`);
        this.db.exec(`RELEASE ${name}`);
      }
      throw err;
    } finally {
      this.txDepth--;
    }
  }

  private all<S extends z.ZodType>(schema: S, sql: string, ...args: SQLInputValue[]): z.infer<S>[] {
    return (this.stmt(sql).all(...args) as Row[]).map((r) => schema.parse(JSON.parse(r.body)));
  }

  private one<S extends z.ZodType>(
    schema: S,
    sql: string,
    ...args: SQLInputValue[]
  ): z.infer<S> | undefined {
    const row = this.stmt(sql).get(...args) as Row | undefined;
    return row ? schema.parse(JSON.parse(row.body)) : undefined;
  }

  // ---------------------------------------------------------------- events

  insertEvent(event: SensorEvent, outcome?: EventOutcome): void {
    this.writeEvent(SensorEvent.parse(event), outcome && EventOutcome.parse(outcome));
  }

  /**
   * Many events in one transaction: one disk flush instead of one per event.
   * Invalid events are skipped rather than failing the batch. Returns how
   * many were skipped.
   */
  insertEvents(entries: readonly { event: SensorEvent; outcome?: EventOutcome }[]): number {
    let skipped = 0;
    this.tx(() => {
      for (const entry of entries) {
        const e = SensorEvent.safeParse(entry.event);
        const o = entry.outcome ? EventOutcome.safeParse(entry.outcome) : undefined;
        if (e.success && (!o || o.success)) this.writeEvent(e.data, o?.data);
        else skipped++;
      }
    });
    return skipped;
  }

  /**
   * An event may already be stored (an alert saves its events at once, with
   * the sensor's raw record); then only its outcome is filled in.
   */
  private writeEvent(e: SensorEvent, outcome?: EventOutcome): void {
    // The agent session and agent the event belongs to: the tracker's tag on a
    // process, or the hook's agent on a tool request (whose process is only the
    // would-be shell). The two are always set together.
    const tag =
      e.kind === 'agent.tool_request' ? e.agent : 'process' in e ? e.process?.agent : undefined;
    const session = tag?.session;
    if (session) this.sessionCounts.delete(session);
    this.stmt(
      `INSERT INTO events (id, ts, kind, source, body, outcome, matched, agent_session, agent_id)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET
         outcome = COALESCE(excluded.outcome, outcome),
         matched = CASE WHEN excluded.outcome IS NULL THEN matched ELSE excluded.matched END,
         agent_session = COALESCE(agent_session, excluded.agent_session),
         agent_id = COALESCE(agent_id, excluded.agent_id)`,
    ).run(
      e.id,
      e.ts,
      e.kind,
      e.source,
      JSON.stringify(e),
      outcome ? JSON.stringify(outcome) : null,
      outcome && outcome.matches.length > 0 ? 1 : 0,
      session ?? null,
      (session && tag?.id) || null,
    );
  }

  /**
   * The feed's page of events, newest first. Every filter walks an index on
   * ts, and text search only looks back a day from where the page starts, so
   * no query scans the whole table on the thread that also runs detection.
   */
  listEventViews(q: EventQuery = {}, now = Date.now()): EventView[] {
    const { sql, args } = eventViewsQuery(q, now);
    const rows = this.db.prepare(sql).all(...args) as {
      body: string;
      outcome: string | null;
      label: string | null;
    }[];
    return rows.map(eventView);
  }

  /**
   * Events since `since`, newest first, of some kinds and holding some text,
   * for Vigil's tools for agents. Text is looked for in at most `scanRows` of
   * the newest events in the window, so a rare word never walks a week of
   * events on the thread that also runs detection. `partial` says the window
   * held more events than that and fewer than `limit` matched.
   */
  searchEvents(q: {
    since: number;
    kinds?: readonly EventKind[];
    text?: string;
    limit: number;
    scanRows: number;
  }): { views: EventView[]; partial: boolean } {
    const where = ['ts >= ?'];
    const args: SQLInputValue[] = [q.since];
    if (q.kinds?.length) {
      where.push(`kind IN (${q.kinds.map(() => '?').join(',')})`);
      args.push(...q.kinds);
    }
    const filter = where.join(' AND ');
    const window = `SELECT body, outcome, label, ts, id FROM events WHERE ${filter}
      ORDER BY ts DESC, id DESC`;
    if (!q.text) {
      const rows = this.db.prepare(`${window} LIMIT ?`).all(...args, q.limit) as EventRow[];
      return { views: rows.map(eventView), partial: false };
    }
    const like = `%${q.text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    const rows = this.db
      .prepare(
        `SELECT body, outcome, label FROM (${window} LIMIT ?)
         WHERE body LIKE ? ESCAPE '\\' ORDER BY ts DESC, id DESC LIMIT ?`,
      )
      .all(...args, q.scanRows, like, q.limit) as EventRow[];
    const partial =
      rows.length < q.limit &&
      this.db
        .prepare(`SELECT ts FROM events WHERE ${filter} ORDER BY ts DESC LIMIT 1 OFFSET ?`)
        .get(...args, q.scanRows) !== undefined;
    return { views: rows.map(eventView), partial };
  }

  /** Stores models' labels on events already written. Unknown ids are ignored. */
  setEventLabels(labels: readonly { eventId: string; label: EventLabel }[]): void {
    this.tx(() => {
      for (const l of labels)
        this.stmt('UPDATE events SET label = ? WHERE id = ?').run(
          JSON.stringify(EventLabel.parse(l.label)),
          l.eventId,
        );
    });
  }

  eventStats(since: number): Omit<EventStats, 'retentionDays'> {
    const byKind = this.db
      .prepare(
        `SELECT kind, COUNT(*) AS n,
           SUM(matched) AS matched
         FROM events WHERE ts >= ? GROUP BY kind`,
      )
      .all(since) as { kind: string; n: number; matched: number }[];
    const byGroup = Object.fromEntries(
      Object.keys(EVENT_GROUPS).map((g) => [g, 0]),
    ) as EventStats['byGroup'];
    let lastHour = 0;
    let matchedLastHour = 0;
    for (const row of byKind) {
      lastHour += row.n;
      matchedLastHour += row.matched;
      const group = (Object.keys(EVENT_GROUPS) as EventGroup[]).find((g) =>
        (EVENT_GROUPS[g] as string[]).includes(row.kind),
      );
      if (group) byGroup[group] += row.n;
    }
    const programs = this.db
      .prepare(
        `SELECT COUNT(DISTINCT json_extract(body, '$.process.path')) AS n
         FROM events WHERE kind = 'process.exec' AND ts >= ?`,
      )
      .get(since) as { n: number };
    const newest = this.db.prepare('SELECT MAX(ts) AS ts FROM events').get() as {
      ts: number | null;
    };
    return {
      lastHour,
      matchedLastHour,
      programsLastHour: programs.n,
      byGroup,
      newest: newest.ts,
    };
  }

  /** Events stored since `since`. */
  countEventsSince(since: number): number {
    const row = this.stmt('SELECT COUNT(*) AS n FROM events WHERE ts >= ?').get(since) as {
      n: number;
    };
    return row.n;
  }

  /** When the newest event of any source arrived, or null if none yet. */
  newestEventAt(): number | null {
    const row = this.stmt('SELECT MAX(ts) AS ts FROM events').get() as { ts: number | null };
    return row.ts;
  }

  /** When this sensor last reported anything, or null if never. */
  lastEventAt(source: string): number | null {
    const row = this.stmt('SELECT MAX(ts) AS ts FROM events WHERE source = ?').get(source) as {
      ts: number | null;
    };
    return row.ts;
  }

  /** Oldest first, for replaying rules over history. */
  *eventsBetween(from: number, to: number): Iterable<SensorEvent> {
    const rows = this.db
      .prepare('SELECT body FROM events WHERE ts >= ? AND ts <= ? ORDER BY ts, id')
      .iterate(from, to) as Iterable<Row>;
    for (const r of rows) yield SensorEvent.parse(JSON.parse(r.body));
  }

  /** Opaque JSON kept next to an alert (the detection that raised it). */
  saveAlertDetection(alertId: string, body: unknown): void {
    this.db
      .prepare('INSERT OR REPLACE INTO alert_detections (alert_id, body) VALUES (?, ?)')
      .run(alertId, JSON.stringify(body));
  }

  getAlertDetection(alertId: string): unknown {
    const row = this.db
      .prepare('SELECT body FROM alert_detections WHERE alert_id = ?')
      .get(alertId) as Row | undefined;
    return row ? (JSON.parse(row.body) as unknown) : undefined;
  }

  getEvent(id: string): SensorEvent | undefined {
    return this.one(SensorEvent, 'SELECT body FROM events WHERE id = ?', id);
  }

  getEvents(ids: readonly string[]): SensorEvent[] {
    if (ids.length === 0) return [];
    // One statement for any number of ids, so the statement cache stays small.
    return this.all(
      SensorEvent,
      'SELECT body FROM events WHERE id IN (SELECT value FROM json_each(?)) ORDER BY ts',
      JSON.stringify(ids),
    );
  }

  /** Events by id with what the rules made of them, oldest first. */
  getEventViews(ids: readonly string[]): EventView[] {
    if (ids.length === 0) return [];
    const rows = this.stmt(
      `SELECT body, outcome, label FROM events
       WHERE id IN (SELECT value FROM json_each(?)) ORDER BY ts`,
    ).all(JSON.stringify(ids)) as EventRow[];
    return rows.map(eventView);
  }

  recentEvents(opts: { kind?: EventKind; since?: number; limit?: number } = {}): SensorEvent[] {
    const limit = opts.limit ?? 200;
    const since = opts.since ?? 0;
    return opts.kind
      ? this.all(
          SensorEvent,
          'SELECT body FROM events WHERE kind = ? AND ts >= ? ORDER BY ts DESC LIMIT ?',
          opts.kind,
          since,
          limit,
        )
      : this.all(
          SensorEvent,
          'SELECT body FROM events WHERE ts >= ? ORDER BY ts DESC LIMIT ?',
          since,
          limit,
        );
  }

  /** Delete events older than `before` that no alert references. Returns rows removed. */
  pruneEvents(before: number): number {
    this.sessionCounts.clear();
    const res = this.stmt(
      `DELETE FROM events WHERE ts < ? AND id NOT IN (
         SELECT j.value FROM alerts, json_each(alerts.body, '$.eventIds') AS j)`,
    ).run(before);
    return Number(res.changes);
  }

  /** Bytes the database holds, not counting free pages SQLite will reuse. */
  usedBytes(): number {
    const n = (sql: string) => Number(Object.values(this.db.prepare(sql).get() ?? {})[0] ?? 0);
    return (n('PRAGMA page_count') - n('PRAGMA freelist_count')) * n('PRAGMA page_size');
  }

  /**
   * Keep the database under `maxBytes` by deleting the oldest events no alert
   * references, a slice at a time. Freed pages are reused by new events, so
   * the file stops growing at about the cap. Returns rows removed.
   */
  pruneEventsToSize(maxBytes: number): number {
    let removed = 0;
    while (this.usedBytes() > maxBytes) {
      const { n } = this.stmt('SELECT COUNT(*) AS n FROM events').get() as { n: number };
      if (Number(n) === 0) break;
      const cutoff = this.stmt('SELECT ts FROM events ORDER BY ts LIMIT 1 OFFSET ?').get(
        Math.max(1, Math.floor(Number(n) / 20)),
      ) as { ts: number } | undefined;
      const gone = this.pruneEvents((cutoff?.ts ?? Number.MAX_SAFE_INTEGER) + 1);
      removed += gone;
      if (gone === 0) break;
    }
    if (removed > 0) this.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    return removed;
  }

  // ---------------------------------------------------------------- rules

  upsertRule(rule: Rule): void {
    const r = Rule.parse(rule);
    this.stmt(
      `INSERT INTO rules (id, version, mode, origin, updated_at, body) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version, mode = excluded.mode,
           origin = excluded.origin, updated_at = excluded.updated_at, body = excluded.body`,
    ).run(r.id, r.version, r.mode, r.origin, r.updatedAt, JSON.stringify(r));
  }

  getRule(id: string): Rule | undefined {
    return this.one(Rule, 'SELECT body FROM rules WHERE id = ?', id);
  }

  listRules(mode?: RuleMode): Rule[] {
    return mode
      ? this.all(Rule, 'SELECT body FROM rules WHERE mode = ? ORDER BY id', mode)
      : this.all(Rule, 'SELECT body FROM rules ORDER BY id');
  }

  insertRuleMatch(match: RuleMatch): void {
    const m = RuleMatch.parse(match);
    this.stmt(
      'INSERT INTO rule_matches (id, rule_id, mode, ts, alert_id, body) VALUES (?, ?, ?, ?, ?, ?)',
    ).run(m.id, m.ruleId, m.mode, m.ts, m.alertId ?? null, JSON.stringify(m));
  }

  /** Match counts per rule since `since`, for the shadow review screen. */
  ruleMatchCounts(since: number): Map<string, number> {
    const rows = this.stmt(
      'SELECT rule_id, COUNT(*) AS n FROM rule_matches WHERE ts >= ? GROUP BY rule_id',
    ).all(since) as { rule_id: string; n: number }[];
    return new Map(rows.map((r) => [r.rule_id, Number(r.n)]));
  }

  // ---------------------------------------------------------------- alerts

  saveAlert(alert: Alert): Alert {
    const a = Alert.parse(alert);
    this.stmt(
      `INSERT INTO alerts (id, created_at, updated_at, status, severity, rule_id, body)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET updated_at = excluded.updated_at, status = excluded.status,
           severity = excluded.severity, body = excluded.body`,
    ).run(a.id, a.createdAt, a.updatedAt, a.status, a.severity, a.ruleId, JSON.stringify(a));
    this.track(a);
    return a;
  }

  /**
   * Needs you and Noticed over every open alert, not just a page of them.
   * Kept per alert as alerts are saved, so a status read never parses alert
   * bodies; read in full once, the first time it's asked for (and again after
   * a rolled-back transaction). Uses shared/attention and shared/piles
   * themselves, so it can't drift from what the lists show.
   */
  openAlertCounts(): { needsYou: number; noticed: number; noticedClearable: number } {
    if (!this.attention) {
      this.attention = new Map();
      for (const a of this.listAlerts({ status: 'open', limit: -1 })) this.track(a);
    }
    let needsYou = 0;
    let noticed = 0;
    let noticedClearable = 0;
    const piles = new Set<string>();
    for (const t of this.attention.values()) {
      if (!t.needs) {
        noticed++;
        if (t.clearable) noticedClearable++;
      } else if (t.pile === undefined) needsYou++;
      else piles.add(t.pile);
    }
    return { needsYou: needsYou + piles.size, noticed, noticedClearable };
  }

  private track(a: Alert): void {
    if (!this.attention) return;
    if (needsDecision(a)) {
      this.attention.set(a.id, { needs: true, pile: pileKey(a), clearable: false });
    } else if (isNoticed(a)) {
      this.attention.set(a.id, { needs: false, pile: undefined, clearable: untouched(a) });
    } else this.attention.delete(a.id);
  }

  getAlert(id: string): Alert | undefined {
    return this.one(Alert, 'SELECT body FROM alerts WHERE id = ?', id);
  }

  /** `limit` defaults to the newest 200; -1 means all of them. */
  listAlerts(opts: { status?: Alert['status']; limit?: number } = {}): Alert[] {
    const limit = opts.limit ?? 200;
    return opts.status
      ? this.all(
          Alert,
          'SELECT body FROM alerts WHERE status = ? ORDER BY created_at DESC LIMIT ?',
          opts.status,
          limit,
        )
      : this.all(Alert, 'SELECT body FROM alerts ORDER BY created_at DESC LIMIT ?', limit);
  }

  // ---------------------------------------------------------------- actions

  saveAction(record: ActionRecord): ActionRecord {
    const r = ActionRecord.parse(record);
    this.stmt(
      `INSERT INTO actions (id, requested_at, status, alert_id, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET status = excluded.status, body = excluded.body`,
    ).run(r.id, r.requestedAt, r.status, r.alertId ?? null, JSON.stringify(r));
    return r;
  }

  getAction(id: string): ActionRecord | undefined {
    return this.one(ActionRecord, 'SELECT body FROM actions WHERE id = ?', id);
  }

  listActions(opts: { alertId?: string; limit?: number } = {}): ActionRecord[] {
    const limit = opts.limit ?? 200;
    return opts.alertId
      ? this.all(
          ActionRecord,
          'SELECT body FROM actions WHERE alert_id = ? ORDER BY requested_at',
          opts.alertId,
        )
      : this.all(
          ActionRecord,
          'SELECT body FROM actions ORDER BY requested_at DESC LIMIT ?',
          limit,
        );
  }

  /** Containment a rule carried out since `since`, counting ones the user later released. */
  countRuleBlocksSince(since: number): number {
    const row = this.stmt(
      `SELECT COUNT(*) AS n FROM actions
         WHERE requested_at >= ? AND status IN ('done', 'undone')
           AND json_extract(body, '$.actor') = 'rule'
           AND json_extract(body, '$.undoes') IS NULL`,
    ).get(since) as { n: number };
    return row.n;
  }

  // ---------------------------------------------------------------- proposals

  saveProposal(proposal: ActionProposal): ActionProposal {
    const p = ActionProposal.parse(proposal);
    this.stmt(
      `INSERT INTO proposals (id, created_at, status, alert_id, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET status = excluded.status, body = excluded.body`,
    ).run(p.id, p.createdAt, p.status, p.alertId ?? null, JSON.stringify(p));
    return p;
  }

  listProposals(
    opts: { alertId?: string; status?: ActionProposal['status'] } = {},
  ): ActionProposal[] {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    if (opts.alertId) {
      where.push('alert_id = ?');
      args.push(opts.alertId);
    }
    if (opts.status) {
      where.push('status = ?');
      args.push(opts.status);
    }
    const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
    return this.all(
      ActionProposal,
      `SELECT body FROM proposals ${clause} ORDER BY created_at DESC`,
      ...args,
    );
  }

  // ---------------------------------------------------------------- AI usage

  addAiRun(run: UsageRun): void {
    const r = UsageRunRow.parse(run);
    // Each attempt has its own id, so a row is never overwritten.
    this.stmt('INSERT OR IGNORE INTO ai_runs (id, ts, provider, body) VALUES (?, ?, ?, ?)').run(
      r.id,
      r.at,
      r.provider,
      JSON.stringify(r),
    );
  }

  listAiRuns(since: number, until = Number.MAX_SAFE_INTEGER): UsageRun[] {
    return this.all(
      UsageRunRow,
      'SELECT body FROM ai_runs WHERE ts >= ? AND ts < ? ORDER BY ts',
      since,
      until,
    );
  }

  pruneAiRuns(before: number): number {
    return Number(this.stmt('DELETE FROM ai_runs WHERE ts < ?').run(before).changes);
  }

  // ---------------------------------------------------------------- agents

  /** New agent sessions. A session already stored (reported again after a restart) is kept. */
  insertAgentSessions(rows: readonly AgentSessionRow[]): void {
    if (rows.length === 0) return;
    this.tx(() => {
      for (const r of rows) {
        const body: z.infer<typeof AgentSessionBody> = {
          rootPath: r.rootPath,
          rootName: basename(r.rootPath),
          seeded: r.seeded,
        };
        if (r.parentSession) body.parentSession = r.parentSession;
        this.stmt(
          `INSERT OR IGNORE INTO agent_sessions (id, agent_id, root_pid, started_at, body)
           VALUES (?, ?, ?, ?, ?)`,
        ).run(r.id, r.agentId, r.rootPid, r.startedAt, JSON.stringify(body));
      }
    });
  }

  /** One agent's sessions, newest first, a page of `limit` before `before`. */
  listAgentSessions(agentId: string, before?: number, limit = 100): AgentSessionView[] {
    return this.sessionViews(
      'agent_id = ? AND started_at < ? ORDER BY started_at DESC, id DESC LIMIT ?',
      agentId,
      before ?? Number.MAX_SAFE_INTEGER,
      limit,
    );
  }

  getAgentSession(id: string): AgentSessionView | undefined {
    return this.sessionViews('id = ?', id)[0];
  }

  /** Whether any session of this agent is stored. */
  hasAgentSessions(agentId: string): boolean {
    return (
      this.stmt('SELECT 1 FROM agent_sessions WHERE agent_id = ? LIMIT 1').get(agentId) !==
      undefined
    );
  }

  /**
   * Sessions with their counts. A session's counts walk its own events
   * through the agent_session index, then are kept until one of its events
   * is written or events are pruned: a page reloaded while an agent works
   * counts again only the sessions that changed.
   */
  private sessionViews(where: string, ...args: SQLInputValue[]): AgentSessionView[] {
    const rows = this.stmt(
      `SELECT id, agent_id, root_pid, started_at, body FROM agent_sessions WHERE ${where}`,
    ).all(...args) as {
      id: string;
      agent_id: string;
      root_pid: number;
      started_at: number;
      body: string;
    }[];
    const missing = rows.map((r) => r.id).filter((id) => !this.sessionCounts.has(id));
    if (missing.length > 0) {
      const counted = this.stmt(
        `SELECT e.agent_session AS sid, COUNT(*) AS events, SUM(e.matched) AS matches,
           MAX(e.ts) AS lastAt,
           SUM(CASE WHEN e.kind = 'agent.tool_request' AND ${ASKED('e')} THEN 1 ELSE 0 END) AS asks,
           SUM(CASE WHEN e.kind = 'agent.tool_request' AND ${DENIED('e')} THEN 1 ELSE 0 END) AS denies
         FROM events e WHERE e.agent_session IN (SELECT value FROM json_each(?))
         GROUP BY e.agent_session`,
      ).all(JSON.stringify(missing)) as {
        sid: string;
        events: number;
        matches: number | null;
        lastAt: number | null;
        asks: number | null;
        denies: number | null;
      }[];
      const found = new Map(counted.map((c) => [c.sid, c]));
      for (const id of missing) {
        const c = found.get(id);
        this.sessionCounts.set(id, {
          events: Number(c?.events ?? 0),
          matches: Number(c?.matches ?? 0),
          lastAt: Number(c?.lastAt ?? 0),
          asks: Number(c?.asks ?? 0),
          denies: Number(c?.denies ?? 0),
        });
        if (this.sessionCounts.size > MAX_SESSION_COUNTS) {
          this.sessionCounts.delete(this.sessionCounts.keys().next().value!);
        }
      }
    }
    return rows.map((r) => {
      const body = AgentSessionBody.parse(JSON.parse(r.body));
      const c = this.sessionCounts.get(r.id)!;
      const view: AgentSessionView = {
        id: r.id,
        agentId: r.agent_id,
        rootPid: Number(r.root_pid),
        rootPath: body.rootPath,
        startedAt: Number(r.started_at),
        lastAt: Math.max(Number(r.started_at), c.lastAt),
        events: c.events,
        matches: c.matches,
        asks: c.asks,
        denies: c.denies,
        seeded: body.seeded,
      };
      if (body.parentSession) view.parentSession = body.parentSession;
      return view;
    });
  }

  /**
   * A session's events with their outcomes: newest first by default, like the
   * feed, or oldest first (how its process tree is built).
   */
  sessionEvents(
    id: string,
    limit = 500,
    opts: { kind?: EventKind; oldestFirst?: boolean } = {},
  ): EventView[] {
    const order = opts.oldestFirst ? 'ASC' : 'DESC';
    const rows = (
      opts.kind
        ? this.stmt(
            `SELECT body, outcome, label FROM events WHERE agent_session = ? AND kind = ?
             ORDER BY ts ${order}, id ${order} LIMIT ?`,
          ).all(id, opts.kind, limit)
        : this.stmt(
            `SELECT body, outcome, label FROM events WHERE agent_session = ?
             ORDER BY ts ${order}, id ${order} LIMIT ?`,
          ).all(id, limit)
    ) as EventRow[];
    return rows.map(eventView);
  }

  /** The pids behind a session's events that matched a rule. */
  sessionMatchedPids(id: string): Set<number> {
    const rows = this.stmt(
      `SELECT DISTINCT json_extract(body, '$.process.pid') AS pid FROM events
       WHERE agent_session = ? AND matched = 1`,
    ).all(id) as { pid: number | null }[];
    return new Set(rows.flatMap((r) => (r.pid === null ? [] : [Number(r.pid)])));
  }

  /**
   * Per agent since `since`: sessions active, matched events, and tool
   * requests asked and denied. lastSeenAt looks at all stored sessions.
   */
  agentStats(since: number): Map<string, AgentStats> {
    const out = new Map<string, AgentStats>();
    const get = (id: string) => {
      let s = out.get(id);
      if (!s) out.set(id, (s = { sessions: 0, matches: 0, asks: 0, denies: 0 }));
      return s;
    };
    const sessions = this.stmt(
      `SELECT agent_id, SUM(CASE WHEN last_at >= ? THEN 1 ELSE 0 END) AS sessions,
         MAX(last_at) AS lastSeenAt
       FROM (SELECT s.agent_id, MAX(s.started_at, COALESCE(
               (SELECT MAX(e.ts) FROM events e WHERE e.agent_session = s.id), 0)) AS last_at
             FROM agent_sessions s)
       GROUP BY agent_id`,
    ).all(since) as { agent_id: string; sessions: number; lastSeenAt: number }[];
    for (const r of sessions) {
      const s = get(r.agent_id);
      s.sessions = Number(r.sessions);
      s.lastSeenAt = Number(r.lastSeenAt);
    }
    const matches = this.stmt(
      `SELECT s.agent_id, COUNT(*) AS n FROM events e JOIN agent_sessions s ON s.id = e.agent_session
       WHERE e.matched = 1 AND e.ts >= ? GROUP BY s.agent_id`,
    ).all(since) as { agent_id: string; n: number }[];
    for (const r of matches) get(r.agent_id).matches = Number(r.n);
    const answers = this.stmt(
      `SELECT json_extract(e.body, '$.agent.id') AS agent_id,
         SUM(CASE WHEN ${ASKED('e')} THEN 1 ELSE 0 END) AS asks,
         SUM(CASE WHEN ${DENIED('e')} THEN 1 ELSE 0 END) AS denies
       FROM events e WHERE e.kind = 'agent.tool_request' AND e.ts >= ?
         AND json_extract(e.body, '$.agent.id') IS NOT NULL
       GROUP BY agent_id`,
    ).all(since) as { agent_id: string; asks: number; denies: number }[];
    for (const r of answers) {
      const s = get(r.agent_id);
      s.asks = Number(r.asks);
      s.denies = Number(r.denies);
    }
    return out;
  }

  /** Stored tool requests since `since`, by the answer Vigil gave. */
  toolRequestCounts(since: number): { deny: number; ask: number; none: number } {
    const r = this.stmt(
      `SELECT COUNT(*) AS n,
         SUM(CASE WHEN ${ASKED('e')} THEN 1 ELSE 0 END) AS asks,
         SUM(CASE WHEN ${DENIED('e')} THEN 1 ELSE 0 END) AS denies
       FROM events e WHERE e.kind = 'agent.tool_request' AND e.ts >= ?`,
    ).get(since) as { n: number; asks: number | null; denies: number | null };
    const deny = Number(r.denies ?? 0);
    const ask = Number(r.asks ?? 0);
    return { deny, ask, none: Number(r.n) - deny - ask };
  }

  /**
   * Programs started since `since`, most recently seen first, for adding an
   * agent by hand. Apple's own programs are left out: none of them is an agent.
   */
  recentExecPrograms(since: number, limit = 50): AgentCandidate[] {
    // With MAX(), SQLite takes the bare columns from the newest row.
    const rows = this.stmt(
      `SELECT json_extract(body, '$.process.path') AS path, MAX(ts) AS lastSeen, COUNT(*) AS n,
         json_extract(body, '$.process.teamId') AS teamId,
         json_extract(body, '$.process.signingId') AS signingId
       FROM events WHERE kind = 'process.exec' AND ts >= ?
         AND COALESCE(json_extract(body, '$.process.signing'), '') <> 'apple'
       GROUP BY path HAVING path IS NOT NULL ORDER BY lastSeen DESC LIMIT ?`,
    ).all(since, limit) as {
      path: string;
      lastSeen: number;
      n: number;
      teamId: string | null;
      signingId: string | null;
    }[];
    return rows.map((r) => ({
      path: r.path,
      name: basename(r.path),
      ...(r.teamId ? { teamId: r.teamId } : {}),
      ...(r.signingId ? { signingId: r.signingId } : {}),
      lastSeen: Number(r.lastSeen),
      count: Number(r.n),
    }));
  }

  /**
   * Program launches since `since`, newest first, at most `max`. Only the
   * fields agent matching reads, pulled out by SQLite rather than parsed here.
   */
  *iterateExecEvents(since: number, max = 200_000): Iterable<ExecRow> {
    const rows = this.db
      .prepare(
        `SELECT json_extract(body, '$.process.pid') AS pid,
           json_extract(body, '$.process.ppid') AS ppid,
           json_extract(body, '$.process.path') AS path,
           json_extract(body, '$.process.args') AS args,
           json_extract(body, '$.process.teamId') AS teamId,
           json_extract(body, '$.process.signingId') AS signingId
         FROM events WHERE kind = 'process.exec' AND ts >= ? ORDER BY ts DESC LIMIT ?`,
      )
      .iterate(since, max) as Iterable<{
      pid: number | null;
      ppid: number | null;
      path: string | null;
      args: string | null;
      teamId: string | null;
      signingId: string | null;
    }>;
    for (const r of rows) {
      if (r.path === null || r.pid === null) continue;
      const row: ExecRow = { pid: Number(r.pid), path: r.path };
      if (r.ppid !== null) row.ppid = Number(r.ppid);
      if (r.args !== null) {
        const args = JSON.parse(r.args) as unknown;
        if (Array.isArray(args)) row.args = args.map(String);
      }
      if (r.teamId !== null) row.teamId = r.teamId;
      if (r.signingId !== null) row.signingId = r.signingId;
      yield row;
    }
  }

  /** Delete sessions that started before `before` and have no events left. Returns rows removed. */
  pruneAgentSessions(before: number): number {
    return Number(
      this.stmt(
        `DELETE FROM agent_sessions WHERE started_at < ? AND NOT EXISTS (
           SELECT 1 FROM events e WHERE e.agent_session = agent_sessions.id)`,
      ).run(before).changes,
    );
  }

  /** Vigil's own AI runs by purpose: runs since `since`, and the last run ever. */
  aiRunStats(since: number): Map<string, { runs: number; lastAt: number }> {
    const rows = this.stmt(
      `SELECT json_extract(body, '$.purpose') AS purpose,
         SUM(CASE WHEN ts >= ? THEN 1 ELSE 0 END) AS runs, MAX(ts) AS lastAt
       FROM ai_runs GROUP BY purpose`,
    ).all(since) as { purpose: string | null; runs: number; lastAt: number }[];
    return new Map(
      rows.flatMap((r) =>
        r.purpose === null
          ? []
          : [[r.purpose, { runs: Number(r.runs), lastAt: Number(r.lastAt) }] as const],
      ),
    );
  }

  // ---------------------------------------------------------------- settings

  getSetting<S extends z.ZodType>(key: string, schema: S, fallback: z.infer<S>): z.infer<S> {
    const row = this.stmt('SELECT value FROM settings WHERE key = ?').get(key) as
      { value: string } | undefined;
    if (!row) return fallback;
    const parsed = schema.safeParse(JSON.parse(row.value));
    return parsed.success ? parsed.data : fallback;
  }

  setSetting(key: string, value: unknown): void {
    this.stmt(
      'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value',
    ).run(key, JSON.stringify(value));
  }

  close(): void {
    this.db.close();
  }
}
