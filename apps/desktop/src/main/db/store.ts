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
import type { z } from 'zod';
import {
  EVENT_GROUPS,
  EventOutcome,
  type EventGroup,
  type EventQuery,
  type EventStats,
  type EventView,
} from '../../shared/ipc.js';
import { migrations } from './schema.js';

type Row = { body: string };

/**
 * Typed access to Vigil's SQLite database. Pure Node (node:sqlite), no Electron,
 * so it runs in tests and in any worker. Every read is validated with zod.
 */
export class Store {
  private readonly statements = new Map<string, StatementSync>();

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

  tx<T>(fn: () => T): T {
    this.db.exec('BEGIN');
    try {
      const out = fn();
      this.db.exec('COMMIT');
      return out;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
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
    this.stmt(
      `INSERT INTO events (id, ts, kind, source, body, outcome) VALUES (?, ?, ?, ?, ?, ?)
       ON CONFLICT (id) DO UPDATE SET outcome = COALESCE(excluded.outcome, outcome)`,
    ).run(
      e.id,
      e.ts,
      e.kind,
      e.source,
      JSON.stringify(e),
      outcome ? JSON.stringify(outcome) : null,
    );
  }

  /** Newest first, for the feed. */
  listEventViews(q: EventQuery = {}): EventView[] {
    const where: string[] = [];
    const args: SQLInputValue[] = [];
    if (q.group) {
      const kinds = EVENT_GROUPS[q.group];
      where.push(`kind IN (${kinds.map(() => '?').join(',')})`);
      args.push(...kinds);
    }
    if (q.matchedOnly) where.push(`json_array_length(outcome, '$.matches') > 0`);
    if (q.before !== undefined) {
      where.push('ts < ?');
      args.push(q.before);
    }
    if (q.text) {
      where.push(`body LIKE ? ESCAPE '\\'`);
      args.push(`%${q.text.replace(/[\\%_]/g, (c) => `\\${c}`)}%`);
    }
    const sql = `SELECT body, outcome FROM events ${where.length ? `WHERE ${where.join(' AND ')}` : ''}
      ORDER BY ts DESC, id DESC LIMIT ?`;
    args.push(q.limit ?? 200);
    const rows = this.db.prepare(sql).all(...args) as { body: string; outcome: string | null }[];
    return rows.map((r) => ({
      event: SensorEvent.parse(JSON.parse(r.body)),
      outcome: r.outcome ? EventOutcome.parse(JSON.parse(r.outcome)) : null,
    }));
  }

  eventStats(since: number): Omit<EventStats, 'retentionDays'> {
    const byKind = this.db
      .prepare(
        `SELECT kind, COUNT(*) AS n,
           SUM(CASE WHEN json_array_length(outcome, '$.matches') > 0 THEN 1 ELSE 0 END) AS matched
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
    return a;
  }

  getAlert(id: string): Alert | undefined {
    return this.one(Alert, 'SELECT body FROM alerts WHERE id = ?', id);
  }

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
