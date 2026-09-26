import type { DatabaseSync, SQLInputValue } from 'node:sqlite';
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
import { migrations } from './schema.js';

type Row = { body: string };

/**
 * Typed access to Vigil's SQLite database. Pure Node (node:sqlite), no Electron,
 * so it runs in tests and in any worker. Every read is validated with zod.
 */
export class Store {
  constructor(private readonly db: DatabaseSync) {
    db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 3000;');
    this.migrate();
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
    return (this.db.prepare(sql).all(...args) as Row[]).map((r) =>
      schema.parse(JSON.parse(r.body)),
    );
  }

  private one<S extends z.ZodType>(
    schema: S,
    sql: string,
    ...args: SQLInputValue[]
  ): z.infer<S> | undefined {
    const row = this.db.prepare(sql).get(...args) as Row | undefined;
    return row ? schema.parse(JSON.parse(row.body)) : undefined;
  }

  // ---------------------------------------------------------------- events

  insertEvent(event: SensorEvent): void {
    const e = SensorEvent.parse(event);
    this.db
      .prepare('INSERT OR IGNORE INTO events (id, ts, kind, source, body) VALUES (?, ?, ?, ?, ?)')
      .run(e.id, e.ts, e.kind, e.source, JSON.stringify(e));
  }

  getEvent(id: string): SensorEvent | undefined {
    return this.one(SensorEvent, 'SELECT body FROM events WHERE id = ?', id);
  }

  getEvents(ids: readonly string[]): SensorEvent[] {
    if (ids.length === 0) return [];
    const marks = ids.map(() => '?').join(',');
    return this.all(
      SensorEvent,
      `SELECT body FROM events WHERE id IN (${marks}) ORDER BY ts`,
      ...ids,
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
    const res = this.db
      .prepare(
        `DELETE FROM events WHERE ts < ? AND id NOT IN (
           SELECT j.value FROM alerts, json_each(alerts.body, '$.eventIds') AS j)`,
      )
      .run(before);
    return Number(res.changes);
  }

  // ---------------------------------------------------------------- rules

  upsertRule(rule: Rule): void {
    const r = Rule.parse(rule);
    this.db
      .prepare(
        `INSERT INTO rules (id, version, mode, origin, updated_at, body) VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET version = excluded.version, mode = excluded.mode,
           origin = excluded.origin, updated_at = excluded.updated_at, body = excluded.body`,
      )
      .run(r.id, r.version, r.mode, r.origin, r.updatedAt, JSON.stringify(r));
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
    this.db
      .prepare(
        'INSERT INTO rule_matches (id, rule_id, mode, ts, alert_id, body) VALUES (?, ?, ?, ?, ?, ?)',
      )
      .run(m.id, m.ruleId, m.mode, m.ts, m.alertId ?? null, JSON.stringify(m));
  }

  /** Match counts per rule since `since`, for the shadow review screen. */
  ruleMatchCounts(since: number): Map<string, number> {
    const rows = this.db
      .prepare('SELECT rule_id, COUNT(*) AS n FROM rule_matches WHERE ts >= ? GROUP BY rule_id')
      .all(since) as { rule_id: string; n: number }[];
    return new Map(rows.map((r) => [r.rule_id, Number(r.n)]));
  }

  // ---------------------------------------------------------------- alerts

  saveAlert(alert: Alert): Alert {
    const a = Alert.parse(alert);
    this.db
      .prepare(
        `INSERT INTO alerts (id, created_at, updated_at, status, severity, rule_id, body)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET updated_at = excluded.updated_at, status = excluded.status,
           severity = excluded.severity, body = excluded.body`,
      )
      .run(a.id, a.createdAt, a.updatedAt, a.status, a.severity, a.ruleId, JSON.stringify(a));
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
    this.db
      .prepare(
        `INSERT INTO actions (id, requested_at, status, alert_id, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET status = excluded.status, body = excluded.body`,
      )
      .run(r.id, r.requestedAt, r.status, r.alertId ?? null, JSON.stringify(r));
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
    this.db
      .prepare(
        `INSERT INTO proposals (id, created_at, status, alert_id, body) VALUES (?, ?, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET status = excluded.status, body = excluded.body`,
      )
      .run(p.id, p.createdAt, p.status, p.alertId ?? null, JSON.stringify(p));
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
    const row = this.db.prepare('SELECT value FROM settings WHERE key = ?').get(key) as
      { value: string } | undefined;
    if (!row) return fallback;
    const parsed = schema.safeParse(JSON.parse(row.value));
    return parsed.success ? parsed.data : fallback;
  }

  setSetting(key: string, value: unknown): void {
    this.db
      .prepare(
        'INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO UPDATE SET value = excluded.value',
      )
      .run(key, JSON.stringify(value));
  }

  close(): void {
    this.db.close();
  }
}
