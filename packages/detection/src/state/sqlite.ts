import type { Proposal, ProposalStore } from '../proposals/pipeline.js';
import type { DetectionEvent, DetectionRule } from '../types.js';
import {
  MemoryBaselineStore,
  MemoryExceptionStore,
  MemoryListStore,
  MemoryRuleStateStore,
  type EventHistory,
  type ListEntryMeta,
  type RuleException,
  type RuleState,
  type Stores,
  type VerdictRecord,
} from './stores.js';

/**
 * The slice of a SQLite handle this package uses. better-sqlite3's Database
 * and node:sqlite's DatabaseSync both satisfy it, so the app passes the handle
 * it already owns.
 */
export interface SqlStatement {
  run(...params: unknown[]): unknown;
  get(...params: unknown[]): unknown;
  all(...params: unknown[]): unknown[];
}
export interface SqlDatabase {
  exec(sql: string): unknown;
  prepare(sql: string): SqlStatement;
}

/** Schema for this package. Every table is prefixed det_. Run in order; each is idempotent. */
export const DETECTION_MIGRATIONS: string[] = [
  `CREATE TABLE IF NOT EXISTS det_baseline (
     scope TEXT NOT NULL, key TEXT NOT NULL, first_seen INTEGER NOT NULL,
     PRIMARY KEY (scope, key)) WITHOUT ROWID`,
  `CREATE TABLE IF NOT EXISTS det_list_entries (
     list TEXT NOT NULL, entry TEXT NOT NULL, source TEXT NOT NULL, updated_at INTEGER NOT NULL,
     PRIMARY KEY (list, entry)) WITHOUT ROWID`,
  `CREATE TABLE IF NOT EXISTS det_exceptions (
     id TEXT PRIMARY KEY, rule_id TEXT NOT NULL, match TEXT NOT NULL,
     created_at INTEGER NOT NULL, note TEXT)`,
  `CREATE TABLE IF NOT EXISTS det_rule_state (
     rule_id TEXT PRIMARY KEY, mode TEXT, fired INTEGER NOT NULL DEFAULT 0, last_fired_at INTEGER)`,
  `CREATE TABLE IF NOT EXISTS det_verdicts (
     detection_id TEXT NOT NULL, rule_id TEXT NOT NULL, verdict TEXT NOT NULL, ts INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS det_verdicts_rule_ts ON det_verdicts (rule_id, ts)`,
  `CREATE TABLE IF NOT EXISTS det_events (
     id TEXT PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL, body TEXT NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS det_events_ts ON det_events (ts)`,
  `CREATE TABLE IF NOT EXISTS det_proposals (
     id TEXT PRIMARY KEY, created_at INTEGER NOT NULL, status TEXT NOT NULL, body TEXT NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS det_rules (
     id TEXT PRIMARY KEY, version INTEGER NOT NULL, body TEXT NOT NULL, updated_at INTEGER NOT NULL)`,
];

export function migrate(db: SqlDatabase): void {
  for (const m of DETECTION_MIGRATIONS) db.exec(m);
}

class SqliteBaselineStore extends MemoryBaselineStore {
  private readonly ins: SqlStatement;
  constructor(db: SqlDatabase) {
    super();
    for (const r of db.prepare('SELECT scope, key FROM det_baseline').all() as Array<{
      scope: string;
      key: string;
    }>) {
      super.add(r.scope, r.key);
    }
    this.ins = db.prepare(
      'INSERT OR IGNORE INTO det_baseline (scope, key, first_seen) VALUES (?, ?, ?)',
    );
  }
  override add(scope: string, key: string, ts: number): void {
    super.add(scope, key);
    this.ins.run(scope, key, ts);
  }
}

class SqliteListStore extends MemoryListStore {
  constructor(private readonly db: SqlDatabase) {
    super();
    const rows = db.prepare('SELECT list, entry FROM det_list_entries').all() as Array<{
      list: string;
      entry: string;
    }>;
    for (const r of rows) super.add(r.list, r.entry);
  }
  override replace(list: string, entries: Iterable<string>, meta: ListEntryMeta): void {
    const arr = [...entries];
    this.db.exec('BEGIN');
    try {
      this.db.prepare('DELETE FROM det_list_entries WHERE list = ?').run(list);
      const ins = this.db.prepare(
        'INSERT OR REPLACE INTO det_list_entries (list, entry, source, updated_at) VALUES (?, ?, ?, ?)',
      );
      for (const e of arr) ins.run(list, e.trim().toLowerCase(), meta.source, meta.updatedAt);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    super.replace(list, arr);
  }
  override add(list: string, entry: string, meta: ListEntryMeta): void {
    this.db
      .prepare(
        'INSERT OR REPLACE INTO det_list_entries (list, entry, source, updated_at) VALUES (?, ?, ?, ?)',
      )
      .run(list, entry.trim().toLowerCase(), meta.source, meta.updatedAt);
    super.add(list, entry);
  }
}

class SqliteExceptionStore extends MemoryExceptionStore {
  constructor(private readonly db: SqlDatabase) {
    super();
    const rows = db
      .prepare('SELECT id, rule_id, match, created_at, note FROM det_exceptions')
      .all() as Array<{
      id: string;
      rule_id: string;
      match: string;
      created_at: number;
      note: string | null;
    }>;
    for (const r of rows) {
      const ex: RuleException = {
        id: r.id,
        ruleId: r.rule_id,
        match: JSON.parse(r.match) as Record<string, string>,
        createdAt: Number(r.created_at),
      };
      if (r.note !== null) ex.note = r.note;
      super.add(ex);
    }
  }
  override add(ex: RuleException): void {
    this.db
      .prepare(
        'INSERT OR REPLACE INTO det_exceptions (id, rule_id, match, created_at, note) VALUES (?, ?, ?, ?, ?)',
      )
      .run(ex.id, ex.ruleId, JSON.stringify(ex.match), ex.createdAt, ex.note ?? null);
    super.add(ex);
  }
  override remove(id: string): void {
    this.db.prepare('DELETE FROM det_exceptions WHERE id = ?').run(id);
    super.remove(id);
  }
}

class SqliteRuleStateStore extends MemoryRuleStateStore {
  private readonly upsert: SqlStatement;
  private readonly insVerdict: SqlStatement;
  private readonly selVerdicts: SqlStatement;
  constructor(db: SqlDatabase) {
    super();
    const rows = db
      .prepare('SELECT rule_id, mode, fired, last_fired_at FROM det_rule_state')
      .all() as Array<{
      rule_id: string;
      mode: string | null;
      fired: number;
      last_fired_at: number | null;
    }>;
    for (const r of rows) {
      const st: RuleState = { ruleId: r.rule_id, fired: Number(r.fired) };
      if (r.mode !== null) st.mode = r.mode as NonNullable<RuleState['mode']>;
      if (r.last_fired_at !== null) st.lastFiredAt = Number(r.last_fired_at);
      super.put(st);
    }
    this.upsert = db.prepare(
      'INSERT OR REPLACE INTO det_rule_state (rule_id, mode, fired, last_fired_at) VALUES (?, ?, ?, ?)',
    );
    this.insVerdict = db.prepare(
      'INSERT INTO det_verdicts (detection_id, rule_id, verdict, ts) VALUES (?, ?, ?, ?)',
    );
    this.selVerdicts = db.prepare(
      'SELECT detection_id, rule_id, verdict, ts FROM det_verdicts WHERE rule_id = ? AND ts >= ? ORDER BY ts',
    );
  }
  override put(s: RuleState): void {
    this.upsert.run(s.ruleId, s.mode ?? null, s.fired, s.lastFiredAt ?? null);
    super.put(s);
  }
  override recordVerdict(v: VerdictRecord): void {
    this.insVerdict.run(v.detectionId, v.ruleId, v.verdict, v.ts);
  }
  override verdicts(ruleId: string, sinceTs: number): VerdictRecord[] {
    return (
      this.selVerdicts.all(ruleId, sinceTs) as Array<{
        detection_id: string;
        rule_id: string;
        verdict: string;
        ts: number;
      }>
    ).map((r) => ({
      detectionId: r.detection_id,
      ruleId: r.rule_id,
      verdict: r.verdict as VerdictRecord['verdict'],
      ts: Number(r.ts),
    }));
  }
}

class SqliteEventHistory implements EventHistory {
  private readonly ins: SqlStatement;
  private readonly sel: SqlStatement;
  private readonly del: SqlStatement;
  constructor(db: SqlDatabase) {
    this.ins = db.prepare(
      'INSERT OR IGNORE INTO det_events (id, ts, kind, body) VALUES (?, ?, ?, ?)',
    );
    this.sel = db.prepare('SELECT body FROM det_events WHERE ts >= ? AND ts <= ? ORDER BY ts');
    this.del = db.prepare('DELETE FROM det_events WHERE ts < ?');
  }
  append(e: DetectionEvent): void {
    this.ins.run(e.id, e.ts, e.kind, JSON.stringify(e));
  }
  *range(fromTs: number, toTs: number): Iterable<DetectionEvent> {
    for (const r of this.sel.all(fromTs, toTs) as Array<{ body: string }>)
      yield JSON.parse(r.body) as DetectionEvent;
  }
  prune(beforeTs: number): number {
    const res = this.del.run(beforeTs) as { changes?: number | bigint };
    return Number(res?.changes ?? 0);
  }
}

class SqliteProposalStore implements ProposalStore {
  constructor(private readonly db: SqlDatabase) {}
  put(p: Proposal): void {
    this.db
      .prepare(
        'INSERT OR REPLACE INTO det_proposals (id, created_at, status, body) VALUES (?, ?, ?, ?)',
      )
      .run(p.id, p.createdAt, p.status, JSON.stringify(p));
  }
  get(id: string): Proposal | undefined {
    const r = this.db.prepare('SELECT body FROM det_proposals WHERE id = ?').get(id) as
      { body: string } | undefined;
    return r ? (JSON.parse(r.body) as Proposal) : undefined;
  }
  list(): Proposal[] {
    return (
      this.db.prepare('SELECT body FROM det_proposals ORDER BY created_at DESC').all() as Array<{
        body: string;
      }>
    ).map((r) => JSON.parse(r.body) as Proposal);
  }
}

/** User-approved and tuned rules, which override the built-in pack by id. */
export interface RuleRepository {
  save(rule: DetectionRule, ts: number): void;
  remove(id: string): void;
  list(): DetectionRule[];
}

class SqliteRuleRepository implements RuleRepository {
  constructor(private readonly db: SqlDatabase) {}
  save(rule: DetectionRule, ts: number): void {
    this.db
      .prepare(
        'INSERT OR REPLACE INTO det_rules (id, version, body, updated_at) VALUES (?, ?, ?, ?)',
      )
      .run(rule.id, rule.version, JSON.stringify(rule), ts);
  }
  remove(id: string): void {
    this.db.prepare('DELETE FROM det_rules WHERE id = ?').run(id);
  }
  list(): DetectionRule[] {
    return (this.db.prepare('SELECT body FROM det_rules').all() as Array<{ body: string }>).map(
      (r) => JSON.parse(r.body) as DetectionRule,
    );
  }
}

export interface SqliteDetectionStores extends Stores {
  proposals: ProposalStore;
  rules: RuleRepository;
}

/** Run migrations and load state from disk. Reads stay in memory; writes go through to SQLite. */
export function sqliteStores(db: SqlDatabase): SqliteDetectionStores {
  migrate(db);
  return {
    baseline: new SqliteBaselineStore(db),
    lists: new SqliteListStore(db),
    exceptions: new SqliteExceptionStore(db),
    ruleState: new SqliteRuleStateStore(db),
    history: new SqliteEventHistory(db),
    proposals: new SqliteProposalStore(db),
    rules: new SqliteRuleRepository(db),
  };
}
