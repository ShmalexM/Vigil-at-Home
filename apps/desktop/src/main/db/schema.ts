/**
 * SQLite schema, applied in order and tracked with `PRAGMA user_version`.
 * Append new migrations; never edit a shipped one.
 *
 * Each table keeps the full zod-validated record as JSON in `body`, plus the
 * columns we filter or sort on. The JSON is the source of truth.
 */
export const migrations: string[] = [
  `
  CREATE TABLE events (
    id TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    body TEXT NOT NULL
  );
  CREATE INDEX events_ts ON events (ts);
  CREATE INDEX events_kind_ts ON events (kind, ts);

  CREATE TABLE rules (
    id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    mode TEXT NOT NULL,
    origin TEXT NOT NULL,
    updated_at INTEGER NOT NULL,
    body TEXT NOT NULL
  );

  CREATE TABLE rule_matches (
    id TEXT PRIMARY KEY,
    rule_id TEXT NOT NULL,
    mode TEXT NOT NULL,
    ts INTEGER NOT NULL,
    alert_id TEXT,
    body TEXT NOT NULL
  );
  CREATE INDEX rule_matches_rule_ts ON rule_matches (rule_id, ts);

  CREATE TABLE alerts (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    body TEXT NOT NULL
  );
  CREATE INDEX alerts_status_created ON alerts (status, created_at);

  CREATE TABLE actions (
    id TEXT PRIMARY KEY,
    requested_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    alert_id TEXT,
    body TEXT NOT NULL
  );
  CREATE INDEX actions_alert ON actions (alert_id);

  CREATE TABLE proposals (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    status TEXT NOT NULL,
    alert_id TEXT,
    body TEXT NOT NULL
  );

  CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
  `,
  // What detection made of each event, for the "What Vigil sees" feed.
  `
  ALTER TABLE events ADD COLUMN outcome TEXT;
  `,
  // The detection behind each alert, so the user's verdict can teach the engine.
  `
  CREATE TABLE alert_detections (
    alert_id TEXT PRIMARY KEY,
    body TEXT NOT NULL
  );
  `,
  // "Rule matches only" in the feed, without scanning every event's JSON.
  `
  ALTER TABLE events ADD COLUMN matched INTEGER NOT NULL DEFAULT 0;
  UPDATE events SET matched = 1 WHERE json_array_length(outcome, '$.matches') > 0;
  CREATE INDEX events_matched_ts ON events (ts) WHERE matched = 1;
  `,
  // Vigil's own AI runs from the prompt log, for the Usage page.
  `
  CREATE TABLE ai_runs (
    id TEXT PRIMARY KEY,
    ts INTEGER NOT NULL,
    provider TEXT NOT NULL,
    body TEXT NOT NULL
  );
  CREATE INDEX ai_runs_ts ON ai_runs (ts);
  `,
  // A model's label on an event no rule matched (hint only; never acts).
  `
  ALTER TABLE events ADD COLUMN label TEXT;
  `,
];
