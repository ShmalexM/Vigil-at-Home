// Disk writes of the event history once it is big: what an event costs when
// the events table already holds hours of them (perf/measure.mjs starts from
// an empty database, where every index still fits in memory).
//   node perf/db-writes.mjs [rows already stored, default 1000000]
// Linux only (reads /proc/self/io). Fills a temporary database with the
// events table and indexes the app uses, then stores 36,000 more events in
// one-second batches of 60 (a busy Mac's rate), once with ids that are a pure
// hash of the log line and once with the time-first ids the sensors use
// (packages/sensors/src/eventId.ts).
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';

const ROWS = Number(process.argv[2] ?? 1_000_000);
const BATCHES = 600;
const PER_BATCH = 60;

const written = () => Number(/write_bytes: (\d+)/.exec(readFileSync('/proc/self/io', 'utf8'))[1]);
const hash = (s) => createHash('sha256').update(s).digest('hex');
const IDS = {
  hash: (_ts, line) => 'santa-log:' + hash(line).slice(0, 32),
  'time-first': (ts, line) =>
    'santa-log:' + ts.toString(16).padStart(12, '0') + hash(line).slice(0, 20),
};

function run(name) {
  const id = IDS[name];
  const dir = mkdtempSync(join(tmpdir(), 'vigil-dbw-'));
  const db = new DatabaseSync(join(dir, 'vigil.db'));
  db.exec(`
    PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL;
    PRAGMA journal_size_limit = ${4 * 1024 * 1024};
    CREATE TABLE events (id TEXT PRIMARY KEY, ts INTEGER NOT NULL, kind TEXT NOT NULL,
      source TEXT NOT NULL, body TEXT NOT NULL, outcome TEXT, matched INTEGER NOT NULL DEFAULT 0,
      label TEXT, agent_session TEXT, agent_id TEXT);
    CREATE INDEX events_ts ON events (ts);
    CREATE INDEX events_kind_ts ON events (kind, ts);
    CREATE INDEX events_matched_ts ON events (ts) WHERE matched = 1;
    CREATE INDEX events_agent_session_ts ON events (agent_session, ts) WHERE agent_session IS NOT NULL;
    CREATE INDEX events_agent_ts ON events (agent_id, ts) WHERE agent_id IS NOT NULL;`);
  const insert = db.prepare(
    'INSERT INTO events (id, ts, kind, source, body, outcome, matched) VALUES (?, ?, ?, ?, ?, ?, 0)',
  );
  const kinds = [
    'process.exec',
    'process.exit',
    'process.exec',
    'process.exit',
    'network.connection',
  ];
  const body = JSON.stringify({ process: { path: '/usr/bin/'.padEnd(250, 'x') } });
  const outcome = '{"checked":24,"matches":[]}';
  let ts = Date.UTC(2026, 9, 1);
  let n = 0;
  const add = () => {
    ts += 16;
    n++;
    insert.run(id(ts, `line ${n}`), ts, kinds[n % kinds.length], 'santa', body, outcome);
  };
  db.exec('BEGIN');
  for (let i = 0; i < ROWS; i++) add();
  db.exec('COMMIT');
  db.exec('PRAGMA wal_checkpoint(TRUNCATE)');

  const before = written();
  const cpu = process.cpuUsage();
  for (let b = 0; b < BATCHES; b++) {
    db.exec('BEGIN');
    for (let i = 0; i < PER_BATCH; i++) add();
    db.exec('COMMIT');
  }
  db.exec('PRAGMA wal_checkpoint(PASSIVE)');
  const used = process.cpuUsage(cpu);
  const events = BATCHES * PER_BATCH;
  db.close();
  rmSync(dir, { recursive: true, force: true });
  return {
    ids: name,
    'KB written per event': ((written() - before) / 1024 / events).toFixed(1),
    'CPU µs per event': ((used.user + used.system) / events).toFixed(1),
  };
}

console.log(`Storing ${BATCHES * PER_BATCH} events on top of ${ROWS} already stored:`);
console.table([run('hash'), run('time-first')]);
