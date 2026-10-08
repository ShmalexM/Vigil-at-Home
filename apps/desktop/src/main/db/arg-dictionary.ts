import type { DatabaseSync, StatementSync } from 'node:sqlite';

const HOUR = 3_600_000;
/** Distinct arguments remembered each way, oldest dropped first; a miss costs one indexed lookup. */
const CACHE_SIZE = 20_000;

/** Shown in place of an argument whose text is gone, which pruning should never allow. */
export const MISSING_ARG = '(argument no longer stored)';

/**
 * Text SQLite stores unchanged: a NUL ends a bound string early, and a lone
 * UTF-16 surrogate becomes U+FFFD. Arguments holding either stay in the body,
 * whose JSON keeps them exactly.
 */
const NOT_STORABLE = /\0|[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Whether `encode` can take these arguments and give them back unchanged. */
export function encodable(args: readonly string[]): boolean {
  return !args.some((a) => NOT_STORABLE.test(a));
}

/**
 * Every distinct command-line argument stored once, as a small number.
 *
 * Program launches repeat their arguments heavily: on a developer's Mac with
 * coding agents, six hours held 31 million arguments but only 165,000
 * distinct ones, and arguments were 88% of what launches took on disk. A
 * launch no rule matched keeps its arguments as a packed list of these
 * numbers (a varint each, usually 2–3 bytes) instead of their text. Nothing
 * is lost: reading an event puts the exact arguments back.
 *
 * Each argument records the newest event time it was used at, at most an
 * hour stale, so pruning can drop the ones no remaining event refers to
 * (see `prune`). Ids are never reused (AUTOINCREMENT).
 */
export class ArgDictionary {
  /** Argument -> id and the last-used time recorded for it. */
  private readonly ids = new Map<string, { id: number; seen: number }>();
  private readonly values = new Map<number, string>();
  private readonly byValue: StatementSync;
  private readonly byId: StatementSync;
  private readonly insert: StatementSync;
  private readonly touch: StatementSync;

  constructor(private readonly db: DatabaseSync) {
    this.byValue = db.prepare('SELECT id, last_ts FROM arg_strings WHERE value = ?');
    this.byId = db.prepare('SELECT value FROM arg_strings WHERE id = ?');
    this.insert = db.prepare('INSERT INTO arg_strings (value, last_ts) VALUES (?, ?)');
    this.touch = db.prepare('UPDATE arg_strings SET last_ts = MAX(last_ts, ?) WHERE id = ?');
  }

  /**
   * The arguments as stored for an event at `ts`; only for `encodable` ones.
   * Call inside the event's transaction.
   */
  encode(args: readonly string[], ts: number): Uint8Array {
    const out: number[] = [];
    for (const a of args) writeVarint(out, this.idOf(a, ts));
    return Uint8Array.from(out);
  }

  /** The exact arguments `encode` was given. */
  decode(blob: Uint8Array): string[] {
    return argIds(blob).map((id) => this.value(id));
  }

  /**
   * Drop arguments last used before `before` minus the hour their last-used
   * time may lag. Every event at or after `before` used its arguments no more
   * than an hour before their recorded time, so none of them loses one.
   * `keep` holds ids older events still use (none, normally: see Store.pruneEvents).
   */
  prune(before: number, keep: ReadonlySet<number> = new Set()): number {
    const n = Number(
      this.db
        .prepare(
          'DELETE FROM arg_strings WHERE last_ts < ? AND id NOT IN (SELECT value FROM json_each(?))',
        )
        .run(before - HOUR, JSON.stringify([...keep])).changes,
    );
    if (n > 0) this.forget();
    return n;
  }

  /** Drop what is remembered in memory, e.g. after a rollback undid inserts and touches. */
  forget(): void {
    this.ids.clear();
    this.values.clear();
  }

  private idOf(value: string, ts: number): number {
    const hit = this.ids.get(value);
    if (hit) {
      if (ts > hit.seen + HOUR) {
        this.touch.run(ts, hit.id);
        hit.seen = ts;
      }
      return hit.id;
    }
    const row = this.byValue.get(value) as { id: number; last_ts: number } | undefined;
    let id: number;
    let seen: number;
    if (row) {
      id = Number(row.id);
      seen = Number(row.last_ts);
      if (ts > seen + HOUR) {
        this.touch.run(ts, id);
        seen = ts;
      }
    } else {
      id = Number(this.insert.run(value, ts).lastInsertRowid);
      seen = ts;
    }
    this.remember(this.ids, value, { id, seen });
    this.remember(this.values, id, value);
    return id;
  }

  /** One argument's text, by id. */
  value(id: number): string {
    const hit = this.values.get(id);
    if (hit !== undefined) return hit;
    const row = this.byId.get(id) as { value: string } | undefined;
    if (!row) return MISSING_ARG;
    this.remember(this.values, id, row.value);
    return row.value;
  }

  private remember<K, V>(map: Map<K, V>, k: K, v: V): void {
    map.set(k, v);
    if (map.size > CACHE_SIZE) map.delete(map.keys().next().value!);
  }
}

function writeVarint(out: number[], n: number): void {
  while (n >= 0x80) {
    out.push((n % 0x80) | 0x80);
    n = Math.floor(n / 0x80);
  }
  out.push(n);
}

/** The ids in a packed list (see ArgDictionary.encode). */
export function argIds(blob: Uint8Array): number[] {
  const out: number[] = [];
  let i = 0;
  while (i < blob.length) {
    let id = 0;
    let shift = 1;
    let b: number;
    do {
      b = blob[i++]!;
      id += (b & 0x7f) * shift;
      shift *= 128;
    } while (b & 0x80 && i < blob.length);
    out.push(id);
  }
  return out;
}
