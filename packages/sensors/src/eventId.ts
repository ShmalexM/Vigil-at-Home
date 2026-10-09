import { createHash } from 'node:crypto';

/**
 * A log line's event id: the same line always gives the same id, so a line
 * read twice (after a restart) is stored once.
 *
 * When the line carries its own time, the id starts with it (12 hex digits of
 * milliseconds) followed by 80 bits of the line's hash. Ids are the events
 * table's primary key, and a key that grows with time is added at the end of
 * its index. A pure hash lands each event on a random page of an index that
 * no longer fits in memory once the table holds a few hours of events, so
 * every event rewrote its own 4 KB page: about five times the disk writes
 * (see docs/performance.md).
 *
 * Lines without a time keep the hash-only id, since "now" differs on a reread.
 */
export function lineEventId(prefix: string, line: string, ts?: number): string {
  const hash = createHash('sha256').update(line).digest('hex');
  if (ts === undefined || !Number.isSafeInteger(ts) || ts < 0 || ts >= 16 ** 12)
    return prefix + hash.slice(0, 32);
  return prefix + ts.toString(16).padStart(12, '0') + hash.slice(0, 20);
}
