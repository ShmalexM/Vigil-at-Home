// Looks closely at the network activity of programs worth watching.
//
// osquery's scheduled connection snapshot runs every 30 s, which is cheap but
// misses connections that open and close between runs. When a program worth
// a closer look starts (unsigned, ad hoc or not trusted by Gatekeeper, or
// downloaded from the internet), its pid is watched for a minute: every 2 s a
// one-off osquery query asks for that pid's sockets only. Most programs never
// trigger it, and a watched program that exits stops being queried, so a
// developer's short-lived build outputs cost almost nothing.
//
//   process.exec (suspicious) ─► watch pid for 60 s
//        every 2 s: osqueryd -S "... WHERE pid IN (watched)" ─► network.connection
//   process.exit ─► stop watching
//
// A query budget per hour caps the cost on a Mac that starts many such
// programs; once it is spent, the scheduled snapshot still covers everything.

import { createHash } from 'node:crypto';
import type { EventOfKind, SensorEvent } from '@vigil/core';
import { defined, pidOf } from '../types.js';

/** Runs one osquery SQL statement and returns its rows, or undefined if osquery could not run. */
export type OsqueryRunner = (sql: string) => Promise<Record<string, string>[] | undefined>;

export interface NetworkBurstOptions {
  run: OsqueryRunner;
  emit: (event: SensorEvent) => void;
  /** How long a program stays watched after it starts. */
  watchMs?: number;
  /** Time between queries while anything is watched. */
  intervalMs?: number;
  /** Most programs watched at once; later ones wait for the scheduled snapshot. */
  maxWatched?: number;
  /** Most queries in any rolling hour. */
  queriesPerHour?: number;
  now?: () => number;
}

const HOUR = 3600_000;
/** How long a connection seen here keeps the scheduled snapshot from reporting it again. */
const SEEN_MS = 15 * 60_000;
const MAX_SEEN = 5000;

/** Whether a launch deserves a closer look at its network activity. */
export function worthWatching(event: SensorEvent): boolean {
  if (event.kind !== 'process.exec') return false;
  const p = event.process;
  if (p.quarantine) return true;
  return (
    p.signing === 'unsigned' ||
    p.signing === 'adhoc' ||
    p.signing === 'invalid' ||
    p.signing === 'unknown'
  );
}

/** The same connection, however it was reported. */
export function connectionKey(e: EventOfKind<'network.connection'>): string {
  return [e.process?.pid ?? 0, e.remoteAddress, e.remotePort ?? '', e.protocol].join('|');
}

function protocolName(v: string | undefined): 'tcp' | 'udp' | 'other' {
  return v === '6' ? 'tcp' : v === '17' ? 'udp' : 'other';
}

function port(v: string | undefined): number | undefined {
  const n = pidOf(v);
  return n !== undefined && n <= 65535 ? n : undefined;
}

/** The scheduled snapshot's query, narrowed to a few pids. */
export function burstQuery(pids: number[]): string {
  return (
    'SELECT DISTINCT p.pid, p.path, p.uid, s.remote_address, s.remote_port, s.local_address, ' +
    's.local_port, s.protocol FROM process_open_sockets s JOIN processes p USING (pid) ' +
    `WHERE p.pid IN (${pids.map((n) => Math.trunc(n)).join(', ')}) AND s.family IN (2, 10, 30) ` +
    "AND s.remote_port != 0 AND s.remote_address NOT IN ('127.0.0.1', '::1', '0.0.0.0', '::', '') " +
    "AND s.remote_address NOT LIKE 'fe80:%';"
  );
}

export class NetworkBurst {
  private readonly watched = new Map<number, number>(); // pid -> watch ends at
  private readonly seen = new Map<string, number>(); // connection key -> seen at
  private readonly spent: number[] = []; // query times in the last hour
  private timer: ReturnType<typeof setTimeout> | undefined;
  private running = false;
  private stopped = false;
  private readonly watchMs: number;
  private readonly intervalMs: number;
  private readonly maxWatched: number;
  private readonly queriesPerHour: number;
  private readonly now: () => number;

  constructor(private readonly opts: NetworkBurstOptions) {
    this.watchMs = opts.watchMs ?? 60_000;
    this.intervalMs = opts.intervalMs ?? 2_000;
    this.maxWatched = opts.maxWatched ?? 32;
    this.queriesPerHour = opts.queriesPerHour ?? 300;
    this.now = opts.now ?? Date.now;
  }

  /** Watch a program's connections for a while. Returns false if it was not taken on. */
  watch(pid: number): boolean {
    if (this.stopped || !Number.isInteger(pid) || pid <= 1) return false;
    if (!this.watched.has(pid) && this.watched.size >= this.maxWatched) return false;
    this.watched.set(pid, this.now() + this.watchMs);
    this.schedule();
    return true;
  }

  /** Stop watching a program, usually because it exited. */
  forget(pid: number): void {
    this.watched.delete(pid);
  }

  /** Feed every sensor event through here: starts and stops watches as programs come and go. */
  observe(event: SensorEvent): void {
    if (event.kind === 'process.exit') this.forget(event.process.pid);
    else if (worthWatching(event) && event.kind === 'process.exec') this.watch(event.process.pid);
  }

  /** True if this connection was already reported here recently, so a later snapshot row is a repeat. */
  alreadyReported(e: EventOfKind<'network.connection'>): boolean {
    const at = this.seen.get(connectionKey(e));
    return at !== undefined && this.now() - at < SEEN_MS;
  }

  isWatching(pid: number): boolean {
    return this.watched.has(pid);
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    this.timer = undefined;
    this.watched.clear();
  }

  private schedule(): void {
    if (this.timer || this.stopped || this.watched.size === 0) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.tick();
    }, this.intervalMs);
    this.timer.unref?.();
  }

  private budgetLeft(now: number): boolean {
    while (this.spent.length > 0 && now - this.spent[0]! >= HOUR) this.spent.shift();
    return this.spent.length < this.queriesPerHour;
  }

  /** One round: query every watched pid at once. Exposed for tests. */
  async tick(): Promise<void> {
    if (this.running || this.stopped) return;
    const now = this.now();
    for (const [pid, until] of this.watched) if (until <= now) this.watched.delete(pid);
    if (this.watched.size === 0) return;
    if (!this.budgetLeft(now)) {
      // Out of budget: let the scheduled snapshot carry on alone.
      this.watched.clear();
      return;
    }
    this.spent.push(now);
    this.running = true;
    try {
      const rows = await this.opts.run(burstQuery([...this.watched.keys()]));
      for (const row of rows ?? []) this.report(row);
    } catch {
      // A failed run is the same as an empty one; the snapshot still runs.
    } finally {
      this.running = false;
      this.schedule();
    }
  }

  private report(c: Record<string, string>): void {
    const event: EventOfKind<'network.connection'> = {
      id: '',
      ts: this.now(),
      source: 'osquery',
      kind: 'network.connection',
      direction: 'outbound',
      protocol: protocolName(c.protocol),
      ...defined({
        remoteAddress: c.remote_address ?? '',
        remotePort: port(c.remote_port),
        localAddress: c.local_address || undefined,
        localPort: port(c.local_port),
      }),
      process: defined({ pid: pidOf(c.pid) ?? 0, path: c.path ?? '', uid: pidOf(c.uid) }),
    };
    const key = connectionKey(event);
    if (this.seen.has(key)) return;
    this.seen.set(key, event.ts);
    if (this.seen.size > MAX_SEEN) {
      const oldest = this.seen.keys().next().value;
      if (oldest !== undefined) this.seen.delete(oldest);
    }
    event.id = 'osquery-burst:' + createHash('sha256').update(key).digest('hex').slice(0, 32);
    this.opts.emit(event);
  }
}

/** Parses `osqueryd -S --json` output into rows; undefined if it isn't a JSON array. */
export function parseOsqueryJson(stdout: string): Record<string, string>[] | undefined {
  try {
    const parsed: unknown = JSON.parse(stdout);
    if (!Array.isArray(parsed)) return undefined;
    return parsed.filter((r): r is Record<string, string> => typeof r === 'object' && r !== null);
  } catch {
    return undefined;
  }
}
