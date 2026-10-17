// The helper's view of its own health, for helper.status: which build is
// running, how often osquery restarts, and errors it keeps logging. The app
// shows these on the Protection card, so a helper left on an old build or a
// log full of the same line is visible without reading helper.log.

import type { System } from './system.js';

declare const __VIGIL_HELPER_BUILD__: { version: string; commit: string } | undefined;

/** The build this helper is, stamped by build-helper.mjs; null when run from source. */
export function helperBuild(): { version: string; commit: string } | null {
  return typeof __VIGIL_HELPER_BUILD__ === 'object' && __VIGIL_HELPER_BUILD__
    ? __VIGIL_HELPER_BUILD__
    : null;
}

const HOUR = 60 * 60_000;
const DAY = 24 * HOUR;

/**
 * Whether osquery's launchd query may slow to its 5 minute safety net because
 * Santa reports launch items, and whether a restart to change that may skip
 * the backoff. The two directions differ on purpose:
 *
 * - Slowing down needs a Santa event in the last 10 minutes, and once osquery
 *   went back to the fast query it stays there for SLOW_HOLD_MS. With one
 *   threshold both ways, a Mac where Santa logs every few minutes flipped
 *   the config, and so restarted osquery, every few checks.
 * - Speeding up is the safe direction (Santa stopped, maybe killed): it
 *   happens once Santa has been quiet for SANTA_GONE_MS, and its restart never
 *   waits on the backoff, so coverage is back within one more check.
 */
export const SANTA_LIVE_MS = 10 * 60_000;
export const SANTA_GONE_MS = 15 * 60_000;
export const SLOW_HOLD_MS = 2 * HOUR;

export class LaunchItemsMode {
  private live = false;
  private fastSince = -Infinity;
  /** What the running osquery has: true for the slow query, undefined until known. */
  private running: boolean | undefined;

  /** Whether the config should use the slow query now. */
  want(lastEventAt: number | null, now: number): boolean {
    const quiet = lastEventAt === null ? Infinity : now - lastEventAt;
    if (this.live) {
      if (quiet >= SANTA_GONE_MS) {
        this.live = false;
        this.fastSince = now;
      }
    } else if (quiet < SANTA_LIVE_MS && now - this.fastSince >= SLOW_HOLD_MS) {
      this.live = true;
    }
    return this.live;
  }

  /** A restart that brings back the fast query (or might) skips the backoff. */
  urgent(): boolean {
    return !this.live && this.running !== false;
  }

  /** After ensureOsquery: what osquery now runs with. */
  applied(state: string, wantSlow: boolean, stillPending: boolean): void {
    if (state === 'restarted' || state === 'started' || (state === 'unchanged' && !stillPending))
      this.running = wantSlow;
  }
}

/** Restarts in the last hour before the helper waits between them: 0, 5, 10, 20, 40, then 60 minutes. */
export function restartGapMs(restartsLastHour: number): number {
  if (restartsLastHour <= 0) return 0;
  return Math.min(5 * 60_000 * 2 ** (restartsLastHour - 1), HOUR);
}

export interface OsqueryRestartStatus {
  /** Restarts in the last hour and day: the helper's own and osquery exiting by itself. */
  lastHour: number;
  lastDay: number;
  lastAt: number | null;
  /** Of those in the last day, how many were osquery exiting on its own (launchd restarted it). */
  exitsLastDay: number;
  /** How osquery last ended on its own, from launchd ("exit code 1", "signal 9"), or null. */
  lastExit: string | null;
  /** A config change waiting for the backoff before osquery restarts to read it, or null. */
  restartDeferredUntil: number | null;
}

/** launchd's run count and last exit for osquery's job, from `launchctl print`. */
export function parseLaunchdJob(out: string): { runs: number; lastExit: string | null } | null {
  const runs = /^\s*runs = (\d+)\s*$/m.exec(out);
  if (!runs) return null;
  const signal = /^\s*last terminating signal = (.+?)\s*$/m.exec(out);
  const code = /^\s*last exit code = (.+?)\s*$/m.exec(out);
  const lastExit = signal
    ? `signal ${signal[1]}`
    : code && code[1] !== '0' && !code[1]!.startsWith('(never')
      ? `exit code ${code[1]}`
      : null;
  return { runs: Number(runs[1]), lastExit };
}

/**
 * Counts osquery's restarts and spaces out the ones the helper makes. A
 * config change still restarts osquery, since it reads its config only at
 * start, but after a few in an hour the next waits (restartGapMs); the
 * change is already on disk and goes in at the next allowed check.
 */
export class OsqueryRestarts {
  private readonly at: { at: number; exit: boolean }[] = [];
  private lastExit: string | null = null;
  private runs: number | undefined;
  private own = 0;
  /** Whether a written config still needs a restart to take effect. */
  pending = false;

  constructor(private readonly now: () => number = Date.now) {}

  private prune(): void {
    const cutoff = this.now() - DAY;
    while (this.at.length && this.at[0]!.at < cutoff) this.at.shift();
  }

  private count(within: number): number {
    const cutoff = this.now() - within;
    return this.at.filter((r) => r.at >= cutoff).length;
  }

  private nextAllowedAt(): number {
    const last = this.at.at(-1)?.at;
    return last === undefined ? 0 : last + restartGapMs(this.count(HOUR));
  }

  mayRestart(): boolean {
    this.prune();
    return this.now() >= this.nextAllowedAt();
  }

  /** After ensureOsquery: what it did. */
  after(state: string): void {
    if (state === 'restarted') {
      this.at.push({ at: this.now(), exit: false });
      this.own++;
      this.pending = false;
    } else if (state === 'deferred') {
      this.pending = true;
    } else if (state === 'started') {
      // A newly loaded job counts its runs from scratch.
      this.runs = undefined;
      this.own = 0;
      this.pending = false;
    }
  }

  /** launchd's view of the job: runs beyond the helper's own restarts are osquery exiting by itself. */
  observe(job: { runs: number; lastExit: string | null } | null): void {
    if (!job) return;
    if (this.runs !== undefined && job.runs >= this.runs) {
      const exits = job.runs - this.runs - this.own;
      for (let i = 0; i < Math.min(exits, 100); i++) this.at.push({ at: this.now(), exit: true });
      if (exits > 0 && job.lastExit) this.lastExit = job.lastExit;
    }
    this.runs = job.runs;
    this.own = 0;
    this.prune();
  }

  status(): OsqueryRestartStatus {
    this.prune();
    const cutoff = this.now() - DAY;
    return {
      lastHour: this.count(HOUR),
      lastDay: this.at.length,
      lastAt: this.at.at(-1)?.at ?? null,
      exitsLastDay: this.at.filter((r) => r.exit && r.at >= cutoff).length,
      lastExit: this.lastExit,
      restartDeferredUntil: this.pending ? Math.max(this.nextAllowedAt(), this.now()) : null,
    };
  }
}

/** Read osquery's launchd job; null when it isn't loaded or launchctl says nothing usable. */
export async function osqueryJob(
  sys: System,
  target: string,
): Promise<{ runs: number; lastExit: string | null } | null> {
  const r = await sys.run('launchctl', ['print', target]);
  return r.code === 0 ? parseLaunchdJob(r.stdout) : null;
}

/** Log lines that say something went wrong, as opposed to what the helper did. */
const PROBLEM =
  /\b(could not|couldn't|can't|cannot|failed|failing|mismatch|error|refused|retrying|warning)\b/i;

export interface RepeatedError {
  /** The line with its numbers and long ids replaced by #, so repeats group. */
  message: string;
  lastHour: number;
  lastDay: number;
  lastAt: number;
}

/** Lines kept apart; more than this and the rarest are dropped. */
export const MAX_KINDS = 50;
/** Times kept per kind, enough to count a line logged every minute for a day. */
export const MAX_TIMES = 1500;

/**
 * Counts the problems the helper logs, grouped by their text with numbers
 * taken out, over the last day. helper.log has no timestamps and is root's,
 * so this is how the app learns that the same error keeps coming back.
 */
export class ErrorTally {
  private readonly kinds = new Map<string, number[]>();

  constructor(private readonly now: () => number = Date.now) {}

  static key(line: string): string {
    return line
      .replace(/[0-9a-f]{12,}/gi, '#')
      .replace(/\d+(\.\d+)*/g, '#')
      .slice(0, 160);
  }

  /** How many kinds of problem are kept. */
  get kindCount(): number {
    return this.kinds.size;
  }

  /** Give it every log line; only problems are counted. */
  note(line: string): void {
    if (!PROBLEM.test(line)) return;
    const key = ErrorTally.key(line);
    let times = this.kinds.get(key);
    if (!times) {
      if (this.kinds.size >= MAX_KINDS) this.dropRarest(this.now() - DAY);
      times = [];
      this.kinds.set(key, times);
    }
    times.push(this.now());
    if (times.length > MAX_TIMES) times.shift();
  }

  /** Drop kinds with nothing in the last day; failing that, the one seen least. */
  private dropRarest(cutoff: number): void {
    for (const [k, t] of this.kinds) if (t.at(-1)! < cutoff) this.kinds.delete(k);
    if (this.kinds.size < MAX_KINDS) return;
    let rarest: string | undefined;
    let fewest = Infinity;
    for (const [k, t] of this.kinds) {
      const recent = t.filter((at) => at >= cutoff).length;
      if (recent < fewest) {
        fewest = recent;
        rarest = k;
      }
    }
    if (rarest !== undefined) this.kinds.delete(rarest);
  }

  /** Problems logged at least `min` times in the last day, most frequent first. */
  repeated(min = 2): RepeatedError[] {
    const now = this.now();
    const out: RepeatedError[] = [];
    for (const [message, times] of this.kinds) {
      while (times.length && times[0]! < now - DAY) times.shift();
      if (!times.length) {
        this.kinds.delete(message);
        continue;
      }
      if (times.length < min) continue;
      out.push({
        message,
        lastHour: times.filter((t) => t >= now - HOUR).length,
        lastDay: times.length,
        lastAt: times.at(-1)!,
      });
    }
    return out.sort((a, b) => b.lastDay - a.lastDay).slice(0, 5);
  }
}
