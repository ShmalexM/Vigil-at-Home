import { runRuleReview, type AnalyzeRunner, type DetectionToolContext } from './tools.js';

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** What the last scheduled review did, for the Rules page and the next run. */
export interface ReviewState {
  lastRunAt?: number;
  lastOkAt?: number;
  lastError?: string;
  lastSummary?: string;
  lastProvider?: string;
  /** Proposals the last run queued for the user, and ones the checks refused. */
  lastQueued?: number;
  lastRefused?: number;
}

export interface ReviewStateStore {
  get(): ReviewState | undefined;
  put(s: ReviewState): void;
}

export class MemoryReviewStateStore implements ReviewStateStore {
  private s: ReviewState | undefined;
  get(): ReviewState | undefined {
    return this.s && { ...this.s };
  }
  put(s: ReviewState): void {
    this.s = { ...s };
  }
}

export interface RuleReviewerOptions {
  /** Time between successful reviews. */
  intervalMs?: number;
  /** Time before trying again after a failure (no provider, quota, timeout). */
  retryMs?: number;
  /** Fewer new events than this since the last review: nothing worth reviewing yet. */
  minNewEvents?: number;
  /** How far back the agent reads. */
  windowHours?: number;
  deadlineMs?: number;
  /** Counts events in a window; the app reads its own events table. */
  countEvents?: (from: number, to: number) => number;
  /** True while the Mac is busy or on battery saver; the review waits. */
  isBusy?: () => boolean;
  now?: () => number;
}

export type ReviewOutcome =
  | { ran: false; reason: 'not_due' | 'no_runner' | 'busy' | 'too_little_activity' | 'running' }
  | { ran: true; ok: boolean; queued: number; refused: number; summary?: string; error?: string };

/**
 * Keeps the rules maintained without anyone asking: about once a day the
 * signed-in AI reads a redacted summary of this Mac's activity and proposes
 * new rules, narrow exclusions for noisy rules, or turning a broken rule
 * down. Everything it proposes goes through the pipeline (checks, 14-day
 * replay) and waits for the user. Nothing here touches a live rule.
 */
export class RuleReviewer {
  private readonly o: Required<Omit<RuleReviewerOptions, 'countEvents' | 'isBusy'>> & {
    countEvents: RuleReviewerOptions['countEvents'] | undefined;
    isBusy: RuleReviewerOptions['isBusy'] | undefined;
  };
  private running = false;

  constructor(
    private readonly runner: () => AnalyzeRunner | undefined,
    private readonly ctx: DetectionToolContext,
    private readonly state: ReviewStateStore = new MemoryReviewStateStore(),
    opts: RuleReviewerOptions = {},
  ) {
    this.o = {
      intervalMs: opts.intervalMs ?? DAY,
      retryMs: opts.retryMs ?? 6 * HOUR,
      minNewEvents: opts.minNewEvents ?? 200,
      windowHours: opts.windowHours ?? 24 * 7,
      deadlineMs: opts.deadlineMs ?? 5 * 60_000,
      now: opts.now ?? ctx.now ?? Date.now,
      countEvents: opts.countEvents,
      isBusy: opts.isBusy,
    };
  }

  status(): ReviewState & { nextDueAt: number } {
    const s = this.state.get() ?? {};
    return { ...s, nextDueAt: this.nextDueAt(s) };
  }

  private nextDueAt(s: ReviewState): number {
    if (s.lastRunAt === undefined) return 0;
    const failed = s.lastOkAt !== s.lastRunAt;
    return s.lastRunAt + (failed ? this.o.retryMs : this.o.intervalMs);
  }

  /**
   * Run a review if one is due. The scheduler calls this often; it decides.
   * A run the scheduler gave up on (`signal`) records nothing about itself.
   */
  async maybeRun(opts: { force?: boolean; signal?: AbortSignal } = {}): Promise<ReviewOutcome> {
    if (this.running) return { ran: false, reason: 'running' };
    const now = this.o.now();
    const s = this.state.get() ?? {};
    if (!opts.force) {
      if (now < this.nextDueAt(s)) return { ran: false, reason: 'not_due' };
      if (this.o.isBusy?.()) return { ran: false, reason: 'busy' };
      if (this.o.countEvents) {
        const since = s.lastOkAt ?? now - this.o.windowHours * HOUR;
        if (this.o.countEvents(since, now) < this.o.minNewEvents)
          return { ran: false, reason: 'too_little_activity' };
      }
    }
    const runner = this.runner();
    if (!runner) return { ran: false, reason: 'no_runner' };

    this.running = true;
    try {
      const res = await runRuleReview(runner, this.ctx, { deadlineMs: this.o.deadlineMs });
      const results = res.submissions.flatMap((s) => s.results);
      // A proposal that failed once and was fixed in the second round counts once, as queued.
      const queued = results.filter((r) => r.result.ok).length;
      const refused = results.filter(
        (r) =>
          !r.result.ok &&
          !results.some((o) => o !== r && o.result.ok && o.kind === r.kind && o.ref === r.ref),
      ).length;
      const next: ReviewState = {
        lastRunAt: now,
        lastQueued: queued,
        lastRefused: refused,
      };
      if (res.ok) next.lastOkAt = now;
      else if (s.lastOkAt !== undefined) next.lastOkAt = s.lastOkAt;
      if (res.summary !== undefined) next.lastSummary = res.summary;
      if (res.error !== undefined) next.lastError = res.error;
      if (!opts.signal?.aborted) this.state.put(next);
      const out: ReviewOutcome = { ran: true, ok: res.ok, queued, refused };
      if (res.summary !== undefined) out.summary = res.summary;
      if (res.error !== undefined) out.error = res.error;
      return out;
    } catch (err) {
      const next: ReviewState = { lastRunAt: now, lastError: (err as Error).message };
      if (s.lastOkAt !== undefined) next.lastOkAt = s.lastOkAt;
      if (!opts.signal?.aborted) this.state.put(next);
      return { ran: true, ok: false, queued: 0, refused: 0, error: (err as Error).message };
    } finally {
      this.running = false;
    }
  }
}
