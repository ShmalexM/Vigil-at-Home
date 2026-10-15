/**
 * Two-lane task scheduler for the main process.
 *
 * - `urgent` work (explaining a fresh alert) always runs before `routine` work
 *   (periodic sensor polls, rule stats, pruning), and keeps running while
 *   routine work is paused on battery or sleep.
 * - Periodic jobs never overlap themselves: a job still queued or running
 *   when its next tick comes skips that tick.
 * - On battery the app slows periodic jobs down (`setSlowdown`): a job runs
 *   at most once every `everyMs × factor`.
 *
 * - A task never gets abandoned: every call it makes to the outside world
 *   (AI providers, connectors, child processes) has its own time limit, so
 *   it finishes on its own. One still running after its expected time
 *   (`stuckAfterMs`) keeps its slot and is marked stuck, so the status can
 *   say work has stopped; its job doesn't start again until it ends.
 *
 * Blocking never goes through here. Blocks run inline in the alert path.
 */
export type Priority = 'urgent' | 'routine';

export interface JobStatus {
  name: string;
  everyMs: number;
  lastStart?: number;
  lastEnd?: number;
  lastError?: string;
  runs: number;
  busy: boolean;
  /** Runs that went past their expected time. */
  timeouts: number;
  /** A run is still going past its expected time: the job's work has stopped for now. */
  stuck: boolean;
}

export type TaskFn<T> = () => Promise<T> | T;

export interface TaskOptions {
  /** How long it may run before it counts as stuck. Infinity for work that is always making progress. */
  stuckAfterMs?: number;
}

interface Task {
  name: string;
  priority: Priority;
  stuckAfterMs: number;
  run: () => Promise<unknown>;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
  /** Told when the task passes its expected time, and when it ends after that. */
  onStuck?: (stuck: boolean) => void;
}

interface Job extends JobStatus {
  fn: TaskFn<void>;
  stuckAfterMs?: number;
  timer?: ReturnType<typeof setInterval>;
}

export interface SchedulerOptions {
  /** Tasks running at once across both lanes. */
  concurrency?: number;
  /** How long a task may run before it counts as stuck (default 30 minutes). */
  stuckAfterMs?: number;
  now?: () => number;
  onError?: (name: string, err: unknown) => void;
}

export const DEFAULT_STUCK_AFTER_MS = 30 * 60_000;

export class Scheduler {
  private readonly queue: Task[] = [];
  private readonly jobs = new Map<string, Job>();
  private running = 0;
  private paused = false;
  private stopped = false;
  private slowdown = 1;
  private readonly concurrency: number;
  private readonly stuckAfterMs: number;
  private readonly now: () => number;
  private readonly onError: (name: string, err: unknown) => void;

  constructor(opts: SchedulerOptions = {}) {
    this.concurrency = Math.max(1, opts.concurrency ?? 2);
    this.stuckAfterMs = opts.stuckAfterMs ?? DEFAULT_STUCK_AFTER_MS;
    this.now = opts.now ?? Date.now;
    this.onError = opts.onError ?? (() => {});
  }

  /** Run `fn` once, in the given lane. Resolves with its result. */
  enqueue<T>(
    name: string,
    fn: TaskFn<T>,
    priority: Priority = 'routine',
    opts: TaskOptions & { onStuck?: (stuck: boolean) => void } = {},
  ): Promise<T> {
    if (this.stopped) return Promise.reject(new Error('Scheduler stopped'));
    return new Promise<T>((resolve, reject) => {
      const task: Task = {
        name,
        priority,
        stuckAfterMs: opts.stuckAfterMs ?? this.stuckAfterMs,
        run: async () => fn(),
        resolve: resolve as (v: unknown) => void,
        reject,
        ...(opts.onStuck ? { onStuck: opts.onStuck } : {}),
      };
      if (priority === 'urgent') {
        // After other urgent tasks, ahead of all routine ones.
        const firstRoutine = this.queue.findIndex((t) => t.priority === 'routine');
        this.queue.splice(firstRoutine === -1 ? this.queue.length : firstRoutine, 0, task);
      } else {
        this.queue.push(task);
      }
      this.pump();
    });
  }

  /** Run `fn` every `everyMs` in the routine lane. `runNow` also queues it immediately. */
  every(
    name: string,
    everyMs: number,
    fn: TaskFn<void>,
    runNow = false,
    opts: TaskOptions = {},
  ): void {
    if (this.jobs.has(name)) throw new Error(`Job already registered: ${name}`);
    const job: Job = { name, everyMs, fn, runs: 0, busy: false, timeouts: 0, stuck: false };
    if (opts.stuckAfterMs !== undefined) job.stuckAfterMs = opts.stuckAfterMs;
    this.jobs.set(name, job);
    job.timer = setInterval(() => this.tick(job), everyMs);
    job.timer.unref?.();
    if (runNow) this.tick(job);
  }

  private tick(job: Job): void {
    if (job.busy || this.stopped) return;
    // A little slack so a job due on this tick isn't pushed to the next one.
    const gap = job.everyMs * this.slowdown - job.everyMs / 2;
    if (this.slowdown > 1 && job.lastStart !== undefined && this.now() - job.lastStart < gap)
      return;
    job.busy = true;
    this.enqueue(
      job.name,
      async () => {
        job.lastStart = this.now();
        try {
          await job.fn();
          delete job.lastError;
        } catch (err) {
          job.lastError = err instanceof Error ? err.message : String(err);
          throw err;
        } finally {
          job.lastEnd = this.now();
          job.runs++;
        }
      },
      'routine',
      {
        ...(job.stuckAfterMs === undefined ? {} : { stuckAfterMs: job.stuckAfterMs }),
        onStuck: (stuck) => {
          job.stuck = stuck;
          if (stuck) job.timeouts++;
        },
      },
    )
      .catch(() => {})
      .finally(() => {
        job.busy = false;
      });
  }

  /** Hold routine work (e.g. on battery saver). Urgent work keeps running. */
  pause(): void {
    this.paused = true;
  }

  resume(): void {
    this.paused = false;
    this.pump();
  }

  /** Run periodic jobs `factor` times less often (1 = normal). Queued work is unaffected. */
  setSlowdown(factor: number): void {
    this.slowdown = Math.max(1, factor);
  }

  /** How many times less often periodic jobs run now (1 = normal; more on battery). */
  get slowdownFactor(): number {
    return this.slowdown;
  }

  get isPaused(): boolean {
    return this.paused;
  }

  stop(): void {
    this.stopped = true;
    for (const job of this.jobs.values()) clearInterval(job.timer);
    this.jobs.clear();
    for (const t of this.queue.splice(0)) t.reject(new Error('Scheduler stopped'));
  }

  status(): JobStatus[] {
    return [...this.jobs.values()].map(({ fn: _fn, timer: _timer, stuckAfterMs: _t, ...s }) => ({
      ...s,
    }));
  }

  /** Tasks running now, stuck ones included. */
  get active(): number {
    return this.running;
  }

  /** Tasks waiting, by lane. */
  pending(): Record<Priority, number> {
    return {
      urgent: this.queue.filter((t) => t.priority === 'urgent').length,
      routine: this.queue.filter((t) => t.priority === 'routine').length,
    };
  }

  private pump(): void {
    while (this.running < this.concurrency) {
      const idx = this.paused ? this.queue.findIndex((t) => t.priority === 'urgent') : 0;
      if (idx === -1 || idx >= this.queue.length) return;
      const [task] = this.queue.splice(idx, 1);
      if (!task) return;
      this.running++;
      let stuck = false;
      const watch = Number.isFinite(task.stuckAfterMs)
        ? setTimeout(() => {
            stuck = true;
            this.onError(
              task.name,
              new Error(
                `${task.name} still running after ${Math.round(task.stuckAfterMs / 1000)} s`,
              ),
            );
            task.onStuck?.(true);
          }, task.stuckAfterMs)
        : undefined;
      watch?.unref?.();
      const done = (): void => {
        clearTimeout(watch);
        if (stuck) task.onStuck?.(false);
        this.running--;
        this.pump();
      };
      task.run().then(
        (v) => {
          task.resolve(v);
          done();
        },
        (err: unknown) => {
          this.onError(task.name, err);
          task.reject(err);
          done();
        },
      );
    }
  }
}
