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
 * - A task still running after its time limit (`taskTimeoutMs`, or the
 *   task's own) gives its slot back, so one call that never returns can't
 *   stall every other job behind it. Its signal is aborted, so it can stop
 *   before writing anything late; its result, if it ever comes, is ignored
 *   and doesn't count as a run, and its job may run again.
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
  /** Runs given up on after `taskTimeoutMs`. */
  timeouts: number;
}

/** A task's work. `signal` is aborted when the task is given up on. */
export type TaskFn<T> = (signal: AbortSignal) => Promise<T> | T;

export interface TaskOptions {
  /** How long it may run before its slot is given back. Infinity for work that is always making progress. */
  timeoutMs?: number;
}

interface Task {
  name: string;
  priority: Priority;
  timeoutMs: number;
  run: (signal: AbortSignal) => Promise<unknown>;
  resolve: (v: unknown) => void;
  reject: (e: unknown) => void;
}

interface Job extends JobStatus {
  fn: TaskFn<void>;
  timeoutMs?: number;
  timer?: ReturnType<typeof setInterval>;
}

export interface SchedulerOptions {
  /** Tasks running at once across both lanes. */
  concurrency?: number;
  /** How long a task may run before its slot is given back (default 30 minutes). */
  taskTimeoutMs?: number;
  now?: () => number;
  onError?: (name: string, err: unknown) => void;
}

export const DEFAULT_TASK_TIMEOUT_MS = 30 * 60_000;

export class TaskTimeoutError extends Error {
  constructor(name: string, ms: number) {
    super(`${name} still running after ${Math.round(ms / 1000)} s; gave up waiting`);
  }
}

export class Scheduler {
  private readonly queue: Task[] = [];
  private readonly jobs = new Map<string, Job>();
  private running = 0;
  private paused = false;
  private stopped = false;
  private slowdown = 1;
  private readonly concurrency: number;
  private readonly taskTimeoutMs: number;
  private readonly now: () => number;
  private readonly onError: (name: string, err: unknown) => void;

  constructor(opts: SchedulerOptions = {}) {
    this.concurrency = Math.max(1, opts.concurrency ?? 2);
    this.taskTimeoutMs = opts.taskTimeoutMs ?? DEFAULT_TASK_TIMEOUT_MS;
    this.now = opts.now ?? Date.now;
    this.onError = opts.onError ?? (() => {});
  }

  /** Run `fn` once, in the given lane. Resolves with its result. */
  enqueue<T>(
    name: string,
    fn: TaskFn<T>,
    priority: Priority = 'routine',
    opts: TaskOptions = {},
  ): Promise<T> {
    if (this.stopped) return Promise.reject(new Error('Scheduler stopped'));
    return new Promise<T>((resolve, reject) => {
      const task: Task = {
        name,
        priority,
        timeoutMs: opts.timeoutMs ?? this.taskTimeoutMs,
        run: async (signal) => fn(signal),
        resolve: resolve as (v: unknown) => void,
        reject,
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
    const job: Job = { name, everyMs, fn, runs: 0, busy: false, timeouts: 0 };
    if (opts.timeoutMs !== undefined) job.timeoutMs = opts.timeoutMs;
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
    const opts = job.timeoutMs === undefined ? {} : { timeoutMs: job.timeoutMs };
    this.enqueue(
      job.name,
      async (signal) => {
        job.lastStart = this.now();
        try {
          await job.fn(signal);
          if (!signal.aborted) delete job.lastError;
        } catch (err) {
          if (!signal.aborted) job.lastError = err instanceof Error ? err.message : String(err);
          throw err;
        } finally {
          // A run given up on was counted then; a late finish changes nothing.
          if (!signal.aborted) {
            job.lastEnd = this.now();
            job.runs++;
          }
        }
      },
      'routine',
      opts,
    )
      .catch((err: unknown) => {
        if (err instanceof TaskTimeoutError) {
          job.timeouts++;
          job.lastError = err.message;
        }
      })
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
    return [...this.jobs.values()].map(({ fn: _fn, timer: _timer, timeoutMs: _t, ...s }) => ({
      ...s,
    }));
  }

  /** Tasks running now, timed-out ones not counted. */
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
      let settled = false;
      const abort = new AbortController();
      const done = (): boolean => {
        if (settled) return false;
        settled = true;
        clearTimeout(watchdog);
        this.running--;
        return true;
      };
      const watchdog = Number.isFinite(task.timeoutMs)
        ? setTimeout(() => {
            if (!done()) return;
            const err = new TaskTimeoutError(task.name, task.timeoutMs);
            abort.abort(err);
            this.onError(task.name, err);
            task.reject(err);
            this.pump();
          }, task.timeoutMs)
        : undefined;
      watchdog?.unref?.();
      task.run(abort.signal).then(
        (v) => {
          if (!done()) return;
          task.resolve(v);
          this.pump();
        },
        (err: unknown) => {
          if (!done()) return;
          this.onError(task.name, err);
          task.reject(err);
          this.pump();
        },
      );
    }
  }
}
