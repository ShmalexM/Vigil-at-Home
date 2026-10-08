import { afterEach, describe, expect, it, vi } from 'vitest';
import { Scheduler, TaskTimeoutError } from './scheduler.js';

const tick = () => new Promise((r) => setImmediate(r));

describe('Scheduler', () => {
  afterEach(() => vi.useRealTimers());

  it('runs urgent work before queued routine work', async () => {
    const s = new Scheduler({ concurrency: 1 });
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const first = s.enqueue('blocker', () => gate);
    const r1 = s.enqueue('r1', () => void order.push('r1'));
    const r2 = s.enqueue('r2', () => void order.push('r2'));
    const u1 = s.enqueue('u1', () => void order.push('u1'), 'urgent');
    const u2 = s.enqueue('u2', () => void order.push('u2'), 'urgent');
    expect(s.pending()).toEqual({ urgent: 2, routine: 2 });
    release();
    await Promise.all([first, r1, r2, u1, u2]);
    expect(order).toEqual(['u1', 'u2', 'r1', 'r2']);
  });

  it('holds routine work while paused but still runs urgent work', async () => {
    const s = new Scheduler();
    s.pause();
    const ran: string[] = [];
    void s.enqueue('routine', () => void ran.push('routine'));
    await s.enqueue('urgent', () => void ran.push('urgent'), 'urgent');
    await tick();
    expect(ran).toEqual(['urgent']);
    s.resume();
    await tick();
    expect(ran).toEqual(['urgent', 'routine']);
  });

  it('never overlaps a periodic job with itself and records errors', async () => {
    vi.useFakeTimers();
    const s = new Scheduler();
    let active = 0;
    let maxActive = 0;
    let calls = 0;
    let release!: () => void;
    s.every('poll', 100, async () => {
      calls++;
      active++;
      maxActive = Math.max(maxActive, active);
      await new Promise<void>((r) => (release = r));
      active--;
      if (calls === 1) throw new Error('boom');
    });
    await vi.advanceTimersByTimeAsync(350); // three ticks, first still running
    expect(calls).toBe(1);
    release();
    await vi.advanceTimersByTimeAsync(0);
    expect(s.status()[0]).toMatchObject({ name: 'poll', runs: 1, lastError: 'boom', busy: false });
    await vi.advanceTimersByTimeAsync(100);
    expect(calls).toBe(2);
    expect(maxActive).toBe(1);
    release();
    s.stop();
  });

  it('rejects queued work on stop', async () => {
    const s = new Scheduler({ concurrency: 1 });
    void s.enqueue('hold', () => new Promise(() => {}));
    const waiting = s.enqueue('later', () => 1);
    s.stop();
    await expect(waiting).rejects.toThrow('stopped');
  });

  it('runs periodic jobs less often while slowed down', async () => {
    vi.useFakeTimers();
    const s = new Scheduler();
    let calls = 0;
    s.every('poll', 100, () => void calls++);
    await vi.advanceTimersByTimeAsync(400);
    expect(calls).toBe(4);
    s.setSlowdown(4);
    await vi.advanceTimersByTimeAsync(800);
    expect(calls).toBe(6);
    s.setSlowdown(1);
    await vi.advanceTimersByTimeAsync(300);
    expect(calls).toBe(9);
    s.stop();
  });

  it('gives a hung task’s slot back so other work keeps running', async () => {
    vi.useFakeTimers();
    const errors: string[] = [];
    const s = new Scheduler({
      concurrency: 1,
      taskTimeoutMs: 1_000,
      onError: (name, err) => errors.push(`${name}: ${(err as Error).message}`),
    });
    const hung = s.enqueue('hung', () => new Promise<void>(() => {}));
    const hungResult = hung.catch((e: unknown) => e);
    const ran: string[] = [];
    const next = s.enqueue('next', () => void ran.push('next'));
    await vi.advanceTimersByTimeAsync(999);
    expect(ran).toEqual([]);
    await vi.advanceTimersByTimeAsync(1);
    await next;
    expect(ran).toEqual(['next']);
    expect(await hungResult).toBeInstanceOf(TaskTimeoutError);
    expect(errors).toEqual(['hung: hung still running after 1 s; gave up waiting']);
    expect(s.active).toBe(0);
  });

  it('ignores a timed-out task that finishes later and doesn’t free its slot twice', async () => {
    vi.useFakeTimers();
    const s = new Scheduler({ concurrency: 1, taskTimeoutMs: 1_000 });
    let finish!: () => void;
    const slow = s.enqueue('slow', () => new Promise<void>((r) => (finish = r))).catch(() => {});
    await vi.advanceTimersByTimeAsync(1_000);
    await slow;
    let release!: () => void;
    const holder = s.enqueue('holder', () => new Promise<void>((r) => (release = r)));
    await vi.advanceTimersByTimeAsync(0);
    expect(s.active).toBe(1);
    finish(); // the abandoned task returns at last
    await vi.advanceTimersByTimeAsync(0);
    expect(s.active).toBe(1);
    const after = s.enqueue('after', () => 'ran');
    await vi.advanceTimersByTimeAsync(0);
    expect(s.pending().routine).toBe(1); // still waits for the one slot
    release();
    await holder;
    expect(await after).toBe('ran');
  });

  it('gives a hung run’s slot back but never starts that job again while it runs', async () => {
    vi.useFakeTimers();
    const s = new Scheduler({ concurrency: 1, taskTimeoutMs: 1_000 });
    let calls = 0;
    s.every(
      'stuck',
      5_000,
      () => {
        calls++;
        return new Promise<void>(() => {});
      },
      true,
    );
    let other = 0;
    s.every('other', 5_000, () => void other++, true);
    await vi.advanceTimersByTimeAsync(1_000);
    expect(s.status()[0]).toMatchObject({ busy: true, timeouts: 1 });
    expect(s.status()[0]!.lastError).toMatch(/gave up waiting/);
    await vi.advanceTimersByTimeAsync(60_000);
    expect(calls).toBe(1);
    expect(other).toBeGreaterThan(5);
  });

  it('runs a slow periodic job once at a time, even after its time-out', async () => {
    // A pack cycle of 14 + 14 + 14 + 1 minutes, given up on at 30 and checked
    // every 5: the next cycle starts only after the slow one has ended.
    vi.useFakeTimers();
    const MIN = 60_000;
    const s = new Scheduler({ taskTimeoutMs: 30 * MIN });
    const ran: string[] = [];
    let cycles = 0;
    let running = 0;
    let overlapped = false;
    const step = (ms: number) => new Promise((r) => setTimeout(r, ms));
    s.every(
      'pack-dogs',
      5 * MIN,
      async () => {
        const first = cycles++ === 0;
        overlapped ||= running > 0;
        running++;
        try {
          for (const [dog, mins] of [
            ['A', 14],
            ['B', 14],
            ['C', 14],
            ['D', 1],
          ] as const) {
            if (!first && dog !== 'D') continue; // A–C are not due again
            await step(mins * MIN);
            ran.push(dog);
          }
        } finally {
          running--;
        }
      },
      true,
    );
    await vi.advanceTimersByTimeAsync(31 * MIN);
    expect(s.status()[0]).toMatchObject({ busy: true, timeouts: 1 });
    await vi.advanceTimersByTimeAsync(12 * MIN); // the slow cycle ends at 43
    expect(ran).toEqual(['A', 'B', 'C', 'D']);
    expect(cycles).toBe(1);
    await vi.advanceTimersByTimeAsync(3 * MIN); // the next check, at 45
    expect(cycles).toBe(2);
    expect(overlapped).toBe(false);
  });

  it('aborts a timed-out run, and its late finish doesn’t count as a run', async () => {
    vi.useFakeTimers();
    const s = new Scheduler({ taskTimeoutMs: 1_000 });
    let finish!: () => void;
    let seen: AbortSignal | undefined;
    let calls = 0;
    s.every(
      'slow',
      5_000,
      (signal) => {
        calls++;
        if (calls > 1) return;
        seen = signal;
        return new Promise<void>((r) => (finish = r));
      },
      true,
    );
    await vi.advanceTimersByTimeAsync(1_000);
    expect(seen?.aborted).toBe(true);
    expect(seen?.reason).toBeInstanceOf(TaskTimeoutError);
    await vi.advanceTimersByTimeAsync(9_000);
    expect(calls).toBe(1); // not again while the first run is still going
    finish(); // the first run returns at last
    await vi.advanceTimersByTimeAsync(0);
    expect(s.status()[0]).toMatchObject({ runs: 0, timeouts: 1, busy: false });
    await vi.advanceTimersByTimeAsync(5_000);
    expect(calls).toBe(2);
    expect(s.status()[0]).toMatchObject({ runs: 1, timeouts: 1 });
    expect(s.status()[0]!.lastError).toBeUndefined();
  });

  it('never gives up on a task with no time limit', async () => {
    vi.useFakeTimers();
    const s = new Scheduler({ taskTimeoutMs: 1_000 });
    let finish!: () => void;
    const long = s.enqueue(
      'sync',
      () => new Promise<string>((r) => (finish = () => r('done'))),
      'routine',
      {
        timeoutMs: Infinity,
      },
    );
    await vi.advanceTimersByTimeAsync(60 * 60_000);
    expect(s.active).toBe(1);
    finish();
    expect(await long).toBe('done');
    expect(s.active).toBe(0);
  });
});
