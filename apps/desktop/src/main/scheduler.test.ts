import { afterEach, describe, expect, it, vi } from 'vitest';
import { Scheduler } from './scheduler.js';

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
});
