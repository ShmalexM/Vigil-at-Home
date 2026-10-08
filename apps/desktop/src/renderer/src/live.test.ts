import { afterEach, describe, expect, it, vi } from 'vitest';
import { LOAD_TIMEOUT_MS, liveLoader } from './live';

/** A load whose answers the test releases one at a time. */
function controlled() {
  const pending: ((v: number) => void)[] = [];
  let calls = 0;
  const load = () =>
    new Promise<number>((resolve) => {
      calls++;
      pending.push(resolve);
    });
  return { load, pending, calls: () => calls };
}
const tick = () => new Promise((r) => setTimeout(r, 0));

describe('liveLoader', () => {
  it('lands a slow answer even while reloads keep coming', async () => {
    const c = controlled();
    const landed: number[] = [];
    const l = liveLoader(c.load, (v) => landed.push(v));
    l.reload();
    // Reloads every "second" while the first load is still running.
    l.reload();
    l.reload();
    l.reload();
    expect(c.calls()).toBe(1);
    c.pending.shift()!(1);
    await tick();
    expect(landed).toEqual([1]);
    // The reloads asked meanwhile run once, not three times.
    expect(c.calls()).toBe(2);
    c.pending.shift()!(2);
    await tick();
    expect(landed).toEqual([1, 2]);
    expect(c.calls()).toBe(2);
  });

  it("drops an answer for the previous key and loads the new key's", async () => {
    const c = controlled();
    const landed: number[] = [];
    const l = liveLoader(c.load, (v) => landed.push(v));
    l.reload();
    l.reset();
    c.pending.shift()!(1);
    await tick();
    expect(landed).toEqual([]);
    expect(c.calls()).toBe(2);
    c.pending.shift()!(2);
    await tick();
    expect(landed).toEqual([2]);
  });

  it('keeps going after a failed load', async () => {
    let n = 0;
    const errors: unknown[] = [];
    const landed: number[] = [];
    const l = liveLoader(
      () => (++n === 1 ? Promise.reject(new Error('boom')) : Promise.resolve(n)),
      (v) => landed.push(v),
      (e) => errors.push(e),
    );
    l.reload();
    l.reload();
    await tick();
    await tick();
    expect(errors).toHaveLength(1);
    expect(landed).toEqual([2]);
  });

  it("lets a new key load at once while the old key's load hangs", async () => {
    const c = controlled();
    const landed: number[] = [];
    const l = liveLoader(c.load, (v) => landed.push(v));
    l.reload();
    l.reset();
    // The first load never answered, yet the new key's load ran.
    expect(c.calls()).toBe(2);
    c.pending[1]!(2);
    await tick();
    expect(landed).toEqual([2]);
    // The old answer, when it finally comes, is ignored and starts nothing.
    c.pending[0]!(1);
    await tick();
    expect(landed).toEqual([2]);
    expect(c.calls()).toBe(2);
  });

  it('drops an old answer that arrives after invalidate, before the next load', async () => {
    // Search A is loading, the user types B, A answers while B waits for typing to settle.
    const c = controlled();
    const landed: number[] = [];
    const l = liveLoader(c.load, (v) => landed.push(v));
    l.reload();
    l.invalidate();
    c.pending.shift()!(1);
    await tick();
    expect(landed).toEqual([]);
    l.reload();
    c.pending.shift()!(2);
    await tick();
    expect(landed).toEqual([2]);
  });

  it('tells a load made elsewhere whether its key is still current', () => {
    const l = liveLoader(
      () => Promise.resolve(0),
      () => {},
    );
    const a = l.guard();
    expect(a()).toBe(true);
    l.invalidate();
    expect(a()).toBe(false);
    expect(l.guard()()).toBe(true);
  });

  it('keeps going after a load that throws instead of rejecting', async () => {
    let n = 0;
    const errors: unknown[] = [];
    const landed: number[] = [];
    const l = liveLoader(
      () => {
        if (++n === 1) throw new Error('boom');
        return Promise.resolve(n);
      },
      (v) => landed.push(v),
      (e) => errors.push(e),
    );
    expect(() => l.reload()).not.toThrow();
    l.reload();
    await tick();
    await tick();
    expect(errors).toHaveLength(1);
    expect(landed).toEqual([2]);
  });

  describe('a load that hangs', () => {
    afterEach(() => {
      vi.useRealTimers();
    });

    it('holds the next one back only until the timeout', async () => {
      vi.useFakeTimers();
      const c = controlled();
      const landed: number[] = [];
      const l = liveLoader(c.load, (v) => landed.push(v));
      l.reload();
      l.reload();
      expect(c.calls()).toBe(1);
      vi.advanceTimersByTime(LOAD_TIMEOUT_MS - 1);
      expect(c.calls()).toBe(1);
      vi.advanceTimersByTime(1);
      // The queued reload ran.
      expect(c.calls()).toBe(2);
      c.pending[1]!(2);
      await vi.runAllTimersAsync();
      expect(landed).toEqual([2]);
      // The hung one answering late doesn't replace the newer answer.
      c.pending[0]!(1);
      await vi.runAllTimersAsync();
      expect(landed).toEqual([2]);
    });
  });
});
