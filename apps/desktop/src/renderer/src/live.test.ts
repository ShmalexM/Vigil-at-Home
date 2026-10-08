import { describe, expect, it } from 'vitest';
import { liveLoader } from './live';

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
});
