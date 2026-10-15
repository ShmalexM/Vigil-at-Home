import { afterEach, describe, expect, it, vi } from 'vitest';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { memoryStore } from './testing.js';

describe('status: stuck background work', () => {
  afterEach(() => vi.useRealTimers());

  it('names a job still running past its expected time, and drops it once it ends', async () => {
    vi.useFakeTimers();
    const core = new VigilCore(memoryStore(), new DryRunExecutor(), true, () => Date.now());
    let finish!: () => void;
    core.scheduler.every(
      'pack-dogs',
      60 * 60_000,
      () => new Promise<void>((r) => (finish = r)),
      true,
      { stuckAfterMs: 1_000 },
    );
    const before = core.status();
    await vi.advanceTimersByTimeAsync(1_000);
    const stuck = core.status();
    expect(stuck.stuckJobs).toEqual(['pack dogs']);
    expect(stuck.reasons).toContain('Background work stuck: pack dogs');
    expect(stuck.level).toBe(before.level);
    finish();
    await vi.advanceTimersByTimeAsync(0);
    expect(core.status().stuckJobs).toEqual([]);
    core.scheduler.stop();
  });
});
