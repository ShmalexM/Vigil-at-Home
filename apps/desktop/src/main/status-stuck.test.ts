import { afterEach, describe, expect, it, vi } from 'vitest';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { memoryStore } from './testing.js';

describe('status: stuck background work', () => {
  afterEach(() => vi.useRealTimers());

  it('names a job whose run was given up on, and drops it once a run finishes', async () => {
    vi.useFakeTimers();
    const core = new VigilCore(memoryStore(), new DryRunExecutor(), true, () => Date.now());
    let hang = true;
    core.scheduler.every(
      'pack-dogs',
      60 * 60_000,
      () => (hang ? new Promise<void>(() => {}) : undefined),
      true,
      { timeoutMs: 1_000 },
    );
    const before = core.status();
    await vi.advanceTimersByTimeAsync(1_000);
    const stuck = core.status();
    expect(stuck.stuckJobs).toEqual(['pack dogs']);
    expect(stuck.reasons).toContain('Background work stuck: pack dogs');
    expect(stuck.level).toBe(before.level);
    hang = false;
    await vi.advanceTimersByTimeAsync(60 * 60_000);
    expect(core.status().stuckJobs).toEqual([]);
    core.scheduler.stop();
  });
});
