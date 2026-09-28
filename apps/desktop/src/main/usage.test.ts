import { describe, expect, it } from 'vitest';
import { memoryStore } from './testing.js';
import { UsageService, usageWindow, type PromptLogLike } from './usage.js';

const HOUR = 60 * 60 * 1000;
// Noon local time, so day arithmetic stays clear of midnight.
const NOW = new Date(2026, 8, 28, 12, 0, 0).getTime();

function entry(over: Partial<PromptLogLike> = {}): PromptLogLike {
  return {
    id: `r${Math.random()}`,
    at: NOW - HOUR,
    purpose: 'explain',
    provider: 'claude',
    outcome: 'ok',
    usage: { inputTokens: 100, cachedInputTokens: 300, outputTokens: 50, costUsd: 0.02 },
    ...over,
  };
}

function service(now = NOW) {
  return new UsageService(memoryStore(), () => now);
}

describe('UsageService', () => {
  it('totals runs by provider, model and task, with Jev and API keys as billed', () => {
    const u = service();
    u.record(entry({ model: 'claude-sonnet-5-5' }));
    u.record(entry({ model: 'claude-sonnet-5-5', outcome: 'timeout' }));
    u.record(
      entry({
        provider: 'jev',
        purpose: 'classify',
        model: 'jev-latest',
        usage: { inputTokens: 1_000_000, cachedInputTokens: 0, outputTokens: 10, costUsd: 0.042 },
      }),
    );
    u.record(
      entry({
        provider: 'codex',
        usage: { inputTokens: 10, cachedInputTokens: 0, outputTokens: 5, costUsd: null },
      }),
    );
    u.record(
      entry({
        provider: 'ollama',
        purpose: 'classify',
        usage: { inputTokens: 20, cachedInputTokens: 0, outputTokens: 5, costUsd: null },
      }),
    );
    // Never reached a provider: not usage.
    u.record(entry({ provider: null, outcome: 'no_provider' }));

    const r = u.report(30);
    expect(r.totals.runs).toBe(5);
    expect(r.totals.failed).toBe(1);
    expect(r.totals.costUsd).toBeCloseTo(0.082);
    expect(r.totals.billedUsd).toBeCloseTo(0.042);
    // Codex has no price; Ollama is free, not unpriced.
    expect(r.totals.unpricedRuns).toBe(1);
    expect(r.totals.totalTokens).toBe(450 * 2 + 1_000_010 + 15 + 25);
    expect(r.providers.map((p) => p.provider)).toEqual(['claude', 'codex', 'jev', 'ollama']);
    expect(r.providers.find((p) => p.provider === 'jev')?.costShare).toBeCloseTo(0.042 / 0.082);

    const codex = r.models.find((m) => m.provider === 'codex');
    expect(codex?.priced).toBe(false);
    expect(r.models.map((m) => m.model).slice(0, 2)).toEqual(['jev-latest', 'claude-sonnet-5-5']);
    expect(r.models[1]?.runs).toBe(2);
    expect(r.purposes.map((p) => p.purpose).sort()).toEqual(['classify', 'explain']);

    const today = r.periods.at(-1)!;
    expect(r.periods).toHaveLength(30);
    expect(today.byProvider.jev?.costUsd).toBeCloseTo(0.042);
  });

  it('leaves out runs before the window and buckets the past 24 hours by hour', () => {
    const u = service();
    u.record(entry({ at: NOW - 40 * HOUR }));
    u.record(entry({ at: NOW - 3 * HOUR - 1 }));
    const day = u.report(1);
    expect(day.resolution).toBe('hour');
    expect(day.periods).toHaveLength(24);
    expect(day.totals.runs).toBe(1);
    expect(day.periods.filter((p) => p.totalTokens > 0)).toHaveLength(1);
    expect(u.report(7).totals.runs).toBe(2);
  });

  it('reports each plan window with its length, and this month on each key', async () => {
    const u = service();
    u.record(entry({ provider: 'jev', purpose: 'classify' }));
    u.setLimitsSource(async () => ({
      plans: [
        {
          provider: 'claude',
          plan: 'max',
          available: true,
          windows: [
            {
              id: 'five_hour',
              label: '5-hour limit',
              kind: 'session',
              usedPercent: 40,
              vigilPercent: 2,
            },
          ],
        },
        { provider: 'codex', available: false, windows: [] },
      ],
      caps: { jev: 5 },
    }));
    const view = await u.limits();
    expect(view.plans).toHaveLength(1);
    expect(view.plans[0]?.windows[0]?.durationMins).toBe(300);
    expect(view.keys).toEqual([{ provider: 'jev', runs: 1, spentUsd: 0.02, capUsd: 5 }]);
  });

  it('shows nothing rather than failing when the vendors cannot be read', async () => {
    const u = service();
    u.setLimitsSource(async () => {
      throw new Error('offline');
    });
    const view = await u.limits();
    expect(view.plans).toEqual([]);
    expect(view.keys).toEqual([]);
  });

  it('prunes runs older than the longest period', () => {
    const u = service();
    u.record(entry({ at: NOW - 120 * 24 * HOUR }));
    u.record(entry());
    expect(u.prune()).toBe(1);
  });
});

describe('usageWindow', () => {
  it('starts at local midnight and includes today', () => {
    const w = usageWindow(7, NOW);
    expect(w.starts).toHaveLength(7);
    expect(new Date(w.starts[0]!).getHours()).toBe(0);
    expect(new Date(w.starts[6]!).getDate()).toBe(28);
  });
});
