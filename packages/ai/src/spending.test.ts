import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { runUsageFromResult, planUsageFromClaude } from './providers/claude.js';
import { createAiRunner } from './runner.js';
import { defaultAiSettings } from './settings.js';
import { spendingDays } from './spending.js';
import type { PromptLogEntry, ProviderAdapter } from './types.js';

const T0 = new Date(2026, 8, 26, 12).getTime();

function entry(patch: Partial<PromptLogEntry>): PromptLogEntry {
  return {
    id: 'x',
    at: T0,
    purpose: 'explain',
    urgency: 'now',
    provider: 'claude',
    systemPrompt: '',
    userPrompt: '',
    outcome: 'ok',
    ...patch,
  };
}

describe('spending', () => {
  it("adds up Vigil's runs per day, provider and job", () => {
    const days = spendingDays(
      [
        entry({
          usage: { inputTokens: 100, cachedInputTokens: 10, outputTokens: 5, costUsd: 0.01 },
        }),
        entry({
          outcome: 'error',
          usage: { inputTokens: 50, cachedInputTokens: 0, outputTokens: 1, costUsd: 0.005 },
        }),
        entry({
          provider: 'codex',
          usage: { inputTokens: 7, cachedInputTokens: 0, outputTokens: 3, costUsd: null },
        }),
        entry({ provider: null, outcome: 'no_provider' }),
        entry({ at: T0 - 40 * 86_400_000 }),
      ],
      T0 - 30 * 86_400_000,
    );
    expect(days).toEqual([
      {
        day: '2026-09-26',
        provider: 'claude',
        purpose: 'explain',
        runs: 2,
        failed: 1,
        inputTokens: 150,
        cachedInputTokens: 10,
        outputTokens: 6,
        costUsd: 0.015,
      },
      {
        day: '2026-09-26',
        provider: 'codex',
        purpose: 'explain',
        runs: 1,
        failed: 0,
        inputTokens: 7,
        cachedInputTokens: 0,
        outputTokens: 3,
        costUsd: null,
      },
    ]);
  });

  it("shows each plan's windows with Vigil's part, read through the vendor's CLI", async () => {
    let used = 20;
    const codex: ProviderAdapter = {
      id: 'codex',
      probe: async () => ({ provider: 'codex', state: 'ready' }),
      readUsage: async () => ({
        plan: 'plus',
        windows: [
          {
            provider: 'codex',
            windowId: 'codex:primary',
            usedPercent: used,
            resetsAt: T0 + 3_600_000,
          },
        ],
      }),
      run: async (input) => {
        used = 25;
        input.onUsage({
          provider: 'codex',
          windowId: 'codex:primary',
          usedPercent: used,
          resetsAt: T0 + 3_600_000,
        });
        return {
          kind: 'ok',
          json: { ok: true },
          audit: { called: [], denied: [] },
          usage: { inputTokens: 9, cachedInputTokens: 0, outputTokens: 2, costUsd: null },
        };
      },
    };
    const log: PromptLogEntry[] = [];
    let now = T0;
    const runner = createAiRunner({
      settings: { ...defaultAiSettings('/tmp/vigil-test'), order: ['codex'] },
      adapters: [codex],
      log: { record: (e) => log.push(e) },
      now: () => now,
    });
    await runner.spending(log);
    await runner.run({
      purpose: 'analyze',
      urgency: 'background',
      instructions: 'x',
      data: {},
      output: z.object({ ok: z.boolean() }),
      deadlineMs: 1_000,
    });
    expect(log[0]?.usage).toEqual({
      inputTokens: 9,
      cachedInputTokens: 0,
      outputTokens: 2,
      costUsd: null,
    });
    now += 1_000;
    const snapshot = await runner.spending(log);
    expect(snapshot.plans.find((p) => p.provider === 'codex')).toEqual({
      provider: 'codex',
      plan: 'plus',
      available: true,
      windows: [
        {
          id: 'codex:primary',
          label: 'Short-term limit',
          kind: 'session',
          usedPercent: 25,
          vigilPercent: 5,
          resetsAt: T0 + 3_600_000,
        },
      ],
    });
    expect(snapshot.plans.find((p) => p.provider === 'claude')?.available).toBe(false);
    expect(snapshot.days[0]).toMatchObject({ provider: 'codex', purpose: 'analyze', runs: 1 });
    expect(snapshot.limits).toEqual({ backgroundSharePercent: 10 });
  });

  it('stops Claude on an API key once the monthly cap is spent', async () => {
    let ran = 0;
    const claude: ProviderAdapter = {
      id: 'claude',
      probe: async () => ({ provider: 'claude', state: 'ready' }),
      run: async () => {
        ran++;
        return { kind: 'ok', json: {}, audit: { called: [], denied: [] } };
      },
    };
    const base = defaultAiSettings('/tmp/vigil-test');
    const runner = createAiRunner({
      settings: {
        ...base,
        order: ['claude'],
        claude: { ...base.claude, mode: 'apiKey' },
        quota: { ...base.quota, apiKeyMonthlyCapUsd: 5 },
      },
      adapters: [claude],
      log: { record: () => {} },
      spentThisMonthUsd: async () => 5.2,
    });
    const result = await runner.run({
      purpose: 'explain',
      urgency: 'now',
      instructions: 'x',
      data: {},
      output: z.object({}),
      deadlineMs: 1_000,
    });
    expect(result).toMatchObject({ ok: false, reason: 'quota' });
    expect(ran).toBe(0);
  });

  it("reads Claude Code's own token counts, cost estimate and plan windows", () => {
    const usage = runUsageFromResult({
      modelUsage: {
        a: {
          inputTokens: 10,
          cacheCreationInputTokens: 5,
          cacheReadInputTokens: 100,
          outputTokens: 20,
          costUSD: 0.02,
        },
        // A small housekeeping model that wrote less; the run is named after the main one.
        b: {
          inputTokens: 1,
          cacheCreationInputTokens: 0,
          cacheReadInputTokens: 0,
          outputTokens: 2,
          costUSD: 0,
        },
      },
    } as unknown as Parameters<typeof runUsageFromResult>[0]);
    expect(usage).toEqual({
      inputTokens: 16,
      cachedInputTokens: 100,
      outputTokens: 22,
      costUsd: 0.02,
      model: 'a',
    });

    const plan = planUsageFromClaude({
      subscription_type: 'max',
      rate_limits_available: true,
      rate_limits: {
        five_hour: { utilization: 42, resets_at: '2026-09-26T15:00:00Z' },
        seven_day: { utilization: 10, resets_at: null },
        model_scoped: [{ display_name: 'Opus', utilization: 3, resets_at: null }],
      },
    } as unknown as Parameters<typeof planUsageFromClaude>[0]);
    expect(plan).toEqual({
      plan: 'max',
      windows: [
        {
          provider: 'claude',
          windowId: 'five_hour',
          usedPercent: 42,
          resetsAt: Date.parse('2026-09-26T15:00:00Z'),
        },
        { provider: 'claude', windowId: 'seven_day', usedPercent: 10 },
        { provider: 'claude', windowId: 'model:Opus', usedPercent: 3 },
      ],
    });
    expect(
      planUsageFromClaude({
        rate_limits_available: false,
        rate_limits: null,
      } as unknown as Parameters<typeof planUsageFromClaude>[0]),
    ).toBeUndefined();
  });
});
