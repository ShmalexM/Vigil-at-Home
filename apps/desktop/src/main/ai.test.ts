import { describe, expect, it } from 'vitest';
import type {
  PromptLogEntry,
  ProviderStatus,
  RunRequest,
  VigilAi,
  VigilAiOptions,
} from '@vigil/ai';
import { AiBridge, type KeySource } from './ai.js';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { sendTestAlert } from './test-alert.js';
import { makeExec, makeRule, memoryStore } from './testing.js';
import type { ApiKeyProvider, SetupMode } from '../shared/setup.js';

const NOW = new Date(2026, 8, 28, 12, 0, 0).getTime();

function keys(saved: Partial<Record<ApiKeyProvider, string>> = {}): KeySource {
  return {
    list: () =>
      Object.fromEntries(Object.entries(saved).map(([p, k]) => [p, { last4: k!.slice(-4) }])),
    get: (p) => (saved[p] ? { key: saved[p]! } : undefined),
  };
}

/** A runner that answers every explain request, and logs it like the real one. */
function fakeAi(opts: VigilAiOptions, calls: RunRequest<unknown>[]): VigilAi {
  const statuses: ProviderStatus[] = opts.settings.order.map((provider) => ({
    provider,
    state: opts.settings[provider].enabled ? 'ready' : 'disabled',
  }));
  return {
    quota: undefined as never,
    listApiModels: async () => [],
    status: async () => statuses,
    signIn: async () => ({
      url: 'https://example.test/sign-in',
      completed: Promise.resolve(true),
      cancel() {},
    }),
    spending: async () => ({
      asOf: NOW,
      plans: [],
      days: [],
      limits: { backgroundSharePercent: 10 },
    }),
    run: async <T>(req: RunRequest<T>) => {
      calls.push(req as RunRequest<unknown>);
      const entry: PromptLogEntry = {
        id: `log-${calls.length}`,
        at: NOW,
        purpose: req.purpose,
        urgency: req.urgency,
        provider: 'claude',
        systemPrompt: '',
        userPrompt: '',
        outcome: 'ok',
        usage: {
          inputTokens: 10,
          cachedInputTokens: 0,
          outputTokens: 5,
          costUsd: 0.01,
          model: 'm-1',
        },
        model: 'm-1',
      };
      opts.log.record(entry);
      const value = req.output.parse({
        verdict: 'suspicious',
        confidence: 0.7,
        summary: 'An unsigned program ran from /tmp.',
      });
      return { ok: true as const, value, provider: 'claude' as const, logId: entry.id };
    },
  };
}

function setup(o: { saved?: Partial<Record<ApiKeyProvider, string>>; mode?: SetupMode } = {}) {
  const store = memoryStore();
  const core = new VigilCore(store, new DryRunExecutor(), true, () => NOW);
  const calls: RunRequest<unknown>[] = [];
  const made: VigilAiOptions[] = [];
  const opened: string[] = [];
  const ai = new AiBridge({
    store,
    usage: core.usage,
    keys: keys(o.saved),
    mode: () => o.mode,
    dataDir: '/tmp/vigil-test',
    openExternal: async (url) => void opened.push(url),
    create: (opts) => {
      made.push(opts);
      return fakeAi(opts, calls);
    },
    now: () => NOW,
  });
  return { store, core, ai, calls, made, opened };
}

/** Lets queued scheduler work and its follow-ups finish. */
async function settle() {
  for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
}

describe('AiBridge settings', () => {
  it('uses the OpenRouter key as the API and lets Jev ride on it', () => {
    const { ai } = setup({ saved: { openrouter: 'sk-or-aaaaaaaaaaaaaaaa1234' }, mode: 'cloud' });
    const s = ai.settings();
    expect(s.mode).toBe('cloud');
    expect(s.api).toMatchObject({ enabled: true, preset: 'openrouter' });
    expect(new URL(s.api.baseUrl).hostname).toBe('openrouter.ai');
    expect(s.jev.enabled).toBe(true);
  });

  it('turns the API off when no key is saved', () => {
    const { ai } = setup();
    expect(ai.settings().api.enabled).toBe(false);
    expect(ai.settings().mode).toBe('both');
  });

  it('hands the runner the TypeSafe key only when one is saved', async () => {
    const none = setup();
    none.ai.ai();
    expect(none.made[0]!.getJevApiKey).toBeUndefined();
    const withKey = setup({ saved: { typesafe: 'ts-aaaaaaaaaaaaaaaaaa9876' } });
    withKey.ai.ai();
    expect(await withKey.made[0]!.getJevApiKey!()).toBe('ts-aaaaaaaaaaaaaaaaaa9876');
  });

  it('keeps the runner until a setting changes', () => {
    const { ai, made } = setup();
    ai.ai();
    ai.ai();
    expect(made).toHaveLength(1);
    ai.setPrefs({ codex: false, monthlyCapUsd: 5 });
    const s = ai.settings();
    expect(s.codex.enabled).toBe(false);
    expect(s.quota.apiKeyMonthlyCapUsd).toBe(5);
    ai.ai();
    expect(made).toHaveLength(2);
    ai.setPrefs({ monthlyCapUsd: null });
    expect(ai.prefs().monthlyCapUsd).toBeUndefined();
  });

  it('rejects prefs the renderer made up', () => {
    const { ai } = setup();
    expect(() => ai.setPrefs({ monthlyCapUsd: -1 })).toThrow();
    expect(() => ai.setPrefs({ claudeUses: 'free' as never })).toThrow();
  });
});

describe('AiBridge explanations', () => {
  it('explains a new popup alert, stores it on the alert and counts the run', async () => {
    const { core, ai, calls } = setup();
    ai.explainAlertsFrom(core);
    const alert = await core.alerts.raise({ rule: makeRule(), events: [makeExec()], actions: [] });
    await settle();
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({ purpose: 'explain', urgency: 'now' });
    const saved = core.store.getAlert(alert.id)!;
    expect(saved.ai).toMatchObject({
      provider: 'claude',
      model: 'm-1',
      verdict: 'suspicious',
      summary: 'An unsigned program ran from /tmp.',
    });
    expect(core.usage.report(1).totals.runs).toBe(1);
    expect(ai.spentThisMonthUsd('claude')).toBeCloseTo(0.01);
  });

  it('never sends the test alert', async () => {
    const { core, ai, calls } = setup();
    ai.explainAlertsFrom(core);
    await sendTestAlert(core.alerts);
    await settle();
    expect(calls).toHaveLength(0);
  });

  it('explains quieter alerts in the background, a few at a time', async () => {
    const { core, ai, calls } = setup();
    ai.explainAlertsFrom(core);
    core.scheduler.pause();
    const quiet = makeRule({ mode: 'alert', fidelity: 'low', severity: 'low' });
    for (let i = 0; i < 6; i++)
      await core.alerts.raise({ rule: quiet, events: [makeExec()], actions: [] });
    core.scheduler.resume();
    await settle();
    expect(calls).toHaveLength(3);
    expect(calls.every((c) => c.urgency === 'background')).toBe(true);
  });
});

describe('AiBridge view', () => {
  it('shows Jev reached through the OpenRouter key', async () => {
    const { ai } = setup({ saved: { openrouter: 'sk-or-aaaaaaaaaaaaaaaa1234' } });
    const v = await ai.view();
    expect(v.jevVia).toBe('openrouter');
    expect(v.api).toEqual({ name: 'OpenRouter', last4: '1234' });
    expect(v.providers.find((p) => p.provider === 'jev')).toMatchObject({ state: 'ready' });
  });

  it('says what Jev needs when there is no key, and nothing in local mode', async () => {
    expect((await setup().ai.view()).providers.find((p) => p.provider === 'jev')).toMatchObject({
      state: 'needs_setup',
    });
    const local = await setup({
      saved: { typesafe: 'ts-aaaaaaaaaaaaaaaaaa9876' },
      mode: 'local',
    }).ai.view();
    expect(local.jevVia).toBeNull();
  });

  it('opens the vendor sign-in page in the browser', async () => {
    const { ai, opened } = setup();
    expect(await ai.signIn('codex')).toEqual({ ok: true });
    expect(opened).toEqual(['https://example.test/sign-in']);
    expect((await ai.signIn('jev')).ok).toBe(false);
  });

  it('passes plan limits and the key cap to the Usage page', async () => {
    const { ai } = setup();
    ai.setPrefs({ monthlyCapUsd: 20 });
    expect(await ai.limits()).toEqual({
      plans: [],
      backgroundSharePercent: 10,
      caps: { api: 20, jev: 20 },
    });
  });
});
