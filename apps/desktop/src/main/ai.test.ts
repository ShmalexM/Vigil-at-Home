import { describe, expect, it } from 'vitest';
import type {
  PromptLogEntry,
  ProviderStatus,
  RunRequest,
  VigilAi,
  VigilAiOptions,
} from '@vigil/ai';
import { defaultAiSettings } from '@vigil/ai';
import { localNames } from '@vigil/ai/redact';
import { AiBridge, type KeySource } from './ai.js';
import { DryRunExecutor, type ActionExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { sendTestAlert } from './test-alert.js';
import { isNoticed } from '../shared/attention.js';
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
        billed: true,
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

function setup(
  o: {
    saved?: Partial<Record<ApiKeyProvider, string>>;
    mode?: SetupMode;
    executor?: ActionExecutor;
  } = {},
) {
  const store = memoryStore();
  const core = new VigilCore(store, o.executor ?? new DryRunExecutor(), true, () => NOW);
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

  it("redacts this Mac's user and host names", () => {
    const { ai } = setup();
    expect(ai.settings().redaction).toEqual({
      ...defaultAiSettings('/x').redaction,
      ...localNames(),
    });
  });

  it('runs Codex on an OpenAI API key when the user picks it', async () => {
    const { ai, made } = setup({ saved: { openai: 'sk-aaaaaaaaaaaaaaaaaaaa5678' } });
    expect(ai.settings().codex.mode).toBe('subscription');
    ai.setPrefs({ codexUses: 'apiKey' });
    expect(ai.settings().codex.mode).toBe('apiKey');
    ai.ai();
    expect(await made.at(-1)!.getOpenAiApiKey!()).toBe('sk-aaaaaaaaaaaaaaaaaaaa5678');
    const codex = (await ai.view()).providers.find((p) => p.provider === 'codex');
    expect(codex).toMatchObject({ canSignIn: false, canShareSignIn: false, signInShared: false });
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
    expect(() => ai.setPrefs({ claudePlan: 'yes' as never })).toThrow();
  });
});

describe('AiBridge explanations', () => {
  it('explains a new popup alert, stores it on the alert and counts the run', async () => {
    const { core, ai, calls } = setup();
    const notes: unknown[] = [];
    ai.on('note', (helper, note) => notes.push({ helper, ...note }));
    ai.explainAlertsFrom(core);
    const alert = await core.alerts.raise({ rule: makeRule(), events: [makeExec()], actions: [] });
    await settle();
    expect(calls).toHaveLength(1);
    // The explainer's notebook keeps what it said and why, filed under the alert.
    expect(notes).toEqual([
      expect.objectContaining({
        helper: 'explainer',
        kind: 'explain',
        ok: true,
        subject: { kind: 'alert', id: alert.id },
        answer: 'Suspicious. An unsigned program ran from /tmp.',
        provider: 'claude',
        model: 'm-1',
      }),
    ]);
    expect(calls[0]).toMatchObject({ purpose: 'explain', urgency: 'now' });
    const saved = core.store.getAlert(alert.id)!;
    expect(saved.ai).toMatchObject({
      provider: 'claude',
      model: 'm-1',
      verdict: 'suspicious',
      summary: 'An unsigned program ran from /tmp.',
    });
    expect(core.usage.report(1).totals.runs).toBe(1);
    expect(ai.spentThisMonthUsd()).toBeCloseTo(0.01);
  });

  it('uses the Claude plan only for an explanation the user asks for', async () => {
    const { core, ai, calls } = setup();
    expect(ai.settings().claude).toMatchObject({ mode: 'apiKey', allowPlan: false });
    ai.setPrefs({ claudePlan: true });
    expect(ai.settings().claude).toMatchObject({ mode: 'apiKey', allowPlan: true });
    ai.explainAlertsFrom(core);
    const alert = await core.alerts.raise({ rule: makeRule(), events: [makeExec()], actions: [] });
    await settle();
    expect(calls[0]).not.toHaveProperty('requestedByUser');
    expect(await ai.explainOnRequest(core, alert.id)).toEqual({ ok: true });
    expect(calls[1]).toMatchObject({ purpose: 'explain', urgency: 'now', requestedByUser: true });
    expect(await ai.explainOnRequest(core, 'gone')).toMatchObject({ ok: false });
  });

  it('tells the AI what really happened, a failed block included', async () => {
    const failing: ActionExecutor = {
      execute: async () => {
        throw new Error('helper not installed');
      },
    };
    const { core, ai, calls } = setup({ executor: failing });
    ai.explainAlertsFrom(core);
    await core.alerts.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [{ kind: 'process.suspend', pid: 4242 }],
    });
    await settle();
    expect(calls[0]?.data).toMatchObject({
      actions: [{ kind: 'process.suspend', status: 'failed', error: 'helper not installed' }],
    });
    expect(calls[0]?.instructions).toContain('a failed or pending action did not happen');
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
    // Six different processes: identical repeats would fold into one alert.
    for (let i = 0; i < 6; i++)
      await core.alerts.raise({
        rule: quiet,
        events: [makeExec('/tmp/evil', 100 + i)],
        actions: [],
      });
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

  it('shows the cloud API as optional, not a problem, when there is no key', async () => {
    const v = await setup({ saved: { typesafe: 'ts-aaaaaaaaaaaaaaaaaa9876' } }).ai.view();
    expect(v.providers.find((p) => p.provider === 'api')).toMatchObject({ state: 'optional' });
    expect(v.providers.find((p) => p.provider === 'jev')).toMatchObject({ state: 'ready' });
    expect(v.jevVia).toBe('typesafe');
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
      // One cap over every key; the runner decides which runs it counts.
      capUsd: 20,
    });
  });

  it('counts every key-billed run, Codex on an OpenAI key included, toward one cap', () => {
    const { ai, store } = setup();
    const run = (
      id: string,
      provider: 'codex' | 'jev' | 'claude',
      costUsd: number | null,
      billed?: boolean,
    ) =>
      store.addAiRun({
        id,
        at: NOW,
        provider,
        purpose: 'explain',
        ok: true,
        inputTokens: 1,
        cachedInputTokens: 0,
        outputTokens: 1,
        costUsd,
        ...(billed !== undefined ? { billed } : {}),
      });
    run('a', 'codex', 0.5, true);
    run('b', 'jev', 0.25, true);
    // A plan run's estimate and a ChatGPT plan run never count.
    run('c', 'claude', 3, false);
    run('d', 'codex', null);
    expect(ai.spentThisMonthUsd()).toBeCloseTo(0.75);
  });
});

describe('AiBridge event labels', () => {
  const unmatched = { checked: 21, matches: [] };

  function labelling(
    answer: (ids: string[]) => { labels: string[]; deferred: string[] },
    as: { label: 'unusual' | 'suspicious'; score: number; by: 'model' | 'jev' } = {
      label: 'unusual',
      score: 0,
      by: 'model',
    },
  ) {
    const store = memoryStore();
    const core = new VigilCore(store, new DryRunExecutor(), true, () => NOW);
    const sent: string[][] = [];
    const ai = new AiBridge({
      store,
      usage: core.usage,
      keys: keys(),
      mode: () => 'local',
      dataDir: '/tmp/vigil-test',
      openExternal: async () => {},
      create: (opts) =>
        Object.assign(fakeAi(opts, []), {
          ...(opts.settings.classifier.enabled
            ? {
                classifier: {
                  classify: async (events: readonly { id: string }[]) => {
                    const ids = events.map((e) => e.id);
                    sent.push(ids);
                    const r = answer(ids);
                    return {
                      ok: true as const,
                      labels: r.labels.map((id) => ({
                        eventId: id,
                        label: as.label,
                        score: as.score,
                        reason:
                          as.by === 'jev'
                            ? 'Unsigned program reading browser data'
                            : 'Local model hint: unusual',
                        by: as.by,
                      })),
                      deferred: r.deferred,
                    };
                  },
                },
              }
            : {}),
        }),
      now: () => NOW,
    });
    return { store, core, ai, sent };
  }

  it('sends only unmatched, non-Apple events, once per program an hour', async () => {
    const { core, ai, sent } = labelling((ids) => ({ labels: ids, deferred: [] }));
    ai.labelEventsFrom(core);
    const a = makeExec('/tmp/a');
    core.ingest(a, unmatched);
    core.ingest(makeExec('/tmp/a'), unmatched); // same program again
    core.ingest(makeExec('/tmp/b'), {
      checked: 21,
      matches: [{ ruleId: 'r', ruleName: 'R', mode: 'alert' }],
    });
    const apple = makeExec('/usr/bin/true');
    if (apple.kind === 'process.exec') apple.process.signing = 'apple';
    core.ingest(apple, unmatched);
    core.events.flush();
    expect(await ai.labelBatch(core.store)).toBe(1);
    expect(sent).toEqual([[a.id]]);
    const [view] = core.store.listEventViews({}).filter((v) => v.event.id === a.id);
    expect(view!.label).toMatchObject({ label: 'unusual', by: 'model' });
  });

  it('caps Apple tools at 30 command lines an hour', async () => {
    const { core, ai, sent } = labelling((ids) => ({ labels: ids, deferred: [] }));
    ai.labelEventsFrom(core);
    for (let i = 0; i < 40; i++) {
      const e = makeExec('/bin/zsh');
      if (e.kind === 'process.exec') {
        e.process.signing = 'apple';
        e.process.args = ['zsh', '-c', `step-${'x'.repeat(i)}`];
      }
      core.ingest(e, unmatched);
    }
    core.ingest(makeExec('/tmp/other'), unmatched);
    core.events.flush();
    await ai.labelBatch(core.store);
    expect(sent[0]).toHaveLength(31);
  });

  it('puts events the model skipped back in the queue', async () => {
    let round = 0;
    const { core, ai, sent } = labelling((ids) =>
      round++ === 0
        ? { labels: ids.slice(0, 1), deferred: ids.slice(1) }
        : { labels: ids, deferred: [] },
    );
    ai.labelEventsFrom(core);
    const events = [makeExec('/tmp/x'), makeExec('/tmp/y')];
    for (const e of events) core.ingest(e, unmatched);
    core.events.flush();
    await ai.labelBatch(core.store);
    await ai.labelBatch(core.store);
    expect(sent).toEqual([events.map((e) => e.id), [events[1]!.id]]);
  });

  it('raises a quiet "worth a look" alert for a strong catch, never for a local hint', async () => {
    const jev = labelling((ids) => ({ labels: ids, deferred: [] }), {
      label: 'suspicious',
      score: 0.9,
      by: 'jev',
    });
    const notes: unknown[] = [];
    jev.ai.on('note', (helper, note) => notes.push({ helper, ...note }));
    jev.ai.labelEventsFrom(jev.core);
    const e = makeExec('/tmp/stealer');
    jev.core.ingest(e, unmatched);
    jev.core.events.flush();
    await jev.ai.labelBatch(jev.core.store);
    const [alert] = jev.core.store.listAlerts({});
    expect(alert).toMatchObject({
      ruleId: 'vigil.worth-a-look',
      title: 'Worth a look: stealer',
      severity: 'low',
      notify: 'silent',
      containment: 'none',
      actionIds: [],
    });
    expect(alert!.summary).toBe(
      'Unsigned program reading browser data. No rule matched this and nothing was blocked. Labelled by Jev.',
    );
    expect(isNoticed(alert!)).toBe(true);
    expect(notes).toEqual([
      expect.objectContaining({
        helper: 'labeller',
        kind: 'label',
        ask: 'Label 1 new event',
        lookedAt: ['stealer started'],
        answer: '1 of 1 stood out',
        provider: 'jev',
      }),
    ]);

    const local = labelling((ids) => ({ labels: ids, deferred: [] }), {
      label: 'suspicious',
      score: 0,
      by: 'model',
    });
    local.ai.labelEventsFrom(local.core);
    local.core.ingest(makeExec('/tmp/stealer'), unmatched);
    local.core.events.flush();
    await local.ai.labelBatch(local.core.store);
    expect(local.core.store.listAlerts({})).toEqual([]);
  });

  it('sends nothing when labelling is off', async () => {
    const { core, ai, sent } = labelling((ids) => ({ labels: ids, deferred: [] }));
    ai.labelEventsFrom(core);
    ai.setPrefs({ labelling: false });
    core.ingest(makeExec('/tmp/z'), unmatched);
    expect(await ai.labelBatch(core.store)).toBe(0);
    expect(sent).toEqual([]);
  });

  it('keeps prefs saved before labelling existed', () => {
    const store = memoryStore();
    store.setSetting('ai.prefs', {
      claude: false,
      codex: true,
      api: true,
      ollama: true,
      jev: true,
      claudeUses: 'subscription',
    });
    const ai = new AiBridge({
      store,
      usage: new VigilCore(store, new DryRunExecutor(), true).usage,
      keys: keys(),
      mode: () => undefined,
      dataDir: '/tmp/vigil-test',
      openExternal: async () => {},
    });
    // A plan picked before it became opt-in doesn't carry over.
    expect(ai.prefs()).toMatchObject({ claude: false, labelling: true, claudePlan: false });
  });
});
