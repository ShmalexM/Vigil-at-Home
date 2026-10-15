import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { QuotaTracker } from './quota.js';
import { createAiRunner, PROBE_DEADLINE_MS } from './runner.js';
import { defaultAiSettings, type AiSettings } from './settings.js';
import { readTool } from './tools.js';
import { watchAiApps, type AiAppsSnapshot } from './watch.js';
import { mayUsePlan } from './types.js';
import type {
  AdapterRunInput,
  AdapterRunOutput,
  PromptLogEntry,
  ProviderAdapter,
  ProviderId,
  ProviderState,
} from './types.js';

const audit = () => ({ called: [], denied: [] });

function fake(
  id: ProviderId,
  run: (input: AdapterRunInput) => Promise<AdapterRunOutput> | AdapterRunOutput,
  state: ProviderState = 'ready',
): ProviderAdapter & { inputs: AdapterRunInput[] } {
  const inputs: AdapterRunInput[] = [];
  return {
    id,
    inputs,
    probe: async () => ({ provider: id, state }),
    run: async (input) => {
      inputs.push(input);
      return run(input);
    },
  };
}

function setup(adapters: ProviderAdapter[], patch: Partial<AiSettings> = {}) {
  const log: PromptLogEntry[] = [];
  const settings = { ...defaultAiSettings('/tmp/vigil-test'), ...patch };
  const runner = createAiRunner({ settings, adapters, log: { record: (e) => log.push(e) } });
  return { runner, log };
}

const Verdict = z.object({ verdict: z.enum(['benign', 'suspicious']), summary: z.string() });
const request = {
  purpose: 'explain' as const,
  urgency: 'now' as const,
  instructions: 'Explain.',
  data: { path: '/Users/alexm/Downloads/x', note: 'me@example.com' },
  output: Verdict,
  deadlineMs: 2_000,
};

describe('runner', () => {
  it('uses the first ready provider and validates the answer', async () => {
    const claude = fake('claude', () => ({
      kind: 'ok',
      json: { verdict: 'benign', summary: 'ok' },
      audit: audit(),
      usage: { inputTokens: 1, cachedInputTokens: 0, outputTokens: 1, costUsd: 0, model: 'm-1' },
    }));
    const { runner, log } = setup([claude]);
    const result = await runner.run(request);
    expect(result).toMatchObject({ ok: true, provider: 'claude', value: { verdict: 'benign' } });
    expect(log).toHaveLength(1);
    expect(log[0]?.model).toBe('m-1');
    expect(log[0]?.userPrompt).toContain('/Users/<user>/Downloads/x');
    expect(log[0]?.userPrompt).not.toContain('me@example.com');
    expect(claude.inputs[0]?.jsonSchema).toMatchObject({
      type: 'object',
      required: ['verdict', 'summary'],
    });
  });

  it('lets a Claude plan take only an explanation the user asked for', async () => {
    expect(mayUsePlan({ purpose: 'explain', requestedByUser: true })).toBe(true);
    expect(mayUsePlan({ purpose: 'explain' })).toBe(false);
    expect(mayUsePlan({ purpose: 'classify', requestedByUser: true })).toBe(false);
    expect(mayUsePlan({ purpose: 'analyze', requestedByUser: true })).toBe(false);
    // The user's own message to the Lead dog may; a chat Vigil starts may not.
    expect(mayUsePlan({ purpose: 'chat', requestedByUser: true })).toBe(true);
    expect(mayUsePlan({ purpose: 'chat' })).toBe(false);

    const answer = () => ({
      kind: 'ok' as const,
      json: { verdict: 'benign', summary: 'ok' },
      audit: audit(),
    });
    // A plan with no API key: it can serve only runs that may use the plan.
    const plan = { ...fake('claude', answer), canServe: async (ok: boolean) => ok };
    const codex = fake('codex', answer);
    const { runner } = setup([plan, codex], { order: ['claude', 'codex'] });

    const asked = await runner.run({ ...request, requestedByUser: true });
    expect(asked).toMatchObject({ ok: true, provider: 'claude' });
    expect(plan.inputs[0]?.mayUsePlan).toBe(true);

    // Automatic explanations, labelling and rule reviews go past it.
    for (const r of [
      { ...request },
      { ...request, purpose: 'classify' as const, requestedByUser: true },
      {
        ...request,
        purpose: 'analyze' as const,
        requestedByUser: true,
        urgency: 'background' as const,
      },
    ]) {
      expect(await runner.run(r)).toMatchObject({ ok: true, provider: 'codex' });
      expect(codex.inputs.at(-1)?.mayUsePlan).toBe(false);
    }
    // Naming Claude outright doesn't get around it.
    const only = await runner.run({ ...request, purpose: 'analyze', providers: ['claude'] });
    expect(only).toMatchObject({ ok: false, reason: 'no_provider' });
    expect(plan.inputs).toHaveLength(1);
  });

  it('says whether an answer came from the Claude plan', async () => {
    const answer = () => ({
      kind: 'ok' as const,
      json: { verdict: 'benign', summary: 'ok' },
      audit: audit(),
    });
    const base = defaultAiSettings('/tmp/vigil-test');
    const onPlan = setup([fake('claude', answer)], {
      claude: { ...base.claude, allowPlan: true },
    }).runner;
    expect(await onPlan.run({ ...request, requestedByUser: true })).toMatchObject({
      provider: 'claude',
      viaPlan: true,
    });
    // A run that may not use the plan goes to the key.
    expect(await onPlan.run(request)).toMatchObject({ provider: 'claude', viaPlan: false });
    // A subscription login is the plan.
    const sub = setup([fake('claude', answer)], {
      claude: { enabled: true, mode: 'subscription' },
    }).runner;
    expect(await sub.run({ ...request, requestedByUser: true })).toMatchObject({ viaPlan: true });
    // Plan not allowed: the key answers.
    const key = setup([fake('claude', answer)]).runner;
    expect(await key.run({ ...request, requestedByUser: true })).toMatchObject({ viaPlan: false });
    const codex = setup([fake('codex', answer)]).runner;
    expect(await codex.run({ ...request, requestedByUser: true })).toMatchObject({
      provider: 'codex',
      viaPlan: false,
    });
  });

  it('skips providers that are not ready, disabled or paused by Vigil', async () => {
    const claude = fake(
      'claude',
      () => ({ kind: 'ok', json: {}, audit: audit() }),
      'needs_sign_in',
    );
    const codex = fake('codex', () => ({ kind: 'ok', json: {}, audit: audit() }));
    const ollama = fake('ollama', () => ({
      kind: 'ok',
      json: { verdict: 'suspicious', summary: 's' },
      audit: audit(),
    }));
    const { runner } = setup([claude, codex, ollama], { pausedByVigil: ['codex'] });
    const result = await runner.run(request);
    expect(result).toMatchObject({ ok: true, provider: 'ollama' });
    expect(claude.inputs).toHaveLength(0);
    expect(codex.inputs).toHaveLength(0);
  });

  it('retries once with the validation error, then gives up', async () => {
    const claude = fake('claude', () => ({
      kind: 'ok',
      json: { verdict: 'maybe' },
      audit: audit(),
    }));
    const { runner, log } = setup([claude], { order: ['claude'] });
    const result = await runner.run(request);
    expect(result).toMatchObject({ ok: false, reason: 'invalid_output' });
    expect(claude.inputs).toHaveLength(2);
    expect(claude.inputs[1]?.userPrompt).toContain('did not match the required format');
    // Each attempt is its own row, tied together by runId, so neither cost is lost.
    expect(log).toHaveLength(2);
    expect(new Set(log.map((e) => e.id)).size).toBe(2);
    expect(log[0]?.runId).toBe(log[1]?.runId);
    expect(log[0]?.id).toBe(log[0]?.runId);
    expect(result.logId).toBe(log[1]?.id);
  });

  it('falls back to the next provider when a subscription is out of quota', async () => {
    const claude = fake('claude', () => ({
      kind: 'quota',
      resetsAt: Date.now() + 60_000,
      audit: audit(),
    }));
    const ollama = fake('ollama', () => ({
      kind: 'ok',
      json: { verdict: 'benign', summary: 'x' },
      audit: audit(),
    }));
    const { runner } = setup([claude, ollama]);
    expect(await runner.run(request)).toMatchObject({ ok: true, provider: 'ollama' });
    // Claude stays blocked until its reset time.
    await runner.run(request);
    expect(claude.inputs).toHaveLength(1);
  });

  it('times out at the deadline even if the provider hangs', async () => {
    const claude = fake('claude', () => new Promise<AdapterRunOutput>(() => {}));
    const { runner } = setup([claude]);
    const result = await runner.run({ ...request, deadlineMs: 50 });
    expect(result).toMatchObject({ ok: false, reason: 'timeout' });
  });

  it('times out at the deadline even if checking the provider hangs', async () => {
    const claude = fake('claude', () => ({
      kind: 'ok',
      json: { verdict: 'benign', summary: 'ok' },
      audit: audit(),
    }));
    let release!: () => void;
    claude.probe = () =>
      new Promise((r) => (release = () => r({ provider: 'claude', state: 'ready' })));
    const { runner, log } = setup([claude]);
    const result = await runner.run({ ...request, deadlineMs: 50 });
    expect(result).toMatchObject({ ok: false, reason: 'timeout' });
    const logged = log.length;
    release(); // the check returns long after; nothing more runs or is logged
    await new Promise((r) => setTimeout(r, 10));
    expect(claude.inputs).toHaveLength(0);
    expect(log).toHaveLength(logged);
  });

  it('ends with the run it was made for, even while its provider is being checked', async () => {
    const claude = fake('claude', () => ({
      kind: 'ok',
      json: { verdict: 'benign', summary: 'ok' },
      audit: audit(),
    }));
    let release!: () => void;
    let checking!: () => void;
    const checked = new Promise<void>((r) => (checking = r));
    claude.probe = () =>
      new Promise((r) => {
        checking();
        release = () => r({ provider: 'claude', state: 'ready' });
      });
    const { runner } = setup([claude]);
    const parent = new AbortController();
    // Its own deadline is far off; the run it serves ends first.
    const result = runner.run({ ...request, deadlineMs: 60_000, signal: parent.signal });
    await checked;
    parent.abort();
    release();
    expect(await result).toMatchObject({ ok: false, reason: 'timeout' });
    await new Promise((r) => setTimeout(r, 10));
    expect(claude.inputs).toHaveLength(0);
  });

  it('treats a provider whose check fails as not usable', async () => {
    const claude = fake('claude', () => ({
      kind: 'ok',
      json: { verdict: 'benign', summary: 'ok' },
      audit: audit(),
    }));
    claude.probe = () => Promise.reject(new Error('codesign timed out on /x'));
    const { runner } = setup([claude]);
    expect(await runner.status()).toEqual([
      expect.objectContaining({ provider: 'claude', state: 'error' }),
    ]);
    expect(await runner.run(request)).toMatchObject({ ok: false });
    expect(claude.inputs).toHaveLength(0);
  });

  it('passes over a provider whose probe never answers', async () => {
    vi.useFakeTimers();
    try {
      const hung: ProviderAdapter = {
        id: 'codex',
        probe: () => new Promise(() => {}),
        run: async () => ({ kind: 'error', message: 'x', audit: audit() }),
      };
      const ollama = fake('ollama', () => ({
        kind: 'ok',
        json: { verdict: 'benign', summary: 'ok' },
        audit: audit(),
      }));
      const { runner } = setup([hung, ollama], { order: ['codex', 'ollama'] });
      const result = runner.run(request);
      await vi.advanceTimersByTimeAsync(PROBE_DEADLINE_MS + 1);
      expect(await result).toMatchObject({ ok: true, provider: 'ollama' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('asks a slow probe again soon, and uses its late answer', async () => {
    vi.useFakeTimers();
    try {
      let probes = 0;
      const slow: ProviderAdapter = {
        id: 'codex',
        probe: () => {
          probes++;
          return new Promise((r) =>
            setTimeout(() => r({ provider: 'codex', state: 'ready' }), PROBE_DEADLINE_MS + 10_000),
          );
        },
        run: async () => ({
          kind: 'ok',
          json: { verdict: 'benign', summary: 'codex' },
          audit: audit(),
        }),
      };
      const ollama = fake('ollama', () => ({
        kind: 'ok',
        json: { verdict: 'benign', summary: 'ok' },
        audit: audit(),
      }));
      const { runner } = setup([slow, ollama], { order: ['codex', 'ollama'] });
      const first = runner.run(request);
      await vi.advanceTimersByTimeAsync(PROBE_DEADLINE_MS + 1);
      expect(await first).toMatchObject({ ok: true, provider: 'ollama' });
      // The same probe answers later; the next run uses it without probing twice.
      await vi.advanceTimersByTimeAsync(10_000);
      expect(await runner.run(request)).toMatchObject({ ok: true, provider: 'codex' });
      expect(probes).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });

  it('starts a new check once a probe that never answers has timed out', async () => {
    vi.useFakeTimers();
    try {
      let probes = 0;
      const codex = fake('codex', () => ({
        kind: 'ok',
        json: { verdict: 'benign', summary: 'ok' },
        audit: audit(),
      }));
      codex.probe = () =>
        ++probes === 1
          ? new Promise(() => {})
          : Promise.resolve({ provider: 'codex', state: 'ready' });
      const { runner } = setup([codex], { order: ['codex'] });
      const first = runner.run({ ...request, deadlineMs: 600_000 });
      await vi.advanceTimersByTimeAsync(PROBE_DEADLINE_MS + 1);
      expect(await first).toMatchObject({ ok: false });
      await vi.advanceTimersByTimeAsync(10 * 60_000);
      const second = runner.run({ ...request, deadlineMs: 600_000 });
      await vi.advanceTimersByTimeAsync(1);
      expect(await second).toMatchObject({ ok: true });
      expect(probes).toBe(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('keeps a check started before sign-in finished from deciding after it', async () => {
    let signedIn = false;
    let probes = 0;
    const releases: (() => void)[] = [];
    let finish!: (ok: boolean) => void;
    const codex = fake('codex', () => ({ kind: 'error', message: 'x', audit: audit() }));
    codex.probe = () => {
      probes++;
      const state = signedIn ? 'ready' : 'needs_sign_in';
      return new Promise((r) => releases.push(() => r({ provider: 'codex', state })));
    };
    codex.signIn = async () => ({
      url: 'https://example.com',
      completed: new Promise<boolean>((r) => (finish = r)),
      cancel: () => {},
    });
    const { runner } = setup([codex], { order: ['codex'] });
    await runner.signIn('codex');
    const before = runner.status(); // a check while signing in
    await Promise.resolve();
    signedIn = true;
    finish(true);
    await new Promise((r) => setTimeout(r, 0));
    const after = runner.status(); // the refresh once signed in
    for (const r of releases) r();
    await before;
    expect((await after)[0]?.state).toBe('ready');
    expect(probes).toBe(2);
    // Nor did the earlier answer land in the cache: a run finds Codex ready.
    expect(await runner.run(request)).toMatchObject({ ok: false, reason: 'error' });
    expect(codex.inputs).toHaveLength(1);
  });

  it('reports no_provider when nothing is set up', async () => {
    const { runner, log } = setup([]);
    expect(await runner.run(request)).toMatchObject({ ok: false, reason: 'no_provider' });
    expect(log[0]?.outcome).toBe('no_provider');
  });

  it('redacts what tools return before the model sees it', async () => {
    const tool = readTool({
      name: 'get_process',
      description: 'Process details',
      input: { pid: z.number() },
      run: async ({ pid }) => ({ pid, exe: '/Users/alexm/bin/x', owner: 'me@example.com' }),
    });
    let seen = '';
    const claude = fake('claude', async (input) => {
      seen = JSON.stringify(await input.tools[0]!.run({ pid: 4 }));
      return { kind: 'ok', json: { verdict: 'benign', summary: 'x' }, audit: audit() };
    });
    const { runner } = setup([claude]);
    await runner.run({ ...request, tools: [tool] });
    expect(seen).toContain('/Users/<user>/bin/x');
    expect(seen).not.toContain('me@example.com');
  });

  it('runs no tool and takes no usage from a model still working after the deadline', async () => {
    let toolRuns = 0;
    let seenSignal: AbortSignal | undefined;
    const tool = readTool({
      name: 'get_process',
      description: 'Process details',
      input: { pid: z.number() },
      run: async (_args, run) => {
        toolRuns++;
        seenSignal = run?.signal;
        return {};
      },
    });
    let late!: (input: AdapterRunInput) => Promise<void>;
    const claude = fake('claude', () => {
      late = async (i) => {
        i.onUsage({ provider: 'claude', windowId: 'five_hour', usedPercent: 5, resetsAt: 1 });
        await i.tools[0]!.run({ pid: 1 });
      };
      return new Promise<AdapterRunOutput>(() => {});
    });
    const { runner } = setup([claude], { order: ['claude'] });
    runner.quota.observe({
      provider: 'claude',
      windowId: 'five_hour',
      usedPercent: 95,
      resetsAt: Date.now() + 3_600_000,
    });
    expect(await runner.run({ ...request, tools: [tool], deadlineMs: 20 })).toMatchObject({
      reason: 'timeout',
    });
    await expect(late(claude.inputs[0]!)).rejects.toThrow('deadline passed');
    expect(toolRuns).toBe(0);
    expect(runner.quota.snapshot('claude').get('five_hour')?.usedPercent).toBe(95);
    // A tool the run did call is handed the run's signal.
    const ok = fake('claude', async (input) => {
      await input.tools[0]!.run({ pid: 2 });
      return { kind: 'ok', json: { verdict: 'benign', summary: 'x' }, audit: audit() };
    });
    await setup([ok]).runner.run({ ...request, tools: [tool] });
    expect(seenSignal).toBeInstanceOf(AbortSignal);
  });

  it("keeps background work within Vigil's share of the window", async () => {
    let used = 0;
    const resetsAt = Date.now() + 3_600_000;
    const claude = fake('claude', (input) => {
      used += 6;
      input.onUsage({ provider: 'claude', windowId: 'five_hour', usedPercent: used, resetsAt });
      return { kind: 'ok', json: { verdict: 'benign', summary: 'x' }, audit: audit() };
    });
    const { runner } = setup([claude], { order: ['claude'] });
    const bg = { ...request, urgency: 'background' as const };
    // First run establishes the window; the next two each use 6%, crossing the 10% share.
    await runner.run(bg);
    await runner.run(bg);
    await runner.run(bg);
    expect(await runner.run(bg)).toMatchObject({ ok: false, reason: 'quota' });
    // Urgent work still runs.
    expect(await runner.run(request)).toMatchObject({ ok: true });
  });
});

describe('quota tracker', () => {
  it('unblocks a rejected provider once its window resets', () => {
    let t = 1_000;
    const q = new QuotaTracker(10, () => t);
    q.observe({
      provider: 'codex',
      windowId: 'p',
      usedPercent: 100,
      rejected: true,
      resetsAt: 5_000,
    });
    expect(q.allowNow('codex')).toBe(false);
    t = 6_000;
    expect(q.allowNow('codex')).toBe(true);
  });

  it('stops background work near a full window even if Vigil used little of it', () => {
    const q = new QuotaTracker(10, () => 0);
    q.observe({ provider: 'claude', windowId: 'seven_day', usedPercent: 93, resetsAt: 10_000 });
    expect(q.allowBackground('claude')).toBe(false);
    expect(q.allowNow('claude')).toBe(true);
  });
});

describe('finding AI apps', () => {
  it('offers sign-in only for providers Vigil can sign in itself', async () => {
    const codex: ProviderAdapter = {
      ...fake('codex', () => ({ kind: 'error', message: 'x', audit: audit() }), 'needs_sign_in'),
      signIn: async () => ({
        url: 'https://example.test',
        completed: Promise.resolve(true),
        cancel: () => {},
      }),
    };
    const claude = fake(
      'claude',
      () => ({ kind: 'error', message: 'x', audit: audit() }),
      'needs_sign_in',
    );
    const { runner } = setup([claude, codex]);
    const status = await runner.status();
    expect(status.find((s) => s.provider === 'codex')?.canSignIn).toBe(true);
    expect(status.find((s) => s.provider === 'claude')?.canSignIn).toBeUndefined();
    await expect(runner.signIn('claude')).rejects.toThrow();
    expect((await runner.signIn('codex')).url).toBe('https://example.test');
  });

  it('reports when an app is installed or signed in, and only then', async () => {
    let state: ProviderState = 'not_installed';
    const adapter: ProviderAdapter = {
      id: 'ollama',
      probe: async () => ({ provider: 'ollama', state }),
      run: async () => ({ kind: 'error', message: 'x', audit: audit() }),
    };
    const { runner } = setup([adapter], { order: ['ollama'] });
    const seen: AiAppsSnapshot[] = [];
    const stop = watchAiApps(runner, {
      intervalMs: 5,
      findCopilot: async () => '/opt/homebrew/bin/copilot',
      onChange: (s) => seen.push(s),
    });
    await vi.waitFor(() => expect(seen).toHaveLength(1));
    await new Promise((r) => setTimeout(r, 30));
    expect(seen).toHaveLength(1);
    state = 'ready';
    await vi.waitFor(() => expect(seen).toHaveLength(2));
    stop();
    expect(seen[0]?.copilot).toEqual({ installed: true, supported: false });
    expect(seen.map((s) => s.providers[0]?.state)).toEqual(['not_installed', 'ready']);
  });
});

describe('what a Claude run is billed to', () => {
  const ok = (): AdapterRunOutput => ({
    kind: 'ok',
    json: { verdict: 'benign', summary: 'ok' },
    audit: audit(),
    usage: { inputTokens: 1, cachedInputTokens: 0, outputTokens: 1, costUsd: 0.01 },
  });
  const claudeWith = (account: string | undefined) => ({
    ...fake('claude', ok),
    probe: async () => ({
      provider: 'claude' as const,
      state: 'ready' as const,
      ...(account ? { account } : {}),
    }),
  });
  const billedFor = async (account: string | undefined, patch: Partial<AiSettings> = {}) => {
    const { runner, log } = setup([claudeWith(account)], { order: ['claude'], ...patch });
    await runner.run(request);
    return log[0] && 'billed' in log[0] ? log[0].billed : 'absent';
  };

  it('is the plan on a claude.ai login, and unknown on any other', async () => {
    const s = defaultAiSettings('/tmp/vigil-test');
    const sub = { claude: { ...s.claude, mode: 'subscription' as const, allowPlan: true } };
    expect(await billedFor('claude.ai', sub)).toBe(false);
    expect(await billedFor('console', sub)).toBe('absent');
    expect(await billedFor(undefined, sub)).toBe('absent');
  });

  it('is the saved key in API key mode', async () => {
    const s = defaultAiSettings('/tmp/vigil-test');
    expect(
      await billedFor('claude.ai', { claude: { ...s.claude, mode: 'apiKey', allowPlan: false } }),
    ).toBe(true);
  });
});
