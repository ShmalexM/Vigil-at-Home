import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import { QuotaTracker } from './quota.js';
import { createAiRunner } from './runner.js';
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

  it('keeps a newer provider check over an older one that answers late', async () => {
    const claude = fake('claude', () => ({
      kind: 'ok',
      json: { verdict: 'benign', summary: 'ok' },
      audit: audit(),
    }));
    let releaseOld!: () => void;
    let calls = 0;
    claude.probe = () =>
      calls++ === 0
        ? new Promise(
            (r) => (releaseOld = () => r({ provider: 'claude', state: 'error', detail: 'old' })),
          )
        : Promise.resolve({ provider: 'claude', state: 'ready' });
    const { runner } = setup([claude]);
    expect(await runner.run({ ...request, deadlineMs: 50 })).toMatchObject({ reason: 'timeout' });
    expect(await runner.status()).toEqual([expect.objectContaining({ state: 'ready' })]);
    releaseOld();
    await new Promise((r) => setTimeout(r, 10));
    expect(await runner.run(request)).toMatchObject({ ok: true });
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
