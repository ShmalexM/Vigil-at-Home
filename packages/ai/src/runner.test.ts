import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { QuotaTracker } from './quota.js';
import { createAiRunner } from './runner.js';
import { defaultAiSettings, type AiSettings } from './settings.js';
import { readTool } from './tools.js';
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
    }));
    const { runner, log } = setup([claude]);
    const result = await runner.run(request);
    expect(result).toMatchObject({ ok: true, provider: 'claude', value: { verdict: 'benign' } });
    expect(log).toHaveLength(1);
    expect(log[0]?.userPrompt).toContain('/Users/<user>/Downloads/x');
    expect(log[0]?.userPrompt).not.toContain('me@example.com');
    expect(claude.inputs[0]?.jsonSchema).toMatchObject({
      type: 'object',
      required: ['verdict', 'summary'],
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
    const { runner } = setup([claude], { order: ['claude'] });
    const result = await runner.run(request);
    expect(result).toMatchObject({ ok: false, reason: 'invalid_output' });
    expect(claude.inputs).toHaveLength(2);
    expect(claude.inputs[1]?.userPrompt).toContain('did not match the required format');
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
