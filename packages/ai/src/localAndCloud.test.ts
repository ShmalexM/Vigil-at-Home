import type { SensorEvent } from '@vigil/core';
import { describe, expect, it, vi } from 'vitest';
import { z } from 'zod';
import {
  classifierRuntime,
  createEventClassifier,
  eventLine,
  pickClassifierModel,
  recommendedClassifierModel,
} from './classifier.js';
import { createVigilAi } from './index.js';
import { memoryPinStore } from './executable.js';
import { createJevClient } from './providers/jev.js';
import { createOllamaAdapter } from './providers/ollama.js';
import { createApiAdapter, isSafeBaseUrl } from './providers/openaiCompatible.js';
import { createAiRunner } from './runner.js';
import { defaultAiSettings } from './settings.js';
import { readTool } from './tools.js';
import type { AdapterRunInput, PromptLogEntry, ProviderAdapter, ProviderId } from './types.js';

const GB = 1024 ** 3;
const audit = () => ({ called: [], denied: [] });

function ready(id: ProviderId, json: unknown = { ok: true }): ProviderAdapter & { runs: number } {
  const a = {
    id,
    runs: 0,
    probe: async () => ({ provider: id, state: 'ready' as const }),
    run: async () => {
      a.runs++;
      return { kind: 'ok' as const, json, audit: audit() };
    },
  };
  return a;
}

const ask = {
  purpose: 'explain' as const,
  urgency: 'now' as const,
  instructions: 'x',
  data: {},
  output: z.object({ ok: z.boolean() }),
  deadlineMs: 1_000,
};

describe('local, cloud or both', () => {
  it('keeps everything on this Mac in local mode', async () => {
    const claude = ready('claude');
    const ollama = ready('ollama');
    const runner = createAiRunner({
      settings: { ...defaultAiSettings('/tmp/v'), mode: 'local' },
      adapters: [claude, ollama],
      log: { record: () => {} },
    });
    expect((await runner.run(ask)).ok).toBe(true);
    expect([claude.runs, ollama.runs]).toEqual([0, 1]);
    expect((await runner.status()).find((s) => s.provider === 'claude')?.state).toBe('disabled');
  });

  it('never uses the local model in cloud mode', async () => {
    const ollama = ready('ollama');
    const runner = createAiRunner({
      settings: { ...defaultAiSettings('/tmp/v'), mode: 'cloud' },
      adapters: [ollama],
      log: { record: () => {} },
    });
    expect(await runner.run(ask)).toMatchObject({ ok: false, reason: 'no_provider' });
    expect(ollama.runs).toBe(0);
  });

  it('stops the API connection once the monthly cap is spent', async () => {
    const api = ready('api');
    const base = defaultAiSettings('/tmp/v');
    const runner = createAiRunner({
      settings: { ...base, order: ['api'], quota: { ...base.quota, apiKeyMonthlyCapUsd: 5 } },
      adapters: [api],
      log: { record: () => {} },
      spentThisMonthUsd: async () => 5,
    });
    expect(await runner.run(ask)).toMatchObject({ ok: false, reason: 'quota' });
    expect(api.runs).toBe(0);
  });

  it('lets a request name the providers it may use', async () => {
    const claude = ready('claude');
    const ollama = ready('ollama');
    const runner = createAiRunner({
      settings: defaultAiSettings('/tmp/v'),
      adapters: [claude, ollama],
      log: { record: () => {} },
    });
    await runner.run({ ...ask, providers: ['ollama'] });
    expect([claude.runs, ollama.runs]).toEqual([0, 1]);
  });
});

describe('a local model', () => {
  it('asks again when a reply is cut off instead of failing', async () => {
    const replies = ['{"ok": tr', '{"ok": true}'];
    const prompts: string[] = [];
    const ollama = createOllamaAdapter({
      baseUrl: 'http://127.0.0.1:11434',
      model: 'm',
      fetch: (async (url: string, init: RequestInit) => {
        if (url.endsWith('/api/tags')) return Response.json({ models: [{ name: 'm' }] });
        if (url.endsWith('/api/show')) return Response.json({ capabilities: ['tools'] });
        const body = JSON.parse(String(init.body)) as {
          messages: Array<{ content: string }>;
          options: { temperature: number };
        };
        prompts.push(body.messages.at(-1)!.content);
        expect(body.options.temperature).toBe(0.2);
        return Response.json({ message: { role: 'assistant', content: replies.shift() } });
      }) as unknown as typeof fetch,
    });
    const log: PromptLogEntry[] = [];
    const runner = createAiRunner({
      settings: { ...defaultAiSettings('/tmp/v'), order: ['ollama'] },
      adapters: [ollama],
      log: { record: (e) => log.push(e) },
    });
    expect(await runner.run(ask)).toMatchObject({ ok: true, value: { ok: true } });
    expect(log.map((e) => e.outcome)).toEqual(['invalid_output', 'ok']);
    expect(prompts[1]).toContain('did not match the required format');
  });
});

describe('OpenAI-style API', () => {
  it('only sends a key over https or to this Mac', () => {
    expect(isSafeBaseUrl('https://openrouter.ai/api/v1')).toBe(true);
    expect(isSafeBaseUrl('http://127.0.0.1:4000/v1')).toBe(true);
    expect(isSafeBaseUrl('http://example.com/v1')).toBe(false);
    expect(isSafeBaseUrl('https://user:pw@example.com/v1')).toBe(false);
    expect(isSafeBaseUrl('not a url')).toBe(false);
  });

  it('says what setup is missing', async () => {
    const noKey = createApiAdapter({
      baseUrl: 'https://x.test/v1',
      getApiKey: async () => undefined,
    });
    expect(await noKey.probe()).toMatchObject({ state: 'needs_setup', detail: 'Add an API key.' });
    const noModel = createApiAdapter({ baseUrl: 'https://x.test/v1', getApiKey: async () => 'k' });
    expect(await noModel.probe()).toMatchObject({
      state: 'needs_setup',
      detail: 'Choose a model.',
    });
    const http = createApiAdapter({
      baseUrl: 'http://x.test/v1',
      model: 'm',
      getApiKey: async () => 'k',
    });
    expect((await http.probe()).state).toBe('needs_setup');
  });

  it("runs Vigil's tools itself, refuses others, and reports tokens and cost", async () => {
    const bodies: Array<Record<string, unknown>> = [];
    const auth: string[] = [];
    const replies = [
      {
        choices: [
          {
            message: {
              role: 'assistant',
              content: null,
              tool_calls: [
                {
                  id: 'c1',
                  type: 'function',
                  function: { name: 'run_shell', arguments: '{"cmd":"id"}' },
                },
                {
                  id: 'c2',
                  type: 'function',
                  function: { name: 'get_finding', arguments: '{"id":"f1"}' },
                },
              ],
            },
          },
        ],
        usage: {
          prompt_tokens: 100,
          completion_tokens: 10,
          prompt_tokens_details: { cached_tokens: 40 },
          cost: 0.001,
        },
      },
      {
        choices: [{ message: { role: 'assistant', content: '{"summary":"done"}' } }],
        usage: { prompt_tokens: 150, completion_tokens: 5, cost: 0.002 },
      },
    ];
    const api = createApiAdapter({
      baseUrl: 'https://openrouter.ai/api/v1/',
      model: 'some/model',
      getApiKey: async () => 'sk-test',
      fetch: (async (url: string, init: RequestInit) => {
        expect(url).toBe('https://openrouter.ai/api/v1/chat/completions');
        auth.push(String((init.headers as Record<string, string>).authorization));
        bodies.push(JSON.parse(String(init.body)));
        return Response.json(replies.shift());
      }) as typeof fetch,
    });
    const out = await api.run({
      systemPrompt: 's',
      userPrompt: 'u',
      jsonSchema: { type: 'object' },
      tools: [
        readTool({
          name: 'get_finding',
          description: 'Read one finding',
          input: { id: z.string() },
          run: async ({ id }) => ({ id }),
        }),
      ],
      signal: new AbortController().signal,
      onUsage: () => {},
    } satisfies AdapterRunInput);
    expect(out).toMatchObject({
      kind: 'ok',
      json: { summary: 'done' },
      audit: { called: ['get_finding'], denied: ['tool: run_shell'] },
    });
    expect(out.usage?.inputTokens).toBe(210);
    expect(out.usage?.cachedInputTokens).toBe(40);
    expect(out.usage?.outputTokens).toBe(15);
    expect(out.usage?.costUsd).toBeCloseTo(0.003);
    expect(auth).toEqual(['Bearer sk-test', 'Bearer sk-test']);
    expect(bodies[0]).toMatchObject({
      model: 'some/model',
      response_format: { type: 'json_schema', json_schema: { strict: true } },
    });
    const toolMessages = (bodies[1]!.messages as Array<{ role: string; content: string }>).filter(
      (m) => m.role === 'tool',
    );
    expect(toolMessages.map((m) => m.content)).toEqual(['Not allowed.', '{"id":"f1"}']);
  });

  it('treats an empty balance or a rate limit as quota', async () => {
    const api = createApiAdapter({
      baseUrl: 'https://x.test/v1',
      model: 'm',
      getApiKey: async () => 'k',
      fetch: (async () => new Response('{}', { status: 402 })) as unknown as typeof fetch,
    });
    const out = await api.run({
      systemPrompt: 's',
      userPrompt: 'u',
      jsonSchema: {},
      tools: [],
      signal: new AbortController().signal,
      onUsage: () => {},
    });
    expect(out.kind).toBe('quota');
  });

  it('lists models with what they support, for setup', async () => {
    const api = createApiAdapter({
      baseUrl: 'https://x.test/v1',
      getApiKey: async () => 'k',
      fetch: (async () =>
        Response.json({
          data: [
            { id: 'a', name: 'A', supported_parameters: ['tools', 'structured_outputs'] },
            { id: 'b' },
          ],
        })) as unknown as typeof fetch,
    });
    expect(await api.listModels()).toEqual([
      { id: 'a', name: 'A', supportsTools: true, supportsStructuredOutput: true },
      { id: 'b' },
    ]);
  });
});

const exec = (id: string, path: string): SensorEvent => ({
  id,
  ts: 1,
  source: 'test',
  kind: 'process.exec',
  process: { pid: 1, path, signing: 'unsigned', parentPath: '/bin/zsh' },
});

describe('event labelling with a small local model', () => {
  it('picks a model that fits the memory, from what is installed', () => {
    expect(recommendedClassifierModel(8 * GB)).toBe('qwen2.5:0.5b');
    expect(recommendedClassifierModel(16 * GB)).toBe('qwen2.5:1.5b');
    const installed = [{ name: 'gpt-oss:20b' }, { name: 'llama3.2:1b' }, { name: 'qwen2.5:1.5b' }];
    expect(pickClassifierModel(installed, 16 * GB)).toBe('qwen2.5:1.5b');
    expect(pickClassifierModel(installed, 8 * GB)).toBe('llama3.2:1b');
    expect(pickClassifierModel([{ name: 'gpt-oss:20b' }], 8 * GB)).toBeUndefined();
    expect(classifierRuntime(8)).toEqual({
      numCtx: 4096,
      numPredict: 2048,
      numThread: 4,
      keepAlive: '1m',
    });
    expect(classifierRuntime(1).numThread).toBe(1);
  });

  it('writes one short line per event', () => {
    expect(eventLine(exec('e1', '/Users/Shared/.x/run'))).toBe(
      'process started /Users/Shared/.x/run [unsigned] parent=/bin/zsh',
    );
  });

  it('labels a batch, drops ids it never sent, and requeues what it skipped', async () => {
    const inputs: AdapterRunInput[] = [];
    const ollama: ProviderAdapter = {
      id: 'ollama',
      probe: async () => ({ provider: 'ollama', state: 'ready' }),
      run: async (input) => {
        inputs.push(input);
        return {
          kind: 'ok',
          json: {
            labels: [
              { id: 'e1', label: 'suspicious', score: 1.4, reason: 'hidden unsigned program' },
              { id: 'zzz', label: 'benign', score: 0, reason: 'made up' },
            ],
          },
          audit: audit(),
        };
      },
    };
    const log: PromptLogEntry[] = [];
    const runner = createAiRunner({
      settings: { ...defaultAiSettings('/tmp/v'), mode: 'local', order: ['ollama'] },
      adapters: [ollama],
      log: { record: (e) => log.push(e) },
    });
    const classifier = createEventClassifier({
      runner,
      maxEventsPerBatch: 2,
      maxBatchesPerHour: 10,
    });
    const result = await classifier.classify([
      exec('e1', '/Users/Shared/.x/run'),
      exec('e2', '/Applications/Safari.app/Contents/MacOS/Safari'),
      exec('e3', '/usr/bin/true'),
    ]);
    expect(result).toEqual({
      ok: true,
      labels: [
        {
          eventId: 'e1',
          label: 'suspicious',
          score: 1,
          reason: 'hidden unsigned program',
          by: 'model',
        },
      ],
      deferred: ['e2', 'e3'],
    });
    expect(inputs[0]!.userPrompt).toContain('e2 process started /Applications/Safari.app');
    expect(inputs[0]!.userPrompt).not.toContain('e3');
    // Every batch shows up in the prompt log, which is what the activity feed reads.
    expect(log.map((e) => [e.purpose, e.provider, e.outcome])).toEqual([
      ['classify', 'ollama', 'ok'],
    ]);
  });

  it('waits when the Mac is busy or the hourly budget is spent', async () => {
    const ollama = ready('ollama', { labels: [] });
    const runner = createAiRunner({
      settings: { ...defaultAiSettings('/tmp/v'), order: ['ollama'] },
      adapters: [ollama],
      log: { record: () => {} },
    });
    let busy = true;
    let now = 0;
    const classifier = createEventClassifier({
      runner,
      maxEventsPerBatch: 5,
      maxBatchesPerHour: 1,
      isBusy: () => busy,
      now: () => now,
    });
    expect(await classifier.classify([exec('e1', '/a')])).toMatchObject({
      ok: false,
      reason: 'busy',
      deferred: ['e1'],
    });
    busy = false;
    expect((await classifier.classify([exec('e1', '/a')])).ok).toBe(true);
    expect(await classifier.classify([exec('e2', '/b')])).toMatchObject({ reason: 'budget' });
    now += 3_600_001;
    expect((await classifier.classify([exec('e2', '/b')])).ok).toBe(true);
    expect(ollama.runs).toBe(2);
  });

  it('comes with the AI when labelling is on', () => {
    const ai = createVigilAi({
      settings: defaultAiSettings('/tmp/v'),
      log: { record: () => {} },
      pins: memoryPinStore(),
    });
    expect(ai.classifier).toBeDefined();
    const off = createVigilAi({
      settings: {
        ...defaultAiSettings('/tmp/v'),
        classifier: { ...defaultAiSettings('/tmp/v').classifier, enabled: false },
      },
      log: { record: () => {} },
      pins: memoryPinStore(),
    });
    expect(off.classifier).toBeUndefined();
  });
});

describe('Jev as the event labeller', () => {
  const jevReply = {
    model: 'jev-1.13.0',
    answers: {
      e1: {
        type: 'choice',
        choice: 'suspicious',
        probabilities: { benign: 0.1, unusual: 0.2, suspicious: 0.7 },
        confidence: 0.64,
      },
      e2: {
        type: 'choice',
        choice: 'benign',
        probabilities: { benign: 0.96, unusual: 0.04, suspicious: 0 },
        confidence: 0.9,
      },
      e9: { type: 'choice', choice: 'suspicious', probabilities: {}, confidence: 1 },
    },
    usage: { input_tokens: 1000, output_tokens: 20 },
  };

  function jevFetch(reply: unknown, status = 200) {
    const calls: Array<{ url: string; auth: string; body: Record<string, unknown> }> = [];
    const f = (async (url: string, init: RequestInit) => {
      calls.push({
        url,
        auth: String((init.headers as Record<string, string>).authorization),
        body: JSON.parse(String(init.body)),
      });
      return status === 200 ? Response.json(reply) : new Response('{}', { status });
    }) as unknown as typeof fetch;
    return { f, calls };
  }

  it('asks one choice question per event and turns probabilities into labels', async () => {
    const { f, calls } = jevFetch(jevReply);
    const log: PromptLogEntry[] = [];
    const jev = createJevClient({
      getApiKey: async () => 'ts-key',
      log: { record: (e) => log.push(e) },
      fetch: f,
    });
    const local = ready('ollama', { labels: [] });
    const classifier = createEventClassifier({
      jev,
      runner: createAiRunner({
        settings: { ...defaultAiSettings('/tmp/v'), order: ['ollama'] },
        adapters: [local],
        log: { record: () => {} },
      }),
      maxEventsPerBatch: 5,
      maxBatchesPerHour: 5,
    });
    const result = await classifier.classify([
      exec('evt-a', '/Users/Shared/.x/run'),
      exec('evt-b', '/usr/bin/true'),
      exec('evt-c', '/bin/ls'),
    ]);

    expect(calls[0]!.url).toBe('https://api.typesafe.ai/v1/systemone');
    expect(calls[0]!.auth).toBe('Bearer ts-key');
    expect(calls[0]!.body).toMatchObject({
      model: 'jev-latest',
      state: { e1: 'process started /Users/Shared/.x/run [unsigned] parent=/bin/zsh' },
      questions: { e1: { type: 'choice', criteria: { benign: expect.any(String) } } },
    });
    expect(Object.keys(calls[0]!.body.questions as object)).toEqual(['e1', 'e2', 'e3']);
    expect(result).toMatchObject({
      ok: true,
      labels: [
        {
          eventId: 'evt-a',
          label: 'suspicious',
          by: 'jev',
          reason: 'Jev: 70% suspicious, confidence 0.64',
        },
        { eventId: 'evt-b', label: 'benign', by: 'jev' },
      ],
      deferred: ['evt-c'],
    });
    if (result.ok) expect(result.labels[0]!.score).toBeCloseTo(0.8);
    expect(local.runs).toBe(0);
    expect(log[0]).toMatchObject({ provider: 'jev', purpose: 'classify', outcome: 'ok' });
    expect(log[0]!.usage?.costUsd).toBeCloseTo(0.000042);
  });

  it('falls back to the local model when Jev refuses the key, is busy, or the cap is spent', async () => {
    for (const [status, allowed] of [
      [401, true],
      [529, true],
      [200, false],
    ] as const) {
      const { f, calls } = jevFetch(jevReply, status);
      const local = ready('ollama', {
        labels: [{ id: 'evt-a', label: 'unusual', score: 0.5, reason: 'odd place' }],
      });
      const classifier = createEventClassifier({
        jev: createJevClient({ getApiKey: async () => 'k', log: { record: () => {} }, fetch: f }),
        jevAllowed: async () => allowed,
        runner: createAiRunner({
          settings: { ...defaultAiSettings('/tmp/v'), order: ['ollama'] },
          adapters: [local],
          log: { record: () => {} },
        }),
        maxEventsPerBatch: 5,
        maxBatchesPerHour: 5,
      });
      const result = await classifier.classify([exec('evt-a', '/Users/Shared/.x/run')]);
      expect(result).toMatchObject({ ok: true, labels: [{ eventId: 'evt-a', by: 'model' }] });
      expect(calls.length).toBe(allowed ? 1 : 0);
      expect(local.runs).toBe(1);
    }
  });

  it('never sends events without a key, or over plain http', async () => {
    const { f, calls } = jevFetch(jevReply);
    const noKey = createJevClient({
      getApiKey: async () => undefined,
      log: { record: () => {} },
      fetch: f,
    });
    expect(await noKey.label([{ id: 'a', line: 'x' }])).toEqual({
      ok: false,
      detail: 'Add a TypeSafe API key.',
    });
    const http = createJevClient({
      baseUrl: 'http://api.typesafe.ai/v1',
      getApiKey: async () => 'k',
      log: { record: () => {} },
      fetch: f,
    });
    expect((await http.label([{ id: 'a', line: 'x' }])).ok).toBe(false);
    expect(calls).toHaveLength(0);
  });

  it('is never used in local mode', async () => {
    const hosts: string[] = [];
    vi.stubGlobal('fetch', async (url: string) => {
      hosts.push(new URL(url).host);
      return new URL(url).host === 'api.typesafe.ai'
        ? Response.json(jevReply)
        : new Response('{}', { status: 503 });
    });
    try {
      const base = defaultAiSettings('/tmp/v');
      const opts = {
        log: { record: () => {} },
        pins: memoryPinStore(),
        getJevApiKey: async () => 'k',
      };
      const events = [exec('evt-a', '/Users/Shared/.x/run')];
      await createVigilAi({ ...opts, settings: { ...base, mode: 'local' } }).classifier!.classify(
        events,
      );
      expect(hosts).not.toContain('api.typesafe.ai');
      const both = await createVigilAi({ ...opts, settings: base }).classifier!.classify(events);
      expect(hosts).toContain('api.typesafe.ai');
      expect(both).toMatchObject({ ok: true, labels: [{ by: 'jev' }] });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
