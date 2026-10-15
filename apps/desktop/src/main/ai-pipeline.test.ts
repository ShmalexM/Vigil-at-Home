import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { AiBridge, type KeySource } from './ai.js';
import { AgentService } from './agents/service.js';
import { DryRunExecutor } from './executor.js';
import { VigilCore } from './service.js';
import { makeExec, makeRule, memoryStore } from './testing.js';
import type { Detector } from './detection.js';
import type { ApiKeyProvider } from '../shared/setup.js';

/**
 * The whole AI path as the app wires it: VigilCore, the real @vigil/ai
 * runner and classifier, and the network faked at fetch. A raised alert must
 * reach an AI and land in ai_runs, unmatched events must be labelled, and when
 * the runs can't reach an AI the Agents page must say why instead of going quiet.
 */

const NOW = new Date(2026, 9, 2, 22, 0, 0).getTime();
const HOUR = 3_600_000;
const unmatched = { checked: 21, matches: [] };

function keys(saved: Partial<Record<ApiKeyProvider, string>>): KeySource {
  return {
    list: () =>
      Object.fromEntries(Object.entries(saved).map(([p, k]) => [p, { last4: k!.slice(-4) }])),
    get: (p) => (saved[p] ? { key: saved[p]! } : undefined),
  };
}

/** Ollama on 127.0.0.1:11434 (when `ollama`), and Jev's API. */
function network(o: { ollama: boolean }) {
  const hits: string[] = [];
  vi.stubGlobal('fetch', async (input: string | URL, init?: RequestInit) => {
    const url = String(input);
    hits.push(url);
    if (url.startsWith('http://127.0.0.1:11434')) {
      if (!o.ollama) throw new TypeError('fetch failed');
      if (url.endsWith('/api/tags'))
        return Response.json({ models: [{ name: 'qwen3:8b', size: 5e9 }] });
      if (url.endsWith('/api/show')) return Response.json({ capabilities: ['tools'] });
      if (url.endsWith('/api/chat')) {
        const body = JSON.parse(String(init?.body)) as { messages: { content: string }[] };
        const classify = body.messages[0]!.content.includes('label events');
        return Response.json({
          message: {
            role: 'assistant',
            content: JSON.stringify(
              classify
                ? { suspicious: [], unusual: [] }
                : { verdict: 'suspicious', summary: 'An unsigned program ran from /tmp.' },
            ),
          },
          prompt_eval_count: 10,
          eval_count: 5,
        });
      }
    }
    if (url.includes('typesafe')) {
      const body = JSON.parse(String(init?.body)) as { questions?: Record<string, unknown> };
      const answers = Object.fromEntries(
        Object.keys(body.questions ?? { e1: 1 }).map((k) => [
          k,
          {
            type: 'choice',
            choice: 'benign',
            probabilities: { benign: 0.9, unusual: 0.1, suspicious: 0 },
            confidence: 0.9,
          },
        ]),
      );
      return Response.json({ model: 'jev-1', answers, usage: { input_tokens: 100 } });
    }
    return new Response('{}', { status: 404 });
  });
  return hits;
}

function app(o: { cap?: number; now?: () => number } = {}) {
  const now = o.now ?? (() => NOW);
  const store = memoryStore();
  const core = new VigilCore(store, new DryRunExecutor(), true, now);
  const ai = new AiBridge({
    store,
    usage: core.usage,
    keys: keys({ typesafe: 'ts-key-1234' }),
    mode: () => 'both',
    dataDir: '/tmp/vigil-pipeline-test',
    openExternal: async () => {},
    now,
  });
  if (o.cap !== undefined) ai.setPrefs({ monthlyCapUsd: o.cap });
  ai.explainAlertsFrom(core);
  ai.labelEventsFrom(core);
  const agents = new AgentService({
    detector: { registry: { onChange: () => () => {} } } as unknown as Detector,
    store,
    alerts: core.alerts,
    scheduler: core.scheduler,
    resourcesPath: '/tmp/vigil-pipeline-test',
    userData: '/tmp/vigil-pipeline-test',
    now,
    heldBack: (id) => ai.heldBack(id),
  });
  return { store, core, ai, agents };
}

async function settle() {
  for (let i = 0; i < 50; i++) await new Promise((r) => setTimeout(r, 0));
}

/** A run already billed to the user's keys this month, worth `usd`. */
function spent(store: ReturnType<typeof memoryStore>, usd: number) {
  store.addAiRun({
    id: 'earlier',
    at: NOW - HOUR,
    provider: 'jev',
    purpose: 'classify',
    ok: true,
    inputTokens: 1,
    cachedInputTokens: 0,
    outputTokens: 1,
    costUsd: usd,
    billed: true,
  });
}

describe('the AI path, end to end', () => {
  beforeEach(() => vi.useRealTimers());
  afterEach(() => vi.unstubAllGlobals());

  it('explains a raised alert and labels unmatched events, every run in ai_runs', async () => {
    network({ ollama: true });
    const { store, core, ai } = app();
    const alert = await core.alerts.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [],
      notify: 'popup',
    });
    await settle();
    expect(store.getAlert(alert.id)!.ai).toMatchObject({ provider: 'ollama' });
    core.ingest(makeExec('/tmp/odd-tool'), unmatched);
    core.events.flush();
    expect(await ai.labelBatch(store)).toBe(1);
    const runs = store.listAiRuns(0);
    expect(runs.map((r) => [r.purpose, r.provider, r.ok])).toEqual([
      ['explain', 'ollama', true],
      ['classify', 'jev', true],
    ]);
    expect(ai.heldBack('explainer')).toBeUndefined();
    expect(ai.heldBack('labeller')).toBeUndefined();
  });

  it('says so on the Agents page when the monthly cap holds every run back', async () => {
    let at = NOW;
    network({ ollama: false });
    const { store, core, ai, agents } = app({ cap: 1, now: () => at });
    spent(store, 1.5);

    await core.alerts.raise({
      rule: makeRule(),
      events: [makeExec()],
      actions: [],
      notify: 'popup',
    });
    await settle();
    core.ingest(makeExec('/tmp/odd-tool'), unmatched);
    core.events.flush();
    expect(await ai.labelBatch(store)).toBe(0);
    // Nothing reached an AI, so nothing was billed or stored as a run.
    expect(store.listAiRuns(0).map((r) => r.id)).toEqual(['earlier']);

    const explainer = () => agents.listVigilHelpers().find((h) => h.id === 'explainer')!;
    const labeller = () => agents.listVigilHelpers().find((h) => h.id === 'labeller')!;
    // The explainer's line shows at once: an alert is waiting on it.
    expect(explainer().held).toEqual({ since: NOW, why: 'No AI app is ready' });
    // The labeller retries quietly for an hour before it says anything.
    expect(labeller().held).toBeUndefined();
    at = NOW + HOUR + 60_000;
    core.ingest(makeExec('/tmp/other-tool'), unmatched);
    core.events.flush();
    await ai.labelBatch(store);
    expect(labeller().held).toEqual({
      since: NOW,
      why: 'This month’s spending cap on your API keys is used up',
    });

    // The next answer clears the line.
    vi.unstubAllGlobals();
    network({ ollama: true });
    ai.setPrefs({ monthlyCapUsd: null });
    core.ingest(makeExec('/tmp/third-tool'), unmatched);
    core.events.flush();
    expect(await ai.labelBatch(store)).toBeGreaterThan(0);
    expect(labeller().held).toBeUndefined();
  });
  it('tells the page when the labeller line appears, and keeps the stronger reason', async () => {
    network({ ollama: false });
    let at = NOW;
    let busy: 'power' | 'load' | undefined;
    const store = memoryStore();
    const core = new VigilCore(store, new DryRunExecutor(), true, () => at);
    const ai = new AiBridge({
      store,
      usage: core.usage,
      keys: keys({ typesafe: 'ts-key-1234' }),
      mode: () => 'both',
      dataDir: '/tmp/vigil-pipeline-test',
      openExternal: async () => {},
      busyReason: () => busy,
      isBusy: () => busy !== undefined,
      now: () => at,
    });
    ai.setPrefs({ monthlyCapUsd: 1 });
    spent(store, 1.5);
    ai.labelEventsFrom(core);
    let changed = 0;
    ai.on('changed', () => changed++);
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    try {
      core.ingest(makeExec('/tmp/odd-tool'), unmatched);
      core.events.flush();
      await ai.labelBatch(store);
      expect(changed).toBe(0);
      // A busy Mac next: the cap stays the reason shown.
      busy = 'power';
      await ai.labelBatch(store);
      at = NOW + HOUR + 2_000;
      vi.advanceTimersByTime(HOUR + 2_000);
      expect(changed).toBe(1);
      expect(ai.heldBack('labeller')?.why).toBe(
        'This month’s spending cap on your API keys is used up',
      );
      await ai.labelBatch(store);
      expect(changed).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });
});
