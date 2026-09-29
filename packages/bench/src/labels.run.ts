/**
 * How well the event labeller separates attacks the rules missed from normal
 * activity. Advisory only in Vigil (a label never blocks), so the questions
 * are: does it flag the misses, and how often does it cry wolf?
 *
 *   VIGIL_BENCH_LABELLER=ollama VIGIL_OLLAMA_MODEL=qwen2.5:0.5b pnpm --filter @vigil/bench bench:labels
 *   VIGIL_BENCH_LABELLER=jev TYPESAFE_API_KEY=... pnpm --filter @vigil/bench bench:labels
 *
 * Without VIGIL_BENCH_LABELLER it only writes the coverage table (which
 * missed attacks would reach the labeller at all).
 */
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import {
  classifierRuntime,
  createAiRunner,
  createClaudeAdapter,
  createEventClassifier,
  createJevClient,
  createOllamaAdapter,
  defaultAiSettings,
  eventLine,
  memoryPinStore,
  type LabelledEvent,
  type PromptLogEntry,
} from '@vigil/ai';
import { describe, expect, it } from 'vitest';
import { labelSet, type LabelSet } from './labels.js';
import { writeResult } from './report.js';

const which = process.env['VIGIL_BENCH_LABELLER'] ?? '';
const BATCH = 20; // the app's maxEventsPerBatch

function classifier(log: PromptLogEntry[], instructions?: string) {
  const record = { record: (e: PromptLogEntry) => void log.push(e) };
  if (which === 'jev') {
    return createEventClassifier({
      jev: createJevClient({
        getApiKey: async () => process.env['TYPESAFE_API_KEY'] || undefined,
        getOpenRouterApiKey: async () => process.env['OPENROUTER_API_KEY'] || undefined,
        log: record,
        timeoutMs: 60_000,
      }),
      maxEventsPerBatch: BATCH,
      maxBatchesPerHour: 10_000,
      ...(instructions ? { instructions } : {}),
    });
  }
  if (which === 'claude') {
    // Claude on an API key (ANTHROPIC_API_KEY) as the labeller, for a reference point.
    const model = process.env['VIGIL_CLAUDE_MODEL'] || undefined;
    return createEventClassifier({
      runner: createAiRunner({
        settings: {
          ...defaultAiSettings('/tmp/vigil-bench'),
          mode: 'both',
          order: ['claude'],
          quota: { backgroundSharePercent: 100 },
        },
        adapters: [
          createClaudeAdapter({
            // Unattended runs need an API key: a Claude plan only explains alerts the
            // user asks about (see mayUsePlan in packages/ai).
            mode: 'apiKey',
            getApiKey: async () => process.env['ANTHROPIC_API_KEY'],
            pins: memoryPinStore(),
            ...(model ? { model } : {}),
          }),
        ],
        log: record,
      }),
      maxEventsPerBatch: BATCH,
      maxBatchesPerHour: 10_000,
      deadlineMs: 300_000,
      ...(instructions ? { instructions } : {}),
    });
  }
  const runtime = classifierRuntime();
  return createEventClassifier({
    runner: createAiRunner({
      settings: { ...defaultAiSettings('/tmp/vigil-bench'), mode: 'local', order: ['ollama'] },
      adapters: [
        createOllamaAdapter({
          baseUrl: process.env['OLLAMA_HOST'] ?? 'http://127.0.0.1:11434',
          model: process.env['VIGIL_OLLAMA_MODEL'] ?? 'qwen2.5:0.5b',
          runtime,
        }),
      ],
      log: record,
    }),
    maxEventsPerBatch: BATCH,
    maxBatchesPerHour: 10_000,
    deadlineMs: 300_000,
    ...(instructions ? { instructions } : {}),
  });
}

/**
 * Prompt variants to compare with the shipped one: every .txt in
 * VIGIL_LABEL_PROMPTS (a folder), or in prompts/labeller when that exists.
 * Each runs on the train and held-out sets.
 */
function variants(): Array<{ name: string; instructions?: string }> {
  const dir =
    process.env['VIGIL_LABEL_PROMPTS'] ?? join(import.meta.dirname, '../prompts/labeller');
  const extra = existsSync(dir)
    ? readdirSync(dir)
        .filter((f) => f.endsWith('.txt'))
        .sort()
        .map((f) => ({
          name: f.slice(0, -4),
          instructions: readFileSync(join(dir, f), 'utf8').trim(),
        }))
    : [];
  return [{ name: 'shipped' }, ...extra];
}

async function labelAll(set: LabelSet, instructions?: string) {
  const log: PromptLogEntry[] = [];
  const c = classifier(log, instructions);
  const labels = new Map<string, LabelledEvent>();
  const batches: Array<{ seconds: number; ok: boolean; detail?: string }> = [];
  for (let i = 0; i < set.cases.length; i += BATCH) {
    const batch = set.cases.slice(i, i + BATCH).map((x) => x.event);
    const t0 = Date.now();
    const r = await c.classify(batch);
    batches.push({
      seconds: (Date.now() - t0) / 1000,
      ok: r.ok,
      ...(!r.ok && r.detail ? { detail: r.detail } : {}),
    });
    if (r.ok) for (const l of r.labels) labels.set(l.eventId, l);
  }
  const rows = set.cases.map((x) => ({
    source: x.source,
    truth: x.truth,
    appSends: x.appSends,
    kind: x.event.kind,
    line: eventLine(x.event).slice(0, 200),
    label: labels.get(x.event.id)?.label ?? null,
  }));
  const labelled = rows.filter((r) => r.label !== null);
  const attacks = labelled.filter((r) => r.truth === 'attack');
  const benign = labelled.filter((r) => r.truth === 'benign');
  const flagged = (xs: typeof rows) => xs.filter((r) => r.label && r.label !== 'benign').length;
  const suspicious = (xs: typeof rows) => xs.filter((r) => r.label === 'suspicious').length;
  const tp = flagged(attacks);
  const fp = flagged(benign);
  return {
    cases: rows.length,
    labelled: labelled.length,
    attacks: attacks.length,
    benign: benign.length,
    // "Flagged" means unusual or suspicious: anything shown as a hint.
    recall: attacks.length ? tp / attacks.length : null,
    recallSuspicious: attacks.length ? suspicious(attacks) / attacks.length : null,
    falseFlagRate: benign.length ? fp / benign.length : null,
    falseSuspiciousRate: benign.length ? suspicious(benign) / benign.length : null,
    precision: tp + fp ? tp / (tp + fp) : null,
    batches,
    secondsPerBatch: batches.reduce((a, b) => a + b.seconds, 0) / Math.max(1, batches.length),
    tokens: {
      input: log.reduce((a, e) => a + (e.usage?.inputTokens ?? 0), 0),
      output: log.reduce((a, e) => a + (e.usage?.outputTokens ?? 0), 0),
    },
    costUsd: log.reduce((a, e) => a + (e.usage?.costUsd ?? 0), 0),
    rows,
  };
}

describe('event labelling benchmark', () => {
  const set = labelSet();
  const heldout = labelSet({ split: 'heldout' });

  it('writes which missed attacks reach the labeller', () => {
    writeResult('label-coverage', {
      at: new Date().toISOString(),
      coverage: set.coverage,
      heldoutCoverage: heldout.coverage,
    });
  });

  it.skipIf(!which)(
    `labels the test sets with ${which || 'nothing'}`,
    async () => {
      const model =
        which === 'jev'
          ? 'jev'
          : which === 'claude'
            ? `claude-${process.env['VIGIL_CLAUDE_MODEL'] || 'default'}`
            : (process.env['VIGIL_OLLAMA_MODEL'] ?? 'qwen2.5:0.5b');
      const slug = model.replace(/[^a-z0-9.]+/gi, '-');
      let labelled = 0;
      for (const v of variants()) {
        const suffix = v.name === 'shipped' ? '' : `-${v.name}`;
        const train = await labelAll(set, v.instructions);
        labelled += train.labelled;
        writeResult(`labels-${slug}${suffix}`, {
          at: new Date().toISOString(),
          model,
          prompt: v.name,
          split: 'train',
          platform: `${process.platform}-${process.arch}`,
          ...train,
        });
        // Held-out: totals only. Tuning reads train rows, never these.
        const { rows: _rows, ...ho } = await labelAll(heldout, v.instructions);
        writeResult(`labels-${slug}${suffix}-heldout`, {
          at: new Date().toISOString(),
          model,
          prompt: v.name,
          split: 'heldout',
          ...ho,
        });
      }
      expect(labelled).toBeGreaterThan(0);
    },
    90 * 60_000,
  );
});
