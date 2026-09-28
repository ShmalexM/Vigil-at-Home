/**
 * Runs one 20-event labelling batch through a real local model and prints
 * what it cost, for the speed budget in docs/performance.md.
 *
 *   VIGIL_LIVE_PROVIDERS=ollama VIGIL_OLLAMA_MODEL=qwen2.5:0.5b npm run test:live
 */
import type { SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { classifierRuntime, createEventClassifier } from '../classifier.js';
import { createOllamaAdapter } from '../providers/ollama.js';
import { createAiRunner } from '../runner.js';
import { defaultAiSettings } from '../settings.js';
import type { PromptLogEntry } from '../types.js';

const live = (process.env.VIGIL_LIVE_PROVIDERS ?? '').split(',').includes('ollama');

function exec(i: number, path: string, signing: 'apple' | 'unsigned' = 'apple'): SensorEvent {
  return {
    id: `evt-${i}`,
    ts: 1,
    source: 'test',
    kind: 'process.exec',
    process: { pid: 100 + i, path, signing, parentPath: '/sbin/launchd' },
  };
}

describe.skipIf(!live)('local event labelling', () => {
  it('labels a 20-event batch with a short answer', async () => {
    const events: SensorEvent[] = [
      exec(0, '/Users/Shared/.cache/.agent', 'unsigned'),
      ...Array.from({ length: 19 }, (_, i) =>
        exec(i + 1, ['/usr/bin/git', '/bin/zsh', '/usr/libexec/xpcproxy', '/usr/bin/ssh'][i % 4]!),
      ),
    ];
    const log: PromptLogEntry[] = [];
    const runtime = classifierRuntime();
    const classifier = createEventClassifier({
      runner: createAiRunner({
        settings: { ...defaultAiSettings('/tmp/vigil-live'), mode: 'local', order: ['ollama'] },
        adapters: [
          createOllamaAdapter({
            baseUrl: 'http://127.0.0.1:11434',
            model: process.env.VIGIL_OLLAMA_MODEL ?? 'qwen2.5:0.5b',
            runtime,
          }),
        ],
        log: { record: (e) => log.push(e) },
      }),
      maxEventsPerBatch: 20,
      maxBatchesPerHour: 60,
      deadlineMs: 240_000,
    });

    const started = Date.now();
    const result = await classifier.classify(events);
    const seconds = (Date.now() - started) / 1000;
    const out = log.reduce((sum, e) => sum + (e.usage?.outputTokens ?? 0), 0);
    console.log(
      `classify: ${seconds.toFixed(1)} s wall, ~${(seconds * runtime.numThread).toFixed(0)} CPU-s ` +
        `(${runtime.numThread} threads), ${out} output tokens, ${log.length} call(s), ` +
        `labels ${JSON.stringify(result.ok ? result.labels.filter((l) => l.label !== 'benign') : result)}`,
    );
    expect(result.ok, JSON.stringify(result)).toBe(true);
  }, 300_000);
});
