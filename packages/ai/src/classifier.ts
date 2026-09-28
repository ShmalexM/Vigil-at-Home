import { cpus, totalmem } from 'node:os';
import type { ProcessRef, SensorEvent } from '@vigil/core';
import { z } from 'zod';
import type { JevAnswer, JevClient } from './providers/jev.js';
import { LOCAL_PROVIDERS } from './types.js';
import type { AiRunner } from './runner.js';

/**
 * Small local models that label events well enough and run on a CPU, smallest
 * first. Vigil only picks from what the user already installed.
 */
export const CLASSIFIER_MODELS = {
  /** For Macs with less than 16 GB of memory. */
  small: ['qwen2.5:0.5b', 'qwen3:0.6b', 'gemma3:1b', 'llama3.2:1b'],
  /** For everything else. */
  regular: [
    'qwen2.5:1.5b',
    'qwen3:1.7b',
    'gemma3:1b',
    'llama3.2:3b',
    'qwen2.5:0.5b',
    'llama3.2:1b',
  ],
} as const;

const GB = 1024 ** 3;

/**
 * Below 16 GB the 0.5B model: 1.5B is half the speed per token and keeps about
 * 1 GB resident (measured on GitHub's Intel and M1 runners, docs/performance.md).
 */
const SMALL_BELOW = 16 * GB;

/** The model setup suggests pulling on this Mac. */
export function recommendedClassifierModel(memoryBytes: number = totalmem()): string {
  return memoryBytes < SMALL_BELOW ? CLASSIFIER_MODELS.small[0] : CLASSIFIER_MODELS.regular[0];
}

/** The first suitable small model the user has installed, or nothing. */
export function pickClassifierModel(
  installed: ReadonlyArray<{ name: string }>,
  memoryBytes: number = totalmem(),
): string | undefined {
  const names = new Set(installed.flatMap((m) => [m.name, m.name.replace(/:latest$/, '')]));
  const list = memoryBytes < SMALL_BELOW ? CLASSIFIER_MODELS.small : CLASSIFIER_MODELS.regular;
  return list.find((m) => names.has(m));
}

/** Ollama settings that keep a small model light: short context, half the cores, unloaded soon. */
export function classifierRuntime(cores: number = cpus().length) {
  return {
    numCtx: 4096,
    // The answer lists only flagged events, so it is short; this stops a loop early.
    numPredict: 256,
    numThread: Math.max(1, Math.floor(cores / 2)),
    keepAlive: '1m',
  } as const;
}

export type EventLabel = 'benign' | 'unusual' | 'suspicious';

export interface LabelledEvent {
  readonly eventId: string;
  readonly label: EventLabel;
  /** 0 to 1: how much a person should look at it. Orders the review list, nothing else. */
  readonly score: number;
  readonly reason: string;
  /** Which model labelled it: the local model or Jev. */
  readonly by: 'model' | 'jev';
}

export type ClassifyResult =
  | {
      readonly ok: true;
      readonly labels: readonly LabelledEvent[];
      readonly deferred: readonly string[];
    }
  | {
      readonly ok: false;
      readonly reason: 'budget' | 'busy' | 'failed';
      readonly deferred: readonly string[];
      readonly detail?: string;
    };

const Output = z.strictObject({
  suspicious: z.array(z.string()),
  unusual: z.array(z.string()),
});

// Output tokens are nearly all of a small model's time on a CPU, and a small
// model writing prose runs long and breaks its JSON. So the answer is just two
// lists of short keys; everything not listed is benign.
const INSTRUCTIONS = [
  "Each line in the data is one event from this Mac, starting with its key (e1, e2...). Vigil's rules did not match these events.",
  'Most are normal. Put the key of each event that looks like malware or an attacker in "suspicious"',
  '(hidden or unsigned programs in odd places, new login items, reading browser or keychain data,',
  'connections to strange hosts, listening ports), and the key of each event a careful person might',
  'want to glance at in "unusual". Leave both lists empty if nothing stands out.',
  // Small models follow an example far better than a description.
  'Example: for "e1 process started /usr/bin/git [apple] parent=/bin/zsh" and',
  '"e2 process started /private/tmp/.u/update [unsigned] parent=/bin/bash"',
  'the answer is {"suspicious":["e2"],"unusual":[]}.',
].join(' ');

const SCORE = { benign: 0, unusual: 0.5, suspicious: 0.9 } as const;

function proc(p: ProcessRef | undefined): string {
  if (!p) return '';
  const signing = p.signing ? ` [${p.signing}]` : '';
  const parent = p.parentPath ? ` parent=${p.parentPath}` : '';
  return ` by ${p.path}${signing}${parent}`;
}

/** One short line per event: small models do better with little text. */
export function eventLine(e: SensorEvent): string {
  switch (e.kind) {
    case 'process.exec':
      return `process started ${e.process.path}${e.process.signing ? ` [${e.process.signing}]` : ''}${
        e.process.args?.length ? ` args=${e.process.args.slice(1, 6).join(' ')}` : ''
      }${e.process.parentPath ? ` parent=${e.process.parentPath}` : ''}${
        e.process.quarantine?.originUrl ? ` downloaded from ${e.process.quarantine.originUrl}` : ''
      }`;
    case 'process.exit':
      return `process exited ${e.process.path}`;
    case 'file':
      return `file ${e.op} ${e.path}${e.newPath ? ` -> ${e.newPath}` : ''}${proc(e.process)}`;
    case 'network.connection':
      return `${e.direction} ${e.protocol} ${e.remoteHost ?? e.remoteAddress}:${e.remotePort ?? ''}${proc(e.process)}`;
    case 'persistence':
      return `${e.mechanism} ${e.change} ${e.path}${e.program ? ` runs ${e.program}` : ''}${proc(e.process)}`;
    case 'santa.decision':
      return `santa ${e.decision} ${e.target} ${e.reason}${e.path ? ` ${e.path}` : ''}${proc(e.process)}`;
    case 'network.listen':
      return `listening ${e.protocol} port ${e.localPort}${proc(e.process)}`;
    case 'browser.extension':
      return `${e.browser} extension ${e.change} ${e.name ?? e.extensionId}${
        e.permissions?.length ? ` permissions=${e.permissions.slice(0, 8).join(',')}` : ''
      }`;
    case 'system.alert':
      return `macOS ${e.subtype}${e.path ? ` ${e.path}` : ''}${proc(e.process)}`;
  }
}

export interface EventClassifierOptions {
  /** A runner limited to where labelling may run (see `createVigilAi`). */
  readonly runner?: AiRunner;
  /**
   * TypeSafe's Jev, tried first when set. If it can't answer (no key, refused,
   * over the monthly cap, down), the batch goes to `runner` instead.
   */
  readonly jev?: JevClient;
  /** False once Jev's spending this month reached the cap. */
  readonly jevAllowed?: () => Promise<boolean>;
  readonly maxEventsPerBatch: number;
  /** Most batches per hour wherever they run, local or cloud. */
  readonly maxBatchesPerHour: number;
  /**
   * CPU time the local model may use per hour, in seconds. Each local batch is
   * charged its wall time x `cpuThreads`, so a slow Mac does fewer batches.
   */
  readonly maxCpuSecondsPerHour?: number;
  /** Threads the local model runs with (see `classifierRuntime`). */
  readonly cpuThreads?: number;
  /** The app says when the Mac is busy or on low battery; labelling then waits. */
  readonly isBusy?: () => boolean;
  readonly deadlineMs?: number;
  readonly now?: () => number;
}

/**
 * Labels events that Vigil's rules and baselines didn't already explain, so a
 * person reviews the odd ones first and the rule analysis has somewhere to
 * start. Advisory only: a label never blocks, releases or allows anything.
 */
export function createEventClassifier(options: EventClassifierOptions) {
  const now = options.now ?? Date.now;
  const sent: number[] = [];
  const cpu: Array<{ at: number; seconds: number }> = [];

  return {
    async classify(events: readonly SensorEvent[]): Promise<ClassifyResult> {
      const batch = events.slice(0, options.maxEventsPerBatch);
      const deferred = events.slice(options.maxEventsPerBatch).map((e) => e.id);
      if (batch.length === 0) return { ok: true, labels: [], deferred };
      const all = events.map((e) => e.id);
      if (options.isBusy?.()) return { ok: false, reason: 'busy', deferred: all };
      const hourAgo = now() - 3_600_000;
      while (sent.length > 0 && sent[0]! < hourAgo) sent.shift();
      while (cpu.length > 0 && cpu[0]!.at < hourAgo) cpu.shift();
      const cpuUsed = cpu.reduce((sum, c) => sum + c.seconds, 0);
      if (
        sent.length >= options.maxBatchesPerHour ||
        (options.maxCpuSecondsPerHour !== undefined && cpuUsed >= options.maxCpuSecondsPerHour)
      )
        return { ok: false, reason: 'budget', deferred: all };
      sent.push(now());

      const ids = new Set(batch.map((e) => e.id));
      const labels = new Map<string, LabelledEvent>();
      const done = () => {
        // Events a model skipped go back in the queue rather than counting as benign.
        const missed = batch.filter((e) => !labels.has(e.id)).map((e) => e.id);
        return {
          ok: true as const,
          labels: [...labels.values()],
          deferred: [...missed, ...deferred],
        };
      };

      let jevDetail: string | undefined;
      if (options.jev && (await (options.jevAllowed?.() ?? Promise.resolve(true)))) {
        const jev = await options.jev.label(batch.map((e) => ({ id: e.id, line: eventLine(e) })));
        if (jev.ok) {
          for (const a of jev.answers) if (ids.has(a.id)) labels.set(a.id, fromJev(a));
          return done();
        }
        jevDetail = jev.detail;
      }
      if (!options.runner)
        return {
          ok: false,
          reason: 'failed',
          deferred: all,
          detail: jevDetail ?? 'No model set up.',
        };

      const keyOf = new Map(batch.map((e, i) => [`e${i + 1}`, e.id]));
      const started = now();
      const result = await options.runner.run({
        purpose: 'classify',
        urgency: 'background',
        instructions: INSTRUCTIONS,
        data: batch.map((e, i) => `e${i + 1} ${eventLine(e)}`),
        output: Output,
        deadlineMs: options.deadlineMs ?? 60_000,
      });
      // A cloud provider costs this Mac nothing; failed local runs used the CPU too.
      if (!result.ok || LOCAL_PROVIDERS.includes(result.provider))
        cpu.push({ at: now(), seconds: ((now() - started) / 1000) * (options.cpuThreads ?? 1) });
      if (!result.ok)
        return {
          ok: false,
          reason: 'failed',
          deferred: all,
          ...(result.detail ? { detail: result.detail } : { detail: result.reason }),
        };

      // A small local model flagged half the Apple binaries in a 20-event test,
      // so its labels are shown as hints and don't reorder the feed (score 0).
      const hintOnly = LOCAL_PROVIDERS.includes(result.provider);
      // Suspicious first, so a key in both lists keeps the stronger label.
      for (const label of ['suspicious', 'unusual'] as const)
        for (const key of result.value[label]) {
          const id = keyOf.get(key.trim());
          if (!id || labels.has(id)) continue;
          labels.set(id, {
            eventId: id,
            label,
            score: hintOnly ? 0 : SCORE[label],
            reason: hintOnly ? `Local model hint: ${label}` : `Cloud model: ${label}`,
            by: 'model',
          });
        }
      for (const id of ids)
        if (!labels.has(id))
          labels.set(id, { eventId: id, label: 'benign', score: 0, reason: '', by: 'model' });
      return done();
    },
  };
}

export type EventClassifier = ReturnType<typeof createEventClassifier>;

/**
 * Jev returns calibrated probabilities, not prose. The score weights unusual at
 * half of suspicious; the reason says how sure it was.
 */
function fromJev(a: JevAnswer): LabelledEvent {
  const p = a.probabilities;
  const pct = Math.round(p[a.label] * 100);
  return {
    eventId: a.id,
    label: a.label,
    score: Math.min(1, p.suspicious + p.unusual / 2),
    reason: `Jev: ${pct}% ${a.label}, confidence ${a.confidence.toFixed(2)}`,
    by: 'jev',
  };
}
