/**
 * The AI rule review, graded: a few review runs with a real Claude on an API
 * key (ANTHROPIC_API_KEY), on the train or held-out episode, each scored by gradeRules. For comparing
 * prompts and models before changing RULE_REVIEW_PROMPT. Costs about what a
 * review costs in the app, per run, so it only runs when asked:
 *
 *   VIGIL_BENCH_REVIEW=1 VIGIL_REVIEW_SPLITS=train,heldout VIGIL_REVIEW_RUNS=3 \
 *     [VIGIL_REVIEW_MODEL=claude-sonnet-5-5] [VIGIL_REVIEW_PROMPT=path/to/prompt.txt] \
 *     [VIGIL_REVIEW_TAG=baseline] pnpm --filter @vigil/bench bench:review
 *
 * Held-out runs record only their grades. Train runs also record what the AI
 * proposed and why the checks refused anything, which is what a prompt change
 * should be based on.
 */
import { readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import {
  createAiRunner,
  createClaudeAdapter,
  defaultAiSettings,
  memoryPinStore,
  type PromptLogEntry,
} from '@vigil/ai';
import { runRuleReview } from '@vigil/detection';
import { describe, expect, it } from 'vitest';
import { writeResult } from './report.js';
import {
  gradeRules,
  meanInterval,
  queuedRules,
  reviewEpisode,
  type ReviewGrade,
  type Split,
} from './review.js';

const on = process.env['VIGIL_BENCH_REVIEW'] === '1';
const splits = (process.env['VIGIL_REVIEW_SPLITS'] ?? 'train,heldout').split(',') as Split[];
const runs = Number(process.env['VIGIL_REVIEW_RUNS'] ?? 3);
const model = process.env['VIGIL_REVIEW_MODEL'] || undefined;
const promptFile = process.env['VIGIL_REVIEW_PROMPT'] || undefined;
const tag = process.env['VIGIL_REVIEW_TAG'] ?? 'baseline';

describe.skipIf(!on)('AI rule review', () => {
  it('reviews and is graded', async () => {
    const instructions = promptFile ? readFileSync(promptFile, 'utf8') : undefined;
    const log: PromptLogEntry[] = [];
    const runner = createAiRunner({
      settings: {
        ...defaultAiSettings(tmpdir()),
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
      log: { record: (e) => void log.push(e) },
    });

    const out: Record<string, unknown> = { tag, model: model ?? 'default', runs, splits: {} };
    for (const split of splits) {
      const grades: ReviewGrade[] = [];
      const detail: unknown[] = [];
      for (let seed = 1; seed <= runs; seed++) {
        const ep = reviewEpisode(split, seed);
        const before = log.length;
        const res = await runRuleReview(runner, ep.ctx, {
          deadlineMs: 8 * 60_000,
          ...(instructions ? { instructions } : {}),
        });
        const rules = queuedRules(ep.pipeline).map((p) => p.rule);
        const grade = gradeRules(split, rules);
        grades.push(grade);
        const cost = log.slice(before).reduce((s, e) => s + (e.usage?.costUsd ?? 0), 0);
        const line = {
          seed,
          ok: res.ok,
          error: res.error,
          costUsd: cost,
          queued: rules.length,
          ...grade,
        };
        if (split === 'train')
          detail.push({
            ...line,
            summary: res.summary,
            rules: rules.map((r) => ({ id: r.id, name: r.name, condition: r.condition })),
            refused: res.submissions.flatMap((s) =>
              s.results
                .filter((x) => !x.result.ok)
                .map((x) => ({ ref: x.ref, errors: x.result.errors })),
            ),
          });
        else detail.push(line);
        console.log(`VIGIL_REVIEW ${tag} ${split} ${JSON.stringify(line)}`);
      }
      (out['splits'] as Record<string, unknown>)[split] = {
        score: meanInterval(grades.map((g) => g.score)),
        recall: meanInterval(grades.map((g) => g.recall)),
        falseAlertsPerDay: meanInterval(grades.map((g) => g.falseAlertsPerDay)),
        runs: detail,
      };
    }
    out['costUsd'] = log.reduce((s, e) => s + (e.usage?.costUsd ?? 0), 0);
    writeResult(`review-${tag}`, out);
    expect(log.length).toBeGreaterThan(0);
  });
});
