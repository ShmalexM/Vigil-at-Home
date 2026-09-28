import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import * as api from '../index.js';
import {
  detectionReadTools,
  runRuleReview,
  RuleReviewOutput,
  type AnalyzeRunner,
} from '../proposals/tools.js';
import { chrome, connect, exec, proc } from './fixtures.js';
import { twoWeeks } from './history.js';

const T_NOW = Date.UTC(2026, 8, 15);

describe('AI tool surface', () => {
  it('gives the agent exactly two read-only tools with JSON-able inputs', () => {
    const { engine, pipeline, stores } = twoWeeks();
    const tools = detectionReadTools({ engine, pipeline, history: stores.history });
    expect(tools.map((t) => t.name).sort()).toEqual(['get_rule_language', 'get_telemetry_summary']);
    for (const t of tools) expect(() => z.toJSONSchema(z.object(t.input))).not.toThrow();
    expect(() => z.toJSONSchema(RuleReviewOutput)).not.toThrow();
  });

  it('answer schema suits strict structured output: every property required, no open objects', () => {
    const walk = (node: unknown): void => {
      if (!node || typeof node !== 'object') return;
      const n = node as Record<string, unknown>;
      if (n.type === 'object') {
        const props = Object.keys((n.properties ?? {}) as object);
        expect(props.length).toBeGreaterThan(0);
        expect([...((n.required ?? []) as string[])].sort()).toEqual(props.sort());
        expect(n.additionalProperties).toBe(false);
      }
      for (const v of Object.values(n)) walk(v);
    };
    walk(z.toJSONSchema(RuleReviewOutput, { io: 'input' }));
  });

  it('does not export a way to mint user approval from the package root', () => {
    expect(Object.keys(api)).not.toContain('userOrigin');
    expect(Object.keys(api)).not.toContain('mintUserOrigin');
  });

  it('summaries are aggregated and redacted', async () => {
    const { engine, pipeline, stores } = twoWeeks();
    const secret = proc({
      path: '/Users/alex.smith/code/tool',
      args: ['tool', '--token=sk-live-123', 'alex@example.com'],
      signing: 'adhoc',
    });
    for (const e of [
      exec(secret),
      connect(secret, '140.82.112.3', 'github.com'),
      connect(chrome, '142.250.1.1', 'google.com'),
    ]) {
      stores.history.append({ ...e, ts: T_NOW - 1000 });
    }
    const [telemetry] = detectionReadTools({
      engine,
      pipeline,
      history: stores.history,
      now: () => T_NOW,
    }).filter((t) => t.name === 'get_telemetry_summary');
    const text = JSON.stringify(await telemetry!.run({ sinceHours: 24 * 30 }));
    expect(text).not.toContain('alex.smith');
    expect(text).not.toContain('sk-live-123');
    expect(text).not.toContain('alex@example.com');
    expect(text).toContain('~/code/tool');
  });

  it('runs a review: submits proposals, then gives the agent one chance to fix rejected ones', async () => {
    const { engine, pipeline, stores } = twoWeeks();
    const good = {
      rule: {
        id: 'paste',
        name: 'Paste site',
        eventKinds: ['network.connection'],
        severity: 'medium',
        mode: 'alert',
        condition: { field: 'remoteHost', op: 'in', value: ['pastebin.com', 'paste.ee'] },
        reasons: ['{{process.name}} talked to {{remoteHost}}'],
      },
      rationale: 'Paste sites move stolen data.',
    };
    const bad = {
      rule: { ...good.rule, id: 'broad', condition: { field: 'remoteHost', op: 'exists' } },
      rationale: 'Anything with a host name.',
    };
    const seen: unknown[] = [];
    const answers = [
      {
        newRules: [good, bad, { ...good, ruleJson: '{not json' }].map((r) => ({
          ruleJson: 'ruleJson' in r ? r.ruleJson : JSON.stringify(r.rule),
          rationale: r.rationale,
          evidence: [],
        })),
        tunings: [
          {
            ruleId: 'new-network-listener',
            exclusionJson: JSON.stringify({
              field: 'process.teamId',
              op: 'eq',
              value: 'ABCDE12345',
            }),
            rationale: 'Docker opens listeners all day.',
            evidence: [],
          },
        ],
        summary: 'Three ideas.',
      },
      { newRules: [], tunings: [], summary: 'Dropped the broad one.' },
    ];
    const runner: AnalyzeRunner = {
      async run(req) {
        seen.push(req.data);
        expect(req.tools?.map((t) => t.name)).toContain('get_telemetry_summary');
        return { ok: true, value: req.output.parse(answers.shift()), provider: 'claude' };
      },
    };
    const out = await runRuleReview(runner, { engine, pipeline, history: stores.history });
    expect(out.ok).toBe(true);
    expect(out.summary).toBe('Dropped the broad one.');
    expect(out.submissions[0]).toMatchObject({ accepted: 2, rejected: 2 });
    expect(JSON.stringify(seen[1])).toContain('ruleJson is not valid JSON');
    expect(JSON.stringify(seen[1])).toContain('broad');
    expect(pipeline.list().filter((p) => p.status === 'awaiting_review')).toHaveLength(2);
  });

  it('reports a runner failure without throwing', async () => {
    const { engine, pipeline, stores } = twoWeeks();
    const runner: AnalyzeRunner = {
      run: async () => ({ ok: false, reason: 'quota', detail: 'five-hour window used up' }),
    };
    const out = await runRuleReview(runner, { engine, pipeline, history: stores.history });
    expect(out).toMatchObject({ ok: false, error: 'quota: five-hour window used up' });
  });
});
