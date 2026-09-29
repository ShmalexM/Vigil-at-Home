import { describe, expect, it } from 'vitest';
import { proveChange } from '../proposals/prover.js';
import { DetectionRule } from '../types.js';
import { DAY, testRule } from './fixtures.js';
import { NOW, twoWeeks } from './history.js';

const baseRule = DetectionRule.parse(
  testRule({
    id: 'unsigned-net-alert',
    name: 'Unsigned program online',
    eventKinds: ['network.connection'],
    severity: 'low',
    mode: 'alert',
    condition: { field: 'process.signing', op: 'in', value: ['unsigned', 'adhoc'] },
    reasons: ['{{process.name}} connected out'],
  }),
);

function withBase() {
  const setup = twoWeeks();
  setup.engine.upsertRule(baseRule);
  return setup;
}

function tune(addExclusion: unknown) {
  const { pipeline } = withBase();
  const res = pipeline.submitTuning(
    { ruleId: baseRule.id, addExclusion, rationale: 'Your own builds are expected.' },
    'claude',
  );
  return { res, p: pipeline.get(res.proposalId!)! };
}

describe('prover: what a change would stop catching', () => {
  it('flags a path exclusion that an unsigned copy at the same path would slip through', () => {
    const { res, p } = tune({ field: 'process.path', op: 'glob', value: ['~/code/**'] });
    expect(p.impact?.verdict).toBe('broad');
    expect(p.impact?.lookAlikes[0]).toMatchObject({
      how: 'An unsigned program at /Users/alex/code/app/bin/server',
    });
    expect(p.impact?.findings[0]).toMatch(/would also be skipped/);
    // The AI hears about it too, so its fix-up can narrow the exclusion.
    expect(res.warnings.join(' ')).toMatch(/Too broad/);
  });

  it('a hash exclusion goes quiet only on that exact program', () => {
    const { res, p } = tune({ field: 'process.sha256', op: 'eq', value: '1'.repeat(64) });
    expect(p.impact).toMatchObject({ verdict: 'narrow', lookAlikes: [] });
    expect(p.impact?.lostEvents).toBe(p.tuning?.removed);
    expect(p.impact?.stopsAlertingOn[0]).toMatchObject({
      what: '/Users/alex/code/app/bin/server -> github.com',
      untrusted: true,
    });
    expect(p.impact?.findings.join(' ')).toMatch(/stayed quiet on \d+ events from 1 source/);
    expect(res.warnings.join(' ')).not.toMatch(/Too broad/);
  });

  it('flags a host exclusion that would hide any program talking to that host', () => {
    const { p } = tune({ field: 'remoteHost', op: 'eq', value: 'github.com' });
    expect(p.impact?.lookAlikes.map((l) => l.how)).toContain(
      'Any unsigned program talking to github.com',
    );
  });

  it('a retirement says it stops alerting on everything the rule looks for', () => {
    const { pipeline } = withBase();
    const res = pipeline.submitRetirement(
      { ruleId: baseRule.id, toMode: 'shadow', rationale: 'Noisy.', evidence: ['x'] },
      'claude',
    );
    const impact = pipeline.get(res.proposalId!)!.impact!;
    expect(impact.verdict).toBe('broad');
    expect(impact.findings[0]).toMatch(/stop alerting on everything/);
  });

  it('a new rule only adds', () => {
    const { pipeline } = twoWeeks();
    const res = pipeline.submitRule(
      {
        rule: {
          id: 'paste',
          name: 'Paste site',
          eventKinds: ['network.connection'],
          severity: 'medium',
          condition: { field: 'remoteHost', op: 'in', value: ['pastebin.com'] },
          reasons: ['{{process.name}} talked to {{remoteHost}}'],
        },
        rationale: 'Paste sites move data.',
      },
      'claude',
    );
    expect(pipeline.get(res.proposalId!)!.impact).toMatchObject({ verdict: 'no_loss' });
  });

  it('turning block down to alert says it stops blocking', () => {
    const { stores } = twoWeeks();
    const impact = proveChange({
      before: baseRule,
      beforeMode: 'block',
      after: baseRule,
      afterMode: 'alert',
      history: stores.history,
      lists: stores.lists,
      from: NOW - 14 * DAY,
      to: NOW,
    });
    expect(impact.verdict).toBe('broad');
    expect(impact.findings).toContain('It would stop blocking. You would get an alert instead.');
    expect(impact.lostEvents).toBe(0);
  });
});
