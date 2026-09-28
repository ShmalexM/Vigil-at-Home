import { describe, expect, it } from 'vitest';
import { userOrigin } from '../user.js';
import { proc, testRule } from './fixtures.js';
import { NOW, twoWeeks } from './history.js';

const pasteRule = {
  id: 'paste-site-upload',
  name: 'Program talking to a paste site',
  eventKinds: ['network.connection'],
  severity: 'medium',
  fidelity: 'medium',
  mode: 'block',
  condition: {
    all: [
      { field: 'remoteHost', op: 'in', value: ['pastebin.com', 'paste.ee'] },
      { field: 'process.signing', op: 'in', value: ['unsigned', 'adhoc'] },
    ],
  },
  reasons: ['{{process.name}} sent data to {{remoteHost}}, a paste site used to move stolen data.'],
};
const why = 'Unsigned programs uploading to paste sites is how stealers exfiltrate.';

const node = proc({ path: '/opt/homebrew/bin/node', signing: 'adhoc', sha256: '2'.repeat(64) });

describe('AI rule proposals', () => {
  it('replays a proposal, forces shadow mode, and waits for the user', () => {
    const { pipeline, engine } = twoWeeks();
    const res = pipeline.submitRule({ rule: pasteRule, rationale: why }, 'claude');
    expect(res.errors).toEqual([]);
    expect(res.ok).toBe(true);
    expect(res.status).toBe('awaiting_review');
    expect(res.replay).toMatchObject({
      hits: 2,
      popups: 2,
      verdict: 'quiet',
      hitsOnAppleSigned: 0,
    });
    const p = pipeline.get(res.proposalId!)!;
    expect(p.rule).toMatchObject({
      id: 'ai-paste-site-upload',
      mode: 'shadow',
      origin: 'ai',
      version: 1,
      provenance: { provider: 'claude', rationale: why },
    });
    expect(engine.getRule('ai-paste-site-upload')).toBeUndefined();
  });

  it('goes live in the mode the user picks, default alert', () => {
    const { pipeline, engine } = twoWeeks();
    const { proposalId } = pipeline.submitRule({ rule: pasteRule, rationale: why }, 'claude');
    expect(() =>
      pipeline.approve(proposalId!, { kind: 'user', via: 'agent', at: 0 } as never),
    ).toThrow(/approval/);
    const live = pipeline.approve(proposalId!, userOrigin('rules-screen'));
    expect(live.mode).toBe('alert');
    expect(engine.modeOf(live)).toBe('alert');
    const d = engine.evaluate({
      id: 'new',
      ts: NOW + 1,
      kind: 'network.connection',
      source: 'test',
      direction: 'outbound',
      protocol: 'tcp',
      remoteAddress: '104.20.1.3',
      remoteHost: 'paste.ee',
      process: node,
    });
    expect(d.find((x) => x.match.ruleId === 'ai-paste-site-upload')?.alert).toBeDefined();
    expect(pipeline.get(proposalId!)).toMatchObject({
      status: 'approved',
      decidedVia: 'rules-screen',
      approvedMode: 'alert',
    });
  });

  it('flags a rule that would interrupt the user all day as noisy', () => {
    const { pipeline } = twoWeeks();
    const res = pipeline.submitRule(
      {
        rule: {
          ...pasteRule,
          id: 'google',
          condition: { field: 'remoteHost', op: 'eq', value: 'google.com' },
        },
        rationale: 'Testing a very broad rule here.',
      },
      'codex',
    );
    expect(res.ok).toBe(true);
    expect(res.replay!.verdict).toBe('noisy');
    expect(res.replay!.notes.join(' ')).toMatch(/times a day/);
  });

  it('refuses to let the AI block on behaviour alone', () => {
    const { pipeline } = twoWeeks();
    const res = pipeline.submitRule(
      {
        rule: {
          ...pasteRule,
          response: [{ kind: 'network.block', address: '{{remoteAddress}}' }],
          condition: { field: 'process.signing', op: 'eq', value: 'adhoc' },
        },
        rationale: 'Block every ad-hoc program.',
      },
      'claude',
    );
    expect(res.ok).toBe(false);
    expect(res.status).toBe('rejected_by_checks');
    expect(res.errors.join(' ')).toMatch(/names a specific/);
  });

  it('refuses release actions in an AI rule', () => {
    const { pipeline } = twoWeeks();
    const res = pipeline.submitRule(
      {
        rule: {
          ...pasteRule,
          id: 'rel',
          response: [{ kind: 'network.unblock', address: '{{remoteAddress}}' }],
        },
        rationale: 'Unblock paste sites automatically.',
      },
      'claude',
    );
    expect(res.errors.join(' ')).toMatch(/releases or allows/);
  });

  it('allows an AI kill rule anchored on a specific hash', () => {
    const { pipeline } = twoWeeks();
    const res = pipeline.submitRule(
      {
        rule: {
          ...pasteRule,
          id: 'stealer-hash',
          severity: 'critical',
          response: [{ kind: 'process.kill', pid: '{{process.pid}}' }],
          condition: { field: 'process.sha256', op: 'eq', value: '9'.repeat(64) },
        },
        rationale: 'This exact binary exfiltrated data.',
      },
      'claude',
    );
    expect(res.errors).toEqual([]);
    expect(res.replay!.hits).toBe(1);
    expect(res.replay!.samples[0]!.wouldDo).toEqual(['process.kill']);
  });

  it('returns fixable errors for malformed rules and unknown lists', () => {
    const { pipeline } = twoWeeks();
    const bad1 = pipeline.submitRule(
      { rule: { id: 'x-rule', name: 'x' }, rationale: 'missing everything here' },
      'claude',
    );
    expect(bad1.ok).toBe(false);
    expect(bad1.errors.length).toBeGreaterThan(0);
    const bad2 = pipeline.submitRule(
      {
        rule: {
          ...pasteRule,
          id: 'lists',
          condition: { inList: { list: 'made_up_list', field: 'remoteHost' } },
        },
        rationale: 'Uses a list that does not exist.',
      },
      'claude',
    );
    expect(bad2.errors.join(' ')).toMatch(/made_up_list/);
    const bad3 = pipeline.submitRule(
      {
        rule: { ...pasteRule, id: 'only-exists', condition: { field: 'remoteHost', op: 'exists' } },
        rationale: 'Fires on anything with a host.',
      },
      'claude',
    );
    expect(bad3.errors.join(' ')).toMatch(/specific/);
  });

  it('rate-limits proposals per provider per day', () => {
    const { pipeline } = twoWeeks({ maxPerDay: 2 });
    const submit = (id: string, provider: string) =>
      pipeline.submitRule(
        { rule: { ...pasteRule, id }, rationale: 'rate limit test rule' },
        provider,
      );
    expect(submit('a-one', 'claude').ok).toBe(true);
    expect(submit('a-two', 'claude').ok).toBe(true);
    expect(submit('a-three', 'claude').errors[0]).toMatch(/Limit/);
    expect(submit('a-four', 'codex').ok).toBe(true);
  });
});

describe('AI tuning proposals', () => {
  const baseRule = testRule({
    id: 'unsigned-net-alert',
    name: 'Unsigned program online',
    eventKinds: ['network.connection'],
    severity: 'low',
    condition: { field: 'process.signing', op: 'in', value: ['unsigned', 'adhoc'] },
    reasons: ['{{process.name}} connected out'],
  });
  const narrow = { field: 'process.path', op: 'glob', value: ['~/code/**'] };

  it('shows how many hits a narrowing removes and applies it on approval', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(baseRule);
    const res = pipeline.submitTuning(
      {
        ruleId: 'unsigned-net-alert',
        addExclusion: narrow,
        rationale: 'Your own builds in ~/code are expected.',
      },
      'claude',
    );
    expect(res.errors).toEqual([]);
    const p = pipeline.get(res.proposalId!)!;
    expect(p.tuning!.removed).toBeGreaterThan(300);
    expect(p.tuning!.hitsAfter).toBe(2);
    pipeline.approve(res.proposalId!, userOrigin('rules-screen'));
    expect(engine.getRule('unsigned-net-alert')).toMatchObject({ version: 2, mode: 'alert' });
  });

  it('refuses an exclusion that would hide a confirmed threat', () => {
    const { pipeline, engine, stores } = twoWeeks();
    engine.upsertRule(baseRule);
    stores.lists.add('user_blocked_sha256', '9'.repeat(64), { source: 'user', updatedAt: 0 });
    const res = pipeline.submitTuning(
      {
        ruleId: 'unsigned-net-alert',
        addExclusion: { field: 'process.path', op: 'glob', value: ['~/Library/**'] },
        rationale: 'Library helpers are fine.',
      },
      'claude',
    );
    expect(res.ok).toBe(false);
    expect(res.errors.join(' ')).toMatch(/hide 1 detection/);
  });

  it('refuses an exclusion that matches everything', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(baseRule);
    const res = pipeline.submitTuning(
      {
        ruleId: 'unsigned-net-alert',
        addExclusion: { field: 'process.path', op: 'glob', value: ['/**'] },
        rationale: 'Silence it entirely.',
      },
      'claude',
    );
    expect(res.errors.join(' ')).toMatch(/specific/);
  });

  it('refuses a stale approval after the rule changed', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(baseRule);
    const res = pipeline.submitTuning(
      {
        ruleId: 'unsigned-net-alert',
        addExclusion: narrow,
        rationale: 'Your own builds are expected.',
      },
      'claude',
    );
    engine.upsertRule({ ...(baseRule as object), version: 5 } as never);
    expect(() => pipeline.approve(res.proposalId!, userOrigin('rules-screen'))).toThrow(/changed/);
  });
});
