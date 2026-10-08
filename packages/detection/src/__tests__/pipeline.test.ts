import { PreflightRequest } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { conditionUsesAgentFields, exclusionHidesAgent, isAgentField } from '../agents/fields.js';
import { toolRequestEvent } from '../agents/preflight.js';
import { ruleLanguageGuide } from '../proposals/tools.js';
import { replayRule } from '../proposals/replay.js';
import { MemoryExceptionStore } from '../state/stores.js';
import { DetectionRule } from '../types.js';
import { userOrigin } from '../user.js';
import { DAY, HOUR, proc, T0, testRule } from './fixtures.js';
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

  it('sends a rule that would interrupt the user all day back to the AI', () => {
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
    expect(res.ok).toBe(false);
    expect(res.status).toBe('rejected_by_checks');
    expect(res.replay!.verdict).toBe('noisy');
    expect(res.errors.join(' ')).toMatch(/alert about [\d.]+ times a day, mostly on .*Chrome/);
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

  it('does not queue the same change twice, and keeps who drafted it', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(baseRule);
    const tune = { ruleId: 'unsigned-net-alert', rationale: 'Your own builds are expected.' };
    const first = pipeline.submitTuning({ ...tune, addExclusion: narrow }, 'claude', 'Scout');
    expect(first.ok).toBe(true);
    expect(pipeline.get(first.proposalId!)).toMatchObject({ by: 'Scout', provider: 'claude' });
    // The same condition with its keys in another order is the same change.
    const again = pipeline.submitTuning(
      { ...tune, addExclusion: { value: ['~/code/**'], op: 'glob', field: 'process.path' } },
      'codex',
    );
    expect(again).toMatchObject({ ok: false, final: true, duplicateOf: first.proposalId });
    const retire = { ruleId: 'unsigned-net-alert', toMode: 'shadow', rationale: 'Noisy.' };
    expect(pipeline.submitRetirement({ ...retire, evidence: ['x'] }, 'claude').ok).toBe(true);
    expect(pipeline.submitRetirement({ ...retire, evidence: ['y'] }, 'claude')).toMatchObject({
      ok: false,
      final: true,
    });
    expect(pipeline.list().filter((p) => p.status === 'awaiting_review')).toHaveLength(2);
    // Once the first is settled, the change can be suggested again.
    pipeline.reject(first.proposalId!, userOrigin('rules-screen'));
    expect(pipeline.submitTuning({ ...tune, addExclusion: narrow }, 'claude').ok).toBe(true);
  });
});

describe('AI proposals about agent rules', () => {
  const watchRule = testRule({
    id: 'agent-secret-command',
    eventKinds: ['process.exec'],
    tags: ['agent-watch'],
    condition: {
      all: [
        { field: 'process.agent.id', op: 'exists' },
        { field: 'process.commandLine', op: 'contains', value: '.aws/credentials' },
      ],
    },
  });
  const toolRule = testRule({
    id: 'my-tool-policy',
    eventKinds: ['agent.tool_request'],
    condition: { field: 'command', op: 'contains', value: 'git push --force' },
    reasons: ['{{tool}} would force-push'],
  });
  const narrow = { field: 'process.sha256', op: 'eq', value: '1'.repeat(64) } as const;
  const tune = (ruleId: string, addExclusion: unknown = narrow) => ({
    ruleId,
    addExclusion,
    rationale: 'This tool is a known build helper.',
  });

  it('refuses to tune or retire an agent rule, for good', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(watchRule);
    engine.upsertRule(toolRule);
    for (const id of ['agent-secret-command', 'my-tool-policy']) {
      expect(pipeline.submitTuning(tune(id), 'claude')).toEqual({
        ok: false,
        errors: ['Agent rules are tuned only by you.'],
        warnings: [],
        final: true,
      });
      const retire = { ruleId: id, toMode: 'shadow', rationale: 'Noisy.', evidence: ['x'] };
      expect(pipeline.submitRetirement(retire, 'claude')).toMatchObject({
        ok: false,
        errors: ['Agent rules are tuned only by you.'],
        final: true,
      });
    }
    expect(pipeline.list()).toEqual([]);
  });

  it('refuses an AI exclusion on agent or tool fields', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(
      testRule({
        id: 'unsigned-net-alert',
        eventKinds: ['network.connection'],
        condition: { field: 'process.signing', op: 'in', value: ['unsigned', 'adhoc'] },
      }),
    );
    const byAgent = { field: 'process.agent.id', op: 'eq', value: 'claude-code' };
    const res = pipeline.submitTuning(
      tune('unsigned-net-alert', { all: [narrow, byAgent] }),
      'claude',
    );
    expect(res.ok).toBe(false);
    expect(res.final).toBeUndefined();
    expect(res.errors.join(' ')).toMatch(/agent or tool-request fields/);
    expect(pipeline.submitTuning(tune('unsigned-net-alert'), 'claude').ok).toBe(true);

    const rule = { ...pasteRule, id: 'paste-quiet', exclusions: [byAgent] };
    const sub = pipeline.submitRule({ rule, rationale: why }, 'claude');
    expect(sub.ok).toBe(false);
    expect(sub.errors.join(' ')).toMatch(/agent or tool-request fields/);
  });

  it('refuses an AI exclusion on the parent, which under an agent is the agent', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(
      testRule({
        id: 'download-pipe-to-shell',
        condition: { field: 'process.commandLine', op: 'contains', value: '| sh' },
      }),
    );
    const parents = [
      { field: 'process.parentName', op: 'in', value: ['claude', 'codex', 'node'] },
      { field: 'process.parentPath', op: 'glob', value: ['**/claude/versions/*'] },
      { all: [narrow, { inList: { list: 'x_y', field: 'process.parentName' } }] },
    ];
    for (const ex of parents) {
      const res = pipeline.submitTuning(tune('download-pipe-to-shell', ex), 'claude');
      expect(res.ok, JSON.stringify(ex)).toBe(false);
      expect(res.errors.join(' ')).toMatch(/agent or tool-request fields/);
    }
    const rule = {
      ...pasteRule,
      id: 'paste-parent',
      exclusions: [{ field: 'process.parentName', op: 'eq', value: 'claude' }],
    };
    expect(pipeline.submitRule({ rule, rationale: why }, 'claude').errors.join(' ')).toMatch(
      /agent or tool-request fields/,
    );
    expect(pipeline.submitTuning(tune('download-pipe-to-shell'), 'claude').ok).toBe(true);
    // Exceptions the user makes are unaffected: parent fields are not agent fields.
    expect(isAgentField('process.parentName')).toBe(false);
    expect(exclusionHidesAgent({ field: 'process.parentPath', op: 'exists' })).toBe(true);
  });

  it('leaves a rule the user wrote about agents to the user, tag or no tag', () => {
    const { pipeline, engine } = twoWeeks();
    engine.upsertRule(
      testRule({
        id: 'my-claude-watch',
        condition: {
          all: [
            { field: 'process.agent.id', op: 'eq', value: 'claude-code' },
            { field: 'process.name', op: 'eq', value: 'curl' },
          ],
        },
      }),
    );
    expect(pipeline.submitTuning(tune('my-claude-watch'), 'claude')).toEqual({
      ok: false,
      errors: ['Agent rules are tuned only by you.'],
      warnings: [],
      final: true,
    });
    const retire = {
      ruleId: 'my-claude-watch',
      toMode: 'shadow',
      rationale: 'Noisy.',
      evidence: ['x'],
    };
    expect(pipeline.submitRetirement(retire, 'claude')).toMatchObject({
      ok: false,
      errors: ['Agent rules are tuned only by you.'],
      final: true,
    });
    // A rule that only carves agents out is still an ordinary rule.
    engine.upsertRule(
      testRule({
        id: 'plain-exec',
        condition: { field: 'process.name', op: 'eq', value: 'curl' },
        exclusions: [{ field: 'process.agent.id', op: 'eq', value: 'claude-code' }],
      }),
    );
    expect(pipeline.submitTuning(tune('plain-exec'), 'claude').ok).toBe(true);
  });

  it('tells the AI which lists anchor a rule and which fields it may not exclude on', () => {
    const text = ruleLanguageGuide().constraints.join(' ');
    expect(text).toMatch(/list lookup on a command line, path or URL does not count/);
    expect(text).toMatch(/process\.parentName/);
    expect(text).toMatch(/tuned and retired only by the user/);
  });

  it('knows which fields describe an agent', () => {
    for (const f of ['process.agent', 'process.agent.id', 'process.ancestors', 'agent.id', 'cwd'])
      expect(isAgentField(f)).toBe(true);
    for (const f of ['process.agentx', 'process.cwd', 'process.path', 'commandLine', 'urls'])
      expect(isAgentField(f)).toBe(false);
    expect(
      conditionUsesAgentFields({ not: { firstSeen: { key: ['process.path', 'tool'] } } }),
    ).toBe(true);
    expect(conditionUsesAgentFields({ inList: { list: 'x_y', field: 'url' } })).toBe(true);
    expect(conditionUsesAgentFields({ any: [narrow, { field: 'path', op: 'exists' }] })).toBe(
      false,
    );
  });
});

describe('replaying tool-request rules', () => {
  let seq = 0;
  /** About 20 Bash requests a day, all in a 2-hour session, for two weeks. */
  function withSessions() {
    const w = twoWeeks();
    for (let day = 0; day < 14; day++)
      for (let i = 0; i < 20; i++) {
        const req = PreflightRequest.parse({
          v: 1,
          method: 'preflight.check',
          host: 'claude-code',
          tool: 'Bash',
          command: `git log --oneline -${i + 1}`,
          commandBytes: 20,
        });
        w.stores.history.append(
          toolRequestEvent(req, { id: `tr${seq++}`, ts: T0 + day * DAY + 9 * HOUR + i * 360_000 }),
        );
      }
    return w;
  }
  const gitRule = {
    id: 'git-asks',
    name: 'Agent runs git',
    eventKinds: ['agent.tool_request'],
    severity: 'low',
    fidelity: 'low',
    condition: {
      all: [
        { field: 'tool', op: 'eq', value: 'Bash' },
        { field: 'command', op: 'contains', value: 'git' },
      ],
    },
    reasons: ['The agent runs git.'],
  };

  it('counts every match as a question, the way pre-flight asks', () => {
    const { stores } = withSessions();
    const { report } = replayRule(
      DetectionRule.parse(testRule({ ...gitRule, mode: 'alert' })),
      { history: stores.history, lists: stores.lists, userExceptions: new MemoryExceptionStore() },
      { from: T0, to: T0 + 14 * DAY },
    );
    expect(report.hits).toBe(280);
    expect(report.popups).toBe(report.hits);
    expect(report.topPrograms).toEqual([{ program: 'Bash', hits: 280 }]);
    expect(report.samples[0]!.subject).toBe('git log --oneline -1');
  });

  it('sends a noisy AI tool-request rule back, naming the tool and command', () => {
    const { pipeline } = withSessions();
    const res = pipeline.submitRule({ rule: gitRule, rationale: why }, 'claude');
    expect(res.status).toBe('rejected_by_checks');
    const msg = res.errors.join(' ');
    expect(msg).toMatch(/20\.0 times a day/);
    expect(msg).toMatch(/Bash/);
    expect(msg).toMatch(/git log/);
    expect(msg).not.toMatch(/\/bin\/zsh/);
  });
});

describe('replaying rules on parent names', () => {
  const ctx = () => {
    const { stores } = twoWeeks();
    return {
      history: stores.history,
      lists: stores.lists,
      userExceptions: new MemoryExceptionStore(),
    };
  };
  const onParent = DetectionRule.parse(
    testRule({
      id: 'osascript-under-python',
      condition: {
        all: [
          { field: 'process.name', op: 'eq', value: 'osascript' },
          { field: 'process.parentName', op: 'eq', value: 'python3' },
        ],
      },
    }),
  );

  it('says the history it would fire on was not kept, rather than "never fired"', () => {
    const { report } = replayRule(onParent, ctx(), { from: T0, to: NOW });
    expect(report.hits).toBe(0);
    expect(report.verdict).toBe('quiet');
    expect(report.notes.join(' ')).toMatch(/undercounts a rule on parent names/);
  });

  it('keeps "never fired" for a rule limited to agents, whose parents are kept', () => {
    const scoped = DetectionRule.parse(
      testRule({
        id: 'osascript-under-agent-python',
        condition: {
          all: [
            { field: 'process.agent.id', op: 'exists' },
            { field: 'process.parentName', op: 'eq', value: 'python3' },
          ],
        },
      }),
    );
    const { report } = replayRule(scoped, ctx(), { from: T0, to: NOW });
    expect(report.verdict).toBe('never_fired');
    expect(report.notes.join(' ')).not.toMatch(/parent names/);
  });

  it('warns the AI that its rule on parent names cannot be measured', () => {
    const { pipeline } = twoWeeks();
    const res = pipeline.submitRule(
      {
        rule: {
          id: 'osa-py',
          name: 'osascript under python',
          eventKinds: ['process.exec'],
          severity: 'medium',
          fidelity: 'medium',
          condition: {
            all: [
              { field: 'process.name', op: 'eq', value: 'osascript' },
              { field: 'process.parentName', op: 'eq', value: 'python3' },
            ],
          },
          reasons: ['{{process.name}} under python'],
        },
        rationale: why,
      },
      'claude',
    );
    expect(res.ok).toBe(true);
    expect(res.warnings.join(' ')).toMatch(/undercounts a rule on parent names/);
  });
});
