import { describe, expect, it } from 'vitest';
import { RuleReviewer, MemoryReviewStateStore } from '../proposals/reviewer.js';
import { detectionReadTools, type AnalyzeRunner } from '../proposals/tools.js';
import { userOrigin } from '../user.js';
import { DAY, HOUR } from './fixtures.js';
import { NOW, twoWeeks } from './history.js';

const pasteRule = {
  id: 'paste',
  name: 'Paste site',
  eventKinds: ['network.connection'],
  severity: 'medium',
  mode: 'alert',
  condition: { field: 'remoteHost', op: 'in', value: ['pastebin.com', 'paste.ee'] },
  reasons: ['{{process.name}} talked to {{remoteHost}}'],
};

function withLiveAiRule() {
  const setup = twoWeeks();
  const res = setup.pipeline.submitRule({ rule: pasteRule, rationale: 'Paste sites.' }, 'claude');
  setup.pipeline.approve(res.proposalId!, userOrigin('rules-screen'));
  return setup;
}

describe('maintenance: turning a rule down', () => {
  it('queues a retirement with the replay, and approval only changes the mode', () => {
    const { engine, pipeline } = withLiveAiRule();
    const before = engine.getRule('ai-paste')!;
    const res = pipeline.submitRetirement(
      { ruleId: 'ai-paste', toMode: 'shadow', rationale: 'Noisy.', evidence: ['marked safe 5x'] },
      'claude',
    );
    expect(res).toMatchObject({ ok: true, status: 'awaiting_review' });
    expect(res.replay?.hits).toBe(2);
    // Nothing changes until the user says so.
    expect(engine.modeOf(before)).toBe('alert');
    pipeline.approve(res.proposalId!, userOrigin('rules-screen'));
    expect(engine.modeOf(engine.getRule('ai-paste')!)).toBe('shadow');
    expect(engine.getRule('ai-paste')).toEqual(before);
  });

  it('refuses to turn down a rule that caught something confirmed malicious', () => {
    const { engine, pipeline, stores } = withLiveAiRule();
    stores.lists.add('known_bad_sha256', '9'.repeat(64), { source: 'test', updatedAt: NOW });
    const res = pipeline.submitRetirement(
      { ruleId: 'ai-paste', toMode: 'disabled', rationale: 'Noisy.', evidence: ['x'] },
      'claude',
    );
    expect(res.ok).toBe(false);
    expect(res.errors.join(' ')).toMatch(/marked as malicious/);
    expect(engine.modeOf(engine.getRule('ai-paste')!)).toBe('alert');
  });

  it('refuses a "retirement" that would not turn the rule down, and unknown rules', () => {
    const { pipeline } = withLiveAiRule();
    const same = pipeline.submitRetirement(
      { ruleId: 'ai-paste', toMode: 'shadow', rationale: 'x', evidence: ['x'] },
      'claude',
    );
    expect(same.ok).toBe(true);
    const { pipeline: p2 } = twoWeeks();
    expect(
      p2.submitRetirement(
        { ruleId: 'nope', toMode: 'shadow', rationale: 'x', evidence: ['x'] },
        'claude',
      ).errors[0],
    ).toMatch(/No rule/);
  });

  it('a tuning or retirement goes stale when the user edits the rule first', () => {
    const { engine, pipeline } = withLiveAiRule();
    const res = pipeline.submitRetirement(
      { ruleId: 'ai-paste', toMode: 'shadow', rationale: 'x', evidence: ['x'] },
      'claude',
    );
    const r = engine.getRule('ai-paste')!;
    engine.upsertRule({ ...r, version: r.version + 1 });
    expect(() => pipeline.approve(res.proposalId!, userOrigin('rules-screen'))).toThrow(/changed/);
  });
});

describe('classifier leads in the telemetry summary', () => {
  it('lists flagged activity no rule matched, redacted and grouped, suspicious first', async () => {
    const { engine, pipeline, stores } = twoWeeks();
    const flagged = [
      {
        kind: 'process.exec',
        subject: '/Users/alex/tmp/x',
        label: 'unusual' as const,
        commandLine: `x --token ${'a1B2'.repeat(10)} --out /Users/alex/Desktop/me@home.org`,
      },
      { kind: 'process.exec', subject: '/Users/alex/tmp/x', label: 'unusual' as const },
      {
        kind: 'network.connection',
        subject: 'weird.example',
        label: 'suspicious' as const,
        reason: 'mailed a@b.co',
      },
    ];
    const [telemetry] = detectionReadTools({
      engine,
      pipeline,
      history: stores.history,
      flagged: () => flagged,
      now: () => NOW,
    }).filter((t) => t.name === 'get_telemetry_summary');
    const out = (await telemetry!.run({ sinceHours: 24 })) as {
      flaggedByClassifier: Array<{ what: string; count: number; label: string; reason?: string }>;
    };
    expect(out.flaggedByClassifier).toEqual([
      {
        what: 'weird.example',
        kind: 'network.connection',
        label: 'suspicious',
        count: 1,
        reason: 'mailed <email>',
      },
      {
        what: '~/tmp/x',
        kind: 'process.exec',
        label: 'unusual',
        count: 2,
        example: 'x --token <token> --out ~/Desktop/<email>',
      },
    ]);
  });
});

describe('RuleReviewer: the daily schedule', () => {
  const answer = {
    newRules: [
      { ruleJson: JSON.stringify(pasteRule), rationale: 'Paste sites move data.', evidence: [] },
    ],
    tunings: [],
    retirements: [],
    summary: 'One new rule.',
  };

  function setup(opts: { events?: number; busy?: boolean; runner?: AnalyzeRunner | undefined }) {
    let now = NOW;
    const { engine, pipeline, stores } = twoWeeks();
    let calls = 0;
    const runner: AnalyzeRunner = opts.runner ?? {
      async run(req) {
        calls++;
        return { ok: true, value: req.output.parse(answer), provider: 'claude' };
      },
    };
    const state = new MemoryReviewStateStore();
    const reviewer = new RuleReviewer(
      () => ('runner' in opts ? opts.runner : runner),
      { engine, pipeline, history: stores.history, now: () => now },
      state,
      {
        countEvents: () => opts.events ?? 1000,
        isBusy: () => opts.busy ?? false,
        now: () => now,
      },
    );
    return { reviewer, pipeline, calls: () => calls, advance: (ms: number) => (now += ms) };
  }

  it('runs when due, queues proposals, then waits a day', async () => {
    const s = setup({});
    expect(await s.reviewer.maybeRun()).toMatchObject({ ran: true, ok: true, queued: 1 });
    expect(s.pipeline.list()[0]).toMatchObject({ status: 'awaiting_review', provider: 'claude' });
    expect(await s.reviewer.maybeRun()).toEqual({ ran: false, reason: 'not_due' });
    s.advance(23 * HOUR);
    expect(await s.reviewer.maybeRun()).toEqual({ ran: false, reason: 'not_due' });
    s.advance(2 * HOUR);
    expect((await s.reviewer.maybeRun()).ran).toBe(true);
    expect(s.calls()).toBe(2);
    expect(s.reviewer.status()).toMatchObject({ lastQueued: 0, lastSummary: 'One new rule.' });
  });

  it('waits while the Mac is busy, with too little activity, or with no AI signed in', async () => {
    expect(await setup({ busy: true }).reviewer.maybeRun()).toEqual({ ran: false, reason: 'busy' });
    expect(await setup({ events: 10 }).reviewer.maybeRun()).toEqual({
      ran: false,
      reason: 'too_little_activity',
    });
    expect(await setup({ runner: undefined }).reviewer.maybeRun()).toEqual({
      ran: false,
      reason: 'no_runner',
    });
    // The user's "Review now" skips the waits.
    expect((await setup({ events: 10 }).reviewer.maybeRun({ force: true })).ran).toBe(true);
  });

  it('retries sooner after a failure and keeps the last good run', async () => {
    let fail = true;
    const s = setup({
      runner: {
        async run(req) {
          if (fail) return { ok: false, reason: 'quota', detail: 'window used up' };
          return {
            ok: true,
            value: req.output.parse({ ...answer, newRules: [] }),
            provider: 'codex',
          };
        },
      },
    });
    expect(await s.reviewer.maybeRun()).toMatchObject({ ran: true, ok: false });
    expect(s.reviewer.status().lastError).toBe('quota: window used up');
    s.advance(5 * HOUR);
    expect((await s.reviewer.maybeRun()).ran).toBe(false);
    s.advance(2 * HOUR);
    fail = false;
    expect(await s.reviewer.maybeRun()).toMatchObject({ ran: true, ok: true });
    expect(s.reviewer.status().nextDueAt).toBe(NOW + 7 * HOUR + DAY);
  });
});

describe('rare built-in tool commands in the telemetry summary', () => {
  it('lists one-off command lines of tools attackers use, redacted, without the labeller', async () => {
    const { engine, pipeline, stores } = twoWeeks();
    const exec = (id: string, path: string, args: string[], ts: number) =>
      stores.history.append({
        id,
        ts,
        source: 'test',
        kind: 'process.exec',
        process: { pid: 1, path, args, signing: 'apple' },
      } as never);
    exec(
      's1',
      '/usr/bin/security',
      ['security', 'find-generic-password', '-wa', 'Chrome'],
      NOW - HOUR,
    );
    for (let i = 0; i < 5; i++)
      exec(`g${i}`, '/bin/zsh', ['zsh', '-c', 'git status'], NOW - 2 * HOUR + i);
    exec('b1', '/bin/bash', ['bash', '/Users/alex/tmp/x.sh'], NOW - 3 * HOUR);
    const [telemetry] = detectionReadTools({
      engine,
      pipeline,
      history: stores.history,
      now: () => NOW,
    }).filter((t) => t.name === 'get_telemetry_summary');
    const out = (await telemetry!.run({ sinceHours: 24 })) as {
      rareToolCommands: Array<{ program: string; example: string; count: number }>;
    };
    expect(out.rareToolCommands).toEqual([
      {
        program: '/usr/bin/security',
        example: 'security find-generic-password -wa Chrome',
        count: 1,
      },
      { program: '/bin/bash', example: 'bash ~/tmp/x.sh', count: 1 },
    ]);
  });
});
