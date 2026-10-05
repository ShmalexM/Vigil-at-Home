import { DatabaseSync } from 'node:sqlite';
import type { RunRequest, RunResult } from '@vigil/ai';
import type { PreflightReply } from '@vigil/core';
import { describe, expect, it, vi } from 'vitest';
import type { z } from 'zod';
import type { ToolListing } from '../agents/tools.js';
import type { ConnectorHub, ConnectorRecord, RemoteTool } from './connectors.js';
import { Notebook } from './notebook.js';
import { PackService, type PackAiStatus } from './service.js';

type Handler = (req: RunRequest<unknown>) => Promise<unknown> | unknown;

const LISTING = (name: string): ToolListing => ({
  name: name as ToolListing['name'],
  title: name.replace(/_/g, ' '),
  description: `${name} tool`,
  inputSchema: { type: 'object', properties: { limit: { type: 'number' } } },
  annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false },
});

const GITHUB: ConnectorRecord = {
  id: 'github',
  name: 'GitHub',
  kind: 'stdio',
  command: 'x',
  secrets: [],
  enabled: true,
};
const REMOTE: RemoteTool[] = [
  {
    name: 'list_issues',
    title: 'List issues',
    description: '',
    inputSchema: { type: 'object', properties: {} },
    readOnlyHint: true,
  },
  {
    name: 'create_issue',
    title: 'Create issue',
    description: '',
    inputSchema: { type: 'object', properties: { title: { type: 'string' } }, required: ['title'] },
    readOnlyHint: false,
  },
];

function setup(
  opts: { status?: Partial<PackAiStatus>; preflight?: PreflightReply['decision'] } = {},
) {
  const settings = new Map<string, unknown>();
  const handlers: Handler[] = [];
  const runs: RunRequest<unknown>[] = [];
  const connectorCalls: [string, string, unknown][] = [];
  const vigilCalls: string[] = [];
  const notebook = new Notebook(new DatabaseSync(':memory:'));
  const connectors: ConnectorHub = {
    list: () => [GITHUB],
    view: () => [],
    tools: async () => REMOTE,
    knownTools: () => REMOTE,
    call: async (id, tool, args) => {
      connectorCalls.push([id, tool, args]);
      return 'ok';
    },
  };
  const pack = new PackService({
    load: <S extends z.ZodType>(key: string, schema: S, fallback: z.infer<S>) =>
      settings.has(key) ? (schema.parse(settings.get(key)) as z.infer<S>) : fallback,
    save: (k, v) => settings.set(k, JSON.parse(JSON.stringify(v))),
    ai: {
      run: async <T>(req: RunRequest<T>): Promise<RunResult<T>> => {
        runs.push(req as RunRequest<unknown>);
        const h = handlers.shift();
        if (!h) return { ok: false, reason: 'no_provider', logId: 'x' };
        const value = await h(req as RunRequest<unknown>);
        return { ok: true, value: req.output.parse(value), provider: 'codex', logId: 'x' };
      },
      modelOf: () => 'gpt-5.5',
      status: async () => ({
        anyReady: true,
        judge: { ready: true, detail: 'Codex checks risky calls' },
        leadMayUsePlan: false,
        ...opts.status,
      }),
    },
    vigilTools: {
      list: () => [LISTING('list_alerts'), LISTING('search_events')],
      call: (name) => {
        vigilCalls.push(name);
        return { v: 1, ok: true, result: { rows: [] } };
      },
    },
    preflight: () => ({ v: 1, decision: opts.preflight ?? 'none', reason: 'A rule says so' }),
    connectors,
    notebook,
    onChange: () => undefined,
  });
  return { pack, handlers, runs, connectorCalls, vigilCalls, notebook };
}

const tool = (req: RunRequest<unknown>, name: string) => {
  const t = req.tools?.find((x) => x.name === name);
  if (!t) throw new Error(`no tool ${name}`);
  return t;
};

const CREATE = {
  kind: 'create',
  name: 'Pip',
  breed: 'chihuahua',
  job: 'Check Downloads every hour.',
  schedule: 'hourly',
  tools: ['vigil.search_events'],
};

describe('the pack', () => {
  it('always has a Lead dog and the three built-in helpers', () => {
    const { pack } = setup();
    expect(pack.dogs().map((d) => [d.role, d.name])).toEqual([
      ['lead', 'Scout'],
      ['helper', 'Sunny'],
      ['helper', 'Biscuit'],
      ['helper', 'Duke'],
    ]);
    pack.updateDog('lead', { name: 'Rex', breed: 'husky' });
    expect(pack.dogs()[0]).toMatchObject({ name: 'Rex', breed: 'husky', role: 'lead' });
  });

  it('runs the Lead dog as the user’s own chat, and pack jobs as background work', async () => {
    const { pack, handlers, runs } = setup();
    handlers.push(() => ({ reply: 'Hi!', actions: [] }));
    await pack.say('hello');
    expect(runs[0]).toMatchObject({ purpose: 'chat', requestedByUser: true });
    expect(runs[0]!.instructions).toContain('hello');

    const dog = pack.adopt({ ...CREATE, breed: 'chihuahua', schedule: 'hourly' } as never);
    handlers.push(() => ({ summary: 'All quiet', findings: [] }));
    await pack.runDog(dog.id);
    expect(runs[1]).toMatchObject({ purpose: 'analyze' });
    expect(runs[1]!.requestedByUser).toBeUndefined();
    expect(pack.dogs().find((d) => d.id === dog.id)?.lastReport).toMatchObject({
      ok: true,
      summary: 'All quiet',
    });
  });

  it('tells the Lead dog which page and item the person had open', async () => {
    const { pack, handlers, runs } = setup();
    handlers.push(() => ({ reply: 'That one is a test.', actions: [] }));
    await pack.say('what is this?', { page: 'alerts', selected: 'alert-123' });
    expect(runs[0]!.data).toMatchObject({ lookingAt: { page: 'alerts', selected: 'alert-123' } });
    handlers.push(() => ({ reply: 'Hi', actions: [] }));
    await pack.say('hi');
    expect(runs[1]!.data).not.toHaveProperty('lookingAt');
    await expect(pack.say('x', { page: '../etc' })).rejects.toThrow();
  });

  it('asks before the Lead dog changes the pack in Ask for approval', async () => {
    const { pack, handlers } = setup();
    handlers.push(() => ({ reply: 'Pip can do that.', actions: [CREATE] }));
    await pack.say('watch downloads');
    expect(pack.dogs().some((d) => d.name === 'Pip')).toBe(false);
    const msg = pack.chat().at(-1)!;
    expect(msg.actions?.[0]).toMatchObject({ kind: 'create', status: 'pending' });
    pack.decideAction(msg.id, msg.actions![0]!.id, true);
    expect(pack.dogs().find((d) => d.name === 'Pip')).toMatchObject({
      createdBy: 'lead',
      breed: 'chihuahua',
    });
    expect(pack.chat().at(-1)!.actions![0]!.status).toBe('done');
  });

  it('lets Full access add dogs straight away, and Let AI decide only with read-only tools', async () => {
    const { pack, handlers } = setup();
    pack.setMode('full');
    handlers.push(() => ({ reply: 'Done.', actions: [CREATE] }));
    await pack.say('go');
    expect(pack.dogs().some((d) => d.name === 'Pip')).toBe(true);

    pack.setMode('auto');
    handlers.push(() => ({
      reply: 'Two more.',
      actions: [
        { ...CREATE, name: 'Taco' },
        { ...CREATE, name: 'Frank', breed: 'dachshund', tools: ['github.create_issue'] },
      ],
    }));
    await pack.say('more');
    const names = pack.dogs().map((d) => d.name);
    expect(names).toContain('Taco');
    expect(names).not.toContain('Frank');
    expect(pack.chat().at(-1)!.actions![1]).toMatchObject({ status: 'pending' });
  });

  it('never lets the Lead dog retire or send off a built-in helper, or the Lead dog itself', async () => {
    const { pack, handlers } = setup();
    pack.setMode('full');
    handlers.push(() => ({
      reply: 'Hmm.',
      actions: [
        { kind: 'retire', dogId: 'helper-explainer' },
        { kind: 'run', dogId: 'lead' },
      ],
    }));
    await pack.say('retire Sunny');
    expect(
      pack
        .chat()
        .at(-1)!
        .actions!.map((a) => a.status),
    ).toEqual(['failed', 'failed']);
    expect(pack.dogs()).toHaveLength(4);
  });

  it('drops tools nobody knows from what the Lead dog asks for', async () => {
    const { pack, handlers } = setup();
    pack.setMode('full');
    handlers.push(() => ({
      reply: 'ok',
      actions: [{ ...CREATE, tools: ['vigil.search_events', 'vigil.rules_edit', 'shell.run'] }],
    }));
    await pack.say('x');
    expect(pack.dogs().find((d) => d.name === 'Pip')?.tools).toEqual(['vigil.search_events']);
  });

  it('runs read-only tools at once, and asks the user before a tool that changes things', async () => {
    const { pack, handlers, connectorCalls, vigilCalls } = setup();
    const dog = pack.adopt({
      ...CREATE,
      tools: ['vigil.search_events', 'github.create_issue'],
    } as never);
    let denied: unknown;
    handlers.push(async (req) => {
      await tool(req, 'search_events').run({});
      const pending = tool(req, 'github_create_issue').run({ title: 'x' });
      await vi.waitFor(async () => expect((await pack.view()).approvals).toHaveLength(1));
      const a = (await pack.view()).approvals[0]!;
      expect(a).toMatchObject({ dogId: dog.id, why: 'mode', toolTitle: 'GitHub › Create issue' });
      expect((await pack.view()).dogs.find((d) => d.id === dog.id)?.mood).toBe('waiting');
      pack.decideTool(a.id, 'deny');
      denied = await pending;
      // Allowed once, it runs.
      const again = tool(req, 'github_create_issue').run({ title: 'y' });
      await vi.waitFor(async () => expect((await pack.view()).approvals).toHaveLength(1));
      pack.decideTool((await pack.view()).approvals[0]!.id, 'allow-once');
      await again;
      return { summary: 'done', findings: [] };
    });
    await pack.runDog(dog.id);
    expect(vigilCalls).toEqual(['search_events']);
    expect(String(denied)).toContain('said no');
    expect(connectorCalls).toEqual([['github', 'create_issue', { title: 'y' }]]);
  });

  it('refuses what a Vigil rule stops, even in Full access', async () => {
    const { pack, handlers, connectorCalls } = setup({ preflight: 'deny' });
    pack.setMode('full');
    const dog = pack.adopt({ ...CREATE, tools: ['github.list_issues'] } as never);
    let answer: unknown;
    handlers.push(async (req) => {
      answer = await tool(req, 'github_list_issues').run({});
      return { summary: 'x', findings: [] };
    });
    await pack.runDog(dog.id);
    expect(String(answer)).toContain('A rule says so');
    expect(connectorCalls).toEqual([]);
  });

  it('in Let AI decide, runs what the AI rates low risk and asks about the rest', async () => {
    const { pack, handlers, runs, connectorCalls } = setup();
    pack.setMode('auto');
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    handlers.push(async (req) => {
      await tool(req, 'github_create_issue').run({ title: 'low' });
      const risky = tool(req, 'github_create_issue').run({ title: 'high' });
      await vi.waitFor(async () => expect((await pack.view()).approvals).toHaveLength(1));
      expect((await pack.view()).approvals[0]).toMatchObject({
        why: 'judged-risky',
        reason: 'posts publicly',
      });
      pack.decideTool((await pack.view()).approvals[0]!.id, 'deny');
      await risky;
      return { summary: 'x', findings: [] };
    });
    handlers.push(() => ({ risk: 'low', reason: 'small' }));
    handlers.push(() => ({ risk: 'high', reason: 'posts publicly' }));
    // The job's handler runs first and calls the judge twice from inside it.
    const order = [...handlers];
    handlers.length = 0;
    handlers.push(order[0]!);
    const judges = [order[1]!, order[2]!];
    const job = pack.runDog(dog.id);
    // Judges are separate runs that start while the job runs.
    handlers.push(...judges);
    await job;
    expect(connectorCalls).toEqual([['github', 'create_issue', { title: 'low' }]]);
    // A pack job's risk checks are background work: never on a Claude plan.
    const judgeRuns = runs.filter((r) => r.instructions.includes('Rate how risky'));
    expect(judgeRuns).toHaveLength(2);
    for (const r of judgeRuns) expect(r).toMatchObject({ purpose: 'analyze' });
    for (const r of judgeRuns) expect(r.requestedByUser).toBeUndefined();
  });

  it('never trusts a server’s read-only hint: connector tools ask unless you set Always allow', async () => {
    const { pack, handlers, connectorCalls } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.list_issues'] } as never);
    const tools = (await pack.view()).tools.find((t) => t.key === 'github.list_issues');
    expect(tools).toMatchObject({ readOnly: false, serverHint: true });
    handlers.push(async (req) => {
      const call = tool(req, 'github_list_issues').run({});
      await vi.waitFor(async () => expect((await pack.view()).approvals).toHaveLength(1));
      expect((await pack.view()).approvals[0]).toMatchObject({ why: 'mode' });
      pack.decideTool((await pack.view()).approvals[0]!.id, 'deny');
      await call;
      return { summary: 'x', findings: [] };
    });
    await pack.runDog(dog.id);
    expect(connectorCalls).toEqual([]);

    // Marked by the user, it runs without asking.
    pack.setToolChoice('github.list_issues', 'allow');
    handlers.push(async (req) => {
      await tool(req, 'github_list_issues').run({});
      return { summary: 'x', findings: [] };
    });
    await pack.runDog(dog.id);
    expect(connectorCalls).toEqual([['github', 'list_issues', {}]]);
  });

  it('in Let AI decide, waits before giving a dog a connector tool its server calls read-only', async () => {
    const { pack, handlers } = setup();
    pack.setMode('auto');
    handlers.push(() => ({
      reply: 'ok',
      actions: [{ ...CREATE, name: 'Lint', tools: ['github.list_issues'] }],
    }));
    await pack.say('x');
    expect(pack.dogs().some((d) => d.name === 'Lint')).toBe(false);
    expect(pack.chat().at(-1)!.actions![0]).toMatchObject({ status: 'pending' });

    pack.setToolChoice('github.list_issues', 'allow');
    handlers.push(() => ({
      reply: 'ok',
      actions: [{ ...CREATE, name: 'Lint', tools: ['github.list_issues'] }],
    }));
    await pack.say('again');
    expect(pack.dogs().some((d) => d.name === 'Lint')).toBe(true);
  });

  it('checks again right before the call: a tool switched off while you were asked does not run', async () => {
    const { pack, handlers, connectorCalls } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    let answer: unknown;
    handlers.push(async (req) => {
      const call = tool(req, 'github_create_issue').run({ title: 'x' });
      await vi.waitFor(async () => expect((await pack.view()).approvals).toHaveLength(1));
      pack.setToolChoice('github.create_issue', 'off');
      pack.decideTool((await pack.view()).approvals[0]!.id, 'allow-once');
      answer = await call;
      return { summary: 'x', findings: [] };
    });
    await pack.runDog(dog.id);
    expect(String(answer)).toContain('switched this tool off');
    expect(connectorCalls).toEqual([]);
  });

  it('hides tools the user switched off', async () => {
    const { pack, handlers } = setup();
    pack.setToolChoice('vigil.search_events', 'off');
    const dog = pack.adopt({
      ...CREATE,
      tools: ['vigil.search_events', 'vigil.list_alerts'],
    } as never);
    let offered: string[] = [];
    handlers.push((req) => {
      offered = (req.tools ?? []).map((t) => t.name);
      return { summary: 'x', findings: [] };
    });
    await pack.runDog(dog.id);
    expect(offered).toEqual(['list_alerts']);
  });

  it('runs scheduled dogs once they are due', async () => {
    const { pack, handlers, runs } = setup();
    const dog = pack.adopt(CREATE as never);
    await pack.runDue();
    expect(runs).toHaveLength(0);
    // An hour later it is due.
    const later = Date.now() + 61 * 60_000;
    vi.useFakeTimers({ now: later, toFake: ['Date'] });
    try {
      handlers.push(() => ({ summary: 'ok', findings: [] }));
      await pack.runDue();
      expect(runs).toHaveLength(1);
      expect(runs[0]).toMatchObject({ purpose: 'analyze', urgency: 'background' });
    } finally {
      vi.useRealTimers();
    }
    expect(pack.dogs().find((d) => d.id === dog.id)?.lastReport?.ok).toBe(true);
  });

  it('talks plainly when the person turns on Plain wording', async () => {
    const { pack, handlers, runs } = setup();
    expect((await pack.view()).voice).toBe('pack');
    handlers.push(() => ({ reply: 'Woof', actions: [] }));
    await pack.say('hi');
    expect(runs[0]!.instructions).toContain('dog humour is fine');
    pack.setVoice('plain');
    handlers.push(() => ({ reply: 'Hello', actions: [] }));
    await pack.say('hi');
    expect(runs[1]!.instructions).toContain('plain wording');
    expect(runs[1]!.instructions).not.toContain('dog humour');
    pack.helperBusy('labeller', true);
    const biscuit = (await pack.view()).dogs.find((d) => d.helper === 'labeller');
    expect(biscuit).toMatchObject({ mood: 'sniffing', activity: 'Labelling new events' });
    expect(() => pack.setVoice('loud' as never)).toThrow();
  });

  describe('notebooks', () => {
    it('writes down what the Lead dog was asked, looked at and the reasons it gave', async () => {
      const { pack, handlers } = setup();
      handlers.push(async (req) => {
        await tool(req, 'list_alerts').run({});
        return {
          reply: 'That one is a test alert.',
          actions: [],
          why: ['list_alerts showed it came from the Test button'],
        };
      });
      await pack.say('what is this?', { page: 'alerts', selected: 'alert-123' });
      const [note] = pack.notes({ dog: 'lead' });
      expect(note).toMatchObject({
        kind: 'chat',
        ok: true,
        ask: 'what is this?',
        subject: { kind: 'alert', id: 'alert-123' },
        answer: 'That one is a test alert.',
        reasons: ['list_alerts showed it came from the Test button'],
        provider: 'codex',
        model: 'gpt-5.5',
      });
      expect(note!.lookedAt).toHaveLength(1);
      // The same note answers "why?" about that alert.
      expect(pack.notes({ subject: { kind: 'alert', id: 'alert-123' } })).toHaveLength(1);
    });

    it('notes a run that failed, and a job’s findings and risk checks', async () => {
      const { pack, handlers } = setup();
      await pack.say('hello');
      expect(pack.notes({ dog: 'lead' })[0]).toMatchObject({ ok: false, ask: 'hello' });

      pack.setMode('auto');
      const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
      handlers.push(async (req) => {
        const call = tool(req, 'github_create_issue').run({ title: 'x' });
        handlers.push(() => ({ risk: 'low', reason: 'files one issue, easy to close' }));
        await call;
        return {
          summary: 'One new unsigned program',
          findings: [{ title: 'unsigned.app ran', severity: 'medium' }],
          why: ['search_events found one exec from Downloads'],
        };
      });
      await pack.runDog(dog.id);
      const [job, judged] = pack.notes({ dog: dog.id });
      expect(job).toMatchObject({
        kind: 'job',
        ask: CREATE.job,
        answer: 'One new unsigned program',
        reasons: ['search_events found one exec from Downloads', 'medium: unsigned.app ran'],
      });
      expect(judged).toMatchObject({
        kind: 'judge',
        answer: 'low risk',
        reasons: ['files one issue, easy to close'],
        subject: { kind: 'tool', id: 'github.create_issue' },
      });
    });

    it('files a built-in helper’s note under that helper', () => {
      const { pack } = setup();
      pack.helperNote('explainer', { kind: 'explain', ok: true, ask: 'Explain', answer: 'Fine' });
      const sunny = pack.dogs().find((d) => d.helper === 'explainer')!;
      expect(pack.notes({ dog: sunny.id })).toHaveLength(1);
      pack.clearNotes(sunny.id);
      expect(pack.notes()).toHaveLength(0);
    });
  });
});
