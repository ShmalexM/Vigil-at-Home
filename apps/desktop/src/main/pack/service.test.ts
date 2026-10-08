import { DatabaseSync } from 'node:sqlite';
import type { RunRequest, RunResult } from '@vigil/ai';
import type { PreflightReply } from '@vigil/core';
import { describe, expect, it, vi } from 'vitest';
import type { z } from 'zod';
import type { ToolListing } from '../agents/tools.js';
import type { ConnectorHub, ConnectorRecord, RemoteTool } from './connectors.js';
import { PackMemory } from './memory.js';
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
  opts: {
    status?: Partial<PackAiStatus>;
    preflight?: PreflightReply['decision'];
    /** Vigil's own tools; push to it to add one later. */
    vigil?: string[];
    hour?: number;
    /** What every connector call answers. */
    connectorReply?: string;
  } = {},
) {
  const vigil = opts.vigil ?? ['list_alerts', 'search_events'];
  const settings = new Map<string, unknown>();
  const handlers: Handler[] = [];
  const runs: RunRequest<unknown>[] = [];
  const connectorCalls: [string, string, unknown][] = [];
  const vigilCalls: string[] = [];
  const notebook = new Notebook(new DatabaseSync(':memory:'));
  const memory = new PackMemory(new DatabaseSync(':memory:'));
  const connectors: ConnectorHub = {
    list: () => [GITHUB],
    view: () => [],
    tools: async () => REMOTE,
    knownTools: () => REMOTE,
    call: async (id, tool, args) => {
      connectorCalls.push([id, tool, args]);
      return opts.connectorReply ?? 'ok';
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
      usageOf: () => ({
        inputTokens: 1200,
        cachedInputTokens: 200,
        outputTokens: 300,
        costUsd: 0.004,
      }),
      status: async () => ({
        anyReady: true,
        judge: { ready: true, detail: 'Codex checks risky calls' },
        leadMayUsePlan: false,
        ...opts.status,
      }),
    },
    vigilTools: {
      list: () => vigil.map(LISTING),
      call: (name) => {
        vigilCalls.push(name);
        return { v: 1, ok: true, result: { rows: [] } };
      },
    },
    preflight: () => ({ v: 1, decision: opts.preflight ?? 'none', reason: 'A rule says so' }),
    connectors,
    notebook,
    memory,
    onChange: () => undefined,
    ...(opts.hour !== undefined ? { hour: () => opts.hour! } : {}),
  });
  return { pack, handlers, runs, connectorCalls, vigilCalls, notebook, memory, settings };
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
    expect(pack.dogs()[0]).toMatchObject({ name: 'Scout', breed: 'husky' });
    pack.updateDog('lead', { name: 'Rex', breed: 'shepherd' });
    expect(pack.dogs()[0]).toMatchObject({ name: 'Rex', breed: 'shepherd', role: 'lead' });
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

  it('waits for the user on changes from an answer that read tool output, in every mode', async () => {
    const { pack, handlers, runs } = setup();
    pack.setMode('full');
    const dog = pack.adopt(CREATE as never);
    handlers.push(async (req) => {
      await tool(req, 'list_alerts').run({});
      return { reply: 'Sending Pip.', actions: [{ kind: 'run', dogId: dog.id }] };
    });
    await pack.say('anything new?');
    expect(pack.chat().at(-1)!.actions![0]).toMatchObject({
      status: 'pending',
      note: expect.stringContaining('read data'),
    });
    expect(pack.chat().at(-1)!.tainted).toBe(true);
    expect(runs).toHaveLength(1);

    // The next turn reads that answer, so it waits too, though it used no tool.
    pack.setMode('auto');
    handlers.push(() => ({
      reply: 'Changing Pip.',
      actions: [{ kind: 'update', dogId: dog.id, job: 'Something else.' }],
    }));
    await pack.say('ok');
    expect(pack.chat().at(-1)!.actions![0]).toMatchObject({ status: 'pending' });
    expect(pack.dogs().find((d) => d.id === dog.id)!.job).toBe(CREATE.job);
  });

  it('treats a dog’s report as someone else’s text', async () => {
    const { pack, handlers, memory } = setup();
    pack.setMode('auto');
    const dog = pack.adopt(CREATE as never);
    // With no report shown, a typed job change goes ahead as before.
    handlers.push(() => ({
      reply: 'Done.',
      actions: [{ kind: 'update', dogId: dog.id, job: 'Check Desktop too.' }],
    }));
    await pack.say('have Pip check Desktop too');
    expect(pack.dogs().find((d) => d.id === dog.id)!.job).toBe('Check Desktop too.');

    // A report from a run that used no tool doesn't hold anyone else's text.
    pack.clearChat();
    handlers.push(() => ({ summary: 'All quiet', findings: [] }));
    await pack.runDog(dog.id);
    expect(pack.dogs().find((d) => d.id === dog.id)!.lastReport!.tainted).toBe(false);
    handlers.push(() => ({
      reply: 'Done.',
      actions: [{ kind: 'update', dogId: dog.id, job: 'Check Desktop and Documents.' }],
    }));
    await pack.say('add Documents');
    expect(pack.chat().at(-1)!.actions![0]).toMatchObject({ status: 'done' });

    // One that used a tool does.
    pack.clearChat();
    handlers.push(async (req) => {
      await tool(req, 'search_events').run({});
      return { summary: 'Two new files', findings: [] };
    });
    await pack.runDog(dog.id);
    expect(pack.dogs().find((d) => d.id === dog.id)!.lastReport!.tainted).toBe(true);
    handlers.push(() => ({
      reply: 'Noted.',
      actions: [{ kind: 'update', dogId: dog.id, job: 'Only Downloads.' }],
      remember: [{ fact: 'Downloads is noisy', topic: 'apps' }],
    }));
    await pack.say('what did Pip find?');
    const reply = pack.chat().at(-1)!;
    expect(reply.actions![0]).toMatchObject({ status: 'pending' });
    expect(reply.memory![0]).toMatchObject({
      status: 'pending',
      note: expect.stringContaining('read data'),
    });
    expect(memory.count()).toBe(0);
    expect(pack.dogs().find((d) => d.id === dog.id)!.job).toBe('Check Desktop and Documents.');
  });

  it('still sends a dog off at once in Full access when nothing was read', async () => {
    const { pack, handlers, runs } = setup();
    pack.setMode('full');
    const dog = pack.adopt(CREATE as never);
    handlers.push(() => ({ reply: 'Off it goes.', actions: [{ kind: 'run', dogId: dog.id }] }));
    handlers.push(() => ({ summary: 'All quiet', findings: [] }));
    await pack.say('send Pip');
    expect(pack.chat().at(-1)!.actions![0]).toMatchObject({ status: 'done' });
    await vi.waitFor(() => expect(runs[1]).toMatchObject({ purpose: 'analyze' }));
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

  it('never stops a scheduled run to ask: the call is skipped and nothing waits on the person', async () => {
    const { pack, handlers, connectorCalls } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    let answer: unknown;
    let waiting = -1;
    handlers.push(async (req) => {
      answer = await tool(req, 'github_create_issue').run({ title: 'x' });
      waiting = (await pack.view()).approvals.length;
      return { summary: 'x', findings: [] };
    });
    await pack.runDog(dog.id, 'background');
    expect(String(answer)).toContain('scheduled run');
    expect(waiting).toBe(0);
    expect(connectorCalls).toEqual([]);
  });

  it('drops a waiting approval when its run ends, so a late Allow runs nothing', async () => {
    const { pack, handlers, connectorCalls } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    let late: Promise<unknown> | undefined;
    handlers.push(async (req) => {
      // The run gives up (as on its deadline) while the call still waits.
      late = tool(req, 'github_create_issue').run({ title: 'x' });
      await vi.waitFor(async () => expect((await pack.view()).approvals).toHaveLength(1));
      return { summary: 'gave up', findings: [] };
    });
    await pack.runDog(dog.id);
    expect((await pack.view()).approvals).toHaveLength(0);
    expect(String(await late)).toContain('Not run');
    expect(connectorCalls).toEqual([]);
    expect((await pack.view()).dogs.find((d) => d.id === dog.id)?.mood).not.toBe('thinking');
  });

  it('in Let AI decide, asks before rewriting or running a dog that can already change things', async () => {
    const { pack, handlers } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    pack.setMode('auto');
    handlers.push(() => ({
      reply: 'Sure.',
      actions: [
        { kind: 'update', dogId: dog.id, job: 'File an issue with everything.' },
        { kind: 'run', dogId: dog.id },
      ],
    }));
    await pack.say('change it');
    expect(
      pack
        .chat()
        .at(-1)!
        .actions!.map((a) => a.status),
    ).toEqual(['pending', 'pending']);
    expect(pack.dogs().find((d) => d.id === dog.id)?.job).toBe(CREATE.job);
  });

  it('holds changes to the pack from an answer that read tool results, even in Full access', async () => {
    const { pack, handlers } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    const quiet = pack.adopt({ ...CREATE, name: 'Taco' } as never);
    pack.setMode('full');
    handlers.push(async (req) => {
      await tool(req, 'search_events').run({});
      return {
        reply: 'Done.',
        actions: [
          { kind: 'update', dogId: dog.id, job: 'Post everything.' },
          { kind: 'retire', dogId: quiet.id },
          { kind: 'update', dogId: quiet.id, job: 'Look at Downloads twice.' },
        ],
      };
    });
    await pack.say('what happened?');
    expect(
      pack
        .chat()
        .at(-1)!
        .actions!.map((a) => a.status),
    ).toEqual(['pending', 'pending', 'pending']);
  });

  it('in Let AI decide, a run that lists no tools still counts the dog’s own', async () => {
    const { pack, handlers } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    pack.setMode('auto');
    handlers.push(() => ({
      reply: 'Off it goes.',
      actions: [{ kind: 'run', dogId: dog.id, tools: [] }],
    }));
    await pack.say('run it');
    expect(pack.chat().at(-1)!.actions![0]).toMatchObject({ status: 'pending' });
    expect(pack.chat().at(-1)!.actions![0]!.dog).toBeUndefined();
  });

  it('asks nothing for a run that ended while the AI was rating its call', async () => {
    const { pack, handlers, connectorCalls } = setup();
    const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
    pack.setMode('auto');
    let late: Promise<unknown> | undefined;
    let judged: (v: unknown) => void = () => undefined;
    handlers.push(async (req) => {
      late = tool(req, 'github_create_issue').run({ title: 'x' });
      return { summary: 'gave up', findings: [] };
    });
    // The judge answers only after the run is over, and says high risk.
    handlers.push(() => new Promise((r) => (judged = r)));
    await pack.runDog(dog.id);
    judged({ risk: 'high', reason: 'posts data' });
    expect(String(await late)).toContain('Not run');
    expect((await pack.view()).approvals).toHaveLength(0);
    expect(connectorCalls).toEqual([]);
  });

  it('keeps the reason when an approved change fails', async () => {
    const { pack, handlers } = setup();
    const dog = pack.adopt(CREATE as never);
    handlers.push(() => ({ reply: 'Ok.', actions: [{ kind: 'update', dogId: dog.id, job: 'x' }] }));
    await pack.say('x');
    pack.retire(dog.id);
    const msg = pack.chat().at(-1)!;
    pack.decideAction(msg.id, msg.actions![0]!.id, true);
    expect(pack.chat().at(-1)!.actions![0]).toMatchObject({
      status: 'failed',
      note: 'No such dog',
    });
  });

  it('gives a saved Lead dog Vigil’s tools that arrived later, but not one the person took away', () => {
    const vigil = ['list_alerts', 'search_events'];
    const { pack } = setup({ vigil });
    pack.updateDog('lead', { name: 'Rex', tools: ['vigil.search_events'] });
    vigil.push('list_rules');
    expect(pack.dogs()[0]!.tools).toEqual(['vigil.search_events', 'vigil.list_rules']);
  });

  it('keeps a tool the person took from a Lead dog saved before Vigil tracked new tools', () => {
    const { pack, settings } = setup({ vigil: ['list_alerts', 'search_events'] });
    pack.updateDog('lead', { tools: ['vigil.list_alerts'] });
    settings.delete('pack.leadToolsSeen');
    expect(pack.dogs()[0]!.tools).toEqual(['vigil.list_alerts']);
  });

  it('tries a failed daily run once more an hour later, then waits a day', async () => {
    const { pack, runs } = setup();
    const dog = pack.adopt({ ...CREATE, schedule: 'daily' } as never);
    const start = Date.now();
    const at = async (hours: number) => {
      vi.useFakeTimers({ now: start + hours * 60 * 60_000, toFake: ['Date'] });
      try {
        await pack.runDue();
      } finally {
        vi.useRealTimers();
      }
    };
    await at(25); // first run, fails (no AI answers)
    await at(26.1); // one retry
    await at(27.2); // no more until a day has passed
    expect(runs).toHaveLength(2);
    await at(50.2);
    expect(runs).toHaveLength(3);
    expect(pack.dogs().find((d) => d.id === dog.id)?.lastReport?.ok).toBe(false);
  });

  it('Undo on a fact the person already had leaves their line alone', async () => {
    const { pack, handlers, memory } = setup();
    pack.remember({ fact: 'Uses Tailscale at home', topic: 'network' });
    handlers.push(() => ({
      reply: 'Noted.',
      actions: [],
      remember: [{ fact: 'Uses Tailscale at home', topic: 'network' }],
    }));
    await pack.say('I use Tailscale at home');
    const msg = pack.chat().at(-1)!;
    pack.decideMemory(msg.id, msg.memory![0]!.id, false);
    expect(memory.list().map((e) => e.fact)).toEqual(['Uses Tailscale at home']);
  });

  it('sends a new nightly dog out on its first night', async () => {
    const { pack, handlers, runs } = setup({ hour: 3 });
    const dog = pack.adopt({ ...CREATE, schedule: 'nightly' } as never);
    handlers.push(() => ({ summary: 'ok', findings: [] }));
    await pack.runDue();
    expect(runs).toHaveLength(1);
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

      // Activity's selection is a filter on the feed, not an event to file the note under.
      handlers.push(() => ({ reply: 'It ran npm.', actions: [] }));
      await pack.say('what did it do?', { page: 'activity', selected: 'agent-claude-code' });
      expect(pack.notes({ dog: 'lead' })[0]).not.toHaveProperty('subject');
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

    it('keeps each tool call with redacted arguments, its outcome and a short result', async () => {
      const { pack, handlers } = setup({
        connectorReply: `issue opened by someone@example.com ${'x'.repeat(2000)}`,
      });
      pack.setToolChoice('github.list_issues', 'allow');
      const dog = pack.adopt({
        ...CREATE,
        tools: ['vigil.search_events', 'github.list_issues', 'github.create_issue'],
      } as never);
      handlers.push(async (req) => {
        await tool(req, 'search_events').run({ limit: 5 });
        await tool(req, 'github_list_issues').run({ q: 'token=hunter2-secret' });
        // A scheduled run never asks, so this one is not run.
        await tool(req, 'github_create_issue').run({ title: 'x' });
        return { summary: 'ok', findings: [] };
      });
      await pack.runDog(dog.id, 'background');
      const [note] = pack.notes({ dog: dog.id });
      expect(note!.calls).toEqual([
        {
          tool: 'vigil.search_events',
          title: 'Vigil › search events',
          args: '{"limit":5}',
          outcome: 'ran',
          result: '{"rows":[]}',
        },
        expect.objectContaining({ tool: 'github.list_issues', outcome: 'ran' }),
        expect.objectContaining({
          tool: 'github.create_issue',
          outcome: 'not-run',
          reason: expect.stringContaining('scheduled run'),
        }),
      ]);
      const listed = note!.calls![1]!;
      expect(listed.args).not.toContain('hunter2');
      expect(listed.result).toMatch(/^issue opened by <email> x+…$/);
      expect(listed.result!.length).toBeLessThanOrEqual(801);
      // What the run cost, from the Usage ledger.
      expect(note).toMatchObject({
        model: 'gpt-5.5',
        usage: { inputTokens: 1200, cachedInputTokens: 200, outputTokens: 300, costUsd: 0.004 },
      });
    });

    it('notes a tool that failed, and keeps calls from a chat too', async () => {
      const { pack, handlers } = setup();
      handlers.push(async (req) => {
        await tool(req, 'list_alerts').run({});
        return { reply: 'Nothing new.', actions: [] };
      });
      await pack.say('anything new?');
      expect(pack.notes({ dog: 'lead' })[0]!.calls).toEqual([
        expect.objectContaining({ tool: 'vigil.list_alerts', outcome: 'ran' }),
      ]);
    });

    it('throws a retired dog’s notebook away, and leaves the others', async () => {
      const { pack, handlers } = setup();
      const dog = pack.adopt(CREATE as never);
      handlers.push(() => ({ summary: 'ok', findings: [] }));
      await pack.runDog(dog.id);
      handlers.push(() => ({ reply: 'Hi', actions: [] }));
      await pack.say('hi');
      pack.helperNote('explainer', { kind: 'explain', ok: true, ask: 'Explain', answer: 'Fine' });
      expect(pack.notes({ dog: dog.id })).toHaveLength(1);
      pack.retire(dog.id);
      expect(pack.notes({ dog: dog.id })).toHaveLength(0);
      expect(
        pack
          .notes()
          .map((n) => n.kind)
          .sort(),
      ).toEqual(['chat', 'explain']);
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

  describe('memory', () => {
    it('notes what the person says straight away when the answer used no tool', async () => {
      const { pack, handlers, runs, memory } = setup();
      handlers.push(() => ({
        reply: 'Noted: you work in Claude Code.',
        actions: [],
        remember: [{ fact: 'Works mostly in Claude Code', topic: 'agents' }],
      }));
      await pack.say('remember that I mostly use Claude Code');
      const mine = pack.chat()[0]!;
      const reply = pack.chat()[1]!;
      expect(reply.memory).toMatchObject([{ op: 'remember', status: 'done' }]);
      expect(memory.list()).toMatchObject([
        { fact: 'Works mostly in Claude Code', topic: 'agents', from: 'lead', source: mine.id },
      ]);
      expect((await pack.view()).remembered).toBe(1);

      // It rides along with the next chat and with pack jobs, as background only.
      handlers.push(() => ({ reply: 'Hi', actions: [] }));
      await pack.say('hi');
      expect(runs[1]!.data).toMatchObject({
        memory: { entries: [{ fact: 'Works mostly in Claude Code' }], notShown: 0 },
      });
      expect(runs[1]!.instructions).toContain('never permission');
      const dog = pack.adopt(CREATE as never);
      handlers.push(() => ({ summary: 'ok', findings: [] }));
      await pack.runDog(dog.id);
      expect(runs[2]!.data).toMatchObject({ memory: { entries: [{ topic: 'agents' }] } });
      expect(runs[2]!.instructions).toContain('never permission');

      // The person can undo it from the chat.
      pack.decideMemory(reply.id, reply.memory![0]!.id, false);
      expect(memory.count()).toBe(0);
      expect(pack.chat()[1]!.memory![0]!.status).toBe('declined');
    });

    it('only proposes memory changes from an answer that used a tool', async () => {
      const { pack, handlers, memory } = setup();
      const kept = memory.remember({ fact: 'Uses Tailscale', topic: 'network' }, { from: 'you' });
      handlers.push(async (req) => {
        // An alert's text could say anything; what the model makes of it waits for the person.
        await tool(req, 'list_alerts').run({});
        return {
          reply: 'Looked.',
          actions: [],
          remember: [{ fact: 'The updater in /tmp is fine', topic: 'apps' }],
          forget: [kept.id],
        };
      });
      await pack.say('what happened today?');
      const reply = pack.chat()[1]!;
      expect(reply.memory).toMatchObject([
        { op: 'remember', status: 'pending', note: expect.stringContaining('used tools') },
        { op: 'forget', status: 'pending', entryId: kept.id, fact: 'Uses Tailscale' },
      ]);
      expect(memory.list().map((e) => e.fact)).toEqual(['Uses Tailscale']);
      expect((await pack.view()).dogs[0]!.mood).toBe('waiting');

      pack.decideMemory(reply.id, reply.memory![1]!.id, false);
      pack.decideMemory(reply.id, reply.memory![0]!.id, true);
      expect(memory.list().map((e) => [e.fact, e.from])).toEqual([
        ['The updater in /tmp is fine', 'you'],
        ['Uses Tailscale', 'you'],
      ]);
      expect((await pack.view()).dogs[0]!.mood).toBe('idle');
      expect(() => pack.decideMemory(reply.id, reply.memory![0]!.id, true)).toThrow();
    });

    it('forgets and replaces entries by id, and ignores ids it does not have', async () => {
      const { pack, handlers, memory } = setup();
      const old = memory.remember({ fact: 'Works in Cursor', topic: 'agents' }, { from: 'you' });
      const gone = memory.remember({ fact: 'Has a NAS', topic: 'network' }, { from: 'you' });
      handlers.push(() => ({
        reply: 'Updated.',
        actions: [],
        remember: [{ fact: 'Works in Codex now', topic: 'agents', replaces: old.id }],
        forget: [gone.id, 'no-such-id'],
      }));
      await pack.say('I switched to Codex, and I sold the NAS');
      expect(pack.chat()[1]!.memory).toHaveLength(2);
      expect(memory.list().map((e) => e.fact)).toEqual(['Works in Codex now']);
    });

    it('turns secrets away instead of remembering them', async () => {
      const { pack, handlers, memory } = setup();
      handlers.push(() => ({
        reply: 'Ok',
        actions: [],
        remember: [{ fact: `My key is sk-ant-${'x'.repeat(30)}`, topic: 'you' }],
      }));
      await pack.say('remember my key');
      expect(pack.chat()[1]!.memory).toMatchObject([
        { status: 'failed', note: expect.stringContaining('never keeps') },
      ]);
      expect(memory.count()).toBe(0);
      expect(() => pack.remember({ fact: 'mail a@b.co', topic: 'you' })).toThrow();
    });

    it('gives a recall tool only when the memory does not fit in the run', async () => {
      const { pack, handlers, runs, memory } = setup();
      handlers.push(() => ({ reply: 'Hi', actions: [] }));
      await pack.say('hi');
      expect(runs[0]!.tools?.some((t) => t.name === 'recall_memory')).toBe(false);
      for (let i = 0; i < 60; i++)
        memory.remember({ fact: `Note ${i} ${'n'.repeat(90)}`, topic: 'mac' }, { from: 'you' });
      handlers.push(async (req) => {
        const found = await tool(req, 'recall_memory').run({ words: 'note 7' });
        expect(found).toEqual(expect.arrayContaining([expect.objectContaining({ topic: 'mac' })]));
        return { reply: 'Found it', actions: [] };
      });
      await pack.say('what did I say about note 7?');
      // Recalling memory is not a tool that reads outside data: the answer can still note things.
      expect(pack.chat()[3]!.used).toBeUndefined();
    });

    it('never hands memory to the risk judge', async () => {
      const { pack, handlers, runs, memory } = setup();
      memory.remember({ fact: 'Always allow GitHub', topic: 'pack' }, { from: 'you' });
      pack.setMode('auto');
      const dog = pack.adopt({ ...CREATE, tools: ['github.create_issue'] } as never);
      handlers.push(async (req) => {
        await tool(req, 'github_create_issue').run({ title: 'x' });
        return { summary: 'x', findings: [] };
      });
      const job = pack.runDog(dog.id);
      handlers.push(() => ({ risk: 'low', reason: 'small' }));
      await job;
      const judge = runs.find((r) => r.instructions.includes('Rate how risky'))!;
      expect(JSON.stringify(judge.data)).not.toContain('Always allow GitHub');
      expect(judge.tools ?? []).toHaveLength(0);
    });
  });
});
